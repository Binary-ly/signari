// Package doctor inspects a deployment and reports what is wrong with it.
//
// # Why this exists
//
// Every feature in this product ships with something that proves it works:
// `proxy check` proves the forward-auth route is protected, `scim verify` proves
// deprovisioning happened, `policy test` proves the rules match their stated
// intent. Each answers one question well.
//
// None of them answers the question an operator actually has on the first day,
// which is "is this deployment sound". That question spans configuration nobody
// checks until it fails: an issuer over plaintext, a root key nobody rotated, a
// SAML provider with no certificate, recovery email that goes to a log file.
//
// # The rule this follows
//
// A finding names what is wrong, why it matters, and what to do. A checker that
// reports "TLS: warning" teaches an operator to ignore it. And a clean result
// says what was checked, because "no findings" and "nothing ran" have looked
// identical at least three times in this project's own history.
package doctor

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Severity ranks a finding.
type Severity int

const (
	// Critical: the deployment is unsafe or a core function is broken.
	Critical Severity = iota
	// Warning: something will fail later, or a protection is off.
	Warning
	// Info: worth knowing, not worth acting on tonight.
	Info
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case Warning:
		return "warning"
	default:
		return "info"
	}
}

// Finding is one thing wrong.
type Finding struct {
	Severity Severity
	Area     string
	Summary  string
	Fix      string
}

// Report is the outcome of an inspection.
type Report struct {
	Findings []Finding
	// Checked names every check that RAN, so a clean report is evidence rather
	// than silence.
	Checked []string
}

func (r *Report) add(sev Severity, area, summary, fix string) {
	r.Findings = append(r.Findings, Finding{sev, area, summary, fix})
}

func (r *Report) ran(what string) { r.Checked = append(r.Checked, what) }

// Count returns how many findings of a severity there are.
func (r *Report) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Inspect examines a deployment.
func Inspect(ctx context.Context, conn *pgx.Conn, issuer string) (*Report, error) {
	r := &Report{}

	checkIssuer(r, issuer)
	checkRootKey(r)
	checkAdminToken(r)
	checkMail(r)
	if err := checkSigningKeys(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkClients(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkSAML(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkFederation(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkOutbox(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkPolicy(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkAdminTokens(ctx, conn, r); err != nil {
		return nil, err
	}

	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity < r.Findings[j].Severity
	})
	return r, nil
}

func checkIssuer(r *Report, issuer string) {
	r.ran("issuer URL")
	switch {
	case issuer == "":
		r.add(Critical, "issuer", "no issuer is configured",
			"set SIGNARI_ISSUER to the public URL relying parties will use")
	case strings.HasPrefix(issuer, "http://"):
		local := strings.Contains(issuer, "localhost") || strings.Contains(issuer, "127.0.0.1")
		sev := Critical
		note := "every token, code and client secret in the flow crosses the network readable"
		if local {
			sev = Info
			note = "acceptable for local development only"
		}
		r.add(sev, "issuer", "the issuer is plaintext HTTP: "+note,
			"serve over HTTPS and set SIGNARI_ISSUER to the https:// URL")
	}
	if strings.HasSuffix(issuer, "/") {
		r.add(Warning, "issuer", "the issuer ends with a slash",
			"remove it: `iss` is compared exactly, and a trailing slash makes every "+
				"token fail validation at relying parties that normalise")
	}
}

func checkRootKey(r *Report) {
	r.ran("root key")
	if os.Getenv("SIGNARI_ROOT_KEY") == "" && os.Getenv("SIGNARI_ROOT_KEY_REF") == "" {
		r.add(Critical, "root key", "no root key is configured",
			"set SIGNARI_ROOT_KEY to base64 of 32 random bytes. It wraps every stored "+
				"private signing key; without it nothing can be unsealed")
	}
}

func checkAdminToken(r *Report) {
	r.ran("admin API token")
	tok := os.Getenv("SIGNARI_ADMIN_TOKEN")
	if tok == "" {
		// Not a finding. The admin API is off unless an address is given, and a
		// deployment that does not run it needs no token.
		return
	}
	if len(tok) < 32 {
		r.add(Critical, "admin API",
			fmt.Sprintf("the admin token is %d characters", len(tok)),
			"use at least 32 random characters. This token is the write surface for "+
				"the entire identity provider, and no rate limit makes a short shared "+
				"secret safe")
	}
}

func checkMail(r *Report) {
	r.ran("outbound mail")
	if os.Getenv("SIGNARI_SMTP_HOST") == "" || os.Getenv("SIGNARI_MAIL_FROM") == "" {
		r.add(Warning, "mail", "no SMTP is configured, so account recovery cannot send email",
			"set SIGNARI_SMTP_HOST and SIGNARI_MAIL_FROM. Until then recovery messages "+
				"are written to the log, which is fine for development and means nobody "+
				"can recover an account in production")
	}
}

func checkSigningKeys(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("signing keys")
	rows, err := conn.Query(ctx, `
		SELECT algorithm, count(*) FILTER (WHERE state = 'active'),
		       count(*) FILTER (WHERE state = 'next')
		FROM core.signing_keys GROUP BY algorithm`)
	if err != nil {
		return err
	}
	defer rows.Close()

	active := map[string]int{}
	for rows.Next() {
		var alg string
		var act, next int
		if err := rows.Scan(&alg, &act, &next); err != nil {
			return err
		}
		active[alg] = act
	}
	if len(active) == 0 {
		r.add(Critical, "keys", "there are no signing keys",
			"run `signari instance create` for this issuer")
		return rows.Err()
	}
	total := 0
	for _, n := range active {
		total += n
	}
	if total == 0 {
		r.add(Critical, "keys", "no signing key is active",
			"run `signari keys rotate` to promote one")
	}
	// SAML needs RS256 specifically, and finding that out when a service provider
	// rejects an assertion is a much worse discovery.
	if active["RS256"] == 0 {
		r.add(Info, "keys", "no active RS256 key",
			"SAML needs one -- most service providers cannot verify ECDSA. Add one "+
				"with `signari keys rotate -alg RS256` before enabling SAML")
	}
	return rows.Err()
}

func checkClients(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("OAuth clients")

	var plaintextRedirects int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM core.client_redirect_uris
		WHERE redirect_uri LIKE 'http://%'
		  AND redirect_uri NOT LIKE 'http://localhost%'
		  AND redirect_uri NOT LIKE 'http://127.0.0.1%'`).Scan(&plaintextRedirects); err != nil {
		return err
	}
	if plaintextRedirects > 0 {
		r.add(Critical, "clients",
			fmt.Sprintf("%d redirect URI(s) are plaintext HTTP on a non-loopback host",
				plaintextRedirects),
			"an authorization code sent to one crosses the network in the clear. "+
				"Re-register those clients with https URIs")
	}

	var noPKCE int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM core.clients WHERE NOT require_pkce AND enabled`).
		Scan(&noPKCE); err != nil {
		return err
	}
	if noPKCE > 0 {
		r.add(Warning, "clients", fmt.Sprintf("%d enabled client(s) do not require PKCE", noPKCE),
			"PKCE is what stops an intercepted authorization code being exchanged by "+
				"somebody else. Turn it on unless a client genuinely cannot do it")
	}
	return nil
}

func checkSAML(ctx context.Context, conn *pgx.Conn, r *Report) error {
	if _, err := conn.Exec(ctx, `SELECT 1 FROM core.saml_providers LIMIT 1`); err != nil {
		return nil // table absent in an old schema; nothing to check
	}
	r.ran("SAML service providers")

	var sloWithoutCert int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM core.saml_providers p
		WHERE p.sp_signing_cert IS NULL
		  AND EXISTS (SELECT 1 FROM core.saml_slo_urls u WHERE u.provider_id = p.id)`).
		Scan(&sloWithoutCert); err != nil {
		return err
	}
	// The same half-configuration in the other direction. The CLI refuses to
	// create it, but the admin console and a hand-written UPDATE can, and the
	// symptom -- every login through that provider refused with a signature error
	// -- looks like the service provider's fault from every angle except this one.
	var signedWithoutCert int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM core.saml_providers
		WHERE want_authn_requests_signed AND sp_signing_cert IS NULL`).
		Scan(&signedWithoutCert); err != nil {
		return err
	}
	if signedWithoutCert > 0 {
		r.add(Critical, "saml",
			fmt.Sprintf("%d provider(s) require signed AuthnRequests but have no signing "+
				"certificate", signedWithoutCert),
			"nothing can verify the signature, so every login through them is refused. "+
				"Register the certificate, or turn the requirement off")
	}

	if sloWithoutCert > 0 {
		r.add(Warning, "saml",
			fmt.Sprintf("%d provider(s) have a logout URL but no signing certificate",
				sloWithoutCert),
			"a LogoutRequest is only acted on when signed, so every logout from those "+
				"providers is refused. Register their certificate with "+
				"`signari saml add-sp -sp-cert`")
	}
	return nil
}

func checkFederation(ctx context.Context, conn *pgx.Conn, r *Report) error {
	if _, err := conn.Exec(ctx, `SELECT 1 FROM core.identity_providers LIMIT 1`); err != nil {
		return nil
	}
	r.ran("external sign-in providers")

	var untrustedSignup int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM core.identity_providers
		WHERE enabled AND allow_signup AND kind = 'oidc' AND NOT trust_email_verification`).
		Scan(&untrustedSignup); err != nil {
		return err
	}
	if untrustedSignup > 0 {
		r.add(Info, "federation",
			fmt.Sprintf("%d generic OIDC provider(s) allow sign-up but their email "+
				"verification is not trusted", untrustedSignup),
			"sign-up through them will always refuse. Either turn off allow_signup, or "+
				"pass -trust-email-verification if you know that provider verifies addresses")
	}
	return nil
}

func checkOutbox(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("delivery queue")

	var parked int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM core.outbox
		WHERE delivered_at IS NULL AND attempts >= 8`).Scan(&parked); err != nil {
		return err
	}
	if parked > 0 {
		r.add(Critical, "logout delivery",
			fmt.Sprintf("%d notice(s) have exhausted their retries and been parked", parked),
			"these are logouts and security events that never reached the relying "+
				"party. Those sessions may still be live at the application. Inspect "+
				"core.outbox last_error and fix the endpoint")
	}
	return nil
}

func checkPolicy(ctx context.Context, conn *pgx.Conn, r *Report) error {
	if _, err := conn.Exec(ctx, `SELECT 1 FROM core.access_policies LIMIT 1`); err != nil {
		return nil
	}
	r.ran("access policy")
	// The document is validated on load by the engine; the useful thing to
	// report here is simply whether one is in force, because "no policy" means
	// "everything is allowed" and that is worth stating out loud.
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM core.access_policies`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		r.add(Info, "policy", "no access policy is in force, so every client is open "+
			"to every user",
			"that may be correct. If not, write one and apply it with `signari policy apply`")
	}
	return nil
}

func checkAdminTokens(ctx context.Context, conn *pgx.Conn, r *Report) error {
	if _, err := conn.Exec(ctx, `SELECT 1 FROM core.admin_tokens LIMIT 1`); err != nil {
		return nil // older schema
	}
	r.ran("admin API tokens")

	var live, expiringSoon, neverUsed int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE revoked_at IS NULL
		                          AND (expires_at IS NULL OR expires_at > now())),
		       count(*) FILTER (WHERE revoked_at IS NULL
		                          AND expires_at BETWEEN now() AND now() + interval '14 days'),
		       count(*) FILTER (WHERE revoked_at IS NULL AND last_used_at IS NULL
		                          AND created_at < now() - interval '30 days')
		FROM core.admin_tokens`).Scan(&live, &expiringSoon, &neverUsed); err != nil {
		return err
	}

	// An expiry that arrives unannounced takes the console down, and the symptom
	// -- every admin action returning 401 -- looks like a credential leak rather
	// than a calendar entry.
	if expiringSoon > 0 {
		r.add(Warning, "admin API",
			fmt.Sprintf("%d admin token(s) expire within 14 days", expiringSoon),
			"mint replacements and cut over before they lapse: `signari admin-token list` "+
				"shows the dates")
	}

	// Not an error, just unearned standing access. A credential nobody has used
	// in a month is one nobody will notice being used by somebody else.
	if neverUsed > 0 {
		r.add(Info, "admin API",
			fmt.Sprintf("%d admin token(s) created over 30 days ago have never been used",
				neverUsed),
			"revoke them: `signari admin-token revoke -token-id <id>`")
	}

	// The environment token grants everything, in every organisation, and cannot
	// be revoked without restarting every node. It is the right break-glass path
	// and the wrong day-to-day one.
	if os.Getenv("SIGNARI_ADMIN_TOKEN") != "" && live == 0 {
		r.add(Warning, "admin API",
			"the admin API is reachable only with SIGNARI_ADMIN_TOKEN and no scoped "+
				"tokens exist",
			"that credential grants every scope in every organisation and cannot be "+
				"revoked without restarting every node. Mint scoped ones with "+
				"`signari admin-token create` and keep the environment token for "+
				"break-glass")
	}
	return nil
}
