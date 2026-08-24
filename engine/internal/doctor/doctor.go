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
	"path/filepath"
	"signari.dev/engine/internal/i18n"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/migrate"
	"signari.dev/engine/internal/pages"
	"sort"
	"strings"
	"time"

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
	if err := checkSAMLCertificateExpiry(ctx, conn, r); err != nil {
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
	if err := checkEmailFactor(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkCredentialLifetimes(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkErasure(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkMTLS(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := checkNotificationChannels(ctx, conn, r); err != nil {
		return nil, err
	}
	checkSchemaPin(r)
	checkTheme(r)

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

// checkNotificationChannels surfaces NIST SP 800-63B-4's two-notification-address
// SHALL per deployment.
//
// The engine SUPPORTS two channels (an account email and a verified SMS number,
// fanned out by internal/httpapi/notify.go), which is what the SHALL asks a CSP
// to do. What it cannot do is make a given account HAVE two -- that depends on
// whether users have enrolled and verified an SMS number. So the finding is
// informational and counts the exposure: active accounts whose only notification
// channel is the email address, where a compromised mailbox means a security
// notice reaches nobody who can act on it. It is Info, not Warning, because
// forcing a second channel is a lockout risk that is the operator's call.
func checkNotificationChannels(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("notification channels")

	var oneChannel int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM core.users u
		WHERE u.status = 'active' AND u.email IS NOT NULL AND u.email <> ''
		  AND NOT EXISTS (
		    SELECT 1 FROM core.sms_otp_credentials s
		    WHERE s.user_id = u.id AND s.verified_at IS NOT NULL)`).Scan(&oneChannel); err != nil {
		return err
	}
	if oneChannel > 0 {
		r.add(Info, "notifications",
			fmt.Sprintf("%d active account(s) have only one notification channel (email)",
				oneChannel),
			"NIST SP 800-63B-4 asks a CSP to support at least two independent "+
				"notification addresses per account, so a security notice reaches the "+
				"owner even if their mailbox is taken over. This engine supports a "+
				"second channel -- a verified SMS number -- and uses it automatically "+
				"when present; these accounts have not enrolled one. Nothing is broken; "+
				"the exposure is that for these accounts a passkey-added or "+
				"reset-requested notice reaches only the email address")
	}
	return nil
}

func checkSigningKeys(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("signing keys")
	rows, err := conn.Query(ctx, `
		SELECT algorithm, count(*) FILTER (WHERE state = 'active'),
		       count(*) FILTER (WHERE state = 'next')
		FROM core.signing_keys WHERE purpose = 'oidc' GROUP BY algorithm`)
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

// checkSAMLCertificateExpiry reports a signing certificate approaching its end.
//
// A SAML certificate here is self-signed for ten years and reused forever,
// deliberately: regenerating it changes its fingerprint, and every service
// provider pinning that fingerprint would begin rejecting assertions -- the
// failure that looks like "SAML randomly stopped working for some users".
//
// The consequence is that the expiry is a cliff nobody is standing near until
// they fall off it. Service providers that validate certificate expiry -- many
// do -- start refusing every assertion on a date chosen a decade earlier, and
// nothing in the system had mentioned it.
//
// core.signing_keys.certificate_not_after was already stored for exactly this
// check. Nothing read it, which is how a stored value becomes a promise the
// system does not keep.
//
// Re-issuing is NOT automated. It has to be coordinated with every service
// provider that pinned the old fingerprint, which is a conversation rather than
// a command -- so the useful thing this can do is give an operator a year of
// notice instead of a morning.
func checkSAMLCertificateExpiry(ctx context.Context, conn *pgx.Conn, r *Report) error {
	rows, err := conn.Query(ctx, `
		SELECT kid, certificate_not_after,
		       (certificate_not_after - now()) < interval '90 days' AS urgent
		FROM core.signing_keys
		WHERE certificate_not_after IS NOT NULL
		  AND certificate_not_after < now() + interval '365 days'
		ORDER BY certificate_not_after`)
	if err != nil {
		return nil // column absent in an old schema
	}
	defer rows.Close()
	r.ran("SAML certificate expiry")

	for rows.Next() {
		var kid string
		var notAfter time.Time
		var urgent bool
		if err := rows.Scan(&kid, &notAfter, &urgent); err != nil {
			return err
		}
		days := int(time.Until(notAfter).Hours() / 24)

		switch {
		case days < 0:
			r.add(Critical, "SAML",
				fmt.Sprintf("the SAML certificate for key %s expired %d days ago",
					kid, -days),
				"Service providers that check expiry are already refusing assertions "+
					"signed with it. Issue a new key and coordinate the new certificate "+
					"with every service provider before switching.")
		case urgent:
			r.add(Warning, "SAML",
				fmt.Sprintf("the SAML certificate for key %s expires in %d days", kid, days),
				"Re-issuing changes the fingerprint, so every service provider "+
					"pinning it needs the new one first. Start that conversation now.")
		default:
			r.add(Info, "SAML",
				fmt.Sprintf("the SAML certificate for key %s expires in %d days", kid, days),
				"No action yet. Re-issuing has to be coordinated with each service "+
					"provider, so this is worth putting in a calendar rather than "+
					"discovering on the day.")
		}
	}
	return rows.Err()
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

// checkEmailFactor catches the combination that locks people out.
//
// Email codes with no way to send email is not a degraded configuration, it is
// an outage: the person is asked for a code that will never arrive, and unlike
// account recovery there is no alternative path in the middle of a sign-in.
func checkEmailFactor(ctx context.Context, conn *pgx.Conn, r *Report) error {
	if _, err := conn.Exec(ctx, `SELECT 1 FROM core.email_otp_credentials LIMIT 1`); err != nil {
		return nil // older schema
	}
	r.ran("email second factor")

	var enrolled int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM core.email_otp_credentials`).Scan(&enrolled); err != nil {
		return err
	}
	if enrolled > 0 && (os.Getenv("SIGNARI_SMTP_HOST") == "" || os.Getenv("SIGNARI_MAIL_FROM") == "") {
		r.add(Critical, "mail",
			fmt.Sprintf("%d user(s) use email as a second factor and no SMTP is configured",
				enrolled),
			"they cannot sign in: the code is written to the log instead of sent. "+
				"Set SIGNARI_SMTP_HOST and SIGNARI_MAIL_FROM")
	}
	return nil
}

// checkMTLS catches the configuration that refuses every mutual-TLS client.
//
// tls_client_auth needs an authority to verify against. Registered without one,
// the client is refused on every request -- correctly, and in a way that looks
// like the client's fault from every angle except this one.
func checkMTLS(ctx context.Context, conn *pgx.Conn, r *Report) error {
	if _, err := conn.Exec(ctx, `SELECT tls_subject_dn FROM core.clients LIMIT 1`); err != nil {
		return nil // older schema
	}
	r.ran("mutual-TLS clients")

	var pkiClients int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM core.clients
		WHERE tls_subject_dn IS NOT NULL OR tls_san_dns IS NOT NULL
		   OR tls_san_uri IS NOT NULL OR tls_san_ip IS NOT NULL
		   OR tls_san_email IS NOT NULL`).Scan(&pkiClients); err != nil {
		return err
	}
	if pkiClients > 0 && os.Getenv("SIGNARI_TLS_CLIENT_CA") == "" {
		r.add(Critical, "mutual-TLS",
			fmt.Sprintf("%d client(s) use tls_client_auth and SIGNARI_TLS_CLIENT_CA is not set",
				pkiClients),
			"there is no authority to verify their certificates against, so every "+
				"request from them is refused. Set it to the CA that issues those "+
				"certificates, or move them to self_signed_tls_client_auth")
	}
	return nil
}

// checkErasure reports how much of this deployment is protected by subject keys.
//
// # What this used to report, and what closed it
//
// The mechanism exists and works. `core.subject_keys` holds each subject's
// data-encryption key wrapped by a root key that is not in the database, with an
// `erased_at` column and a constraint that a shredded key has no DEK. The audit
// chain hashes ciphertext rather than plaintext precisely so it stays verifiable
// after a shred. `keys.EraseSubject` performs the destruction and is tested.
//
// For a long time NOTHING CALLED IT. There was no admin API, CLI or console path
// that erased a subject, so a deployment holding personal data had no way to
// destroy it on request -- a mechanism with no handle, in a schema that advertised
// the capability everywhere.
//
// That is closed. `signari erase subject` and `POST /admin/subjects/{id}/erase`
// both invoke it, each requiring the subject identifier to be repeated as the
// confirmation rather than a boolean, because which subject is the only mistake
// here that nobody can undo.
//
// The open question was never the mechanism but the SEMANTICS -- immediate,
// delay-and-notify like account recovery, or two-person -- and this check said so
// for good reason. The engine implements immediate and refuses to erase a still
// active account unless the caller says what should happen to it, which is a
// guard rather than a choice: an erased subject can never hold a key again, so an
// account left active afterwards fails permanently rather than working with less
// data.
//
// The check stays because the number is still worth knowing: it says how much of
// this deployment is protected by subject keys, and therefore how much a single
// erasure destroys. Info, always -- it reports scale, not a fault.
func checkErasure(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("subject erasure")

	var subjects, erased int
	if err := conn.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE erased_at IS NOT NULL)
		FROM core.subject_keys`).Scan(&subjects, &erased); err != nil {
		// The table not existing is not a doctor failure; an older schema is a
		// migration problem and is reported by the migration check.
		return nil
	}
	reportErasure(r, subjects)
	return nil
}

// reportErasure is the judgement, separated from the query so it can be tested
// the way every other check in this package is.
func reportErasure(r *Report, subjects int) {
	if subjects == 0 {
		// Nothing is protected by a subject key yet, so nothing needs erasing.
		return
	}
	r.add(Info, "erasure",
		fmt.Sprintf("%d subject key(s) are stored; each one is what an erasure destroys",
			subjects),
		"Erasing one destroys the key its data is sealed with, permanently and "+
			"including in every backup taken beforehand. Run it with `signari "+
			"erase subject -subject-id <uuid> -confirm <uuid>` or POST to "+
			"/admin/subjects/{id}/erase; both require the identifier to be "+
			"repeated as the confirmation, because which subject is the only "+
			"mistake here that nobody can undo. See docs/erasure.md.")
}

// checkCredentialLifetimes reports the credential configurations that hold
// passive signing keys in the JWKS.
//
// # The trap this defused, and what it became
//
// `keys.MinPassiveBeforeRetire` is 24 hours, and its comment says the value
// "must exceed the longest lifetime of any token it signed". That was true when
// it was written: access and ID tokens live five minutes, logout tokens and
// security event tokens less, and refresh tokens are opaque -- looked up by
// hash, never signed.
//
// OID4VCI changed it. A verifiable credential is signed with the same
// `oidc`-purpose key, and its lifetime is an operator-configured interval on
// `core.credential_configurations` with **no ceiling**. A credential issued for
// ninety days, signed by a key retired twenty-four hours after demotion, would
// stop verifying with eighty-nine days left to run.
//
// When this check was written there was no retirement path at all, so the hazard
// was latent and aimed at whoever built one: they would reach for that constant,
// and the deployments where reaching for it is wrong are exactly the ones that
// cannot notice.
//
// **Retirement now exists, and it does not reach for the constant.**
// keys.RequiredPassiveDwell takes the maximum of the floor and the longest
// credential lifetime on the instance, so a key stays published for exactly as
// long as anything it signed can still be valid. The failure this check was
// written to prevent cannot now occur.
//
// So the finding changed meaning rather than going away. These configurations are
// the reason a passive key will sit in the JWKS for weeks or months, and an
// operator looking at a key that will not retire deserves to be told which
// configuration is holding it rather than left to work it out. That is an
// operational fact, reported at Info, not a warning about anything broken.
func checkCredentialLifetimes(ctx context.Context, conn *pgx.Conn, r *Report) error {
	r.ran("credential lifetime against key retention")

	// Probe for the table separately, so that every error after this point can
	// be treated as real. `Query` reports a missing relation through `rows.Err`
	// rather than at call time, and a check that cannot distinguish "old schema"
	// from "the database is broken" either breaks doctor on old schemas or goes
	// silent on real ones. `checkErasure` sidesteps this by using `QueryRow`;
	// this check needs many rows, so it asks first.
	var present *string
	if err := conn.QueryRow(ctx,
		`SELECT to_regclass('core.credential_configurations')::text`).Scan(&present); err != nil || present == nil {
		// An older schema is a migration matter, reported by the migration check.
		return nil
	}

	// DISTINCT because `config_id` is unique per organisation, not per
	// deployment: without it, ten tenants sharing one configuration name are
	// reported ten times as if they were ten separate problems. Longest first,
	// because the worst offender is the one worth reading.
	//
	// The boundary is deliberately exclusive, though the constant's own comment
	// -- "must exceed the longest lifetime of any token it signed" -- reads as
	// though it should be inclusive. The window starts at *demotion*, and
	// `Set.Active` hands out only active keys, so a demoted key never signs
	// again. A credential signed at time T by a key demoted at D >= T is
	// published until D+24h and expires at T+lifetime <= D+lifetime. It can
	// therefore outlive its key only when lifetime > 24h; at exactly 24h the key
	// is still published at every instant the credential is valid. Flagging that
	// case would be a false positive, and a diagnostic nobody believes is worse
	// than no diagnostic.
	//
	// `IS NOT NULL` is redundant against three-valued logic -- `NULL > interval`
	// is already not TRUE -- and kept because a credential with no expiry is the
	// one case where a reader would most want to know it was considered.
	rows, err := conn.Query(ctx, `
		SELECT DISTINCT config_id, lifetime
		FROM core.credential_configurations
		WHERE lifetime IS NOT NULL AND lifetime > $1::interval
		ORDER BY lifetime DESC, config_id`,
		keys.MinPassiveBeforeRetire.String())
	if err != nil {
		return err
	}
	defer rows.Close()

	var over []string
	for rows.Next() {
		var id string
		var life time.Duration
		if err := rows.Scan(&id, &life); err != nil {
			return err
		}
		over = append(over, fmt.Sprintf("%s (%s)", id, life.Round(time.Hour)))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	reportCredentialLifetimes(r, over)
	return nil
}

// reportCredentialLifetimes is the judgement, separated from the query so it can
// be tested the way every other check in this package is.
func reportCredentialLifetimes(r *Report, over []string) {
	if len(over) == 0 {
		return
	}
	// A deployment with a hundred configurations must not turn one finding into
	// a wall of text -- but a truncated list that does not say it is truncated
	// reads as the whole answer. Name the count, show the longest few, and say
	// what was left out.
	const shown = 5
	listed, extra := over, 0
	if len(listed) > shown {
		listed, extra = listed[:shown], len(over)-shown
	}
	summary := fmt.Sprintf("%d credential configuration(s) outlive the %s key retention floor: %s",
		len(over), keys.MinPassiveBeforeRetire, strings.Join(listed, ", "))
	if extra > 0 {
		summary += fmt.Sprintf(", and %d more (longest first)", extra)
	}
	r.add(Info, "keys", summary,
		"These credentials are signed by the same key as access and ID tokens, so a "+
			"demoted key must stay in the JWKS until the longest of them expires. "+
			"Nothing is wrong: `signari keys retire` computes the dwell from these "+
			"lifetimes rather than from the 24h floor, so no credential can be left "+
			"unverifiable. This is why a passive key may remain published for weeks "+
			"or months -- run `signari keys retire -dry-run` to see the deadline and "+
			"which configuration set it.")
}

// checkSchemaPin reports whether this binary actually performs the drift check it
// is built to perform.
//
// # The failure this makes visible
//
// migrate.Verify compares the schema VERSION always, and the schema FINGERPRINT
// only when ExpectedFingerprint was pinned at build time. Unpinned, it returns
// before it ever reads the live schema -- so the check exists, is tested, and does
// nothing.
//
// That is invisible from outside. Nothing logs it, no endpoint reports it, and the
// engine starts normally either way; the only symptom is that a hand-patched
// database is accepted, which is the exact situation the fingerprint exists to
// catch and the one where nobody is watching. The variable's own comment has
// always said the zero value is "acceptable during early development, never in a
// release", and until now nothing checked.
//
// Warning rather than Critical: the version counter still gates every ordinary
// upgrade, so a database that is simply behind is still refused. What is missing
// is detection of drift WITHIN a version, which needs somebody to have edited the
// schema by hand.
func checkSchemaPin(r *Report) {
	r.ran("schema fingerprint pinning")
	if migrate.ExpectedFingerprint != "" {
		return
	}
	r.add(Warning, "schema",
		"this binary has no pinned schema fingerprint, so it accepts any database "+
			"at the right version, including one that has been hand-patched",
		"Build with the fingerprint pinned: `scripts/build-release.sh`, or pass "+
			"--build-arg SIGNARI_SCHEMA_FINGERPRINT=\"$(scripts/schema-fingerprint.sh)\" "+
			"to docker build. The version counter still gates upgrades either way; "+
			"what is missing is noticing drift within a version, which is what the "+
			"fingerprint is for.")
}

// checkTheme reports whether an operator's page overrides are actually in force.
//
// # The failure this makes visible
//
// A theme whose page fails validation is refused and the built-in is served in
// its place. That is the right behaviour for a running server -- the alternative
// is a mistyped filename locking every user out of every application -- but it
// means the symptom of a broken theme is a page that looks *normal*. An operator
// who wrote a theme, deployed it, and sees the stock sign-in form has no way to
// tell "the theme was refused" from "I set the wrong directory" or "I edited the
// wrong file", and the warning that would have said so scrolled past at startup.
//
// So this reports both halves: what was refused, and -- when nothing is
// configured at all -- that nothing is.
//
// Warning rather than Critical for a refusal: the deployment is serving correct,
// working pages. What it is not doing is what the operator asked for.
func checkTheme(r *Report) {
	r.ran("page theme")

	dir := os.Getenv("SIGNARI_THEME_DIR")
	if dir == "" {
		// Not a finding. Most deployments never theme anything, and reporting the
		// absence of an optional feature on every run is how a report stops being
		// read.
		return
	}

	set, problems, err := pages.Load(dir)
	if err != nil {
		r.add(Critical, "theme",
			"SIGNARI_THEME_DIR is set to "+dir+" and cannot be read: "+err.Error(),
			"Point it at a readable directory, or unset it to serve the built-in "+
				"pages. Every sign-in page is currently coming from the binary.")
		return
	}
	for _, p := range problems {
		// The error from Load already names the file, says the built-in is being
		// used, and gives the reason. Restating any of that here produces a finding
		// that says the same thing twice before it says anything.
		r.add(Warning, "theme", p.Error(),
			"Run `signari theme check -theme-dir "+dir+"` to see it in isolation. "+
				"The page a user sees is correct and working -- it is simply not "+
				"yours, and nothing on the page says so.")
	}
	if set == nil {
		return
	}
	var overridden int
	for _, n := range set.Names() {
		if set.Origin(n) != "built-in" {
			overridden++
		}
	}
	if overridden == 0 && len(problems) == 0 && !hasLocaleOverrides(dir) {
		r.add(Warning, "theme",
			"SIGNARI_THEME_DIR is set to "+dir+" but no page there overrides "+
				"anything, so every page is the built-in one",
			"Check the filenames: a page is overridden by a file named exactly "+
				"after it, such as `login.html` or `layout.html`. "+
				"`signari theme list` prints every name and where it is coming from.")
	}

	checkLanguages(r, set.Bundle())
}

// hasLocaleOverrides reports whether a theme directory carries a catalogue.
//
// A directory holding only locales/ is a complete and normal theme -- rewording
// without forking a page is the cheapest thing an operator can do -- so it must
// not be reported as one that overrides nothing.
func hasLocaleOverrides(dir string) bool {
	entries, err := os.ReadDir(filepath.Join(dir, "locales"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			return true
		}
	}
	return false
}

// checkLanguages reports catalogues that are loaded but incomplete.
//
// A half-translated language is the finding worth making, because it is the one
// that looks fine from here: the page renders, the fallback fills the gaps in
// English, and the only person who sees the result is somebody signing in who
// now has a page half in their language and half in another. On a screen asking
// for a password, that reads as a tampered-with site.
func checkLanguages(r *Report, b *i18n.Bundle) {
	if b == nil {
		return
	}
	for _, lang := range b.Languages() {
		if lang == i18n.Default {
			continue
		}
		missing := b.Missing(lang)
		if len(missing) == 0 {
			continue
		}
		shown := missing[0]
		if len(missing) > 1 {
			shown = fmt.Sprintf("%s and %d more", shown, len(missing)-1)
		}
		r.add(Warning, "theme",
			fmt.Sprintf("the %s pages are missing %d message(s) -- %s -- and "+
				"fall back to English", lang, len(missing), shown),
			"Run `signari i18n status` for the full list. Until they are "+
				"translated, anybody whose browser asks for "+lang+" gets a "+
				"sign-in page in two languages at once.")
	}
}
