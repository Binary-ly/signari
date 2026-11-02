package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/tokens"
)

// ClientSettings are a client's per-client token settings. A nil field is left
// as it is, so each surface changes only what it was asked to.
type ClientSettings struct {
	// AccessTokenTTL is how long an access token lives, and so how long one
	// outlives its revocation (ADR-007). A minute to tokens.MaxAccessTokenTTL.
	AccessTokenTTL *time.Duration
	// RefreshTokenTTL is how long a refresh token lives. Five minutes to a year.
	RefreshTokenTTL *time.Duration
	// RefreshReuseGrace is how long after a rotation the old token may be presented
	// once more for the same answer, 0 for never and MaxRefreshReuseGrace at most.
	// Past that reuse is a theft signal again, which is the whole point of rotating.
	RefreshReuseGrace *time.Duration
	// IDTokenAlg signs the client's ID and access tokens: ES256 by default, one
	// of ClientAlgorithms, and only one the client's instance holds an active
	// key for, since a token endpoint asked to sign with a key it does not have
	// answers every request with an error.
	IDTokenAlg *string
	// AccessTokenAlg signs the client's access tokens alone, for a resource server
	// that takes something else; "" goes back to IDTokenAlg. The same rules.
	AccessTokenAlg *string
	// RolesClaim names the claim the client's tokens carry a person's roles in
	// the application under; "" carries none.
	RolesClaim *string
	// LoginUI is the page of the client's own that an authorization request is
	// sent to for a sign-in, and what lets it walk one over JSON; "" is this
	// server's page.
	LoginUI *string
	// AccessTokenFormat is jwt, or opaque for a handle a resource server
	// introspects. A token already issued stays what it is.
	AccessTokenFormat *string
	// SubjectType is public, or pairwise for a subject that means nothing outside
	// the client's sector. Changing it changes what the client calls everybody.
	SubjectType *string
	// Sector is who shares a pairwise subject. "" keeps the one it has, or takes
	// the host of the client's redirect URIs when they have only one.
	Sector *string
	// SecurityProfile is none, or fapi2 to hold the client to that profile. Every
	// change through here is checked against the profile the client ends up with.
	SecurityProfile *string
	// RequirePAR refuses any authorization the client did not push first (RFC
	// 9126 §6, require_pushed_authorization_requests).
	RequirePAR *bool
	// RequireState refuses an authorization request with no `state` (0210).
	RequireState *bool
	// FirstParty skips the consent screen for the client (migration 0010). An
	// operator's decision only; dynamic registration never sets it.
	FirstParty *bool
	// IssuerAlias pins the client to a legacy issuer its instance claims, so
	// its tokens are minted under that `iss` during a migration. Only a live
	// alias of the client's own instance; empty clears it.
	IssuerAlias *string
	// MinimumACR is the weakest authentication the client accepts: "1" a
	// single factor, "2" multi-factor (migration 0166), "3" multi-factor with
	// a WebAuthn assertion, "4" with a device-bound key (0174).
	MinimumACR *string
	// ConsentLifetime is how long a person's consent to the client lasts
	// before they are asked again (0188): an hour to ten years, or 0 for a
	// consent that does not expire.
	ConsentLifetime *time.Duration
}

// Bounds of a consent's lifetime, the schema's own CHECK.
const (
	MinConsentLifetime = time.Hour
	MaxConsentLifetime = 3650 * 24 * time.Hour
)

// ClientACRs are the floors a client may be given, the schema's own CHECK.
var ClientACRs = []string{"1", "2", "3", "4"}

// loginUIShape is the CHECK on clients.login_ui_url, said here with its reason.
var loginUIShape = regexp.MustCompile(`^(https://[^#]+|http://(localhost|127\.0\.0\.1)(:[0-9]+)?(/[^#]*)?)$`)

// protocolClaimNames are what no setting may name, the CHECK on clients.roles_claim
// and on claim_mappers: a relying party reads them to decide who and how strongly.
var protocolClaimNames = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "azp", "nonce", "auth_time", "acr",
	"amr", "sid", "at_hash", "c_hash", "s_hash", "client_id", "scope", "cnf"}

// ClientAlgorithms are the JWS algorithms a client may be set to sign with,
// the schema's own CHECK. No symmetric algorithm, ever.
var ClientAlgorithms = []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
	"EdDSA"}

// The bounds, which migration 0144 enforces in the schema as well.
const (
	MinAccessTokenTTL  = time.Minute
	MinRefreshTokenTTL = 5 * time.Minute
	MaxRefreshTokenTTL = 365 * 24 * time.Hour
	// MaxRefreshReuseGrace is the bound on a retry, which only the code holds: a
	// network that loses an answer retries within seconds, and any longer is a
	// window in which a stolen token goes unnoticed.
	MaxRefreshReuseGrace = 30 * time.Second
)

// ErrInvalidClientSetting wraps every reason a setting is refused.
var ErrInvalidClientSetting = errors.New("invalid client setting")

// SetClientSettings writes a client's token settings. The one writer, behind
// `client set-lifetimes` and `client set-alg`, the client PATCH, `signari
// apply` and, for the algorithm alone, dynamic registration.
//
// Both lifetimes had a column since the first schema and no writer, so every
// client's access tokens lived five minutes and its refresh tokens thirty days
// whatever the console said; the access lifetime was not even read.
func SetClientSettings(ctx context.Context, tx pgx.Tx, clientID string, s ClientSettings) error {
	if err := CheckClientSettings(s); err != nil {
		return err
	}
	if d := s.AccessTokenTTL; d != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET access_token_ttl_s = $2, updated_at = now()
			WHERE client_id = $1`, clientID, int(d.Seconds()))); err != nil {
			return err
		}
	}
	if d := s.RefreshTokenTTL; d != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET refresh_token_ttl_s = $2, updated_at = now()
			WHERE client_id = $1`, clientID, int(d.Seconds()))); err != nil {
			return err
		}
	}
	if d := s.RefreshReuseGrace; d != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET refresh_reuse_grace_s = $2, updated_at = now()
			WHERE client_id = $1`, clientID, int(d.Seconds()))); err != nil {
			return err
		}
	}
	held := func(alg string) error {
		var known, held bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1),
			       EXISTS (SELECT 1 FROM core.signing_keys k
			                 JOIN core.organizations o ON o.instance_id = k.instance_id
			                 JOIN core.clients c ON c.org_id = o.id
			                WHERE c.client_id = $1 AND k.algorithm = $2
			                  AND k.state = 'active' AND k.purpose = 'oidc')`,
			clientID, alg).Scan(&known, &held); err != nil {
			return err
		}
		if !known {
			return ErrClientNotFound
		}
		if !held {
			return fmt.Errorf("%w: this instance holds no active %s signing key, so every token "+
				"for the client would fail to sign; publish one with `signari keys rotate -alg %s` "+
				"and promote it with the same command after the dwell", ErrInvalidClientSetting, alg, alg)
		}
		return nil
	}
	if a := s.IDTokenAlg; a != nil {
		if err := held(*a); err != nil {
			return err
		}
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET id_token_signed_alg = $2, updated_at = now()
			WHERE client_id = $1`, clientID, *a)); err != nil {
			return err
		}
	}
	if a := s.AccessTokenAlg; a != nil {
		if *a != "" {
			if err := held(*a); err != nil {
				return err
			}
		}
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET access_token_signed_alg = NULLIF($2, ''),
			updated_at = now() WHERE client_id = $1`, clientID, *a)); err != nil {
			return err
		}
	}
	if v := s.RolesClaim; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET roles_claim = NULLIF($2, ''),
			updated_at = now() WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if v := s.LoginUI; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET login_ui_url = NULLIF($2, ''),
			updated_at = now() WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if v := s.AccessTokenFormat; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET access_token_format = $2,
			updated_at = now() WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if s.SubjectType != nil || s.Sector != nil {
		if err := setSubjectType(ctx, tx, clientID, s); err != nil {
			return err
		}
	}
	if v := s.RequirePAR; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET require_pushed_authorization = $2,
			updated_at = now() WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if v := s.RequireState; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET require_state = $2, updated_at = now()
			WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if v := s.FirstParty; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET first_party = $2, updated_at = now()
			WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if v := s.IssuerAlias; v != nil {
		alias := strings.TrimSpace(*v)
		if alias != "" {
			// The schema's trigger (0015) checks registration; liveness too, here,
			// since a client pinned to a retired alias would mint under the
			// instance's own issuer from the first token.
			var live bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM core.instance_issuer_aliases a
				                 JOIN core.organizations o ON o.instance_id = a.instance_id
				                 JOIN core.clients c ON c.org_id = o.id
				                WHERE c.client_id = $1 AND a.issuer = $2
				                  AND (a.retire_after IS NULL OR a.retire_after > now()))`,
				clientID, alias).Scan(&live); err != nil {
				return err
			}
			if !live {
				return fmt.Errorf("%w: %s is not an alias this client's instance claims now; register "+
					"it with `signari instance add-alias`", ErrInvalidClientSetting, alias)
			}
		}
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET issuer_alias = NULLIF($2, ''),
			updated_at = now() WHERE client_id = $1`, clientID, alias)); err != nil {
			return err
		}
	}
	if v := s.MinimumACR; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET minimum_acr = $2,
			updated_at = now() WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if d := s.ConsentLifetime; d != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET consent_lifetime_s = NULLIF($2, 0),
			updated_at = now() WHERE client_id = $1`, clientID, int(d.Seconds()))); err != nil {
			return err
		}
	}
	if v := s.SecurityProfile; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET security_profile = $2,
			updated_at = now() WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	return checkSecurityProfile(ctx, tx, clientID)
}

// checkSecurityProfile refuses to leave a client out of the profile it is held to, last,
// so a change to several settings at once is judged on where they end up.
func checkSecurityProfile(ctx context.Context, tx pgx.Tx, clientID string) error {
	var profile string
	err := tx.QueryRow(ctx, `SELECT security_profile FROM core.clients WHERE client_id = $1`, clientID).Scan(&profile)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && profile == "none") {
		return nil
	}
	if err != nil {
		return err
	}
	c, err := clients.Lookup(ctx, tx, clientID)
	if err != nil {
		return err
	}
	if problems := c.ProfileProblems(); len(problems) > 0 {
		return fmt.Errorf("%w: this client would not meet the %s profile: %s", ErrInvalidClientSetting, profile,
			strings.Join(problems, "; "))
	}
	return nil
}

// CheckClientSettings refuses what SetClientSettings would, without a
// database, so `signari plan` says so before anything is applied.
func CheckClientSettings(s ClientSettings) error {
	if d := s.AccessTokenTTL; d != nil &&
		(*d < MinAccessTokenTTL || *d > tokens.MaxAccessTokenTTL || *d%time.Second != 0) {
		return fmt.Errorf("%w: an access token lifetime must be whole seconds from %s to %s, "+
			"since it is also how long a revoked token goes on working", ErrInvalidClientSetting,
			MinAccessTokenTTL, tokens.MaxAccessTokenTTL)
	}
	if d := s.RefreshTokenTTL; d != nil &&
		(*d < MinRefreshTokenTTL || *d > MaxRefreshTokenTTL || *d%time.Second != 0) {
		return fmt.Errorf("%w: a refresh token lifetime must be whole seconds from %s to %s",
			ErrInvalidClientSetting, MinRefreshTokenTTL, MaxRefreshTokenTTL)
	}
	if d := s.RefreshReuseGrace; d != nil && (*d < 0 || *d > MaxRefreshReuseGrace || *d%time.Second != 0) {
		return fmt.Errorf("%w: a refresh retry grace must be whole seconds from 0 to %s",
			ErrInvalidClientSetting, MaxRefreshReuseGrace)
	}
	if a := s.IDTokenAlg; a != nil && !slices.Contains(ClientAlgorithms, *a) {
		return fmt.Errorf("%w: %q is not a signing algorithm a client may use (%s)",
			ErrInvalidClientSetting, *a, strings.Join(ClientAlgorithms, ", "))
	}
	if a := s.AccessTokenAlg; a != nil && *a != "" && !slices.Contains(ClientAlgorithms, *a) {
		return fmt.Errorf("%w: %q is not a signing algorithm a client may use (%s)",
			ErrInvalidClientSetting, *a, strings.Join(ClientAlgorithms, ", "))
	}
	if v := s.AccessTokenFormat; v != nil && *v != "jwt" && *v != "opaque" {
		return fmt.Errorf("%w: an access token is jwt or opaque, not %q", ErrInvalidClientSetting, *v)
	}
	if v := s.SecurityProfile; v != nil && *v != "none" && *v != clients.ProfileFAPI2 {
		return fmt.Errorf("%w: a security profile is none or %s, not %q", ErrInvalidClientSetting,
			clients.ProfileFAPI2, *v)
	}
	if v := s.SubjectType; v != nil && *v != "public" && *v != "pairwise" {
		return fmt.Errorf("%w: a subject is public or pairwise, not %q", ErrInvalidClientSetting, *v)
	}
	if v := s.Sector; v != nil && *v != "" && !sectorShape.MatchString(strings.ToLower(*v)) {
		return fmt.Errorf("%w: a sector is a host name, not %q", ErrInvalidClientSetting, *v)
	}
	if v := s.RolesClaim; v != nil && (len(*v) > 128 || slices.Contains(protocolClaimNames, *v)) {
		return fmt.Errorf("%w: %q is part of the token's own structure, or too long to be a claim's name, so "+
			"roles cannot be carried in it", ErrInvalidClientSetting, *v)
	}
	if v := s.LoginUI; v != nil && *v != "" && !loginUIShape.MatchString(*v) {
		return fmt.Errorf("%w: a login page is https, or http on this machine, with no fragment, not %q",
			ErrInvalidClientSetting, *v)
	}
	if d := s.ConsentLifetime; d != nil && *d != 0 &&
		(*d < MinConsentLifetime || *d > MaxConsentLifetime || *d%time.Second != 0) {
		return fmt.Errorf("%w: a consent lifetime must be whole seconds from %s to %s, or 0 for "+
			"a consent that does not expire", ErrInvalidClientSetting, MinConsentLifetime, MaxConsentLifetime)
	}
	if a := s.MinimumACR; a != nil && !slices.Contains(ClientACRs, *a) {
		return fmt.Errorf("%w: %q is not an acr a client may require: 1, a single factor; 2, "+
			"multi-factor; 3, with a passkey or security key; or 4, with a key bound to its device",
			ErrInvalidClientSetting, *a)
	}
	return nil
}

// clientUpdated turns an UPDATE that matched no client into ErrClientNotFound.
func clientUpdated(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

// sectorShape is a host name, the shape a sector has to have to be read as one.
var sectorShape = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// setSubjectType stores how a client names people. The sector is stored and not worked
// out as it is needed, because a change to a redirect URI must not change what the client
// calls everybody it already knows.
func setSubjectType(ctx context.Context, tx pgx.Tx, clientID string, s ClientSettings) error {
	var kind, sector string
	err := tx.QueryRow(ctx, `SELECT subject_type, sector FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&kind, &sector)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrClientNotFound
	}
	if err != nil {
		return err
	}
	if s.SubjectType != nil {
		kind = *s.SubjectType
	}
	if s.Sector != nil && *s.Sector != "" {
		sector = strings.ToLower(*s.Sector)
	}
	if kind == "pairwise" && sector == "" {
		if sector, err = sectorOfRedirects(ctx, tx, clientID); err != nil {
			return err
		}
	}
	return clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET subject_type = $2, sector = $3, updated_at = now()
		WHERE client_id = $1`, clientID, kind, sector))
}

// sectorOfRedirects is the one host a client's redirect URIs have. Several say nothing
// of which is the sector, and a loopback or a custom scheme says nothing of whose it is:
// every native application on a machine would share one.
func sectorOfRedirects(ctx context.Context, tx pgx.Tx, clientID string) (string, error) {
	rows, err := tx.Query(ctx, `SELECT redirect_uri FROM core.client_redirect_uris WHERE client_id = $1`, clientID)
	if err != nil {
		return "", err
	}
	uris, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", err
	}
	hosts := map[string]bool{}
	for _, uri := range uris {
		u, err := url.Parse(uri)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if ip := net.ParseIP(host); host == "" || host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return "", fmt.Errorf("%w: %s says nothing of whose this client is: name its sector",
				ErrInvalidClientSetting, uri)
		}
		hosts[host] = true
	}
	if len(hosts) != 1 {
		return "", fmt.Errorf("%w: this client's redirect URIs have %d hosts, so they cannot say what its sector "+
			"is: name it", ErrInvalidClientSetting, len(hosts))
	}
	for host := range hosts {
		return host, nil
	}
	return "", nil
}

// ClientSettingsView is what SetClientSettings writes, read back.
type ClientSettingsView struct {
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	RefreshReuseGrace time.Duration
	IDTokenAlg        string
	AccessTokenAlg    string
	RolesClaim        string
	LoginUI           string
	AccessTokenFormat string
	SubjectType       string
	Sector            string
	SecurityProfile   string
	RequirePAR        bool
	RequireState      bool
	FirstParty        bool
	IssuerAlias       string
	MinimumACR        string
	// ConsentLifetime is 0 for a consent that does not expire.
	ConsentLifetime time.Duration
}

// ClientSettingsOf reads a client's token settings.
func ClientSettingsOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (ClientSettingsView, error) {
	var v ClientSettingsView
	var access, refresh, grace, consent int
	err := q.QueryRow(ctx, `SELECT access_token_ttl_s, refresh_token_ttl_s, refresh_reuse_grace_s, id_token_signed_alg,
		       COALESCE(access_token_signed_alg, ''), COALESCE(roles_claim, ''), access_token_format,
		       subject_type, sector, security_profile,
		       require_pushed_authorization, first_party, COALESCE(issuer_alias, ''), minimum_acr,
		       COALESCE(consent_lifetime_s, 0), require_state, COALESCE(login_ui_url, '')
		FROM core.clients WHERE client_id = $1`, clientID).
		Scan(&access, &refresh, &grace, &v.IDTokenAlg, &v.AccessTokenAlg, &v.RolesClaim, &v.AccessTokenFormat,
			&v.SubjectType, &v.Sector, &v.SecurityProfile, &v.RequirePAR, &v.FirstParty, &v.IssuerAlias, &v.MinimumACR, &consent, &v.RequireState, &v.LoginUI)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrClientNotFound
	}
	v.AccessTokenTTL = time.Duration(access) * time.Second
	v.RefreshTokenTTL = time.Duration(refresh) * time.Second
	v.RefreshReuseGrace = time.Duration(grace) * time.Second
	v.ConsentLifetime = time.Duration(consent) * time.Second
	return v, err
}
