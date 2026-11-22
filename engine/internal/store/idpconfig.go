package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// An upstream identity provider as a configuration file declares it (6.19):
// what IdentityProviders lists, plus the client id, the endpoints and a SAML
// upstream's settings, which a plan compares and an export writes.

// ErrIdPSecretForAnotherClient is a provider holding a client secret given
// another client id, issuer or token endpoint without one: the secret was
// issued for the old ones, and would be sent to the new token endpoint.
var ErrIdPSecretForAnotherClient = errors.New("a provider's client secret was issued with its client id for its " +
	"token endpoint; changing either needs the secret given again, or it would be sent where it was never meant to go")

// SAMLUpstreamSettings are a SAML upstream's.
type SAMLUpstreamSettings struct {
	EntityID, SSOURL, CertPEM, NameIDFormat string
	ForceAuthn, AllowUnsolicited            bool
	SkewSeconds                             int
}

// IdentityProviderSettings is the part of a provider IdentityProviderRow does
// not carry. Never the client secret, only whether one is held.
type IdentityProviderSettings struct {
	ClientID, AuthorizeURL, TokenURL, UserinfoURL, JWKSURL string
	HasSecret                                              bool
	SAML                                                   *SAMLUpstreamSettings
}

// IdentityProviderSettingsOf reads every provider's settings, by slug.
func IdentityProviderSettingsOf(ctx context.Context, q Querier, orgID string) (map[string]IdentityProviderSettings,
	error) {
	rows, err := q.Query(ctx, `
		SELECT p.slug, p.client_id, COALESCE(p.authorize_url, ''), COALESCE(p.token_url, ''),
		       COALESCE(p.userinfo_url, ''), COALESCE(p.jwks_url, ''), p.client_secret IS NOT NULL,
		       s.entity_id IS NOT NULL, COALESCE(s.entity_id, ''), COALESCE(s.sso_url, ''),
		       COALESCE(s.cert_pem, ''), COALESCE(s.name_id_format, ''), COALESCE(s.force_authn, false),
		       COALESCE(s.allow_unsolicited, false), COALESCE(s.skew_seconds, 0)
		  FROM core.identity_providers p LEFT JOIN core.saml_sources s ON s.provider_id = p.id
		 WHERE p.org_id = $1::uuid`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]IdentityProviderSettings{}
	for rows.Next() {
		var slug string
		var p IdentityProviderSettings
		var isSAML bool
		var s SAMLUpstreamSettings
		if err := rows.Scan(&slug, &p.ClientID, &p.AuthorizeURL, &p.TokenURL, &p.UserinfoURL, &p.JWKSURL,
			&p.HasSecret, &isSAML, &s.EntityID, &s.SSOURL, &s.CertPEM, &s.NameIDFormat, &s.ForceAuthn,
			&s.AllowUnsolicited, &s.SkewSeconds); err != nil {
			return nil, err
		}
		if isSAML {
			p.SAML = &s
		}
		out[slug] = p
	}
	return out, rows.Err()
}

// IdentityProviderSecret opens a provider's client secret, so a plan can say
// whether the one a configuration file names differs. Never shown.
func IdentityProviderSecret(ctx context.Context, q outpostDB, root *keys.RootKey, orgID, slug string) (string, error) {
	var sealed []byte
	if err := q.QueryRow(ctx, `SELECT client_secret FROM core.identity_providers WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&sealed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrProviderUnknown
		}
		return "", err
	}
	if len(sealed) == 0 {
		return "", nil
	}
	if root == nil {
		return "", fmt.Errorf("provider %q's client secret is sealed and no root key is loaded", slug)
	}
	plain, err := root.Open(sealed, "idp_client_secret")
	if err != nil {
		return "", fmt.Errorf("provider %q's client secret does not open: %w", slug, err)
	}
	return string(plain), nil
}

// IdentityProviderUpdate is what changes about a registered provider, a nil
// field left as it is. The kind is fixed once registered; the settings
// ChangeIdentityProvider writes are its.
type IdentityProviderUpdate struct {
	Name, ClientID, ClientSecret, Issuer         *string
	AuthorizeURL, TokenURL, UserinfoURL, JWKSURL *string
	AllowSignup, AllowLinking                    *bool
	// SAML replaces a SAML upstream's settings whole, checked as at
	// registration.
	SAML *SAMLUpstreamSettings
}

// UpdateIdentityProvider changes a registered provider as a configuration
// file declares it (6.19), the result checked as IdentityProviderSpec checks a
// new one.
func UpdateIdentityProvider(ctx context.Context, q outpostDB, root *keys.RootKey, orgID, slug string,
	u IdentityProviderUpdate) error {
	var kind, clientID, issuer, tokenURL string
	var held bool
	if err := q.QueryRow(ctx, `SELECT kind, client_id, COALESCE(issuer, ''), COALESCE(token_url, ''),
		client_secret IS NOT NULL FROM core.identity_providers WHERE org_id = $1::uuid AND slug = $2`, orgID, slug).
		Scan(&kind, &clientID, &issuer, &tokenURL, &held); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProviderUnknown
		}
		return err
	}
	differs := func(want *string, have string) bool { return want != nil && *want != have }
	if held && u.ClientSecret == nil && (differs(u.ClientID, clientID) || differs(u.Issuer, issuer) ||
		differs(u.TokenURL, tokenURL)) {
		return ErrIdPSecretForAnotherClient
	}
	if u.SAML != nil {
		if kind != "saml" {
			return idpInvalid{fmt.Sprintf("%s is a %s provider, not a SAML upstream", slug, kind)}
		}
		spec := IdentityProviderSpec{Slug: slug, Kind: "saml", EntityID: u.SAML.EntityID, SSOURL: u.SAML.SSOURL,
			CertPEM: u.SAML.CertPEM, NameIDFormat: u.SAML.NameIDFormat, SkewSeconds: u.SAML.SkewSeconds}
		if err := spec.Validate(); err != nil {
			return err
		}
		u.SAML.NameIDFormat = spec.NameIDFormat
	}
	var sealed []byte
	if u.ClientSecret != nil && *u.ClientSecret != "" {
		if root == nil {
			return errors.New("sealing a client secret needs the root key")
		}
		var err error
		if sealed, err = root.Seal([]byte(*u.ClientSecret), "idp_client_secret"); err != nil {
			return fmt.Errorf("sealing the client secret: %w", err)
		}
	}
	if _, err := q.Exec(ctx, `
		UPDATE core.identity_providers SET
			display_name  = COALESCE($3::text, display_name),
			client_id     = COALESCE($4::text, client_id),
			client_secret = CASE WHEN $5::boolean THEN $6::bytea ELSE client_secret END,
			issuer        = CASE WHEN $7::text IS NULL THEN issuer ELSE NULLIF($7::text, '') END,
			authorize_url = CASE WHEN $8::text IS NULL THEN authorize_url ELSE NULLIF($8::text, '') END,
			token_url     = CASE WHEN $9::text IS NULL THEN token_url ELSE NULLIF($9::text, '') END,
			userinfo_url  = CASE WHEN $10::text IS NULL THEN userinfo_url ELSE NULLIF($10::text, '') END,
			jwks_url      = CASE WHEN $11::text IS NULL THEN jwks_url ELSE NULLIF($11::text, '') END,
			allow_signup  = COALESCE($12::boolean, allow_signup),
			allow_linking = COALESCE($13::boolean, allow_linking),
			updated_at    = now()
		 WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, u.Name, u.ClientID, u.ClientSecret != nil, sealed,
		u.Issuer, u.AuthorizeURL, u.TokenURL, u.UserinfoURL, u.JWKSURL, u.AllowSignup, u.AllowLinking); err != nil {
		return err
	}
	if u.SAML == nil {
		return nil
	}
	_, err := q.Exec(ctx, `
		UPDATE core.saml_sources s SET entity_id = $3, sso_url = $4, cert_pem = $5, name_id_format = $6,
		       force_authn = $7, allow_unsolicited = $8, skew_seconds = $9
		  FROM core.identity_providers p
		 WHERE p.id = s.provider_id AND p.org_id = $1::uuid AND p.slug = $2`, orgID, slug, u.SAML.EntityID,
		u.SAML.SSOURL, u.SAML.CertPEM, u.SAML.NameIDFormat, u.SAML.ForceAuthn, u.SAML.AllowUnsolicited,
		u.SAML.SkewSeconds)
	return err
}
