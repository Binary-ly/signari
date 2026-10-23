package store

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
)

// Registering an upstream identity provider, as `signari idp add`, `idp
// add-issuer` and the Admin API do it (6.07): the checks, the discovery that
// makes a wrong issuer fail in front of the person who typed it, and the rows.

// ErrIdPSlugTaken is a slug another provider has, in any organisation: it is
// the sign-in URL /login/with/<slug>, which names no organisation.
var ErrIdPSlugTaken = errors.New("another identity provider in this deployment has that slug")

// IdentityProviderSpec is one provider to register.
type IdentityProviderSpec struct {
	Slug, Name string
	// Kind is a named provider (google, github, microsoft and the rest of
	// federation's presets), oidc, saml, or assertion: an issuer that only
	// publishes signing keys, for the jwt-bearer grant.
	Kind string
	// ClientID and ClientSecret are what the provider issued; SAML and an
	// assertion issuer have neither.
	ClientID, ClientSecret string
	// Issuer is the one a generic OIDC provider is discovered from, the `iss`
	// an assertion issuer's JWTs carry, and an override for a named provider.
	Issuer string
	// JWKSURL is where an assertion issuer publishes its keys, and where
	// discovery found a generic provider's.
	JWKSURL string
	// AuthorizeURL, TokenURL and UserinfoURL are a generic provider's, filled
	// by Resolve.
	AuthorizeURL, TokenURL, UserinfoURL string
	AllowSignup, AllowLinking           bool
	// TrustEmailVerification believes the provider's email_verified, for a
	// generic OIDC provider or a SAML upstream.
	TrustEmailVerification bool
	// A SAML upstream's: the entity ID every assertion's Issuer is matched
	// against, where AuthnRequests go, the certificate assertions are
	// verified with, the NameID format, and the clock tolerance.
	EntityID, SSOURL, CertPEM, NameIDFormat string
	AllowUnsolicited, ForceAuthn            bool
	SkewSeconds                             int
}

func (s *IdentityProviderSpec) invalid(format string, a ...any) error {
	return idpInvalid{fmt.Sprintf(format, a...)}
}

// Validate refuses what the provider could not work with, and fills the
// defaults: the name is the slug, a SAML NameID is persistent.
func (s *IdentityProviderSpec) Validate() error {
	s.Slug, s.Kind = strings.TrimSpace(s.Slug), strings.TrimSpace(s.Kind)
	if s.Slug == "" {
		return s.invalid("a provider needs a slug, the short name in /login/with/<slug>")
	}
	if s.Name == "" {
		s.Name = s.Slug
	}
	switch s.Kind {
	case "saml":
		return s.validateSAML()
	case "assertion":
		switch {
		case s.Issuer == "":
			return s.invalid("an assertion issuer needs the exact issuer its assertions carry in iss")
		case s.JWKSURL == "":
			return s.invalid("an assertion issuer needs the URL publishing its signing keys")
		case s.AllowSignup || s.AllowLinking:
			return s.invalid("an assertion issuer signs nobody in, so it can neither create accounts nor be " +
				"linked to one by a person")
		case s.TrustEmailVerification:
			return s.invalid("an assertion issuer signs nobody in, so no address of its is recorded")
		}
		return nil
	}
	if _, err := federation.PresetFor(federation.Kind(s.Kind)); err != nil {
		return s.invalid("%v", err)
	}
	switch {
	case s.ClientID == "":
		return s.invalid("a %s provider needs the client id it issued", s.Kind)
	case s.Kind == "oidc" && s.Issuer == "":
		return s.invalid("a generic OIDC provider needs its issuer, so its endpoints and signing keys can be " +
			"discovered")
	case s.TrustEmailVerification && s.Kind != "oidc":
		return s.invalid("a %s provider's email_verified is believed or not as that provider is known to "+
			"behave; only a generic OIDC provider's is set here", s.Kind)
	}
	return nil
}

func (s *IdentityProviderSpec) validateSAML() error {
	switch {
	case s.EntityID == "":
		return s.invalid("a SAML upstream needs its entity ID, which is matched exactly against the Issuer in " +
			"every assertion")
	case s.SSOURL == "":
		return s.invalid("a SAML upstream needs the URL AuthnRequests are sent to")
	case s.CertPEM == "":
		return s.invalid("a SAML upstream needs the certificate assertions are verified against: without it " +
			"there is nothing to check a signature with, and an unverified assertion is an attacker's choice " +
			"of user")
	case s.ClientID != "" || s.ClientSecret != "":
		return s.invalid("a SAML upstream has no client id or secret")
	case s.SkewSeconds < 0 || s.SkewSeconds > 300:
		return s.invalid("a clock tolerance of %d seconds is outside 0 to 300: a large one quietly extends "+
			"how long a captured assertion can be replayed", s.SkewSeconds)
	}
	// transient is deliberately absent: a NameID that differs on every
	// sign-in would create a new orphaned account each time.
	switch s.NameIDFormat {
	case "":
		s.NameIDFormat = "persistent"
	case "persistent", "emailAddress", "unspecified":
	default:
		return s.invalid("the NameID format must be persistent, emailAddress or unspecified, not %q. "+
			"transient is refused: it is a different value on every sign-in, so an account linked to it "+
			"would be abandoned the moment it was created", s.NameIDFormat)
	}
	// The SSO URL becomes a Location header sent to everybody starting a
	// sign-in, so its scheme is checked here rather than trusted later.
	u, err := url.Parse(s.SSOURL)
	switch {
	case err != nil:
		return s.invalid("the SSO URL %q is not a URL: %v", s.SSOURL, err)
	case u.Scheme != "https" && u.Scheme != "http":
		return s.invalid("the SSO URL must be http or https, not %q: it is sent to a browser as a redirect",
			u.Scheme)
	case u.Host == "":
		return s.invalid("the SSO URL %q has no host", s.SSOURL)
	case u.Scheme == "http" && !strings.HasPrefix(u.Host, "localhost") && !strings.HasPrefix(u.Host, "127.0.0.1"):
		return s.invalid("the SSO URL is plaintext http. The AuthnRequest names this engine and the person " +
			"being signed in, and the response comes back over the same browser session; use https")
	}
	// Parsed now, so a PEM that is not a certificate is refused here rather
	// than at every sign-in.
	block, _ := pem.Decode([]byte(s.CertPEM))
	if block == nil {
		return s.invalid("the certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return s.invalid("the certificate does not parse: %v", err)
	}
	if time.Now().After(cert.NotAfter) {
		return s.invalid("the certificate expired on %s, so every assertion it signs would be refused",
			cert.NotAfter.Format("2006-01-02"))
	}
	return nil
}

// Resolve reaches the provider before anything is stored, so a wrong issuer
// or key URL fails in front of the person who typed it rather than at the
// first sign-in: a generic OIDC provider is discovered, and an assertion
// issuer's keys are read, answering how many. hc is the client the engine
// reaches the provider with at sign-in, so an address it would refuse then is
// refused now.
func (s *IdentityProviderSpec) Resolve(ctx context.Context, hc *http.Client) (keyCount int, err error) {
	switch s.Kind {
	case "oidc":
		d, err := federation.Discover(ctx, hc, s.Issuer)
		if err != nil {
			return 0, s.invalid("discovering %s: %v", s.Issuer, err)
		}
		s.AuthorizeURL, s.TokenURL, s.UserinfoURL, s.JWKSURL = d.AuthorizeURL, d.TokenURL, d.UserinfoURL, d.JWKSURL
	case "assertion":
		set, err := federation.FetchJWKS(ctx, hc, s.JWKSURL)
		if err != nil {
			return 0, s.invalid("reading %s: %v", s.JWKSURL, err)
		}
		return len(set.Keys), nil
	}
	return 0, nil
}

// AddIdentityProvider stores a validated, resolved provider in the
// organisation and answers its id. A SAML upstream writes two rows, so q
// should be a transaction. The client secret is sealed under the root key;
// root may be nil when there is none.
func AddIdentityProvider(ctx context.Context, q outpostDB, root *keys.RootKey, orgID string,
	s IdentityProviderSpec) (string, error) {
	var sealed []byte
	if s.ClientSecret != "" {
		if root == nil {
			return "", errors.New("sealing a client secret needs the root key")
		}
		var err error
		if sealed, err = root.Seal([]byte(s.ClientSecret), "idp_client_secret"); err != nil {
			return "", fmt.Errorf("sealing the client secret: %w", err)
		}
	}
	var id string
	var err error
	switch s.Kind {
	case "saml":
		err = q.QueryRow(ctx, `
			INSERT INTO core.identity_providers
				(org_id, slug, display_name, kind, client_id, scopes, allow_signup, allow_linking,
				 trust_email_verification)
			VALUES ($1::uuid, $2, $3, 'saml', '', '{}', $4, $5, $6)
			RETURNING id::text`, orgID, s.Slug, s.Name, s.AllowSignup, s.AllowLinking,
			s.TrustEmailVerification).Scan(&id)
		if err == nil {
			_, err = q.Exec(ctx, `
				INSERT INTO core.saml_sources
					(provider_id, org_id, entity_id, sso_url, cert_pem, name_id_format, force_authn,
					 allow_unsolicited, skew_seconds)
				VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)`, id, orgID, s.EntityID, s.SSOURL,
				s.CertPEM, s.NameIDFormat, s.ForceAuthn, s.AllowUnsolicited, s.SkewSeconds)
		}
	case "assertion":
		// Assertions stay refused until somebody allows them: registering
		// trust and granting it are two decisions.
		err = q.QueryRow(ctx, `
			INSERT INTO core.identity_providers
				(org_id, slug, display_name, kind, client_id, issuer, jwks_url, allow_signup, allow_linking,
				 enabled, allow_jwt_bearer)
			VALUES ($1::uuid, $2, $3, 'assertion', '', $4, $5, false, false, true, false)
			RETURNING id::text`, orgID, s.Slug, s.Name, s.Issuer, s.JWKSURL).Scan(&id)
	default:
		if s.Kind == "oidc" && s.AuthorizeURL == "" {
			return "", errors.New("a generic OIDC provider is stored only once Resolve has discovered it")
		}
		preset, perr := federation.PresetFor(federation.Kind(s.Kind))
		if perr != nil {
			return "", perr
		}
		err = q.QueryRow(ctx, `
			INSERT INTO core.identity_providers
				(org_id, slug, display_name, kind, client_id, client_secret, issuer, authorize_url, token_url,
				 userinfo_url, jwks_url, scopes, allow_signup, allow_linking, trust_email_verification)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, NULLIF($7,''), NULLIF($8,''), NULLIF($9,''), NULLIF($10,''),
			        NULLIF($11,''), $12, $13, $14, $15)
			RETURNING id::text`, orgID, s.Slug, s.Name, s.Kind, s.ClientID, sealed, s.Issuer, s.AuthorizeURL,
			s.TokenURL, s.UserinfoURL, s.JWKSURL, preset.Scopes, s.AllowSignup, s.AllowLinking,
			s.TrustEmailVerification).Scan(&id)
	}
	if err != nil {
		if isUniqueViolation(err) {
			return "", ErrIdPSlugTaken
		}
		return "", err
	}
	return id, nil
}
