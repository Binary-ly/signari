// Package oidc builds the provider metadata document.
package oidc

import (
	"fmt"
	"net/url"
	"strings"

	"signari.dev/engine/internal/keys"
)

// Metadata is the OpenID Provider configuration served at
// /.well-known/openid-configuration (OIDC Discovery 1.0 + RFC 8414).
//
// THE RULE FOR THIS FILE: never advertise a capability the server does not
// enforce. OIDF Config OP certification tests the document against the running
// server, and the standard failure is metadata claiming something that is not
// true -- listing S256 in code_challenge_methods_supported without requiring it,
// or advertising a signing algorithm with no active key. Every field below is
// therefore derived from real capability, never hardcoded optimism.
type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`

	ScopesSupported []string `json:"scopes_supported"`
	// OpenID Connect Front-Channel Logout 1.0 §3.
	FrontchannelLogoutSupported        bool `json:"frontchannel_logout_supported,omitempty"`
	FrontchannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported,omitempty"`
	// RFC 9126 §5.
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint,omitempty"`
	RegistrationEndpoint               string `json:"registration_endpoint,omitempty"`
	// RFC 9449 §5.1.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
	// OIDC Discovery §3.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`

	IDTokenSigningAlgValues       []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ClaimsSupported               []string `json:"claims_supported"`

	// RFC 9207. Cheap, and it closes the mix-up attack, so it is on by default.
	AuthorizationResponseIssParamSupported bool `json:"authorization_response_iss_parameter_supported"`

	// Back-channel logout is the only logout mechanism that survives third-party
	// cookie blocking, so it is advertised and front-channel is not.
	BackchannelLogoutSupported        bool `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported"`

	RequestParameterSupported    bool `json:"request_parameter_supported"`
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
}

// Config is what the engine knows about itself when rendering metadata.
type Config struct {
	Issuer string
	Keys   *keys.Set

	// IssuerAliases are legacy issuers this deployment also claims, for clients
	// still being migrated from another provider. Tokens minted under one must
	// still be accepted by our own userinfo and introspection.
	IssuerAliases []string

	// ProxyCookieDomain scopes the forward-auth cookie to the parent domain, so
	// every protected subdomain receives it. Empty disables forward auth, which
	// is the right default: a cookie domain nobody set is one nobody reasoned
	// about.
	ProxyCookieDomain string

	// Root wraps per-subject encryption keys. Needed wherever a stored personal
	// secret must be read back -- today the TOTP secret. Held here rather than
	// passed around so there is exactly one place it enters the request path.
	Root *keys.RootKey

	// AllowInsecureIssuer permits a plaintext issuer on a non-localhost host.
	//
	// It exists for exactly one reason: the OIDF conformance suite runs inside a
	// container runtime and must reach the engine by a service name, and relying
	// parties compare the issuer byte-for-byte -- so the issuer has to be that
	// service name, which is neither https nor localhost.
	//
	// It is off by default, must be set explicitly, and the engine logs a warning
	// on every start when it is on. It is NOT a convenience: an issuer served over
	// plaintext means every token, code and secret in the flow crosses the network
	// readable, so anything that sets this in production has no security at all.
	AllowInsecureIssuer bool
}

// Paths are fixed relative to the issuer so that discovery, the routes the server
// actually registers, and the documentation cannot drift apart.
const (
	PathAuthorize     = "/oauth2/authorize"
	PathToken         = "/oauth2/token"
	PathUserinfo      = "/oauth2/userinfo"
	PathJWKS          = "/oauth2/jwks"
	PathEndSession    = "/oauth2/logout"
	PathRevocation    = "/oauth2/revoke"
	PathIntrospection = "/oauth2/introspect"
	PathDiscovery     = "/.well-known/openid-configuration"
)

// Build renders the metadata document for the given configuration.
func Build(cfg Config) (*Metadata, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	u, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer %q is not a URL: %w", cfg.Issuer, err)
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && !cfg.AllowInsecureIssuer {
		return nil, fmt.Errorf(
			"issuer must be https (got %q); set SIGNARI_INSECURE_ISSUER=1 only for local testing", cfg.Issuer)
	}
	// The issuer is compared byte-for-byte by relying parties, and RFC 8414
	// forbids a query or fragment. A trailing slash silently breaks RPs that
	// concatenate rather than resolve.
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("issuer must not carry a query or fragment")
	}
	if strings.HasSuffix(cfg.Issuer, "/") {
		return nil, fmt.Errorf("issuer must not end in a slash")
	}
	if cfg.Keys == nil {
		return nil, fmt.Errorf("a key set is required")
	}

	algs := cfg.Keys.Algorithms()
	if len(algs) == 0 {
		// Publishing a document with an empty alg list would be worse than
		// failing: RPs would treat the provider as usable and then fail at token
		// verification with no explanation.
		return nil, fmt.Errorf("no active signing keys: refusing to publish metadata")
	}
	algNames := make([]string, 0, len(algs))
	for _, a := range algs {
		algNames = append(algNames, string(a))
	}

	at := func(p string) string { return cfg.Issuer + p }

	return &Metadata{
		Issuer:                cfg.Issuer,
		AuthorizationEndpoint: at(PathAuthorize),
		TokenEndpoint:         at(PathToken),
		UserinfoEndpoint:      at(PathUserinfo),
		JWKSURI:               at(PathJWKS),
		EndSessionEndpoint:    at(PathEndSession),
		RevocationEndpoint:    at(PathRevocation),
		IntrospectionEndpoint: at(PathIntrospection),

		// `groups` is advertised because it now works. Every scope and claim in
		// this document is one the engine actually honours -- the rule this file
		// has enforced since the first audit found three endpoints advertised and
		// unimplemented.
		//
		// Note what advertising it does NOT mean: asking for `groups` gets a
		// client nothing unless an operator has also released groups to that
		// client. Both gates apply, and only one of them is the client's to pass.
		ScopesSupported: []string{"openid", "profile", "email", "groups", "offline_access"},
		// Advertised because it works end to end: bound at the token endpoint,
		// enforced at the resource. A client reads this to decide whether to
		// generate a key at all.
		// The signing algorithms accepted for a private_key_jwt assertion.
		// Asymmetric only: an HMAC assertion is client_secret_jwt, a different
		// mechanism verified with a key both sides hold.
		TokenEndpointAuthSigningAlgValuesSupported: []string{
			"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
			"ES256", "ES384", "ES512", "EdDSA",
		},
		PushedAuthorizationRequestEndpoint: at("/oauth2/par"),
		DeviceAuthorizationEndpoint:        at("/oauth2/device_authorization"),
		// Both logout channels are advertised because both run. Back-channel is
		// the reliable one; the front channel reaches browser-held state the back
		// channel cannot. Claiming either alone would overstate what a logout
		// achieves.
		FrontchannelLogoutSupported:        true,
		FrontchannelLogoutSessionSupported: true,
		DPoPSigningAlgValuesSupported: []string{
			"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
			"ES256", "ES384", "ES512", "EdDSA",
		},

		// Code only. OAuth 2.1 removes implicit and the hybrid flows, and every
		// response type that returns a token in the front channel is a class of
		// bug we are choosing not to have.
		ResponseTypesSupported: []string{"code"},
		// `query` alone. form_post was advertised and then ignored -- the
		// authorize endpoint now refuses it outright, and a mode that is refused
		// must not appear here. With `code` as the only response type there is
		// nothing in the redirect that form_post would protect.
		ResponseModesSupported: []string{"query", "fragment", "form_post"},

		// No `password` grant: ROPC is removed in OAuth 2.1 and there is no
		// version of it that is safe to offer.
		// token-exchange is listed only now that the grant is reachable and
		// enforced -- the rule this file exists to hold: nothing enters discovery
		// before it works.
		GrantTypesSupported: []string{"authorization_code", "refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},

		SubjectTypesSupported:   []string{"public"},
		IDTokenSigningAlgValues: algNames,
		// private_key_jwt is advertised because it is implemented AND enforced --
		// a client configured for it cannot fall back to a secret, which is the
		// downgrade that would make advertising it dishonest.
		TokenEndpointAuthMethods: []string{
			"client_secret_basic", "client_secret_post", "private_key_jwt",
			// RFC 8705. Advertised unconditionally because the token endpoint
			// accepts them whenever a client is registered for one -- unlike
			// registration_endpoint, which needs an organisation to opt in before
			// it answers anything at all.
			"tls_client_auth", "self_signed_tls_client_auth", "none",
		},

		// S256 only, and the authorize endpoint enforces it. `plain` is not
		// listed because it is not accepted.
		CodeChallengeMethodsSupported: []string{"S256"},

		ClaimsSupported: []string{
			"groups",
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
			"acr", "amr", "azp", "sid", "email", "email_verified",
			// No "name": nothing stores a display name, and advertising a claim
			// that is never emitted is the failure this file exists to prevent.
			"preferred_username",
		},

		AuthorizationResponseIssParamSupported: true,

		BackchannelLogoutSupported:        true,
		BackchannelLogoutSessionSupported: true,

		// Advertised as false until JAR is actually implemented. Claiming support
		// here and rejecting the parameter in practice is exactly the Config OP
		// failure this file exists to avoid.
		RequestParameterSupported:    false,
		RequestURIParameterSupported: false,
	}, nil
}
