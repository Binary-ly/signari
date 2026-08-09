// Package oidc builds the provider metadata document.
package oidc

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/sulimanbenhalim/idp/engine/internal/keys"
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

	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ResponseModesSupported []string `json:"response_modes_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
	SubjectTypesSupported  []string `json:"subject_types_supported"`

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
			"issuer must be https (got %q); set IDP_INSECURE_ISSUER=1 only for local testing", cfg.Issuer)
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

		ScopesSupported: []string{"openid", "profile", "email", "offline_access"},

		// Code only. OAuth 2.1 removes implicit and the hybrid flows, and every
		// response type that returns a token in the front channel is a class of
		// bug we are choosing not to have.
		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query", "form_post"},

		// No `password` grant: ROPC is removed in OAuth 2.1 and there is no
		// version of it that is safe to offer.
		GrantTypesSupported: []string{"authorization_code", "refresh_token", "client_credentials"},

		SubjectTypesSupported:    []string{"public"},
		IDTokenSigningAlgValues:  algNames,
		TokenEndpointAuthMethods: []string{"client_secret_basic", "client_secret_post", "none"},

		// S256 only, and the authorize endpoint enforces it. `plain` is not
		// listed because it is not accepted.
		CodeChallengeMethodsSupported: []string{"S256"},

		ClaimsSupported: []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
			"acr", "amr", "azp", "sid", "email", "email_verified",
			"name", "preferred_username",
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
