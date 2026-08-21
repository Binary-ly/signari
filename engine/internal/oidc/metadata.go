// Package oidc builds the provider metadata document.
package oidc

import (
	"fmt"
	"net/url"
	"signari.dev/engine/internal/abca"
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
	// CIBA Core 1.0 §4 metadata. The delivery modes are listed explicitly:
	// "poll" and "ping". Push is absent because it hands the token itself to the
	// notification endpoint, which needs a different security analysis from
	// handing over an identifier the client must still authenticate to redeem.
	//
	// Ping is per-CLIENT, so advertising it changes nothing for a client
	// registered to poll -- and a client registered for ping that sends no
	// notification token is refused at the backchannel endpoint rather than
	// issued an auth_req_id it would wait on forever. That is the rule this file
	// exists to keep: the document may only claim what the server enforces.
	// UMA 2.0 Federated Authorization §2: where a resource server asks for a
	// permission ticket.
	PermissionEndpoint                string   `json:"permission_endpoint,omitempty"`
	BackchannelAuthenticationEndpoint string   `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelTokenDeliveryModes     []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelUserCodeSupported      *bool    `json:"backchannel_user_code_parameter_supported,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	// RFC 9449 §5.1.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
	// OIDC Discovery §3.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	// RFC 9396 §10. Populated per deployment at request time, because the
	// registered types are a deployment's own list -- so this is empty in the
	// static document and filled in by the discovery handler.
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	SubjectTypesSupported []string `json:"subject_types_supported"`

	IDTokenSigningAlgValues  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`

	// §8 makes these two a MUST once the Client Attestation PoP mechanism is
	// offered: "The Authorization Server or Resource Server MUST include
	// client_attestation_signing_alg_values_supported and
	// client_attestation_pop_signing_alg_values_supported in its published
	// metadata if the Client Attestation PoP JWT mechanism is used."
	ClientAttestationAlgs    []string `json:"client_attestation_signing_alg_values_supported,omitempty"`
	ClientAttestationPoPAlgs []string `json:"client_attestation_pop_signing_alg_values_supported,omitempty"`

	// §6.1: "it MUST signal support for the challenge endpoint by including the
	// metadata entry challenge_endpoint containing the URL of the endpoint".
	ChallengeEndpoint             string   `json:"challenge_endpoint,omitempty"`
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

	RefuseClonedAuthenticators bool
}

// Paths are fixed relative to the issuer so that discovery, the routes the server
// actually registers, and the documentation cannot drift apart.
const (
	PathAuthorize  = "/oauth2/authorize"
	PathToken      = "/oauth2/token"
	PathUserinfo   = "/oauth2/userinfo"
	PathJWKS       = "/oauth2/jwks"
	PathEndSession = "/oauth2/logout"
	PathRevocation = "/oauth2/revoke"
	// PathAttestationChallenge is draft-ietf-oauth-attestation-based-client-auth-10 §6.1.
	PathAttestationChallenge = "/oauth2/attestation-challenge"
	PathIntrospection        = "/oauth2/introspect"
	PathDiscovery            = "/.well-known/openid-configuration"
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
		// §6.1 and §8: the challenge endpoint and the two algorithm lists are
		// advertised together with the method, because a client is told to fetch
		// a challenge only by finding this entry.
		ChallengeEndpoint:        at(PathAttestationChallenge),
		ClientAttestationAlgs:    abca.SigningAlgs(),
		ClientAttestationPoPAlgs: abca.SigningAlgs(),
		IntrospectionEndpoint:    at(PathIntrospection),

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
		PermissionEndpoint:                 at("/uma2/permission"),
		BackchannelAuthenticationEndpoint:  at("/oauth2/backchannel"),
		// Ping is per-client: a client registered for poll experiences no change
		// from this being advertised, and a client registered for ping is refused
		// at the backchannel endpoint if it sends no notification token.
		BackchannelTokenDeliveryModes:      []string{"poll", "ping"},
		// Advertised as false rather than omitted. §7.1 gates `user_code` on this
		// being true, and a client reading an absent field has to guess; a client
		// reading `false` knows not to send one, which is exactly what the
		// endpoint enforces.
		BackchannelUserCodeSupported: &cibaUserCodeUnsupported,
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
		// All three, and all three are served.
		//
		// This comment used to say "`query` alone... the authorize endpoint now
		// refuses [form_post] outright, and a mode that is refused must not
		// appear here" -- directly above a line listing three modes. It described
		// a state that ended when form_post was implemented, and nobody updated
		// it.
		//
		// Stale in the worst place: this is exactly where a reader checks the
		// advertise-only-what-you-serve invariant, and the comment told them the
		// list was shorter than it is. The invariant itself holds --
		// `ValidateAuthz` accepts query, fragment and form_post, and
		// `internal/httpapi/responsemode.go` renders all three, form_post as a
		// self-posting HTML page.
		ResponseModesSupported: []string{"query", "fragment", "form_post"},

		// No `password` grant: ROPC is removed in OAuth 2.1 and there is no
		// version of it that is safe to offer.
		// token-exchange is listed only now that the grant is reachable and
		// enforced -- the rule this file exists to hold: nothing enters discovery
		// before it works.
		//
		// The OID4VCI pre-authorized code grant is here for the same reason: the
		// token endpoint dispatches it, a wallet can redeem an offer without
		// sending client_id at all, and `signari credential offer` mints one. It
		// was deliberately absent while only the rules existed.
		GrantTypesSupported: []string{"authorization_code", "refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
			"urn:openid:params:grant-type:ciba",
			"urn:ietf:params:oauth:grant-type:uma-ticket"},

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
			// draft-ietf-oauth-attestation-based-client-auth-10 §8. Only the
			// Client Attestation PoP form is advertised; the DPoP combined mode
			// (`attest_jwt_client_auth_dpop`) is not implemented, and advertising
			// a method we would refuse is the exact dishonesty this file exists
			// to prevent.
			abca.MethodPoP,
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

// cibaUserCodeUnsupported backs the pointer in the metadata, so the field is
// emitted as an explicit false rather than omitted.
var cibaUserCodeUnsupported = false
