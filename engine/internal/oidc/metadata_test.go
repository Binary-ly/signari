package oidc

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
)

func activeSet(t *testing.T, algs ...keys.Algorithm) *keys.Set {
	t.Helper()
	var ks []keys.Key
	for _, alg := range algs {
		k, err := keys.Generate(keys.NewKID(), alg)
		if err != nil {
			t.Fatal(err)
		}
		active, err := keys.WithState(k, keys.StateActive)
		if err != nil {
			t.Fatal(err)
		}
		ks = append(ks, active)
	}
	set, err := keys.NewSet(ks...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// An issuer a relying party would compare wrongly, or reach in plaintext, is
// refused before any document exists to be cached; so is a document that
// would advertise no signing algorithm.
func TestAnIssuerRelyingPartiesCannotUseIsRefused(t *testing.T) {
	set := activeSet(t, keys.ES256)
	next, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := keys.NewSet(next) // published, not yet signing
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		cfg  Config
		says string
	}{
		{"no issuer", Config{Keys: set}, "issuer is required"},
		{"plaintext", Config{Issuer: "http://idp.example.test", Keys: set}, "must be https"},
		{"a query", Config{Issuer: "https://idp.example.test?tenant=a", Keys: set}, "query or fragment"},
		{"a fragment", Config{Issuer: "https://idp.example.test#a", Keys: set}, "query or fragment"},
		{"a trailing slash", Config{Issuer: "https://idp.example.test/", Keys: set}, "slash"},
		{"not a URL", Config{Issuer: "https://idp.example.test/%zz", Keys: set}, "not a URL"},
		{"no key set", Config{Issuer: "https://idp.example.test"}, "key set"},
		{"no active key", Config{Issuer: "https://idp.example.test", Keys: unsigned}, "no active signing keys"},
	} {
		md, err := Build(c.cfg)
		if err == nil {
			t.Errorf("%s: built a document for %q", c.name, md.Issuer)
			continue
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: the refusal %q does not say %q", c.name, err, c.says)
		}
	}

	// The two plaintext issuers that are allowed, each for its stated reason.
	for _, cfg := range []Config{
		{Issuer: "http://localhost:8080", Keys: set},
		{Issuer: "http://signari:8080", Keys: set, AllowInsecureIssuer: true},
		{Issuer: "https://idp.example.test/tenants/a", Keys: set},
	} {
		if _, err := Build(cfg); err != nil {
			t.Errorf("%s was refused: %v", cfg.Issuer, err)
		}
	}
}

// Every endpoint hangs off the issuer exactly as given, so discovery and the
// routes cannot name different hosts or paths.
func TestEveryEndpointIsTheIssuerPlusItsFixedPath(t *testing.T) {
	const iss = "https://idp.example.test/tenants/a"
	md, err := Build(Config{Issuer: iss, Keys: activeSet(t, keys.ES256)})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"issuer", md.Issuer, iss},
		{"authorization_endpoint", md.AuthorizationEndpoint, iss + PathAuthorize},
		{"token_endpoint", md.TokenEndpoint, iss + PathToken},
		{"userinfo_endpoint", md.UserinfoEndpoint, iss + PathUserinfo},
		{"jwks_uri", md.JWKSURI, iss + PathJWKS},
		{"end_session_endpoint", md.EndSessionEndpoint, iss + PathEndSession},
		{"revocation_endpoint", md.RevocationEndpoint, iss + PathRevocation},
		{"introspection_endpoint", md.IntrospectionEndpoint, iss + PathIntrospection},
		{"challenge_endpoint", md.ChallengeEndpoint, iss + PathAttestationChallenge},
	} {
		if c.got != c.want {
			t.Errorf("%s is %q, want %q", c.name, c.got, c.want)
		}
	}
	for _, ep := range []string{md.PushedAuthorizationRequestEndpoint, md.DeviceAuthorizationEndpoint,
		md.PermissionEndpoint, md.BackchannelAuthenticationEndpoint} {
		if !strings.HasPrefix(ep, iss+"/") {
			t.Errorf("%q is not under the issuer", ep)
		}
	}
}

// The ID token algorithms are the active keys' algorithms and nothing more,
// so a key published for a coming rotation is not advertised before it signs.
func TestOnlyAlgorithmsWithAnActiveKeyAreAdvertised(t *testing.T) {
	set := activeSet(t, keys.ES256, keys.EdDSA)
	next, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Replace(append(set.Keys(), next)...); err != nil {
		t.Fatal(err)
	}
	md, err := Build(Config{Issuer: "https://idp.example.test", Keys: set})
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Clone(md.IDTokenSigningAlgValues)
	slices.Sort(got)
	if want := []string{"ES256", "EdDSA"}; !slices.Equal(got, want) {
		t.Errorf("id_token_signing_alg_values_supported is %q, want %q", got, want)
	}

	// No list a client chooses an algorithm from may offer a symmetric one or
	// none: a shared-secret signature is something either side can forge.
	for name, list := range map[string][]string{
		"id_token":        md.IDTokenSigningAlgValues,
		"token endpoint":  md.TokenEndpointAuthSigningAlgValuesSupported,
		"DPoP":            md.DPoPSigningAlgValuesSupported,
		"attestation":     md.ClientAttestationAlgs,
		"attestation PoP": md.ClientAttestationPoPAlgs,
	} {
		for _, alg := range list {
			if strings.HasPrefix(alg, "HS") || strings.EqualFold(alg, "none") {
				t.Errorf("the %s list offers %q", name, alg)
			}
		}
	}
}

// What the document says it refuses, it says explicitly: a client reading an
// absent field has to guess, and the guesses here are the unsafe ones.
func TestWhatIsRefusedIsSaidRatherThanOmitted(t *testing.T) {
	md, err := Build(Config{Issuer: "https://idp.example.test", Keys: activeSet(t, keys.ES256)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"backchannel_user_code_parameter_supported",
		"request_parameter_supported",
		"request_uri_parameter_supported",
	} {
		if v, ok := doc[field]; !ok || v != false {
			t.Errorf("%s is %v (present %v), want an explicit false", field, v, ok)
		}
	}
	if doc["authorization_response_iss_parameter_supported"] != true {
		t.Errorf("RFC 9207's iss parameter is not advertised")
	}

	if !slices.Equal(md.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Errorf("code_challenge_methods_supported is %q; plain is not accepted", md.CodeChallengeMethodsSupported)
	}
	if !slices.Equal(md.ResponseTypesSupported, []string{"code"}) {
		t.Errorf("response_types_supported is %q; no token is returned in the front channel", md.ResponseTypesSupported)
	}
	if slices.Contains(md.GrantTypesSupported, "password") || slices.Contains(md.GrantTypesSupported, "implicit") {
		t.Errorf("grant_types_supported offers a removed grant: %q", md.GrantTypesSupported)
	}
	for _, c := range []string{"name", "given_name", "family_name", "preferred_username"} {
		if !slices.Contains(md.ClaimsSupported, c) {
			t.Errorf("claims_supported lacks %s, which profile releases", c)
		}
	}
}

// ui_locales_supported appears only when there is a choice to make.
func TestUILocalesAreAdvertisedOnlyWhenThereIsAChoice(t *testing.T) {
	set := activeSet(t, keys.ES256)
	for _, c := range []struct {
		loaded []string
		want   []string
	}{
		{nil, nil},
		{[]string{"en"}, nil},
		{[]string{"en", "ar"}, []string{"en", "ar"}},
	} {
		md, err := Build(Config{Issuer: "https://idp.example.test", Keys: set, UILocalesSupported: c.loaded})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(md.UILocalesSupported, c.want) {
			t.Errorf("with %q loaded, ui_locales_supported is %q, want %q", c.loaded, md.UILocalesSupported, c.want)
		}
		raw, _ := json.Marshal(md)
		if present := strings.Contains(string(raw), "ui_locales_supported"); present != (c.want != nil) {
			t.Errorf("with %q loaded, the field is present=%v", c.loaded, present)
		}
	}
}
