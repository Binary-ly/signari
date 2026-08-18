package oidfed

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var jwks = json.RawMessage(`{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"k1"}]}`)

func good() Params {
	return Params{
		EntityID:       "https://idp.example",
		FederationJWKS: jwks,
		Lifetime:       24 * time.Hour,
	}
}

// §3.1.2, of `authority_hints`: "MUST NOT be the empty array []. This Claim MUST
// NOT be present in Entity Configurations of Trust Anchors with no Superiors."
//
// The empty array is exactly what a naive implementation emits for "no
// superiors", and it is the one value forbidden outright. Absent and empty mean
// different things here, so nil and []string{} must not be treated alike.
func TestTheHintClaimsAreNeverTheEmptyArray(t *testing.T) {
	t.Run("an empty slice is refused, not normalised", func(t *testing.T) {
		p := good()
		p.AuthorityHints = []string{}
		if _, err := Build(p, time.Now()); err == nil {
			t.Fatal("an empty authority_hints was accepted; §3.1.2 forbids [] " +
				"and a caller passing it believes it is saying something")
		}
		p = good()
		p.TrustAnchorHints = []string{}
		if _, err := Build(p, time.Now()); err == nil {
			t.Fatal("an empty trust_anchor_hints was accepted")
		}
	})

	t.Run("nil means a Trust Anchor and is omitted from the JSON", func(t *testing.T) {
		c, err := Build(good(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(c)
		for _, claim := range []string{"authority_hints", "trust_anchor_hints"} {
			if strings.Contains(string(raw), claim) {
				t.Errorf("%s appears in a Trust Anchor's configuration: %s", claim, raw)
			}
		}
	})

	t.Run("a populated hint list survives", func(t *testing.T) {
		p := good()
		p.AuthorityHints = []string{"https://anchor.example"}
		c, err := Build(p, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(c)
		if !strings.Contains(string(raw), `"authority_hints":["https://anchor.example"]`) {
			t.Errorf("authority_hints was not emitted: %s", raw)
		}
	})
}

// §9: the Entity Identifier "MUST use the https scheme and contain a host
// component and MAY also contain port and path components".
func TestTheEntityIdentifierIsConstrained(t *testing.T) {
	for _, bad := range []string{
		"",
		"http://idp.example",      // not https
		"https://",                // no host
		"idp.example",             // not a URL
		"https://idp.example?x=1", // query
		"https://idp.example#f",   // fragment
		"https://u@idp.example",   // user-info
	} {
		if err := ValidateEntityID(bad); err == nil {
			t.Errorf("%q was accepted as an Entity Identifier", bad)
		}
	}
	for _, ok := range []string{
		"https://idp.example",
		"https://idp.example:8443",
		"https://idp.example/tenant/a",
	} {
		if err := ValidateEntityID(ok); err != nil {
			t.Errorf("%q was refused: %v", ok, err)
		}
	}

	// A hint is an Entity Identifier too, and gets the same treatment.
	p := good()
	p.AuthorityHints = []string{"http://anchor.example"}
	if _, err := Build(p, time.Now()); err == nil {
		t.Error("a plaintext authority hint was accepted")
	}
}

// §9: "If the Entity Identifier contains a trailing "/" character, it MUST be
// removed before concatenating /.well-known/openid-federation."
//
// Concatenating naively yields a doubled slash, which many servers answer and
// some do not — so it fails for some federation members and not others, which is
// the worst way for it to fail.
func TestTheConfigurationURLDropsATrailingSlash(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://idp.example", "https://idp.example/.well-known/openid-federation"},
		{"https://idp.example/", "https://idp.example/.well-known/openid-federation"},
		{"https://idp.example///", "https://idp.example/.well-known/openid-federation"},
		{"https://idp.example/tenant", "https://idp.example/tenant/.well-known/openid-federation"},
		{"https://idp.example/tenant/", "https://idp.example/tenant/.well-known/openid-federation"},
	} {
		got, err := ConfigurationURL(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ConfigurationURL(%q) = %q, want %q", c.in, got, c.want)
		}
		if strings.Contains(strings.TrimPrefix(got, "https://"), "//") {
			t.Errorf("%q produced a doubled slash: %s", c.in, got)
		}
	}
}

// iss and sub are both the Entity Identifier — that identity is what makes the
// statement an Entity *Configuration* rather than a Subordinate Statement.
func TestIssuerAndSubjectAreIdentical(t *testing.T) {
	c, err := Build(good(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != c.Subject {
		t.Fatalf("iss = %q, sub = %q; §3.1.1 makes them identical for an Entity "+
			"Configuration", c.Issuer, c.Subject)
	}
	if c.Issuer != "https://idp.example" {
		t.Errorf("iss = %q", c.Issuer)
	}
}

// jwks is REQUIRED (§3.1.1). A configuration with no keys cannot be verified.
func TestAConfigurationNeedsKeys(t *testing.T) {
	p := good()
	p.FederationJWKS = nil
	if _, err := Build(p, time.Now()); err == nil {
		t.Fatal("an Entity Configuration with no jwks was built")
	}
}
