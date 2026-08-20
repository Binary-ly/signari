package oidfed

import (
	"encoding/base64"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

// §6.2.1's worked example, used verbatim as the test matrix.
//
// The chain: LE, I1-about-LE, I2-about-I1, TA-about-I2. The specification lists
// three arrangements that satisfy the constraints and one that does not, so the
// arithmetic is checked against the authors' own arithmetic rather than mine.
func TestMaxPathLengthAgainstTheSpecificationsExample(t *testing.T) {
	chainOf := func(c1, c2, c3 *Constraints) []Statement {
		return []Statement{
			{Issuer: "https://le.example.com", Subject: "https://le.example.com"},
			{Issuer: "https://i1.example.com", Subject: "https://le.example.com", Constraints: c1},
			{Issuer: "https://i2.example.com", Subject: "https://i1.example.com", Constraints: c2},
			{Issuer: "https://ta.example.com", Subject: "https://i2.example.com", Constraints: c3},
		}
	}
	mpl := func(n int) *Constraints { return &Constraints{MaxPathLength: ptr(n)} }

	for _, tc := range []struct {
		name    string
		chain   []Statement
		wantErr bool
	}{
		// "The TA specifies a max_path_length that is greater than or equal to 2."
		{"TA allows 2", chainOf(nil, nil, mpl(2)), false},
		{"TA allows 3", chainOf(nil, nil, mpl(3)), false},
		// "TA specifies a max_path_length of 2, I2 specifies a max_path_length of
		// 1, and I1 omits the max_path_length constraint."
		{"TA 2, I2 1, I1 absent", chainOf(nil, mpl(1), mpl(2)), false},
		// "Neither TA nor I2 specifies any max_path_length constraint while I1
		// sets max_path_length to 0."
		{"only I1, set to 0", chainOf(mpl(0), nil, nil), false},
		// "The Trust Chain does not fulfill the constraints if... The TA sets the
		// max_path_length to 1."
		{"TA sets 1 — the specification's own failing case", chainOf(nil, nil, mpl(1)), true},
		// And the strictest value at the wrong level.
		{"I2 sets 0 with I1 below it", chainOf(nil, mpl(0), nil), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := applyConstraints(tc.chain)
			if tc.wantErr && err == nil {
				t.Error("the chain violates max_path_length and was accepted")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("the specification says this chain fulfils the constraints: %v", err)
			}
		})
	}
}

// §6.2.1: "The max_path_length constraint MUST have a value greater than or
// equal to zero."
func TestANegativeMaxPathLengthIsRefused(t *testing.T) {
	chain := []Statement{
		{Issuer: "https://le.example.com", Subject: "https://le.example.com"},
		{Issuer: "https://ta.example.com", Subject: "https://le.example.com",
			Constraints: &Constraints{MaxPathLength: ptr(-1)}},
	}
	if err := applyConstraints(chain); err == nil {
		t.Error("a negative max_path_length was accepted; §6.2.1 requires >= 0")
	}
}

// §6.2.2 / RFC 5280 §4.2.1.10 domain semantics, including the case that separates
// a correct implementation from a plausible one.
func TestNamingConstraintDomainSemantics(t *testing.T) {
	for _, tc := range []struct {
		host, constraint string
		want             bool
	}{
		// "the domain name constraint ".example.com" is satisfied by both
		// host.example.com and my.host.example.com"
		{"host.example.com", ".example.com", true},
		{"my.host.example.com", ".example.com", true},
		// "However, the domain name constraint ".example.com" is not satisfied by
		// "example.com"." — the bare domain is NOT in its own subtree.
		{"example.com", ".example.com", false},
		// "When the domain name constraint does not begin with a period, it
		// specifies a host." — exact, so no subdomain match.
		{"host.example.com", "host.example.com", true},
		{"sub.host.example.com", "host.example.com", false},
		{"example.com", "host.example.com", false},
		// Case folding, and a trailing root dot.
		{"HOST.Example.COM", ".example.com", true},
		{"host.example.com.", ".example.com", true},
		// A lookalike that must not match: notexample.com ends with the string
		// "example.com" but is a different domain.
		{"notexample.com", ".example.com", false},
		{"notexample.com", "example.com", false},
	} {
		if got := domainMatches(tc.host, tc.constraint); got != tc.want {
			t.Errorf("domainMatches(%q, %q) = %v, want %v",
				tc.host, tc.constraint, got, tc.want)
		}
	}
}

// "Any name matching a restriction in the excluded list is invalid, regardless of
// the information appearing in the permitted list."
//
// The ordering an implementation gets wrong by checking permitted first and
// returning early on a match.
func TestExcludedBeatsPermitted(t *testing.T) {
	nc := &NamingConstraints{
		Permitted: []string{".example.com"},
		Excluded:  []string{"east.example.com"},
	}
	if err := nc.permits("https://west.example.com"); err != nil {
		t.Errorf("a permitted name was refused: %v", err)
	}
	err := nc.permits("https://east.example.com")
	if err == nil {
		t.Fatal("an excluded name was accepted because it also matched the " +
			"permitted list; excluded wins regardless")
	}
	if !strings.Contains(err.Error(), "excluded") {
		t.Errorf("the refusal does not say it was excluded: %v", err)
	}
}

// The control this is actually for: an Intermediate must not be able to vouch for
// a name outside the subtree its superior delegated.
//
// Every signature in this chain is genuine and every link joins up. Only the
// constraint stops it — which is why §10.2 makes enforcing it a MUST, and why an
// implementation that validates signatures and skips this looks correct.
func TestAnIntermediateCannotVouchOutsideItsDelegatedSubtree(t *testing.T) {
	chain := []Statement{
		// A leaf belonging to somebody else entirely.
		{Issuer: "https://victim.other-org.example", Subject: "https://victim.other-org.example"},
		// An Intermediate the Trust Anchor delegated only *.partner.example to.
		{Issuer: "https://i1.partner.example", Subject: "https://victim.other-org.example"},
		{Issuer: "https://ta.example.com", Subject: "https://i1.partner.example",
			Constraints: &Constraints{NamingConstraints: &NamingConstraints{
				Permitted: []string{".partner.example"},
			}}},
	}
	err := applyConstraints(chain)
	if err == nil {
		t.Fatal("an Intermediate delegated .partner.example vouched for " +
			"victim.other-org.example and the chain was accepted")
	}
	if !strings.Contains(err.Error(), "victim.other-org.example") {
		t.Errorf("the refusal should name the offending entity: %v", err)
	}
}

// §6.2.3 through the real resolution path, not just the filter helper.
//
// A superior that constrains its subtree to relying parties must not be able to
// have an OpenID Provider resolved beneath it — and federation_entity must still
// resolve, because §6.2.3 exempts it.
func TestEntityTypeConstraintIsEnforcedDuringResolution(t *testing.T) {
	subject := `{"iss":"https://le.example.com","sub":"https://le.example.com",` +
		`"metadata":{"openid_provider":{"issuer":"https://le.example.com"},` +
		`"federation_entity":{"organization_name":"Leaf"}}}`

	chain := []Statement{
		{Issuer: "https://le.example.com", Subject: "https://le.example.com",
			Raw: unsignedJWS(subject)},
		{Issuer: "https://ta.example.com", Subject: "https://le.example.com",
			Raw:         unsignedJWS(`{"iss":"https://ta.example.com","sub":"https://le.example.com"}`),
			Constraints: &Constraints{AllowedEntityTypes: ptr([]string{"openid_relying_party"})}},
	}

	if _, err := MetadataOf(chain, "openid_provider"); err == nil {
		t.Error("openid_provider resolved beneath a superior that allows only " +
			"openid_relying_party; §6.2.3 requires it to be removed")
	}
	// federation_entity is exempt and must survive.
	if _, err := MetadataOf(chain, "federation_entity"); err != nil {
		t.Errorf("federation_entity was refused, and §6.2.3 says it is always "+
			"allowed and MUST NOT be in the constraint: %v", err)
	}
}

// unsignedJWS builds a compact JWS whose payload is the given JSON.
//
// claimsOf only base64-decodes the payload; signature verification happened in
// ValidateChain, before any of this runs. These tests are about §6.2's
// arithmetic, so a real signature would add setup and prove nothing extra.
func unsignedJWS(payload string) string {
	b64 := base64.RawURLEncoding.EncodeToString
	return b64([]byte(`{"alg":"none"}`)) + "." + b64([]byte(payload)) + ".sig"
}
