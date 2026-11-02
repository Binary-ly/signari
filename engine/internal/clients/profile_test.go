package clients

import (
	"strings"
	"testing"
)

// meeting is a client that meets the profile, by private_key_jwt and DPoP.
func meeting() *Client {
	return &Client{SecurityProfile: ProfileFAPI2, Type: "confidential", TokenEndpointAuthMethod: "private_key_jwt",
		DPoPBoundAccessTokens: true, RequirePAR: true, RequirePKCE: true, ResponseTypes: []string{"code"},
		IDTokenAlg: "ES256", RedirectURIs: []string{"https://rp.test/cb"}}
}

// Message Signing asks all of that and a signature at each end, and neither is asked of
// a client held only to the Security Profile.
func TestMessageSigningAsksForASignatureAtEachEnd(t *testing.T) {
	held := func() *Client {
		c := meeting()
		c.SecurityProfile = ProfileFAPI2MessageSigning
		c.RequireSignedRequest, c.AuthorizationResponseAlg = true, "ES256"
		return c
	}
	if got := held().ProfileProblems(); len(got) != 0 {
		t.Fatalf("a client that meets it: %q", got)
	}
	for name, tc := range map[string]struct {
		change func(*Client)
		says   string
	}{
		"unsigned requests":     {func(c *Client) { c.RequireSignedRequest = false }, "signed request objects"},
		"no response algorithm": {func(c *Client) { c.AuthorizationResponseAlg = "" }, "authorization responses"},
		"a response algorithm":  {func(c *Client) { c.AuthorizationResponseAlg = "RS256" }, "authorization responses"},
		"the base profile too":  {func(c *Client) { c.RequirePAR = false }, "pushed"},
	} {
		c := held()
		tc.change(c)
		if got := c.ProfileProblems(); len(got) != 1 || !strings.Contains(got[0], tc.says) {
			t.Errorf("%s: %q, want one problem saying %q", name, got, tc.says)
		}
	}
	if !held().FAPI2() {
		t.Error("a client held to Message Signing is not held to the profile it builds on")
	}
	base := meeting()
	if base.MessageSigning() || len(base.ProfileProblems()) != 0 {
		t.Errorf("the Security Profile alone asked for signatures: %q", base.ProfileProblems())
	}
}

// Each requirement on a client's settings, named when it is the only one broken, and
// nothing asked of a client that is not held to a profile.
func TestProfileProblemsNameEachRequirement(t *testing.T) {
	if got := meeting().ProfileProblems(); len(got) != 0 {
		t.Fatalf("a client that meets the profile: %q", got)
	}
	for _, alg := range FAPI2Algorithms {
		c := meeting()
		c.IDTokenAlg = alg
		if got := c.ProfileProblems(); len(got) != 0 {
			t.Errorf("%s: %q", alg, got)
		}
	}
	cases := map[string]struct {
		change func(*Client)
		says   string
	}{
		"public":                {func(c *Client) { c.Type = "public" }, "confidential"},
		"by a secret":           {func(c *Client) { c.TokenEndpointAuthMethod = "client_secret_basic" }, "client_secret_basic"},
		"bearer":                {func(c *Client) { c.DPoPBoundAccessTokens = false }, "sender-constrained"},
		"not pushed":            {func(c *Client) { c.RequirePAR = false }, "pushed"},
		"no PKCE":               {func(c *Client) { c.RequirePKCE = false }, "PKCE"},
		"hybrid":                {func(c *Client) { c.AllowHybrid = true }, "response_type"},
		"another response type": {func(c *Client) { c.ResponseTypes = []string{"code", "code id_token"} }, "response_type"},
		"RS256":                 {func(c *Client) { c.IDTokenAlg = "RS256" }, "RS256"},
		"RS256 on access alone": {func(c *Client) { c.AccessAlg = "RS256" }, "RS256"},
		"RS256 on userinfo":     {func(c *Client) { c.UserinfoSignedAlg = "RS256" }, "RS256"},
		"RS256 on introspect":   {func(c *Client) { c.IntrospectionSignedAlg = "RS256" }, "RS256"},
		"PS384":                 {func(c *Client) { c.IDTokenAlg = "PS384" }, "PS384"},
		"plain http":            {func(c *Client) { c.RedirectURIs = []string{"http://rp.test/cb"} }, "http://rp.test/cb"},
	}
	for name, tc := range cases {
		c := meeting()
		tc.change(c)
		got := c.ProfileProblems()
		if len(got) != 1 || !strings.Contains(got[0], tc.says) {
			t.Errorf("%s: %q, want one problem saying %q", name, got, tc.says)
		}
		c.SecurityProfile = "none"
		if got := c.ProfileProblems(); len(got) != 0 {
			t.Errorf("%s, held to nothing: %q", name, got)
		}
	}

	// The other ways of meeting it.
	tls := meeting()
	tls.TokenEndpointAuthMethod, tls.TLSSubjectDN = "none", "CN=rp"
	tls.DPoPBoundAccessTokens, tls.TLSBoundTokens = false, true
	if got := tls.ProfileProblems(); len(got) != 0 {
		t.Errorf("mutual TLS for both: %q", got)
	}
	native := meeting()
	native.RedirectURIs = []string{"http://127.0.0.1:8000/cb", "http://localhost/cb", "http://[::1]/cb", "com.example:/cb"}
	if got := native.ProfileProblems(); len(got) != 0 {
		t.Errorf("a native client on a loopback address: %q", got)
	}
}
