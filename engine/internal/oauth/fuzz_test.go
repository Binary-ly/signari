package oauth

import (
	"net/url"
	"testing"

	"signari.dev/engine/internal/clients"
)

// Authorization request parsing runs before ANY authentication, on whatever a
// browser was pointed at. Every field here is attacker-controlled.
func FuzzValidateAuthz(f *testing.F) {
	f.Add("response_type=code&client_id=x&redirect_uri=https://a.test/cb&scope=openid")
	f.Add("redirect_uri=%%%%&state=%00%00")
	f.Add("resource=https://a#f&resource=//evil")
	f.Add("acr_values=" + string(rune(0)) + "&max_age=-999999999999999999999")
	f.Add("code_challenge=&code_challenge_method=S256")

	c := &clients.Client{
		ClientID: "x", Type: "public", Enabled: true,
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"openid"}, RedirectURIs: []string{"https://a.test/cb"},
		RequirePKCE: true, PKCEMethods: []string{"S256"},
	}

	f.Fuzz(func(t *testing.T, raw string) {
		q, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		req := ParseAuthz(q)
		// Must always terminate with a decision. A panic here is reachable by
		// anyone who can make a browser follow a link.
		_ = ValidateAuthz(req, c, nil)
		_ = validateResources(req.Resources)
	})
}

// PKCE verification takes a verifier straight from the token request body.
func FuzzVerifyPKCE(f *testing.F) {
	f.Add("S256", "abc", "def")
	f.Add("plain", "", "")
	f.Add("S256", string([]byte{0xff, 0xfe}), "\x00")
	f.Fuzz(func(t *testing.T, method, challenge, verifier string) {
		_ = VerifyPKCE(method, challenge, verifier)
	})
}
