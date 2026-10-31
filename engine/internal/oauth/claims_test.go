package oauth

import (
	"net/url"
	"testing"

	"signari.dev/engine/internal/clients"
)

// A request for a claim is a request for its scope and nothing else (9.11): the parameter
// releases nothing a client is not registered for, and it can be run again on a request
// that came back from sign-in.
func TestClaimsCompileToWhatTheServerAlreadyDecides(t *testing.T) {
	c := &clients.Client{Scopes: []string{"openid", "email", "profile"}}
	for name, tc := range map[string]struct {
		claims, scope, acr string
		wantScope, wantACR string
		wantSubject        string
		refused            bool
	}{
		"no claims": {scope: "openid", wantScope: "openid"},
		"a claim asks for its scope": {claims: `{"userinfo":{"email":null}}`, scope: "openid",
			wantScope: "openid email"},
		"either member": {claims: `{"id_token":{"given_name":{"essential":true}}}`, scope: "openid",
			wantScope: "openid profile"},
		"a scope already asked for is not doubled": {claims: `{"userinfo":{"email":null,"email_verified":null}}`,
			scope: "openid email", wantScope: "openid email"},
		"a scope the client lacks is dropped, essential or not": {
			claims: `{"userinfo":{"groups":{"essential":true}}}`, scope: "openid", wantScope: "openid"},
		"a claim with no scope asks for nothing": {claims: `{"userinfo":{"shoe_size":null}}`, scope: "openid",
			wantScope: "openid"},
		"an essential acr joins acr_values": {claims: `{"id_token":{"acr":{"essential":true,"values":["2"]}}}`,
			scope: "openid", acr: "1", wantScope: "openid", wantACR: "1 2"},
		"an essential acr by value": {claims: `{"id_token":{"acr":{"essential":true,"value":"2"}}}`,
			scope: "openid", wantScope: "openid", wantACR: "2"},
		"a voluntary acr is a preference": {claims: `{"id_token":{"acr":{"values":["2"]}}}`, scope: "openid",
			wantScope: "openid"},
		"a subject is named": {claims: `{"id_token":{"sub":{"value":"ada"}}}`, scope: "openid", wantScope: "openid",
			wantSubject: "ada"},
		"two subjects are refused": {claims: `{"id_token":{"sub":{"value":"ada"}},"userinfo":{"sub":{"value":"bob"}}}`,
			scope: "openid", refused: true},
		"a subject that is no string is refused": {claims: `{"id_token":{"sub":{"value":7}}}`, scope: "openid",
			refused: true},
		"not JSON":      {claims: `email`, scope: "openid", refused: true},
		"not an object": {claims: `["email"]`, scope: "openid", refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			q := url.Values{"scope": {tc.scope}}
			if tc.claims != "" {
				q.Set("claims", tc.claims)
			}
			if tc.acr != "" {
				q.Set("acr_values", tc.acr)
			}
			subject, err := CompileClaims(q, c)
			if tc.refused {
				if err == nil {
					t.Fatal("accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if q.Get("scope") != tc.wantScope || q.Get("acr_values") != tc.wantACR || subject != tc.wantSubject {
				t.Errorf("compiled to scope %q, acr %q, subject %q", q.Get("scope"), q.Get("acr_values"), subject)
			}
			again, err := CompileClaims(q, c)
			if err != nil || again != subject || q.Get("scope") != tc.wantScope || q.Get("acr_values") != tc.wantACR {
				t.Errorf("run again it gave scope %q, acr %q, subject %q (%v)", q.Get("scope"), q.Get("acr_values"), again, err)
			}
		})
	}
}
