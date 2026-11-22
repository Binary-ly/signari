package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// `outpost run` starts what the token was issued for and nothing else, and says what to do
// about a kind nothing runs. A token is bound to one protocol: the check was in the
// answer to the hello all along and nothing read it (8.31).
func TestAnOutpostRunsWhatItsTokenWasIssuedFor(t *testing.T) {
	kind := "ldap"
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"dmz","kind":"` + kind + `"}`))
	}))
	t.Cleanup(core.Close)
	run := func(asked, radiusClients string) error {
		return outpostRun(core.URL, "token", asked, ":0", "", "", "", false, radiusClients)
	}
	for _, c := range []struct{ token, asked, want string }{
		{"ldap", "radius", "issued for a ldap outpost"},
		{"radius", "ldap", "issued for a radius outpost"},
		{"radius", "radius", "give -radius-clients"},
		{"desktop", "desktop", "docs/desktop-login.md"},
		{"pdp", "pdp", "docs/authorization.md"},
		{"proxy", "proxy", "/proxy/verify"},
	} {
		kind = c.token
		err := run(c.asked, "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("a %s token run as %s said %v, want %q", c.token, c.asked, err, c.want)
		}
	}
}
