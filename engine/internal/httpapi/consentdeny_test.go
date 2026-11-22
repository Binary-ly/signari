package httpapi

import (
	"net/url"
	"strings"
	"testing"
)

// A refusal on the consent page is reported to the client, and only to a
// redirect the client registered: the request comes back from the form, so it
// is the browser's to change, and it was redirected to wherever it said.
func TestAConsentRefusalGoesOnlyToARegisteredRedirect(t *testing.T) {
	f := newSignInFixture(t)
	clearSignInBucket(t, f.pool)
	b := newTestBrowser(t, f.srv.Routes())
	b.post("/login", b.get("/login"), url.Values{"username": {f.email}, "password": {signInTestPassword}})
	if b.value(SessionCookieName) == "" {
		t.Fatal("the fixture did not sign in")
	}
	authz := url.Values{"client_id": {f.clientID}, "response_type": {"code"},
		"redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"}}
	deny := func(q url.Values) string {
		t.Helper()
		return b.post("/consent", b.get("/login"), url.Values{"decision": {"deny"}, "authz": {q.Encode()}}).Header().Get("Location")
	}
	if loc := deny(authz); !strings.HasPrefix(loc, "https://rp.test/cb") || !strings.Contains(loc, "error=access_denied") {
		t.Errorf("a refusal was not reported to the client: %q", loc)
	}
	authz.Set("redirect_uri", "https://elsewhere.test/cb")
	if loc := deny(authz); strings.Contains(loc, "elsewhere.test") {
		t.Errorf("a refusal was reported to a redirect the client never registered: %q", loc)
	}
}
