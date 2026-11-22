package httpapi

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// RFC 9126 §2: "The rules for client authentication as defined in [RFC6749] for
// token endpoint requests, including the applicable authentication methods,
// apply for the PAR endpoint as well."
//
// RFC 6749 §5.2 makes a WWW-Authenticate challenge mandatory on a 401 answering
// a client that authenticated through the Authorization header, and RFC 9110
// §11.6.1 requires one on any 401 at all.
//
// `writeTokenError` attaches it, with the §5.2 citation, and has since it was
// written. PAR used `writeError`, which does not — so the same client
// authentication failure produced a challenge at one endpoint and a bare 401 at
// the other.
//
// Found while checking whether the challenge existed at all. It did, centrally,
// and the sweep that suggested otherwise was searching function-scoped while the
// header is set in a different function — a false positive that the test caught
// before it became a redundant change.
// A pushed request is bounded (2.58): maxPARBody was declared and applied to
// nothing, so a push parsed up to net/http's 10 MB form ceiling.
func TestAnOversizedPushIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	push := func(state string) int {
		t.Helper()
		form := url.Values{"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
			"response_type": {"code"}, "scope": {"openid"}, "state": {state},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"}}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "198.51.100.58:1234"
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := push(strings.Repeat("s", maxPARBody)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("a push past the cap answered %d, want 413", code)
	}
	if code := push("s"); code != http.StatusCreated {
		t.Errorf("an ordinary push answered %d, want 201", code)
	}
}

func TestPARAnswersAFailedClientAuthWithAChallenge(t *testing.T) {
	f := newTokenFixture(t)

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"no-such-client"},
		"redirect_uri":  {"https://rp.test/cb"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("no-such-client:wrong")))

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rec.Code, truncate(rec.Body.String(), 200))
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("PAR answered a failed client authentication with a bare 401. The " +
			"token endpoint attaches a challenge to exactly this error, and RFC " +
			"9126 §2 applies the token endpoint's client authentication rules here")
	}
}

// The token endpoint's behaviour, asserted alongside so the two cannot drift
// apart again without a test noticing.
func TestTheTokenEndpointAndPARAgreeOnTheChallenge(t *testing.T) {
	f := newTokenFixture(t)
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("no-such-client:wrong"))

	challenge := func(path string, form url.Values) string {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Header().Get("WWW-Authenticate")
	}

	tok := challenge("/oauth2/token", url.Values{"grant_type": {"client_credentials"}})
	par := challenge("/oauth2/par", url.Values{
		"response_type": {"code"}, "client_id": {"no-such-client"},
		"redirect_uri": {"https://rp.test/cb"},
	})
	if tok != par {
		t.Errorf("the two endpoints answer the same failure differently:\n"+
			"  token: %q\n  par:   %q", tok, par)
	}
}
