package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OWASP ASVS 5.0 V10.6.2 — forced-logout denial of service.
//
//	"Verify that the OpenID Provider mitigates denial of service through forced
//	logout. By obtaining explicit confirmation from the end-user or, if present,
//	validating parameters in the logout request (initiated by the relying
//	party), such as the id_token_hint."
//
// OIDC RP-Initiated Logout 1.0 §2 states it the same way: the OP "SHOULD ask the
// End-User whether to log out" unless a valid `id_token_hint` is present.
//
// The attack is one HTML tag. `<img src="https://id.example.com/oauth2/logout">`
// on any page a victim visits signs them out here, as often as the page loads,
// from anywhere on the internet. No credential is stolen; the product simply
// stops staying signed in, and nobody can tell that from a bug.

func endSessionGET(t *testing.T, srv *Server, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout"+query, nil)
	// A browser that has a session here — which is the whole premise of the
	// attack. Without a cookie there is nothing to confirm.
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "some-session-value"})
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// A bare GET from a browser with a session must NOT terminate anything. It must
// ask.
func TestABareLogoutGETAsksBeforeSigningOut(t *testing.T) {
	f := newTokenFixture(t)

	rec := endSessionGET(t, f.srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with a confirmation page", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<form method=\"post\"") {
		t.Fatalf("no confirmation form was rendered; a cross-site image tag would "+
			"sign this browser out:\n%s", body)
	}
	if !strings.Contains(body, csrfFormField) {
		t.Error("the confirmation form carries no CSRF token, so the confirmation " +
			"could itself be forged")
	}
	// The session cookie must NOT have been cleared by merely asking.
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge < 0 {
			t.Error("the session cookie was cleared by a request that only asked " +
				"for confirmation")
		}
	}
}

// The confirmation must preserve what the relying party sent, or confirming
// would lose the post-logout redirect and the state.
func TestTheConfirmationFormPreservesTheRelyingPartysParameters(t *testing.T) {
	f := newTokenFixture(t)

	rec := endSessionGET(t, f.srv,
		"?post_logout_redirect_uri=https%3A%2F%2Frp.test%2Fbye&state=xyz123&client_id=abc")
	body := rec.Body.String()
	for _, want := range []string{"post_logout_redirect_uri", "state=xyz123", "client_id=abc"} {
		if !strings.Contains(body, want) {
			t.Errorf("the form action drops %q, so confirming would lose it:\n%s", want, body)
		}
	}
}

// A POST without a CSRF token is refused. This is the confirmation itself being
// forged — the attack the form exists to stop, aimed one level up.
func TestALogoutPOSTWithoutCSRFIsRefused(t *testing.T) {
	f := newTokenFixture(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "some-session-value"})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusSeeOther || rec.Code == http.StatusOK {
		t.Fatalf("a POST with no CSRF token was accepted (status %d); the "+
			"confirmation step would be forgeable", rec.Code)
	}
}

// And the escape hatch the specification names: a request carrying a VERIFIED
// id_token_hint identifies the relying party that asked, so no confirmation is
// needed. An unverified hint is just a string the attacker chose, so it must not
// count — that is the difference between validating a parameter and seeing one.
func TestAnUnverifiedIDTokenHintDoesNotSkipConfirmation(t *testing.T) {
	f := newTokenFixture(t)

	rec := endSessionGET(t, f.srv, "?id_token_hint=not.a.real.token")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<form method=\"post\"") {
		t.Fatalf("an unverified id_token_hint skipped the confirmation (status %d); "+
			"any attacker can put a string in that parameter", rec.Code)
	}
}

// A browser with no session is not asked anything: there is nothing to end, and
// a page saying "sign out?" to somebody who is not signed in is worse than
// useless.
func TestNoSessionMeansNoConfirmationPage(t *testing.T) {
	f := newTokenFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<form method=\"post\"") {
		t.Error("a browser with no session was asked to confirm signing out")
	}
}
