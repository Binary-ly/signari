package httpapi

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
)

var parkedAuthz = regexp.MustCompile(`name="authz" value="([^"]*)"`)

// An authorization request sent as a form, with nobody signed in yet (2.08). The pages
// that park a request read it from the URL's query, and a POST has none, so the person
// signed in and ended on a page about nothing, the application never hearing back.
func TestAnAuthorizationRequestPostedBeforeSignInIsStillThereAfterIt(t *testing.T) {
	f := newSignInFixture(t)

	req := httptest.NewRequest(http.MethodPost, oidc.PathAuthorize, strings.NewReader(f.plainAuthz()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.handleAuthorize(rec, req)
	m := parkedAuthz.FindStringSubmatch(rec.Body.String())
	if rec.Code != http.StatusOK || m == nil {
		t.Fatalf("no sign-in form answered it (%d): %.300s", rec.Code, rec.Body.String())
	}
	parked := html.UnescapeString(m[1])
	if !strings.Contains(parked, url.QueryEscape(f.clientID)) || !strings.Contains(parked, "state=s") {
		t.Fatalf("the sign-in page holds %q, which is not the request", parked)
	}

	signedIn := f.signInWith(t, parked)
	back := signedIn.Header().Get("Location")
	if signedIn.Code != http.StatusSeeOther || !strings.Contains(back, "state=s") {
		t.Fatalf("the sign-in answered %d, %q", signedIn.Code, back)
	}
	session := cookieFrom(signedIn, SessionCookieName)
	if session == nil {
		t.Fatal("the sign-in set no session")
	}

	// And on through the same endpoint to the application, by the URL it was sent back
	// to, as a browser would. The first redirect is the fixture's own consent, if any.
	again := httptest.NewRequest(http.MethodGet, back, nil)
	again.AddCookie(session)
	end := httptest.NewRecorder()
	f.srv.handleAuthorize(end, again)
	switch location := end.Header().Get("Location"); {
	case strings.HasPrefix(location, "https://rp.test/cb") && strings.Contains(location, "code="):
	case end.Code == http.StatusOK && strings.Contains(end.Body.String(), `name="authz"`) &&
		strings.Contains(end.Body.String(), "state=s"):
		// Consent, carrying the request on.
	default:
		t.Errorf("the request ended at %d, %q: %.300s", end.Code, location, end.Body.String())
	}
}

// Still one place at a time: a POST that also carries a query is the request the
// duplicate-parameter rule cannot see into, and it is refused before anything is read.
func TestAPostedAuthorizationRequestMustNotAlsoCarryAQuery(t *testing.T) {
	f := newSignInFixture(t)
	req := httptest.NewRequest(http.MethodPost, oidc.PathAuthorize+"?scope=admin", strings.NewReader(f.plainAuthz()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.handleAuthorize(rec, req)
	if parkedAuthz.MatchString(rec.Body.String()) || !strings.Contains(rec.Body.String(), "in the body alone") {
		t.Errorf("answered %d: %.300s", rec.Code, rec.Body.String())
	}
}
