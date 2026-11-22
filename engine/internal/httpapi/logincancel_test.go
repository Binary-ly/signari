package httpapi

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// The sign-in page lets a person say no to the application, and the application hears
// it: access_denied, "the resource owner ... denied the request" (specs/rfc6749.txt
// :1523-1525), with its state. The only way out was to close the page, and the
// application waited on a response that never came (13.01, FAPI 2.0's
// user-rejects-authentication). The account picker's Cancel already did this.
func TestASignInCanBeCancelledAndTheApplicationIsTold(t *testing.T) {
	f := newSignInFixture(t)
	page := f.authorizeWith(t, "", nil)
	body := page.Body.String()
	if !strings.Contains(body, `name="cancel"`) {
		t.Fatalf("the sign-in page offers no way to cancel: %d %.300s", page.Code, body)
	}
	form := url.Values{"cancel": {"1"}}
	for _, m := range regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range page.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc.String(), "https://rp.test/cb") {
		t.Fatalf("cancelling answered %d to %q: %.300s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if q := loc.Query(); q.Get("error") != "access_denied" || q.Get("state") != "s" {
		t.Errorf("the application was told %v", q)
	}
}
