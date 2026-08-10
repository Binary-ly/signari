package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newCSRFServer builds the minimum Server the sign-in form paths touch. No
// database: reaching one would mean a forged request got past the CSRF check,
// and a nil-pointer panic is a perfectly clear way to find that out.
func newCSRFServer() *Server {
	return &Server{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		login: newBucket(5, 20),
	}
}

// getLogin renders the form and returns the issued cookie value and the value
// embedded in the hidden field.
func getLogin(t *testing.T, s *Server, existing string) (cookie, field string, rec *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	if existing != "" {
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: existing})
	}
	rec = httptest.NewRecorder()
	s.handleLoginGet(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			cookie = c.Value
		}
	}
	body := rec.Body.String()
	const marker = `name="` + csrfFormField + `" value="`
	if i := strings.Index(body, marker); i >= 0 {
		rest := body[i+len(marker):]
		field = rest[:strings.Index(rest, `"`)]
	}
	return cookie, field, rec
}

// The form is useless unless the value the browser stores and the value the form
// submits are the same string.
func TestLoginFormCarriesTheCookieToken(t *testing.T) {
	s := newCSRFServer()
	cookie, field, rec := getLogin(t, s, "")

	if cookie == "" {
		t.Fatal("GET /login issued no CSRF cookie")
	}
	if !validCSRFValue(cookie) {
		t.Errorf("issued cookie %q is not a well-formed token", cookie)
	}
	if field == "" {
		t.Fatal("the rendered form carries no CSRF field")
	}
	if field != cookie {
		t.Errorf("form field %q != cookie %q", field, cookie)
	}

	// The attributes are the whole reason double-submit is safe here.
	var c *http.Cookie
	for _, got := range rec.Result().Cookies() {
		if got.Name == CSRFCookieName {
			c = got
		}
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Errorf("cookie name %q lacks the __Host- prefix that blocks subdomain injection", c.Name)
	}
	if !c.Secure || c.Path != "/" || c.Domain != "" {
		t.Errorf("__Host- requires Secure, Path=/ and no Domain; got secure=%v path=%q domain=%q",
			c.Secure, c.Path, c.Domain)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
}

// Two open sign-in tabs is an ordinary thing to do. If rendering rotated the
// token, submitting the first tab would fail for no reason the user can see.
func TestTokenIsStableAcrossRenders(t *testing.T) {
	s := newCSRFServer()
	first, _, _ := getLogin(t, s, "")

	cookie, field, _ := getLogin(t, s, first)
	if cookie != "" && cookie != first {
		t.Errorf("second render replaced the token: %q -> %q", first, cookie)
	}
	if field != first {
		t.Errorf("second render embedded %q, want the existing token %q", field, first)
	}
}

func postLogin(s *Server, cookie, field string) *httptest.ResponseRecorder {
	form := url.Values{"username": {"someone"}, "password": {"hunter2"}}
	if field != "" {
		form.Set(csrfFormField, field)
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	s.rateLimitedLogin(rec, req)
	return rec
}

// Login CSRF forces a victim into the ATTACKER's session, which then records
// whatever they do next as the attacker's own activity. Every one of these
// shapes is what such a request actually looks like.
func TestForgedLoginIsRejected(t *testing.T) {
	good, _, _ := getLogin(t, newCSRFServer(), "")
	other, _, _ := getLogin(t, newCSRFServer(), "")

	cases := []struct {
		name          string
		cookie, field string
	}{
		// A cross-site POST carries no cookie at all -- this is the real attack.
		{"no cookie, no field", "", ""},
		{"no cookie, guessed field", "", good},
		// An absent cookie must not make an absent field "match".
		{"cookie but no field", good, ""},
		{"both empty strings", "", ""},
		{"mismatched", good, other},
		{"malformed cookie", "not-a-token", "not-a-token"},
		{"truncated field", good, good[:len(good)-1]},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh server per case: nil db, so anything that survives the check
			// panics rather than quietly proceeding to verify credentials.
			rec := postLogin(newCSRFServer(), tc.cookie, tc.field)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("got %d, want 403", rec.Code)
			}
		})
	}
}

// A matching pair must pass, or the control is just an outage.
func TestMatchingPairPassesTheCheck(t *testing.T) {
	tok, _, _ := getLogin(t, newCSRFServer(), "")

	form := url.Values{csrfFormField: {tok}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: tok})
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}

	if !checkCSRF(req) {
		t.Fatal("a matching cookie and field were rejected")
	}
}

// The limiter is one global bucket. If forged posts were charged against it, an
// attacker page loaded by a handful of visitors would deny sign-in to everyone
// -- so the CSRF check has to come first.
func TestForgedPostsDoNotExhaustTheLoginLimiter(t *testing.T) {
	s := newCSRFServer() // capacity 20

	for i := 0; i < 40; i++ {
		if rec := postLogin(s, "", ""); rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: got %d, want 403", i, rec.Code)
		}
	}

	if !s.login.allow() {
		t.Fatal("forged posts drained the login rate limiter; real users are locked out")
	}
}

func TestValidCSRFValue(t *testing.T) {
	good, _, _ := getLogin(t, newCSRFServer(), "")
	for _, bad := range []string{"", " ", "short", good + "x", good[:10], strings.Repeat("!", 43)} {
		if validCSRFValue(bad) {
			t.Errorf("accepted %q as a token", bad)
		}
	}
	if !validCSRFValue(good) {
		t.Errorf("rejected an issued token %q", good)
	}
}
