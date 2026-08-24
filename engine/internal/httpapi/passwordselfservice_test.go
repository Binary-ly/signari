package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A voluntary password change must prove the CURRENT password.
//
// This is the property that separates it from the forced flow: the session may
// be one an attacker captured, and changing a password without the old one turns
// a stolen cookie into permanent ownership. So a wrong current password changes
// nothing, and the account still authenticates with the original.
func TestVoluntaryPasswordChangeRequiresTheCurrentPassword(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	out := f.attempt(t, f.email, signInTestPassword)
	if out.sessionCookie == "" {
		t.Fatal("could not sign in to obtain a session")
	}

	// GET the form to mint a CSRF cookie+field, carrying the session cookie.
	getReq := httptest.NewRequest(http.MethodGet, "/account/password", nil)
	getReq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: out.sessionCookie})
	getRec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /account/password = %d, want 200", getRec.Code)
	}
	csrfCookie, csrfField := extractCSRF(t, getRec)

	post := func(current, next string) *httptest.ResponseRecorder {
		form := url.Values{"current": {current}, "password": {next}, "confirm": {next},
			csrfFormField: {csrfField}}
		req := httptest.NewRequest(http.MethodPost, "/account/password",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: out.sessionCookie})
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	// Wrong current password: refused, and the original still works.
	rec := post("not-the-current-password", "a-brand-new-passphrase-9271")
	if rec.Code == http.StatusSeeOther {
		t.Fatal("a change with the wrong current password succeeded (303 redirect); " +
			"it must be refused")
	}
	var stored string
	if err := f.pool.QueryRow(ctx,
		`SELECT hash FROM core.password_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if _, verr := f.srv.hasher.Verify(ctx, stored, signInTestPassword); verr != nil {
		t.Error("the stored password no longer verifies against the original; a " +
			"failed change must leave the credential untouched")
	}

	// Right current password: succeeds (redirects to sign in) and the new one works.
	rec = post(signInTestPassword, "a-brand-new-passphrase-9271")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a change with the correct current password got %d, want 303", rec.Code)
	}
	if err := f.pool.QueryRow(ctx,
		`SELECT hash FROM core.password_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if _, verr := f.srv.hasher.Verify(ctx, stored, "a-brand-new-passphrase-9271"); verr != nil {
		t.Error("after a successful change the new password does not verify")
	}
}

// extractCSRF pulls the CSRF cookie value and the hidden field value from a
// rendered page, so a test can submit a request that passes the double-submit
// check.
func extractCSRF(t *testing.T, rec *httptest.ResponseRecorder) (cookie, field string) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			cookie = c.Value
		}
	}
	body := rec.Body.String()
	marker := `name="` + csrfFormField + `" value="`
	if i := strings.Index(body, marker); i >= 0 {
		rest := body[i+len(marker):]
		field = rest[:strings.Index(rest, `"`)]
	}
	if cookie == "" || field == "" {
		t.Fatalf("could not extract a CSRF cookie (%q) and field (%q) from the page", cookie, field)
	}
	return cookie, field
}
