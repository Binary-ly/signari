package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The step-up requirement that nothing the person does can satisfy.
//
// # The loop
//
// A client sends acr_values=2. The subject has no second factor enrolled. The
// authorize endpoint finds the session insufficient and renders the sign-in
// form; a correct password produces a password-only session, which reports
// acr=1 because that is what happened; the redirect lands back at authorize,
// which finds it insufficient and renders the form again.
//
// Nothing errors. Every component behaves correctly in isolation -- the acr is
// derived honestly, the step-up check is right to refuse, the login page is the
// reasonable response to "we need authentication". The person sees two pages
// alternating forever with no explanation, and no action available to them ends
// it.
//
// Found by tracing the journey rather than by any test failing, which is the
// point: a loop is not an error condition, so nothing was watching for one.

// authorizeWithACR asks the authorize endpoint for a multi-factor context,
// presenting a session cookie.
func (f *signInFixture) authorizeWithACR(t *testing.T, sessionCookie string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{
		"client_id":     {f.clientID},
		"acr_values":    {"2"},
		"scope":         {"openid"},
		"response_type": {"code"},
		"redirect_uri":  {"https://rp.test/cb"},
		"state":         {"s"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	if sessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionCookie})
	}
	rec := httptest.NewRecorder()
	f.srv.handleAuthorize(rec, req)
	return rec
}

// TestAnUnreachableAuthenticationContextIsRefusedRatherThanLooped.
//
// The subject has no second factor, so acr_values=2 can never be reached. The
// endpoint must say so -- to the CLIENT, as the error OIDC defines for exactly
// this -- rather than showing a form that cannot help.
func TestAnUnreachableAuthenticationContextIsRefusedRatherThanLooped(t *testing.T) {
	f := newSignInFixture(t)

	sessionCookie := f.signInAndReturnCookie(t)
	if sessionCookie == "" {
		t.Fatal("the fixture could not sign in, so this test cannot check what happens next")
	}

	rec := f.authorizeWithACR(t, sessionCookie)

	loc := rec.Header().Get("Location")
	switch {
	case rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "password"):
		t.Fatal("the authorize endpoint rendered the sign-in form again for a requirement " +
			"no sign-in can meet; this is the loop")
	case loc == "":
		t.Fatalf("expected a redirect carrying an error, got status %d", rec.Code)
	}

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("the redirect is not a URL: %v", err)
	}
	if got := u.Query().Get("error"); got != "unmet_authentication_requirements" {
		t.Errorf("error=%q; OIDC defines unmet_authentication_requirements for a context "+
			"that cannot be reached", got)
	}
	if !strings.HasPrefix(loc, "https://rp.test/cb") {
		t.Errorf("the error went to %q rather than the client's redirect_uri", loc)
	}
}

// TestAReachableStepUpStillShowsTheForm is the other half, and it is what stops
// the fix above from being "refuse every step-up".
//
// The subject HAS a second factor, so acr_values=2 is reachable by signing in
// again. That must still produce a sign-in form.
func TestAReachableStepUpStillShowsTheForm(t *testing.T) {
	f := newSignInFixture(t)

	sessionCookie := f.signInAndReturnCookie(t)
	if sessionCookie == "" {
		t.Fatal("the fixture could not sign in")
	}

	// Enrolled AFTER signing in, so the live session is still password-only --
	// which is exactly the situation step-up exists for.
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`,
		f.userID, f.orgID); err != nil {
		t.Fatalf("enrolling a second factor: %v", err)
	}

	rec := f.authorizeWithACR(t, sessionCookie)
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "unmet_authentication_requirements") {
		t.Fatal("a step-up the subject CAN satisfy was refused; they have a second factor " +
			"and were never asked for it")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected the sign-in form, got status %d (%s)",
			rec.Code, rec.Header().Get("Location"))
	}
}

// signInAndReturnCookie performs a password sign-in and returns the session
// cookie value.
func (f *signInFixture) signInAndReturnCookie(t *testing.T) string {
	t.Helper()
	get := httptest.NewRequest(http.MethodGet, "/login", nil)
	grec := httptest.NewRecorder()
	f.srv.handleLoginGet(grec, get)
	var csrfCookie string
	for _, c := range grec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			csrfCookie = c.Value
		}
	}
	const marker = `name="` + csrfFormField + `" value="`
	body := grec.Body.String()
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no CSRF field in the sign-in form")
	}
	rest := body[i+len(marker):]
	csrfField := rest[:strings.Index(rest, `"`)]

	form := url.Values{
		"username": {f.email}, "password": {signInTestPassword},
		csrfFormField: {csrfField},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
	rec := httptest.NewRecorder()
	f.srv.rateLimitedLogin(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return c.Value
		}
	}
	return ""
}
