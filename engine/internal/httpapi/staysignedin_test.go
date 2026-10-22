package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/store"
)

// "Stay signed in on this device" (5.11): a session cookie that outlasts the
// browser, for what the session has left, where the organisation offers it and
// the person asks for it -- and not because a second factor's "remember this
// device" was ticked.

// postLogin submits the sign-in form with extra fields.
func (f *signInFixture) postLogin(t *testing.T, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	get := httptest.NewRequest(http.MethodGet, "/login", nil)
	grec := httptest.NewRecorder()
	f.srv.handleLoginGet(grec, get)
	m := csrfValue.FindStringSubmatch(grec.Body.String())
	csrfCookie := cookieFrom(grec, CSRFCookieName)
	if m == nil || csrfCookie == nil {
		t.Fatal("no CSRF field in the sign-in form")
	}
	form := url.Values{"username": {f.email}, "password": {signInTestPassword}, csrfFormField: {m[1]}}
	for k, v := range extra {
		form[k] = v
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.rateLimitedLogin(rec, req)
	return rec
}

func (f *signInFixture) offerStaySignedIn(t *testing.T, on bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.SetPersistentSessions(ctx, tx, f.orgID, on); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// loginPage is the sign-in page an application's authorization request leads
// to, which is how the page knows whose organisation it is: a bare /login on a
// deployment with several, like the shared test database, belongs to none.
func loginPage(f *signInFixture) string {
	rec := httptest.NewRecorder()
	authz := url.QueryEscape("client_id=" + f.clientID + "&response_type=code")
	f.srv.handleLoginGet(rec, httptest.NewRequest(http.MethodGet, "/login?authz="+authz, nil))
	return rec.Body.String()
}

func TestStayingSignedInOutlastsTheBrowserOnlyWhenOfferedAndAsked(t *testing.T) {
	f := newSignInFixture(t)
	stay := url.Values{stayField: {"1"}}

	if strings.Contains(loginPage(f), `name="stay_signed_in"`) {
		t.Error("the sign-in page offers to stay signed in where the organisation does not")
	}
	clearSignInBucket(t, f.pool)
	if c := cookieFrom(f.postLogin(t, stay), SessionCookieName); c == nil || c.MaxAge != 0 {
		t.Fatalf("asked where it is not offered: %+v, want a browser-session cookie", c)
	}

	f.offerStaySignedIn(t, true)
	if !strings.Contains(loginPage(f), `name="stay_signed_in"`) {
		t.Fatal("the sign-in page does not offer to stay signed in where the organisation does")
	}
	clearSignInBucket(t, f.pool)
	if c := cookieFrom(f.postLogin(t, nil), SessionCookieName); c == nil || c.MaxAge != 0 {
		t.Errorf("not asked: %+v, want a browser-session cookie", c)
	}
	clearSignInBucket(t, f.pool)
	c := cookieFrom(f.postLogin(t, stay), SessionCookieName)
	if c == nil || c.MaxAge < int((12*time.Hour).Seconds())-60 || c.MaxAge > int((12*time.Hour).Seconds()) {
		t.Fatalf("asked and offered: %+v, want a cookie lasting the session's twelve hours", c)
	}
}

// Through a second factor, which completes the sign-in in a later request: the
// choice made on the password page carries over, and the code page's own
// "remember this device" is not mistaken for it.
func TestStayingSignedInSurvivesASecondFactorAndIsNotRememberThisDevice(t *testing.T) {
	f, _ := enrolFixture(t)
	secret := giveTOTP(t, f)
	f.offerStaySignedIn(t, true)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.organizations SET remember_device_days = 30 WHERE id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	step := mfa.Counter(time.Now(), mfa.DefaultPeriod)

	complete := func(page *httptest.ResponseRecorder, code string, form url.Values) *http.Cookie {
		t.Helper()
		m := csrfValue.FindStringSubmatch(page.Body.String())
		if m == nil || !strings.Contains(page.Body.String(), `action="/login/mfa"`) {
			t.Fatalf("no code page: %d", page.Code)
		}
		form.Set("code", code)
		form.Set(csrfFormField, m[1])
		r := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookieFrom(page, PendingCookieName))
		r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
		if c := cookieFrom(page, RememberCookieName); c != nil {
			r.AddCookie(c)
		}
		r.RemoteAddr = testClientIP(t) + ":5555"
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return cookieFrom(rec, SessionCookieName)
	}

	clearSignInBucket(t, f.pool)
	page := f.postLogin(t, url.Values{stayField: {"1"}})
	if cookieFrom(page, RememberCookieName) == nil {
		t.Fatal("the choice was not kept for the second factor")
	}
	if c := complete(page, mfa.Code(secret, step, mfa.DefaultDigits), url.Values{}); c == nil || c.MaxAge <= 0 {
		t.Errorf("asked on the password page, through a second factor: %+v, want a lasting cookie", c)
	}

	clearSignInBucket(t, f.pool)
	page = f.postLogin(t, nil)
	if c := complete(page, mfa.Code(secret, step+1, mfa.DefaultDigits), url.Values{"remember": {"1"}}); c == nil || c.MaxAge != 0 {
		t.Errorf("only \"remember this device\" ticked: %+v, want a browser-session cookie", c)
	}
}

// A provider's sign-in leaves the page by a link, so the choice rides on it and
// is kept across the round trip.
func TestStayingSignedInIsKeptAcrossAProvidersRoundTrip(t *testing.T) {
	f := newSignInFixture(t)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login/with/nobody?"+stayField+"=1", nil))
	if c := cookieFrom(rec, RememberCookieName); c == nil || c.MaxAge <= 0 || !c.HttpOnly || !c.Secure {
		t.Errorf("the provider link's choice was not kept: %+v", c)
	}
}
