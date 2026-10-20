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

// A device remembered after a second factor, through the sign-in pages: it
// skips the challenge until it is forgotten -- by the person, by signing out
// everywhere, by the organisation -- and never where a client requires
// multi-factor. A second factor was asked at every sign-in on every device.

// signInWith runs the password step with extra cookies and returns the answer.
func (f *signInFixture) signInWith(t *testing.T, authz string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	get := httptest.NewRecorder()
	f.srv.handleLoginGet(get, httptest.NewRequest(http.MethodGet, "/login", nil))
	m := csrfValue.FindStringSubmatch(get.Body.String())
	csrf := cookieFrom(get, CSRFCookieName)
	form := url.Values{"username": {f.email}, "password": {signInTestPassword}, csrfFormField: {m[1]}}
	if authz != "" {
		form.Set("authz", authz)
	}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrf)
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.rateLimitedLogin(rec, r)
	return rec
}

// answerCode posts the authenticator's code on the code page that rec is,
// ticking the remember box when asked.
func (f *signInFixture) answerCode(t *testing.T, page *httptest.ResponseRecorder, secret []byte,
	step int64, remember bool) *httptest.ResponseRecorder {
	t.Helper()
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("the code page carries no CSRF field: %d", page.Code)
	}
	code := mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod)+step, mfa.DefaultDigits)
	form := url.Values{"code": {code}, csrfFormField: {m[1]}}
	if remember {
		form.Set("remember", "1")
	}
	r := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieFrom(page, PendingCookieName))
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func TestARememberedDeviceSkipsTheSecondFactorUntilForgotten(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	secret := giveTOTP(t, f)
	ctx := context.Background()
	setDays := func(days int) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.SetRememberDeviceDays(ctx, tx, f.orgID, days); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	challenged := func(rec *httptest.ResponseRecorder) bool {
		return cookieFrom(rec, SessionCookieName) == nil && cookieFrom(rec, PendingCookieName) != nil
	}
	// Each remembering spends a code, and a spent counter cannot be used again:
	// the three uses take the previous, current and next periods, the most the
	// verifier's skew of one accepts.
	step := int64(-2)
	remember := func() *http.Cookie {
		t.Helper()
		page := f.signInWith(t, "")
		if !strings.Contains(page.Body.String(), `name="remember"`) {
			t.Fatal("the code page offers no box to remember the device")
		}
		step++
		rec := f.answerCode(t, page, secret, step, true)
		device := cookieFrom(rec, DeviceCookieName)
		if cookieFrom(rec, SessionCookieName) == nil || device == nil {
			t.Fatalf("a right code with the box ticked gave %d, session %v, device %v",
				rec.Code, cookieFrom(rec, SessionCookieName) != nil, device != nil)
		}
		return device
	}

	// Off by default: no box, and nothing to remember.
	if page := f.signInWith(t, ""); strings.Contains(page.Body.String(), `name="remember"`) {
		t.Error("the box is offered where the organisation has not turned it on")
	}

	setDays(30)
	device := remember()
	rec := f.signInWith(t, "", device)
	if challenged(rec) || cookieFrom(rec, SessionCookieName) == nil {
		t.Fatalf("a remembered device was asked for the second factor again: %d", rec.Code)
	}
	var amr []string
	if err := f.pool.QueryRow(ctx, `SELECT amr FROM core.sessions WHERE cookie_hash = $1`,
		store.HashToken(cookieFrom(rec, SessionCookieName).Value)).Scan(&amr); err != nil {
		t.Fatal(err)
	}
	if strings.Join(amr, " ") != "pwd" {
		t.Errorf("a remembered device's session has amr %q; the device proved nothing this time", amr)
	}

	// A client that asks for multi-factor is asked, device or not.
	if rec := f.signInWith(t, "client_id="+f.clientID+"&acr_values=2", device); !challenged(rec) {
		t.Error("a remembered device skipped the factor a client asked for")
	}
	// A device another person remembered counts for nobody else: the fixture's
	// device cookie, presented for a token it does not hold, is not a device.
	if rec := f.signInWith(t, "", &http.Cookie{Name: DeviceCookieName, Value: "not-a-device"}); !challenged(rec) {
		t.Error("an unknown device cookie skipped the second factor")
	}

	// Forgotten by the person.
	f.formPost(t, cookie, "/account/devices", "/account/devices/forget", url.Values{"id": {"all"}})
	if rec := f.signInWith(t, "", device); !challenged(rec) {
		t.Fatal("a forgotten device still skipped the second factor")
	}

	// Forgotten by signing out everywhere.
	device = remember()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TerminateSessions(ctx, tx, "", f.userID, store.ReasonUserRevoke); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := f.signInWith(t, "", device); !challenged(rec) {
		t.Fatal("signing out everywhere left a remembered device skipping the second factor")
	}

	// Forgotten by the organisation turning it off.
	device = remember()
	setDays(0)
	if rec := f.signInWith(t, "", device); !challenged(rec) {
		t.Fatal("a device remembered before the organisation turned the feature off still skips")
	}
}
