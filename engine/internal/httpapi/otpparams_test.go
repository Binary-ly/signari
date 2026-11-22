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

// An organisation chooses what authenticator apps are enrolled with, every
// credential keeps what it was enrolled with, and a hardware token counts its
// presses (4.12). Everything was SHA-1, six digits, thirty seconds.

func setTOTPPolicy(t *testing.T, f *signInFixture, p store.TOTPPolicy) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetTOTPPolicy(ctx, tx, f.orgID, p); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// postCode submits code on the code page that page is.
func (f *signInFixture) postCode(t *testing.T, page *httptest.ResponseRecorder, code string) *httptest.ResponseRecorder {
	t.Helper()
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("the code page carries no CSRF field: %d", page.Code)
	}
	form := url.Values{"code": {code}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieFrom(page, PendingCookieName))
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func TestAppsAreEnrolledWithTheOrganisationsChoiceAndKeepIt(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	ctx := context.Background()
	setTOTPPolicy(t, f, store.TOTPPolicy{Algorithm: "SHA256", Digits: 8, Period: 60 * time.Second})

	page := accountGET(f, cookie, "/account/mfa/totp")
	m := csrfValue.FindStringSubmatch(page.Body.String())
	csrfCookie := cookieFrom(page, CSRFCookieName)
	if m == nil || csrfCookie == nil {
		t.Fatal("the introduction carries no CSRF token")
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		form.Set(csrfFormField, m[1])
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		r.AddCookie(csrfCookie)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}
	// Through the page's otpauth link, which until now read {URI}: the
	// message substituted strings only, and the handler passes a template.URL.
	start := post("/account/mfa/totp/start", url.Values{})
	for _, want := range []string{`href="otpauth://totp/`, "algorithm=SHA256", "digits=8", "period=60"} {
		if !strings.Contains(start.Body.String(), want) {
			t.Errorf("the enrolment page's link lacks %s", want)
		}
	}
	tx, _ := f.pool.Begin(ctx)
	pending, err := store.LoadTOTPEnrolment(ctx, tx, f.userID, f.srv.cfg.Root)
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Algorithm != "SHA256" || pending.Digits != 8 || pending.Period != time.Minute || len(pending.Secret) != 32 {
		t.Fatalf("the enrolment is %s, %d digits, %s, a %d-byte secret", pending.Algorithm, pending.Digits,
			pending.Period, len(pending.Secret))
	}
	p := mfa.Params{Algorithm: mfa.SHA256, Digits: 8, Period: time.Minute}
	now := mfa.Counter(time.Now(), time.Minute)
	if rec := post("/account/mfa/totp", url.Values{"code": {p.Code(pending.Secret, now)}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "recovery") {
		t.Fatalf("confirming the SHA-256 code gave %d", rec.Code)
	}

	// The organisation goes back to the default; this phone keeps working.
	setTOTPPolicy(t, f, store.DefaultTOTPPolicy)
	codePage := f.signInWith(t, "")
	if cookieFrom(codePage, PendingCookieName) == nil {
		t.Fatalf("the password left no pending sign-in: %d", codePage.Code)
	}
	sha1 := mfa.Params{Digits: 8, Period: time.Minute}.Code(pending.Secret, now+1)
	if rec := f.postCode(t, codePage, sha1); sessionSet(rec) {
		t.Fatal("the same secret's SHA-1 code signed in a SHA-256 authenticator")
	}
	if rec := f.postCode(t, codePage, p.Code(pending.Secret, now+1)); !sessionSet(rec) {
		t.Fatalf("the SHA-256 code after the choice changed did not sign in: %d", rec.Code)
	}
}

func TestAHardwareTokenSignsInByItsPresses(t *testing.T) {
	f, _ := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	ctx := context.Background()
	seed := []byte("12345678901234567890")
	// mfa's HOTP vectors, presses 0 to 15 of this seed.
	p := mfa.Params{}
	press := func(n int64) string { return p.Code(seed, n) }
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AssignOTPToken(ctx, tx, f.userID, f.orgID, seed, "hotp", "SHA1", 6,
		30*time.Second, 1, f.srv.cfg.Root); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	counter := func() (n int64, failed int) {
		t.Helper()
		if err := f.pool.QueryRow(ctx, `SELECT last_used_counter, failed_attempts FROM core.totp_credentials
			WHERE user_id = $1::uuid`, f.userID).Scan(&n, &failed); err != nil {
			t.Fatal(err)
		}
		return n, failed
	}

	// Pressed once in a pocket: press 3 after press 1 is within the look-ahead.
	if rec := f.postCode(t, f.signInWith(t, ""), press(3)); !sessionSet(rec) {
		t.Fatalf("press 3 after 1 did not sign in: %d", rec.Code)
	}
	if n, _ := counter(); n != 3 {
		t.Fatalf("the token's counter is %d after press 3", n)
	}
	page := f.signInWith(t, "")
	// The same press again is a replay, not charged as a guess.
	if rec := f.postCode(t, page, press(3)); sessionSet(rec) {
		t.Fatal("press 3 signed in twice")
	}
	if _, failed := counter(); failed != 0 {
		t.Errorf("a replayed press was charged as a guess (%d)", failed)
	}
	// Beyond the look-ahead: refused, and charged.
	if rec := f.postCode(t, page, press(3+mfa.HOTPLookAhead+1)); sessionSet(rec) {
		t.Fatal("a press beyond the look-ahead signed in")
	}
	if _, failed := counter(); failed != 1 {
		t.Errorf("a wrong press was charged %d times", failed)
	}
	// The next press does.
	if rec := f.postCode(t, page, press(4)); !sessionSet(rec) {
		t.Fatalf("press 4 did not sign in: %d", rec.Code)
	}
	if n, failed := counter(); n != 4 || failed != 0 {
		t.Errorf("after press 4 the counter is %d with %d failures", n, failed)
	}
}
