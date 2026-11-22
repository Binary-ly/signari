package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A password the sign-in made somebody change (5.04): the change goes through,
// the sign-in finishes, and the holder is told -- queued in the transaction the
// sign-in commits, so it goes out exactly when the change does.
func TestAForcedPasswordChangeTellsTheHolder(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.password_credentials
		SET must_change = true, must_change_reason = 'set by an administrator'
		WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	held := f.attempt(t, f.email, signInTestPassword)
	if held.signedIn() || held.pendingCookie == "" {
		t.Fatalf("the flagged password was not held for a change: %d", held.status)
	}
	m := csrfValue.FindStringSubmatch(held.body)
	if m == nil {
		t.Fatal("the change page carries no CSRF field")
	}
	const next = "quiet-harbour-nine-stones-4417"
	form := url.Values{"password": {next}, "confirm": {next}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login/password-change", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: PendingCookieName, Value: held.pendingCookie})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	if cookieFrom(rec, SessionCookieName) == nil {
		t.Fatalf("the change did not finish the sign-in: %d %s", rec.Code, truncate(rec.Body.String(), 200))
	}
	if n := queuedNotices(t, f.pool, f.userID, store.NoticePasswordChanged); n != 1 {
		t.Errorf("%d password-changed notices queued, want 1", n)
	}
}
