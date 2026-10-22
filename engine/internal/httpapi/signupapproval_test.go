package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Self-sign-up held for an administrator's approval (5.19): pending, it signs
// nobody in by any route, its own right password says why, recovery passes it
// over, and approval lets it in and tells the person.
func TestAPendingSelfSignUpCannotSignInUntilApproved(t *testing.T) {
	j := newPasskeyJourney(t)
	ctx := context.Background()
	j.openSignup(t)
	if _, err := j.pool.Exec(ctx, `UPDATE core.signup_rules SET require_approval = true WHERE org_id = $1::uuid`, j.orgID); err != nil {
		t.Fatal(err)
	}
	mailer := &captureMailer{}
	j.srv.mailer = mailer
	clearSignInBucket(t, j.pool)
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	email := "pending-" + hex.EncodeToString(raw[:4]) + "@example.test"
	password := "a-pending-pass-" + hex.EncodeToString(raw)
	t.Cleanup(func() {
		c := context.Background()
		_, _ = j.pool.Exec(c, `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' IN
			(SELECT id::text FROM core.users WHERE email = $2)`, store.AccountNoticeTopic, email)
		_, _ = j.pool.Exec(c, `DELETE FROM core.users WHERE org_id = $1::uuid AND email = $2`, j.orgID, email)
	})

	b := newTestBrowser(t, j.h)
	done := b.post("/signup", b.get("/signup"), url.Values{"email": {email}, "password": {password}})
	if !strings.Contains(done.Body.String(), "waits for an administrator") || strings.Contains(done.Body.String(), `href="/login"`) {
		t.Fatalf("the finished sign-up does not say it waits: %d %s", done.Code, truncate(done.Body.String(), 300))
	}
	var userID, status string
	if err := j.pool.QueryRow(ctx, `SELECT id::text, status FROM core.users WHERE org_id = $1::uuid AND email = $2`,
		j.orgID, email).Scan(&userID, &status); err != nil || status != "pending" {
		t.Fatalf("the account is %q (%v), want pending", status, err)
	}

	signIn := func(pw string) *httptest.ResponseRecorder {
		t.Helper()
		return b.post("/login", b.get("/login"), url.Values{"username": {email}, "password": {pw}})
	}
	if rec := signIn(password); b.value(SessionCookieName) != "" || !strings.Contains(rec.Body.String(), "waiting for an administrator") {
		t.Errorf("a pending account with its right password: session %v, %s", b.value(SessionCookieName) != "",
			truncate(rec.Body.String(), 300))
	}
	if rec := signIn("not-" + password); strings.Contains(rec.Body.String(), "waiting for an administrator") {
		t.Error("a wrong password was told the account is pending")
	}
	b.post("/recover", b.get("/recover"), url.Values{"identifier": {email}, "username": {email}, "email": {email}})
	var requests int
	if err := j.pool.QueryRow(ctx, `SELECT count(*) FROM core.recovery_requests WHERE user_id = $1::uuid`, userID).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Errorf("%d recovery request(s) made for a pending account", requests)
	}

	tx, err := j.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.ApproveUser(ctx, tx, userID)
	if err != nil || !approved {
		t.Fatalf("approving: %v %v", approved, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := j.srv.DeliverAccountNotice(ctx, store.AccountNotice{UserID: userID, Notice: store.NoticeAccountApproved}); err != nil {
		t.Fatal(err)
	}
	told := false
	for _, m := range mailer.messages() {
		told = told || (m.To == email && m.Subject == "Your account is ready")
	}
	if !told {
		t.Errorf("approval did not tell the person: %+v", mailer.messages())
	}
	clearSignInBucket(t, j.pool)
	if signIn(password); b.value(SessionCookieName) == "" {
		t.Error("the approved account did not sign in")
	}
}

// The check is completeSignIn's, for every way in: one that reaches it for an
// account that is not active, as a provider's sign-in did for a deactivated
// one, makes no session and records the refusal.
func TestNoSessionIsMadeForAnAccountThatIsNotActive(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	for _, status := range []string{"deactivated", "pending"} {
		if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = $2 WHERE id = $1::uuid`, f.userID, status); err != nil {
			t.Fatal(err)
		}
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		f.srv.completeSignIn(rec, httptest.NewRequest(http.MethodPost, "/login", nil), tx, f.userID, f.orgID,
			[]string{"fed"}, "")
		_ = tx.Rollback(ctx)
		if cookieFrom(rec, SessionCookieName) != nil {
			t.Errorf("a %s account was given a session", status)
		}
		var refused int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE subject_id = $1::uuid
			AND event_type = $2 AND detail->>'reason' = $3`, f.userID, audit.EventLoginFailed, "account_"+status).Scan(&refused); err != nil {
			t.Fatal(err)
		}
		if refused == 0 {
			t.Errorf("the refusal of a %s account was not recorded", status)
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'active' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
}
