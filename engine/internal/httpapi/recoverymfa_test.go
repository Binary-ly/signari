package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/store"
)

// A second factor in recovery (5.12): proven on the link's page it waives the
// delay; a flow's mfa stage before the reset requires it; a flow may end signed
// in. Email never counts: it is what the link came by.

// recoveryTOTP gives the fixture's person an authenticator and returns its secret.
func recoveryTOTP(t *testing.T, f *tokenFixture) []byte {
	t.Helper()
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	secret, _, err := mfa.GenerateSecret(mfa.SHA1)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.StartTOTPEnrolment(ctx, tx, f.userID, f.orgID, secret,
		string(mfa.SHA1), mfa.DefaultDigits, mfa.DefaultPeriod, root); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteTOTPEnrolment(ctx, tx, f.userID, 0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return secret
}

// pendingResetToken is a request made just now, so the delay is still running.
func pendingResetToken(t *testing.T, f *tokenFixture) string {
	t.Helper()
	ctx := context.Background()
	token, hash, err := newRecoveryToken()
	if err != nil {
		t.Fatal(err)
	}
	_, cancelHash, err := newRecoveryToken()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.CreateRecoveryRequest(ctx, tx, f.userID, f.orgID, hash, cancelHash, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return token
}

func resetPage(t *testing.T, f *tokenFixture, token string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/recover/reset?token="+url.QueryEscape(token), nil))
	return rec.Body.String()
}

func postResetFactor(t *testing.T, f *tokenFixture, token, code string) *httptest.ResponseRecorder {
	t.Helper()
	tok, cookie := signupCSRF(t, f)
	form := url.Values{"token": {token}, "code": {code}, csrfFormField: {tok}}
	req := httptest.NewRequest(http.MethodPost, "/recover/reset/factor", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.RemoteAddr = uniqueTestAddr(t) + ":54321"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestAProvenSecondFactorGivesZeroDelay(t *testing.T) {
	f := newTokenFixture(t)
	givePassword(t, f)
	secret := recoveryTOTP(t, f)
	token := pendingResetToken(t, f)
	step := mfa.Counter(time.Now(), mfa.DefaultPeriod)

	page := resetPage(t, f, token)
	if !strings.Contains(page, "not usable yet") || !strings.Contains(page, `action="/recover/reset/factor"`) {
		t.Fatalf("the waiting page does not offer a second factor: %s", truncate(page, 400))
	}
	if strings.Contains(page, `action="/recover/reset"`) {
		t.Fatal("the new-password form is shown while the delay runs")
	}
	if rec := postResetFactor(t, f, token, wrongTOTP(secret)); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "not valid") {
		t.Fatalf("a wrong code: %d", rec.Code)
	}
	before := passwordChangedAt(t, f)
	if rec := postResetFactor(t, f, token, mfa.Code(secret, step, mfa.DefaultDigits)); rec.Code != http.StatusSeeOther {
		t.Fatalf("the right code: %d %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	if page := resetPage(t, f, token); !strings.Contains(page, `action="/recover/reset"`) {
		t.Fatalf("after the factor the reset is still not usable: %s", truncate(page, 400))
	}
	if rec := postReset(t, f, token, "a-perfectly-good-new-password-42"); rec.Code != http.StatusOK {
		t.Fatalf("the reset after the factor: %d", rec.Code)
	}
	if after := passwordChangedAt(t, f); !after.After(before) {
		t.Error("the password was not changed")
	}
	var proven, waived int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM core.audit_events WHERE subject_id = $1::uuid
		          AND event_type = 'account.recovery_factor_proven' AND detail->>'was_pending' = 'true'),
		       (SELECT count(*) FROM core.audit_events WHERE subject_id = $1::uuid
		          AND event_type = 'account.password_reset' AND detail->>'waived_by' = 'otp')`,
		f.userID).Scan(&proven, &waived); err != nil {
		t.Fatal(err)
	}
	if proven != 1 || waived != 1 {
		t.Errorf("recorded: factor proven %d, reset waived by the factor %d; want 1, 1", proven, waived)
	}
}

// An emailed code reaches the mailbox the link already proved, so it is no
// second factor here.
func TestAnEmailedCodeDoesNotWaiveTheDelay(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	email, err := store.EmailForUser(ctx, f.pool, f.userID)
	if err != nil || email == "" {
		t.Fatalf("the fixture's address: %v", err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.StartEmailOTPEnrolment(ctx, tx, f.userID, f.orgID, email); err != nil {
		t.Fatal(err)
	}
	code, _, err := store.IssueEmailOTPEnrolment(ctx, tx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := store.ConfirmEmailOTPEnrolment(ctx, tx, f.userID, code); err != nil || !ok {
		t.Fatalf("proving the address: %v %v", ok, err)
	}
	// The enrolment code was sent a moment ago, and a second is paced.
	if _, err := tx.Exec(ctx, `UPDATE core.email_otp_credentials SET last_sent_at = now() - interval '10 minutes'
		WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	live, _, err := store.IssueEmailOTP(ctx, tx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	token := pendingResetToken(t, f)
	if rec := postResetFactor(t, f, token, live); rec.Code == http.StatusSeeOther {
		t.Fatal("an emailed code waived the delay")
	}
	if page := resetPage(t, f, token); !strings.Contains(page, "not usable yet") {
		t.Error("the reset became usable on an emailed code")
	}
}

// A flow with mfa before the reset holds the reset until a factor is proven,
// and refuses it for somebody with none to prove.
func TestARecoveryFlowWithMFABeforeTheResetWorks(t *testing.T) {
	const doc = `
version: 1
flows:
  - name: recovery-with-a-factor
    on: recovery
    stages: [identify, email_otp, mfa, password_change, done]
    tests: [{name: as written, given: {}, expect: [identify, email_otp, mfa, password_change, done]}]
`
	t.Run("with a factor", func(t *testing.T) {
		f := newTokenFixture(t)
		givePassword(t, f)
		secret := recoveryTOTP(t, f)
		applyRecoveryFlow(t, f, doc)
		token := newResetToken(t, f)
		page := resetPage(t, f, token)
		if !strings.Contains(page, `action="/recover/reset/factor"`) || strings.Contains(page, `action="/recover/reset"`) {
			t.Fatalf("the reset page does not ask for the factor first: %s", truncate(page, 400))
		}
		before := passwordChangedAt(t, f)
		postReset(t, f, token, "a-perfectly-good-new-password-42")
		if after := passwordChangedAt(t, f); !after.Equal(before) {
			t.Fatal("the password was reset without the second factor the flow requires")
		}
		code := mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.DefaultDigits)
		if rec := postResetFactor(t, f, token, code); rec.Code != http.StatusSeeOther {
			t.Fatalf("the factor: %d", rec.Code)
		}
		postReset(t, f, token, "a-perfectly-good-new-password-42")
		if after := passwordChangedAt(t, f); !after.After(before) {
			t.Error("the reset did not happen after the factor was proven")
		}
	})
	t.Run("with none", func(t *testing.T) {
		f := newTokenFixture(t)
		givePassword(t, f)
		applyRecoveryFlow(t, f, doc)
		token := newResetToken(t, f)
		if page := resetPage(t, f, token); !strings.Contains(page, "has none that can be used here") {
			t.Errorf("somebody with no second factor was not told: %s", truncate(page, 400))
		}
		before := passwordChangedAt(t, f)
		postReset(t, f, token, "a-perfectly-good-new-password-42")
		if after := passwordChangedAt(t, f); !after.Equal(before) {
			t.Error("the password was reset with no second factor proven")
		}
	})
}

// A password the policy refuses re-renders the form with a CSRF token, so the
// next one can be submitted. It came back without one, and a person whose
// first choice was refused could not try a second.
func TestARefusedNewPasswordLeavesAFormThatWorks(t *testing.T) {
	f := newTokenFixture(t)
	givePassword(t, f)
	token := newResetToken(t, f)
	body := postReset(t, f, token, "x").Body.String()
	if m := csrfValue.FindStringSubmatch(body); m == nil {
		t.Fatalf("the form shown after a refused password carries no CSRF token: %s", truncate(body, 400))
	}
}

// A flow ending in `session` signs the person in once the password is set.
func TestARecoveryFlowCanEndSignedIn(t *testing.T) {
	f := newTokenFixture(t)
	givePassword(t, f)
	applyRecoveryFlow(t, f, `
version: 1
flows:
  - name: recovery-signs-in
    on: recovery
    stages: [identify, email_otp, password_change, session]
    tests: [{name: as written, given: {}, expect: [identify, email_otp, password_change, session]}]
`)
	token := newResetToken(t, f)
	rec := postReset(t, f, token, "a-perfectly-good-new-password-42")
	c := cookieFrom(rec, SessionCookieName)
	if c == nil || c.Value == "" {
		t.Fatalf("the reset did not end signed in: %d %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	sid, live, err := store.ResolveSessionCookie(context.Background(), f.pool, store.HashToken(c.Value))
	if err != nil || !live || sid == "" {
		t.Fatalf("the session is not live: %v", err)
	}
	var amr []string
	if err := f.pool.QueryRow(context.Background(), `SELECT amr FROM core.sessions WHERE sid = $1`, sid).Scan(&amr); err != nil {
		t.Fatal(err)
	}
	if len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("the session says it was signed in by %v, want the password just chosen", amr)
	}
}
