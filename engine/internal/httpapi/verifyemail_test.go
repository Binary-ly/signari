package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// Self-sign-up under a rule requiring a proved address (5.01), through the
// routes a browser calls: the account is made, its first sign-in is held at
// the verify_email stage with a code mailed to the address, a wrong code is
// refused, the right one issues the session and marks the address verified,
// and the next sign-in is not held.

const verifyTestPassword = "seven-lamps-drift-inland-42"

// signUp makes an account through /signup and returns its address.
func signUp(t *testing.T, f *tokenFixture) string {
	t.Helper()
	email := fmt.Sprintf("verify-%d@example.test", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, email)
	})
	rec := postSignup(t, f, url.Values{"email": {email}, "password": {verifyTestPassword}})
	if rec.Code != http.StatusOK || !accountExists(t, f, email) {
		t.Fatalf("signing up: %d %s", rec.Code, truncate(rec.Body.String(), 200))
	}
	return email
}

// logIn runs the password step for email.
func logIn(t *testing.T, f *tokenFixture, email string) *httptest.ResponseRecorder {
	t.Helper()
	get := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/login", nil))
	m := csrfValue.FindStringSubmatch(get.Body.String())
	if m == nil {
		t.Fatalf("the sign-in page carries no CSRF field: %d", get.Code)
	}
	form := url.Values{"username": {email}, "password": {verifyTestPassword}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieFrom(get, CSRFCookieName))
	r.RemoteAddr = uniqueTestAddr(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// postVerify posts to path from the page form carrying the held sign-in.
func postVerify(t *testing.T, f *tokenFixture, form *httptest.ResponseRecorder, pending *http.Cookie,
	path, code string) *httptest.ResponseRecorder {
	t.Helper()
	m := csrfValue.FindStringSubmatch(form.Body.String())
	if m == nil {
		t.Fatalf("the page carries no CSRF field: %d %s", form.Code, truncate(form.Body.String(), 200))
	}
	values := url.Values{csrfFormField: {m[1]}}
	if code != "" {
		values.Set("code", code)
	}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(pending)
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	r.RemoteAddr = uniqueTestAddr(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

var codeInMail = regexp.MustCompile(`\b(\d{6})\b`)

// mailedCode is the code in the newest message to address.
func mailedCode(t *testing.T, mailer *captureMailer, address string) (string, int) {
	t.Helper()
	msgs := mailer.messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].To == address {
			if m := codeInMail.FindStringSubmatch(msgs[i].Body); m != nil {
				return m[1], len(msgs)
			}
		}
	}
	t.Fatalf("no code was mailed to %s", address)
	return "", 0
}

// userinfoVerified is what /userinfo says of email's address, to a token with
// the email scope.
func userinfoVerified(t *testing.T, f *tokenFixture, email string) any {
	t.Helper()
	var userID string
	if err := f.pool.QueryRow(context.Background(), `SELECT id::text FROM core.users WHERE email = $1`,
		email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	k, err := f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
		Issuer: f.srv.cfg.Issuer, Subject: userID, Audience: []string{f.clientID},
		Expiry: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
		JTI: fmt.Sprintf("verify-email-%d", now.UnixNano()), ClientID: f.clientID, Scope: "openid email",
	}, tokens.TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, oidc.PathUserinfo, nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var body map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatalf("userinfo: %d %s", rec.Code, rec.Body.String())
	}
	return body["email_verified"]
}

func verifiedAt(t *testing.T, f *tokenFixture, email string) (verified bool, pending int) {
	t.Helper()
	if err := f.pool.QueryRow(context.Background(), `
		SELECT u.email_verified_at IS NOT NULL,
		       (SELECT count(*) FROM core.email_verifications v WHERE v.user_id = u.id)
		  FROM core.users u WHERE u.email = $1`, email).Scan(&verified, &pending); err != nil {
		t.Fatal(err)
	}
	return verified, pending
}

func TestASelfSignUpProvesItsAddressBeforeItsFirstSession(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	email := signUp(t, f)
	if v, p := verifiedAt(t, f, email); v || p != 1 {
		t.Fatalf("after sign-up: verified %v, outstanding %d", v, p)
	}
	if got := userinfoVerified(t, f, email); got != false {
		t.Fatalf("userinfo says email_verified %v before anything was proved", got)
	}

	held := logIn(t, f, email)
	if cookieFrom(held, SessionCookieName) != nil {
		t.Fatal("a session was issued before the address was proved")
	}
	pending := cookieFrom(held, PendingCookieName)
	if pending == nil || !strings.Contains(held.Body.String(), `action="/login/verify-email"`) {
		t.Fatalf("the sign-in was not held at the address check: %d %s", held.Code,
			truncate(held.Body.String(), 300))
	}
	code, _ := mailedCode(t, mailer, email)

	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	refused := postVerify(t, f, held, pending, "/login/verify-email", wrong)
	if cookieFrom(refused, SessionCookieName) != nil || !strings.Contains(refused.Body.String(), "not right") {
		t.Fatalf("a wrong code: %d %s", refused.Code, truncate(refused.Body.String(), 200))
	}

	signedIn := postVerify(t, f, refused, pending, "/login/verify-email", code)
	if cookieFrom(signedIn, SessionCookieName) == nil {
		t.Fatalf("the right code issued no session: %d %s", signedIn.Code, truncate(signedIn.Body.String(), 300))
	}
	if v, p := verifiedAt(t, f, email); !v || p != 0 {
		t.Fatalf("after the right code: verified %v, outstanding %d", v, p)
	}
	if got := userinfoVerified(t, f, email); got != true {
		t.Errorf("userinfo says email_verified %v after the address was proved", got)
	}
	// Spent: the same code a second time is no proof of anything.
	if again := postVerify(t, f, held, pending, "/login/verify-email", code); cookieFrom(again, SessionCookieName) != nil {
		t.Error("the code signed in twice")
	}

	// The next sign-in is not held.
	if next := logIn(t, f, email); cookieFrom(next, SessionCookieName) == nil {
		t.Errorf("a proved address was held again: %d %s", next.Code, truncate(next.Body.String(), 200))
	}
}

func TestARuleThatDoesNotAskForAProvedAddressHoldsNobody(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.signup_rules SET require_verified_email = false WHERE org_id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	f.srv.mailer = &captureMailer{}
	email := signUp(t, f)
	if _, p := verifiedAt(t, f, email); p != 0 {
		t.Fatalf("%d verifications outstanding under a rule that asks for none", p)
	}
	if rec := logIn(t, f, email); cookieFrom(rec, SessionCookieName) == nil {
		t.Errorf("held anyway: %d %s", rec.Code, truncate(rec.Body.String(), 200))
	}
}

// Past the ceiling no code is accepted, the right one included, and the page
// says what is left: a password reset, whose link proves the address.
func TestAnAddressConfirmationClosesAfterTooManyWrongCodes(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	email := signUp(t, f)
	held := logIn(t, f, email)
	pending := cookieFrom(held, PendingCookieName)
	code, _ := mailedCode(t, mailer, email)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.email_verifications v
		SET failed_attempts = $2 FROM core.users u WHERE u.id = v.user_id AND u.email = $1`,
		email, store.EmailVerificationCeiling); err != nil {
		t.Fatal(err)
	}
	rec := postVerify(t, f, held, pending, "/login/verify-email", code)
	if cookieFrom(rec, SessionCookieName) != nil {
		t.Fatal("a closed confirmation accepted a code")
	}
	if !strings.Contains(rec.Body.String(), `href="/recover"`) {
		t.Errorf("the closed page does not point at recovery: %s", truncate(rec.Body.String(), 300))
	}
}

// The address check and the password change are answered by one query. Read
// first for verify_email, it must still leave a flagged password flagged for an
// unconditional password_change stage later in the flow.
func TestTheAddressCheckLeavesAFlaggedPasswordFlagged(t *testing.T) {
	f := newSignInFixture(t)
	f.applyFlow(t, `
version: 1
flows:
  - name: verify-then-change
    on: authentication
    stages:
      - password
      - {stage: verify_email, when: email_verification_pending}
      - password_change
      - session
    tests:
      - {name: x, given: {}, expect: [password, password_change, session]}
`)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.password_credentials
		SET must_change = true, must_change_reason = 'set by an administrator'
		WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(t, f.email, signInTestPassword); got.signedIn() {
		t.Fatal("a flagged password signed in once the address check had asked first")
	}
}

// A completed reset proves the address its link went to, ending a
// confirmation; one sent before the address changed proves nothing.
func TestACompletedResetProvesTheAddressItWentTo(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	for _, moved := range []bool{false, true} {
		email := fmt.Sprintf("reset-proves-%d@example.test", time.Now().UnixNano())
		var userID string
		if err := f.pool.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
			VALUES ($1::uuid, sha256($2::bytea) || sha256($2::bytea || 'x'), $2) RETURNING id::text`,
			f.orgID, email).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, userID) })
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RequireEmailVerification(ctx, tx, userID, f.orgID); err != nil {
			t.Fatal(err)
		}
		req, err := store.CreateRecoveryRequest(ctx, tx, userID, f.orgID,
			store.HashToken(email+"t"), store.HashToken(email+"c"), "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if moved {
			if _, err := tx.Exec(ctx, `UPDATE core.users SET email = 'moved-' || email WHERE id = $1::uuid`,
				userID); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.AddressProvedByRecovery(ctx, tx, req.ID, userID); err != nil {
			t.Fatal(err)
		}
		var verified bool
		var outstanding int
		if err := tx.QueryRow(ctx, `SELECT email_verified_at IS NOT NULL,
			(SELECT count(*) FROM core.email_verifications WHERE user_id = $1::uuid)
			FROM core.users WHERE id = $1::uuid`, userID).Scan(&verified, &outstanding); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if want := !moved; verified != want || (outstanding == 0) != want {
			t.Errorf("address moved %v: verified %v, outstanding %d", moved, verified, outstanding)
		}
	}
}
