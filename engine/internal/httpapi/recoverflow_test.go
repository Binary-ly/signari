package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/captcha"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/store"
)

// Driving the recovery flow (9q option 3).
//
// The point of these is narrower than "recovery works" and is the only thing
// that distinguishes this change from the bug it fixes. Before it, a recovery
// flow was parsed, safety-analysed by rules written specifically for it, had its
// own cases pass, installed cleanly -- and governed nothing, because no endpoint
// read it. Every one of those checks would still have passed.
//
// So these assert that the OPERATOR'S FILE changes what the endpoints do:
// removing a stage removes it, adding one the engine cannot run stops the
// journey, and closing the flow closes recovery. A test that only proved a
// password can be reset would pass equally against the wiring that ignored the
// file.

// applyRecoveryFlow installs a recovery flow for the fixture's organisation.
//
// Through flow.Parse first, exactly as `signari flow apply` does, so a test
// cannot install a document the CLI would refuse -- which would prove the driver
// handles input the product cannot produce.
func applyRecoveryFlow(t *testing.T, f *tokenFixture, doc string) {
	t.Helper()
	if _, err := flow.Parse([]byte(doc)); err != nil {
		t.Fatalf("the test's own flow document does not load: %v", err)
	}
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sign_in_flows (org_id, document) VALUES ($1::uuid, $2)
		ON CONFLICT (org_id) DO UPDATE SET document = EXCLUDED.document, applied_at = now()`,
		f.orgID, doc); err != nil {
		t.Fatalf("applying the flow: %v", err)
	}
	f.srv.reloadFlows(ctx)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.sign_in_flows WHERE org_id = $1::uuid`, f.orgID)
		f.srv.reloadFlows(context.Background())
	})
}

// applyRecoveryFlowAtDefaultOrg installs a recovery flow where the REQUEST half
// will look for it.
//
// `/recover` reads the default organisation's flow rather than the account's, so
// that the journey cannot vary by account -- see recoverflow.go. A test that
// installs against the fixture's own organisation therefore exercises the reset
// half only, and would report the request half as working whatever it did.
// The fixture gives its instance a RANDOM issuer, so `defaultOrg` -- which joins
// organisations to the instance whose issuer equals the server's -- finds
// nothing, and the request half falls back to the built-in flow whatever is
// installed. The server is pointed at the fixture's own instance for the
// duration of the test, the same technique enableSelfSignup uses and for the
// same reason.
func applyRecoveryFlowAtDefaultOrg(t *testing.T, f *tokenFixture, doc string) {
	t.Helper()
	if _, err := flow.Parse([]byte(doc)); err != nil {
		t.Fatalf("the test's own flow document does not load: %v", err)
	}
	ctx := context.Background()

	var issuer string
	if err := f.pool.QueryRow(ctx, `
		SELECT i.issuer FROM core.instances i
		JOIN core.organizations o ON o.instance_id = i.id
		WHERE o.id = $1::uuid`, f.orgID).Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	beforeIssuer := f.srv.cfg.Issuer
	f.srv.cfg.Issuer = issuer
	t.Cleanup(func() { f.srv.cfg.Issuer = beforeIssuer })

	orgID, err := f.srv.defaultOrg(ctx)
	if err != nil {
		t.Fatalf("resolving the default organisation: %v", err)
	}
	if orgID != f.orgID {
		t.Fatalf("the default organisation resolved to %s, not the fixture's %s; the "+
			"request half would read a different flow than this test installs",
			orgID, f.orgID)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sign_in_flows (org_id, document) VALUES ($1::uuid, $2)
		ON CONFLICT (org_id) DO UPDATE SET document = EXCLUDED.document, applied_at = now()`,
		orgID, doc); err != nil {
		t.Fatalf("applying the flow: %v", err)
	}
	f.srv.reloadFlows(ctx)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.sign_in_flows WHERE org_id = $1::uuid`, orgID)
		f.srv.reloadFlows(context.Background())
	})
}

// givePassword gives the fixture's user a password credential.
//
// Without one there is nothing for a reset to change: ConsumeRecovery's UPDATE
// matches no row, the journey reports success, and a test asserting on the
// credential compares two absences and sees no change. Unreachable in
// production, where starting recovery requires the credential lookup to find
// one, but it makes a test silently vacuous.
func givePassword(t *testing.T, f *tokenFixture) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id')
		ON CONFLICT (user_id) DO NOTHING`,
		f.userID, f.orgID, "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$fixture"); err != nil {
		t.Fatalf("fixture credential: %v", err)
	}
}

// newResetToken creates a live, already-effective recovery request for the
// fixture's user and returns the token that reaches the reset form.
//
// The request is created directly rather than by posting to /recover, because
// these tests are about what the RESET half does with the flow, and going
// through the request half would couple them to mail delivery.
func newResetToken(t *testing.T, f *tokenFixture) string {
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

	// An hour in the past, so the enforced delay has already elapsed and the
	// reset form is live rather than pending.
	if _, err := store.CreateRecoveryRequest(ctx, tx, f.userID, f.orgID,
		hash, cancelHash, "", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("creating the recovery request: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return token
}

// postReset submits the new-password form with a valid CSRF pair.
func postReset(t *testing.T, f *tokenFixture, token, password string) *httptest.ResponseRecorder {
	t.Helper()
	tok, cookie := signupCSRF(t, f)
	form := url.Values{}
	form.Set("token", token)
	form.Set("password", password)
	form.Set(csrfFormField, tok)

	req := httptest.NewRequest(http.MethodPost, "/recover/reset", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.RemoteAddr = uniqueTestAddr(t) + ":54321"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// passwordChangedAt reports the credential's last update, so a test can prove a
// refused journey left the account alone rather than trusting a status code.
func passwordChangedAt(t *testing.T, f *tokenFixture) time.Time {
	t.Helper()
	var at time.Time
	if err := f.pool.QueryRow(context.Background(),
		`SELECT coalesce(max(updated_at), 'epoch'::timestamptz)
		   FROM core.password_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&at); err != nil {
		t.Fatalf("reading the credential timestamp: %v", err)
	}
	return at
}

// A flow naming a stage this engine cannot run must refuse the reset and leave
// the credential untouched.
//
// `mfa` is the realistic case and the reason this matters: an operator demanding
// a second factor before a password reset. Skipping it would reset the password
// having proved strictly less than the file requires -- the original bug, one
// level down, and in the direction that costs a real security control.
func TestARecoveryFlowNamingAnUndrivableStageRefusesAndChangesNothing(t *testing.T) {
	f := newTokenFixture(t)
	applyRecoveryFlow(t, f, `
version: 1
flows:
  - name: mfa-before-reset
    on: recovery
    stages:
      - identify
      - email_otp
      - mfa
      - password_change
      - done
    tests:
      - name: demands a second factor
        given: {}
        expect: [identify, email_otp, mfa, password_change, done]
`)
	givePassword(t, f)
	token := newResetToken(t, f)
	before := passwordChangedAt(t, f)

	rec := postReset(t, f, token, "a-perfectly-good-new-password-42")

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d: a flow demanding a stage the engine cannot "+
			"run must refuse the journey, not complete it", rec.Code, http.StatusNotImplemented)
	}
	if after := passwordChangedAt(t, f); !after.Equal(before) {
		t.Error("the password was changed by a journey that was refused. The refusal " +
			"has to happen before anything is written, or a flow the engine cannot " +
			"honour still resets credentials")
	}
}

// The refusal must come before the password policy runs, so a flow the engine
// cannot honour is reported as such rather than as a bad password.
func TestAnUndrivableRecoveryStageIsReportedBeforeThePasswordIsJudged(t *testing.T) {
	f := newTokenFixture(t)
	applyRecoveryFlow(t, f, `
version: 1
flows:
  - name: mfa-before-reset
    on: recovery
    stages: [identify, email_otp, mfa, password_change, done]
    tests:
      - name: demands a second factor
        given: {}
        expect: [identify, email_otp, mfa, password_change, done]
`)
	token := newResetToken(t, f)

	// Deliberately too short. A driver that checked the password first would
	// report a policy failure and never mention the stage it cannot run.
	rec := postReset(t, f, token, "x")

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d: the unsupported stage must be reported "+
			"before the password is judged, or an operator debugging a broken flow "+
			"is told their user chose a bad password", rec.Code, http.StatusNotImplemented)
	}
}

// A flow that closes recovery closes it, at the request half, for every
// identifier alike.
func TestARecoveryFlowThatDeniesRefusesTheRequest(t *testing.T) {
	f := newTokenFixture(t)
	applyRecoveryFlowAtDefaultOrg(t, f, `
version: 1
flows:
  - name: recovery-closed
    on: recovery
    stages: [identify, deny]
    tests:
      - name: closed
        given: {}
        expect: [identify, deny]
`)
	tok, cookie := signupCSRF(t, f)
	form := url.Values{}
	form.Set("username", "somebody@example.test")
	form.Set(csrfFormField, tok)
	req := httptest.NewRequest(http.MethodPost, "/recover", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.RemoteAddr = uniqueTestAddr(t) + ":54321"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d: a recovery flow ending in deny must close "+
			"the endpoint", rec.Code, http.StatusForbidden)
	}
}

// The operator's file decides whether /recover challenges, not the captcha mode.
//
// The challenge is configured to fire on every request and the flow does not
// mention captcha, so the request must go through. This is the test that fails
// if the driver reads the file and ignores it: the built-in flow DOES carry a
// captcha stage, so a wiring that always used the default would challenge here.
func TestARecoveryFlowWithoutCaptchaIsNotChallenged(t *testing.T) {
	f := newTokenFixture(t)
	before := f.srv.captcha
	f.srv.captcha = captcha.New(captcha.Config{
		Mode: captcha.ModeAlways, Provider: captcha.Turnstile,
		SiteKey: "site-key-for-the-test", Secret: "secret",
	}, nil)
	t.Cleanup(func() { f.srv.captcha = before })
	applyRecoveryFlowAtDefaultOrg(t, f, `
version: 1
flows:
  - name: no-challenge
    on: recovery
    stages: [identify, email_otp, password_change, done]
    tests:
      - name: recovers
        given: {}
        expect: [identify, email_otp, password_change, done]
`)
	tok, cookie := signupCSRF(t, f)
	form := url.Values{}
	form.Set("username", "nobody@example.test")
	form.Set(csrfFormField, tok)
	req := httptest.NewRequest(http.MethodPost, "/recover", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.RemoteAddr = uniqueTestAddr(t) + ":54321"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: the flow omits captcha, so a challenge "+
			"configured to fire on every request must not stop this", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(strings.ToLower(body), "captcha") {
		t.Error("a challenge was rendered by a flow that does not name the captcha stage")
	}
}

// The mirror, and the test that proves the request half READS the file rather
// than merely being handed one.
//
// An UNCONDITIONAL captcha stage must challenge even in adaptive mode with no
// failures recorded, where the built-in flow's `when: captcha_required` would
// not. Only the operator's file can produce a challenge here.
//
// Its absence was a surviving mutant: with the driver neutralised so the file was
// read and then ignored, the no-challenge test above still passed, because the
// fallback plan omits captcha too. A test that cannot fail when the feature is
// removed is not evidence the feature exists.
func TestARecoveryFlowCanDemandACaptchaAdaptiveModeWouldNot(t *testing.T) {
	f := newTokenFixture(t)
	before := f.srv.captcha
	// Adaptive with no failures seen: Required() is false, so captcha_required is
	// false and a conditional stage would be skipped.
	f.srv.captcha = captcha.New(captcha.Config{
		Mode: captcha.ModeAdaptive, Provider: captcha.Turnstile,
		SiteKey: "site-key-for-the-test", Secret: "secret",
		FailuresBeforeChallenge: 3,
	}, nil)
	t.Cleanup(func() { f.srv.captcha = before })

	applyRecoveryFlowAtDefaultOrg(t, f, `
version: 1
flows:
  - name: always-challenge-recovery
    on: recovery
    stages:
      - captcha
      - identify
      - email_otp
      - password_change
      - done
    tests:
      - name: always challenged
        given: {}
        expect: [captcha, identify, email_otp, password_change, done]
`)
	tok, cookie := signupCSRF(t, f)
	form := url.Values{}
	form.Set("username", "nobody@example.test")
	form.Set(csrfFormField, tok)
	req := httptest.NewRequest(http.MethodPost, "/recover", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.RemoteAddr = uniqueTestAddr(t) + ":54321"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	// Two assertions, and both are needed.
	//
	// The EFFECT: no recovery request was created, so the stage actually stopped
	// the journey rather than being noted and passed.
	if recoveryRequestCount(t, f) != 0 {
		t.Error("an unconditional captcha stage did not stop the request; a recovery " +
			"request was created with no challenge response")
	}
	// The FORM: the re-rendered page carries the challenge. Without this the
	// refusal is a dead end -- the person is told to solve a captcha that is not
	// on the page, and adaptive mode would not have drawn one.
	if !strings.Contains(rec.Body.String(), "site-key-for-the-test") {
		t.Errorf("the form was re-rendered without the challenge on it, so there is "+
			"nothing for the person to solve. status: %d", rec.Code)
	}
}

// recoveryRequestCount counts live recovery requests for the fixture's user.
func recoveryRequestCount(t *testing.T, f *tokenFixture) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.recovery_requests
		  WHERE user_id = $1::uuid AND cancelled_at IS NULL AND consumed_at IS NULL`,
		f.userID).Scan(&n); err != nil {
		t.Fatalf("counting recovery requests: %v", err)
	}
	return n
}

// The ordinary journey still works, under the operator's own file, and actually
// changes the credential.
func TestARecoveryFlowResetsThePassword(t *testing.T) {
	f := newTokenFixture(t)
	applyRecoveryFlow(t, f, `
version: 1
flows:
  - name: plain-recovery
    on: recovery
    stages: [identify, email_otp, password_change, done]
    tests:
      - name: recovers
        given: {}
        expect: [identify, email_otp, password_change, done]
`)
	givePassword(t, f)
	token := newResetToken(t, f)
	before := passwordChangedAt(t, f)

	rec := postReset(t, f, token, "a-perfectly-good-new-password-42")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if after := passwordChangedAt(t, f); !after.After(before) {
		t.Errorf("the reset reported success without changing the credential.\nbody: %s",
			rec.Body.String())
	}
}
