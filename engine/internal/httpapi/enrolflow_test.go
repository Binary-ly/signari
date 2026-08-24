package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/captcha"
	"signari.dev/engine/internal/flow"
)

// Driving the enrolment flow (9q option 2).
//
// The captcha tests in signupcaptcha_test.go prove /signup challenges when the
// BUILT-IN flow says to. These prove the stronger claim: the operator's own
// enrolment file governs the journey. A file that removes the challenge removes
// it; a file that names a stage the engine cannot run stops the sign-up rather
// than silently skipping it. Without both, "the flow drives /signup" is
// indistinguishable from a wiring that reads the file and ignores it.

// applyEnrolFlow installs an enrolment flow for the fixture's organisation.
//
// Through flow.Parse first, exactly as `signari flow apply` does, so the test
// cannot install a document the CLI would refuse. Reloaded synchronously, because
// a stale cache is otherwise refreshed in the background and the POST would race
// it.
func applyEnrolFlow(t *testing.T, f *tokenFixture, doc string) {
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
	})
}

// postSignup submits the form with a valid CSRF pair and a unique source address.
func postSignup(t *testing.T, f *tokenFixture, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	tok, cookie := signupCSRF(t, f)
	form.Set(csrfFormField, tok)
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.RemoteAddr = uniqueTestAddr(t) + ":54321"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

func accountExists(t *testing.T, f *tokenFixture, email string) bool {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.users WHERE email = $1`, email).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// A challenge is configured to fire on EVERY request, and the enrolment flow does
// not mention captcha. The account must be created anyway: the flow, not the
// captcha mode, decides whether /signup challenges.
//
// This is the test the wiring exists to pass. Under the old hardcoded
// `if s.captcha.Required { verify }`, ModeAlways would refuse this exact
// submission -- which is what TestSignUpRefusesAnUnsolvedChallenge asserts for the
// built-in flow. Here the operator's file has removed the stage, and so the
// challenge is gone.
func TestEnrolmentFlowWithoutCaptchaSkipsTheChallenge(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	withCaptcha(t, f) // ModeAlways: the old code would challenge unconditionally
	applyEnrolFlow(t, f, `
version: 1
flows:
  - name: no-captcha-signup
    on: enrolment
    stages:
      - create_user
      - done
    tests:
      - name: straight through
        given: {}
        expect: [create_user, done]
`)

	const addr = "no-challenge@example.test"
	rec := postSignup(t, f, url.Values{
		"email":    {addr},
		"password": {"a-perfectly-fine-password-42"},
		// No captcha response, exactly what a script sends.
	})

	if !accountExists(t, f, addr) {
		t.Fatalf("the enrolment flow lists no captcha stage, yet sign-up was refused "+
			"as though it did -- the file is not driving the journey (status %d): %s",
			rec.Code, truncate(rec.Body.String(), 300))
	}
}

// The mirror: an UNCONDITIONAL captcha stage challenges even when adaptive mode,
// left to itself, would not. The file adds a challenge the hardcoded path never
// would, because that path only ever asked `if s.captcha.Required`.
func TestEnrolmentFlowCanDemandACaptchaAdaptiveModeWouldNot(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	// Adaptive mode with no failures seen: captcha.Required is FALSE, so the state
	// the flow is planned against has captcha_required=false. Only the flow's
	// UNCONDITIONAL captcha stage can make a challenge happen here.
	before := f.srv.captcha
	f.srv.captcha = captcha.New(captcha.Config{
		Mode: captcha.ModeAdaptive, Provider: captcha.Turnstile,
		SiteKey: "site-key-for-the-test", Secret: "secret",
		FailuresBeforeChallenge: 3,
	}, nil)
	t.Cleanup(func() { f.srv.captcha = before })
	applyEnrolFlow(t, f, `
version: 1
flows:
  - name: always-challenge-signup
    on: enrolment
    stages:
      - captcha
      - create_user
      - done
    tests:
      - name: always challenged
        given: {}
        expect: [captcha, create_user, done]
`)

	const addr = "must-challenge@example.test"
	rec := postSignup(t, f, url.Values{
		"email":    {addr},
		"password": {"a-perfectly-fine-password-42"},
	})

	if accountExists(t, f, addr) {
		t.Fatalf("an unconditional captcha stage did not stop a sign-up with no "+
			"challenge response; the account was created (status %d)", rec.Code)
	}
}

// A flow that names a stage the engine cannot execute at enrolment -- enrol_mfa,
// forced second-factor enrolment (9q option 3) -- must STOP the sign-up, not
// create the account and skip the stage. Skipping it would make an account
// without the second factor the operator required: the exact "a written flow
// governs nothing" bug wearing a driver.
func TestEnrolmentFlowFailsClosedOnAStageItCannotDrive(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	applyEnrolFlow(t, f, `
version: 1
flows:
  - name: forced-mfa-signup
    on: enrolment
    stages:
      - enrol_mfa
      - create_user
      - done
    tests:
      - name: enrol then create
        given: {}
        expect: [enrol_mfa, create_user, done]
`)

	const addr = "forced-mfa@example.test"
	rec := postSignup(t, f, url.Values{
		"email":    {addr},
		"password": {"a-perfectly-fine-password-42"},
	})

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("sign-up under a flow with an undriven stage answered %d, want 501; "+
			"a stage the engine cannot run must stop the journey, not be skipped", rec.Code)
	}
	if accountExists(t, f, addr) {
		t.Error("an account was created despite the enrolment flow requiring a stage " +
			"the engine skipped; the operator's enrol_mfa did nothing")
	}
}

// The ordinary path still works: the driven built-in flow creates an account.
func TestSignupCreatesAnAccountUnderTheDrivenFlow(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f) // no custom flow: the built-in default-sign-up drives

	const addr = "newcomer-driven@example.test"
	rec := postSignup(t, f, url.Values{
		"email":    {addr},
		"password": {"a-perfectly-fine-password-42"},
	})

	if !accountExists(t, f, addr) {
		t.Fatalf("the driven built-in enrolment flow did not create an account "+
			"(status %d): %s", rec.Code, truncate(rec.Body.String(), 300))
	}
}
