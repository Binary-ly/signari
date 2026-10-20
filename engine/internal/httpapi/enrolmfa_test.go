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

// A flow that requires a second factor enrols one, through the pages a browser
// walks: the password, the enrolment on the pending sign-in, the recovery
// codes, and the sign-in going on. An `mfa` stage demanded of everybody turned
// away somebody with nothing enrolled, and `enrol_mfa` was refused at parse
// because nothing drove it.

const enrolOrChallenge = `
version: 1
flows:
  - name: enrol-or-challenge
    on: authentication
    stages:
      - password
      - {stage: mfa, when: user_has_second_factor}
      - {stage: enrol_mfa, when: not user_has_second_factor}
      - session
    tests:
      - name: nothing enrolled
        given: {}
        expect: [password, enrol_mfa, session]
      - name: a factor
        given: {user_has_second_factor: true}
        expect: [password, mfa, session]
`

// enrolStep is a browser the walk is holding for enrolment.
type enrolStep struct {
	f          *signInFixture
	pending    string
	csrfCookie string
	csrfField  string
}

func (e *enrolStep) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form.Set(csrfFormField, e.csrfField)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: PendingCookieName, Value: e.pending})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: e.csrfCookie})
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	e.f.srv.Routes().ServeHTTP(rec, r)
	// A step that re-issues the pending sign-in carries it on.
	if c := cookieFrom(rec, PendingCookieName); c != nil {
		e.pending = c.Value
	}
	return rec
}

// enrolThrough walks the held sign-in through the enrolment, checking each
// page, and returns the answer to going on and the enrolled secret.
func enrolThrough(t *testing.T, f *signInFixture) (*enrolStep, *httptest.ResponseRecorder, []byte) {
	t.Helper()
	ctx := context.Background()
	got := f.attempt(t, f.email, signInTestPassword)
	if got.signedIn() || got.pendingCookie == "" {
		t.Fatalf("a password with nothing enrolled under a flow requiring a factor gave "+
			"session %v, pending %v", got.signedIn(), got.pendingCookie != "")
	}
	if !strings.Contains(got.body, `action="/login/enrol-mfa/start"`) {
		t.Fatal("the held sign-in does not offer the enrolment")
	}
	m := csrfValue.FindStringSubmatch(got.body)
	if m == nil {
		t.Fatal("the enrolment page carries no CSRF field")
	}
	// The sign-in form's CSRF cookie, which the page's field repeats.
	e := &enrolStep{f: f, pending: got.pendingCookie, csrfField: m[1], csrfCookie: m[1]}

	if rec := e.post(t, "/login/enrol-mfa/start", url.Values{}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `class="secret"`) {
		t.Fatalf("starting the enrolment gave %d without a secret", rec.Code)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	enrolment, err := store.LoadTOTPEnrolment(ctx, tx, f.userID, f.srv.cfg.Root)
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatalf("no enrolment after starting one: %v", err)
	}

	if rec := e.post(t, "/login/enrol-mfa", url.Values{"code": {"000000"}}); cookieFrom(rec, SessionCookieName) != nil ||
		!strings.Contains(rec.Body.String(), `action="/login/enrol-mfa"`) {
		t.Fatalf("a wrong code gave %d and did not ask again", rec.Code)
	}
	code := mfa.Code(enrolment.Secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.DefaultDigits)
	rec := e.post(t, "/login/enrol-mfa", url.Values{"code": {code}})
	if !strings.Contains(rec.Body.String(), `action="/login/enrol-mfa/continue"`) {
		t.Fatalf("a right code gave %d without the recovery codes and the way on", rec.Code)
	}
	if has, err := store.HasSecondFactor(ctx, f.pool, f.userID); err != nil || !has {
		t.Fatalf("after enrolling, the account has a factor: %v (%v)", has, err)
	}

	return e, e.post(t, "/login/enrol-mfa/continue", url.Values{}), enrolment.Secret
}

func enrolFlowFixture(t *testing.T, doc string) *signInFixture {
	t.Helper()
	f := newSignInFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	f.applyFlow(t, doc)
	return f
}

func sessionAMR(t *testing.T, f *signInFixture, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	session := cookieFrom(rec, SessionCookieName)
	if session == nil {
		t.Fatalf("no session: %d", rec.Code)
	}
	var amr []string
	if err := f.pool.QueryRow(context.Background(), `SELECT amr FROM core.sessions WHERE cookie_hash = $1`,
		store.HashToken(session.Value)).Scan(&amr); err != nil {
		t.Fatal(err)
	}
	return amr
}

// Enrolled, then asked for the new factor at once by the flow's mfa stage,
// and multi-factor once its code is given; the next sign-in is challenged,
// not enrolled again.
func TestAFlowThatRequiresAFactorEnrolsOne(t *testing.T) {
	f := enrolFlowFixture(t, enrolOrChallenge)
	e, rec, secret := enrolThrough(t, f)
	if cookieFrom(rec, SessionCookieName) != nil || !strings.Contains(rec.Body.String(), `action="/login/mfa"`) {
		t.Fatalf("with a factor now enrolled, the flow's mfa stage did not ask for it: %d", rec.Code)
	}
	// The next period's code: the one that confirmed the enrolment is spent.
	code := mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod)+1, mfa.DefaultDigits)
	rec = e.post(t, "/login/mfa", url.Values{"code": {code}})
	if amr := sessionAMR(t, f, rec); !strings.Contains(strings.Join(amr, " "), "mfa") {
		t.Errorf("password and the enrolled authenticator gave amr %q", amr)
	}

	// The next sign-in is challenged for the factor, not enrolled again.
	next := f.attempt(t, f.email, signInTestPassword)
	if next.signedIn() || strings.Contains(next.body, "/login/enrol-mfa") ||
		!strings.Contains(next.body, `action="/login/mfa"`) {
		t.Error("with a factor enrolled the next sign-in was not challenged for it")
	}
}

// With an unconditional mfa stage after enrolment, the password step leaves the
// enrolling to the walk. It refused before the walk ran, so a flow written to
// enrol everybody who had nothing turned every one of them away.
func TestAnUnconditionalMFAStageAfterEnrolmentEnrolsFirst(t *testing.T) {
	f := enrolFlowFixture(t, `
version: 1
flows:
  - name: enrol-then-ask
    on: authentication
    stages:
      - password
      - {stage: enrol_mfa, when: not user_has_second_factor}
      - mfa
      - session
    tests:
      - name: nothing enrolled
        given: {}
        expect: [password, enrol_mfa, mfa, session]
`)
	got := f.attempt(t, f.email, signInTestPassword)
	if !strings.Contains(got.body, `action="/login/enrol-mfa/start"`) {
		t.Fatalf("somebody with nothing enrolled was not offered the enrolment: %d %.120s",
			got.status, got.body)
	}
}

// Under a flow that only enrols, the sign-in goes on with what it proved: the
// password. Enrolling proves nothing about who holds it.
func TestEnrollingAFactorAddsNothingToTheSignIn(t *testing.T) {
	f := enrolFlowFixture(t, `
version: 1
flows:
  - name: enrol-only
    on: authentication
    stages:
      - password
      - {stage: enrol_mfa, when: not user_has_second_factor}
      - session
    tests:
      - name: nothing enrolled
        given: {}
        expect: [password, enrol_mfa, session]
`)
	_, rec, _ := enrolThrough(t, f)
	if amr := sessionAMR(t, f, rec); len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("the session's amr is %q; enrolling a factor proves nothing about who "+
			"holds the password, so it must stay pwd", amr)
	}
}

// The enrolment pages answer only a sign-in the enrol_mfa stage held. The code
// step's pending sign-in is for somebody WITH a factor; taken here, a password
// alone would replace their authenticator with one of the caller's.
func TestTheEnrolmentPagesRefuseTheCodeStepsPendingSignIn(t *testing.T) {
	f, _ := enrolFixture(t)
	original := giveTOTP(t, f)
	ctx := context.Background()
	f.applyFlow(t, enrolOrChallenge)

	got := f.attempt(t, f.email, signInTestPassword)
	if got.pendingCookie == "" || !strings.Contains(got.body, `action="/login/mfa"`) {
		t.Fatal("a password for an account with a factor was not sent to the code step")
	}
	m := csrfValue.FindStringSubmatch(got.body)
	e := &enrolStep{f: f, pending: got.pendingCookie, csrfField: m[1], csrfCookie: m[1]}
	for _, path := range []string{"/login/enrol-mfa/start", "/login/enrol-mfa", "/login/enrol-mfa/continue"} {
		rec := e.post(t, path, url.Values{"code": {"000000"}})
		if cookieFrom(rec, SessionCookieName) != nil || rec.Code != http.StatusSeeOther ||
			rec.Header().Get("Location") != "/login" {
			t.Errorf("%s took the code step's pending sign-in: %d %q", path, rec.Code,
				rec.Header().Get("Location"))
		}
	}
	// And a sign-in the stage did hold, for somebody who has gained a factor
	// since: they are let on to the challenge, never to an enrolment.
	w := httptest.NewRecorder()
	if err := f.srv.setPendingCookieFor(w, f.userID, f.orgID, []string{"pwd"}, "", "enrol_mfa"); err != nil {
		t.Fatal(err)
	}
	e.pending = cookieFrom(w, PendingCookieName).Value
	if rec := e.post(t, "/login/enrol-mfa/start", url.Values{}); strings.Contains(rec.Body.String(), `class="secret"`) ||
		!strings.Contains(rec.Body.String(), `action="/login/mfa"`) {
		t.Errorf("an enrolment began for somebody with a factor: %d", rec.Code)
	}
	var started int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.totp_enrolments WHERE user_id = $1::uuid`,
		f.userID).Scan(&started); err != nil {
		t.Fatal(err)
	}
	tx, _ := f.pool.Begin(ctx)
	still, err := store.LoadTOTP(ctx, tx, f.userID, f.srv.cfg.Root)
	_ = tx.Rollback(ctx)
	if started != 0 || err != nil || string(still.Secret) != string(original) {
		t.Fatal("the code step's pending sign-in started or changed an enrolment")
	}
}
