package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// An emailed code as the first factor (5.16).

const emailOrPasswordFlow = `
version: 1
flows:
  - name: email-or-password
    on: authentication
    stages:
      - one_of:
          - {stage: email_otp, when: proved_by_email}
          - {stage: password}
      - session
    tests:
      - {name: by email, given: {proved_by_email: true}, expect: [email_otp, session]}
      - {name: by password, given: {}, expect: [password, session]}
`

// emailStart submits the sign-in form's "Email me a code" for identifier.
func (f *signInFixture) emailStart(t *testing.T, identifier string) *httptest.ResponseRecorder {
	t.Helper()
	authz := "client_id=" + f.clientID + "&response_type=code"
	get := httptest.NewRecorder()
	f.srv.handleLoginGet(get, httptest.NewRequest(http.MethodGet, "/login?authz="+url.QueryEscape(authz), nil))
	m := csrfValue.FindStringSubmatch(get.Body.String())
	if m == nil {
		t.Fatal("no CSRF token on the sign-in page")
	}
	form := url.Values{"username": {identifier}, "authz": {authz}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login/email", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieFrom(get, CSRFCookieName))
	r.RemoteAddr = uniqueTestAddr(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func (f *signInFixture) emailVerify(t *testing.T, page *httptest.ResponseRecorder, code string) *httptest.ResponseRecorder {
	t.Helper()
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("no CSRF token on the code page")
	}
	form := url.Values{"code": {code}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login/email/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieFrom(page, EmailCodeCookieName))
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	r.RemoteAddr = uniqueTestAddr(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// signInCodeNotices are the queued sign-in codes for a person.
func (f *signInFixture) signInCodeNotices(t *testing.T) []store.AccountNotice {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT payload FROM core.outbox
		WHERE topic = $1 AND payload->>'user_id' = $2 AND payload->>'notice' = $3 ORDER BY id`,
		store.AccountNoticeTopic, f.userID, store.NoticeSignInCode)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []store.AccountNotice
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var n store.AccountNotice
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func TestAnEmailedCodeSignsInWhereTheFlowTakesIt(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, f.userID)
	})

	if strings.Contains(loginPage(f), `formaction="/login/email"`) {
		t.Fatal("the sign-in page offers an emailed code where the flow does not take one")
	}
	if page := f.emailStart(t, f.email); !strings.Contains(page.Body.String(), "not available here") {
		t.Fatalf("an emailed sign-in started where the flow does not take one: %s", truncate(page.Body.String(), 300))
	}

	f.applyFlow(t, emailOrPasswordFlow)
	if !strings.Contains(loginPage(f), `formaction="/login/email"`) {
		t.Fatal("the sign-in page does not offer the emailed code the flow takes")
	}
	clearSignInBucket(t, f.pool)
	page := f.emailStart(t, f.email)
	if cookieFrom(page, EmailCodeCookieName) == nil || cookieFrom(page, PendingCookieName) != nil {
		t.Fatal("the code page must hold its own token and no pending sign-in")
	}
	notices := f.signInCodeNotices(t)
	if len(notices) != 1 || len(mailer.messages()) != 0 {
		t.Fatalf("queued %d code(s), sent %d mail(s) while the page waited; want 1 queued and none sent",
			len(notices), len(mailer.messages()))
	}
	if err := f.srv.DeliverAccountNotice(ctx, notices[0]); err != nil {
		t.Fatal(err)
	}
	msgs := mailer.messages()
	if len(msgs) != 1 || msgs[0].To != f.email {
		t.Fatalf("delivering sent %+v", msgs)
	}
	// Its own words: the second factor's mail, which an emailed sign-in once
	// shared keys with, tells the reader that somebody has their password.
	if !strings.Contains(msgs[0].Body, "Your code to sign in is") || strings.Contains(msgs[0].Body, "password") {
		t.Errorf("the sign-in code went out under another mail's text: %q", msgs[0].Body)
	}
	code := sixDigits.FindString(msgs[0].Body)
	if code == "" {
		t.Fatalf("no code in the mail: %q", msgs[0].Body)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if rec := f.emailVerify(t, page, wrong); cookieFrom(rec, SessionCookieName) != nil {
		t.Fatal("a wrong code signed in")
	}
	rec := f.emailVerify(t, page, code)
	c := cookieFrom(rec, SessionCookieName)
	if c == nil || c.Value == "" {
		t.Fatalf("the right code did not sign in: %d %s", rec.Code, truncate(rec.Body.String(), 300))
	}
	sid, _, err := store.ResolveSessionCookie(ctx, f.pool, store.HashToken(c.Value))
	if err != nil || sid == "" {
		t.Fatal(err)
	}
	var amr []string
	var acr string
	if err := f.pool.QueryRow(ctx, `SELECT amr, acr FROM core.sessions WHERE sid = $1`, sid).Scan(&amr, &acr); err != nil {
		t.Fatal(err)
	}
	if len(amr) != 1 || amr[0] != oauth.AMROTP || acr != oauth.ACRSingleFactor {
		t.Errorf("the session says amr %v acr %q, want [otp] and single-factor", amr, acr)
	}
}

// The offer is not the guard: a code asked for while the flow took one, typed
// after the operator stopped taking it, is refused by the flow itself.
func TestAnEmailedCodeIsRefusedOnceTheFlowStopsTakingIt(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, f.userID)
	})
	f.applyFlow(t, emailOrPasswordFlow)
	clearSignInBucket(t, f.pool)
	page := f.emailStart(t, f.email)
	notices := f.signInCodeNotices(t)
	if len(notices) != 1 {
		t.Fatalf("queued %d code(s), want 1", len(notices))
	}
	if err := f.srv.DeliverAccountNotice(ctx, notices[0]); err != nil {
		t.Fatal(err)
	}
	code := sixDigits.FindString(mailer.messages()[0].Body)

	f.applyFlow(t, `
version: 1
flows:
  - name: password-only
    on: authentication
    stages: [password, session]
    tests:
      - {name: by password, given: {}, expect: [password, session]}
`)
	if rec := f.emailVerify(t, page, code); cookieFrom(rec, SessionCookieName) != nil {
		t.Fatal("an emailed code signed in under a flow that takes only a password")
	}
}

// Somebody who signs in only by emailed code can delete their own account under
// the built-in unenrolment flow, as somebody signed in any other way can.
func TestAnEmailedCodeSignInMayDeleteTheAccount(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, f.userID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.subject_keys WHERE subject_id = $1::uuid`, f.userID)
	})
	f.applyFlow(t, emailOrPasswordFlow) // names no unenrolment flow, so the built-in one decides
	clearSignInBucket(t, f.pool)
	page := f.emailStart(t, f.email)
	notices := f.signInCodeNotices(t)
	if len(notices) != 1 {
		t.Fatalf("queued %d code(s), want 1", len(notices))
	}
	if err := f.srv.DeliverAccountNotice(ctx, notices[0]); err != nil {
		t.Fatal(err)
	}
	signedIn := cookieFrom(f.emailVerify(t, page, sixDigits.FindString(mailer.messages()[0].Body)), SessionCookieName)
	if signedIn == nil {
		t.Fatal("the emailed code did not sign in")
	}
	if p := accountGET(f, signedIn.Value, "/account/delete").Body.String(); strings.Contains(p, "does not let accounts be deleted") {
		t.Fatalf("deletion refused to an emailed-code sign-in: %s", truncate(p, 300))
	}
	f.formPost(t, signedIn.Value, "/account/delete", "/account/delete", url.Values{"confirm": {f.email}})
	if f.accountRows(t) != 0 {
		t.Error("the account was not deleted")
	}
}

// emailSignIn asks for a code, delivers it, and types it, returning the answer.
func (f *signInFixture) emailSignIn(t *testing.T, mailer *captureMailer) *httptest.ResponseRecorder {
	t.Helper()
	ctx := context.Background()
	page := f.emailStart(t, f.email)
	notices := f.signInCodeNotices(t)
	if len(notices) == 0 {
		t.Fatal("no sign-in code queued")
	}
	before := len(mailer.messages())
	if err := f.srv.DeliverAccountNotice(ctx, notices[len(notices)-1]); err != nil {
		t.Fatal(err)
	}
	msgs := mailer.messages()
	if len(msgs) != before+1 {
		t.Fatalf("delivering sent %d mail(s)", len(msgs)-before)
	}
	return f.emailVerify(t, page, sixDigits.FindString(msgs[len(msgs)-1].Body))
}

const emailThenSecondFactorFlow = `
version: 1
flows:
  - name: email-then-second-factor
    on: authentication
    stages:
      - one_of:
          - {stage: email_otp, when: proved_by_email}
          - {stage: password}
      - {stage: mfa, when: user_has_second_factor}
      - session
    tests:
      - {name: by email with a factor, given: {proved_by_email: true, user_has_second_factor: true}, expect: [email_otp, mfa, session]}
      - {name: by email without one, given: {proved_by_email: true}, expect: [email_otp, session]}
      - {name: by password, given: {}, expect: [password, session]}
`

// The mailbox is one factor however many codes go to it. After an emailed code,
// an email second factor is neither counted, sent nor accepted: counted, a
// person whose only second factor is email was sent a second code to the same
// mailbox and given a session recorded as multi-factor.
func TestTheMailboxIsNotBothFactors(t *testing.T) {
	sessionAMR := func(t *testing.T, f *signInFixture, rec *httptest.ResponseRecorder) []string {
		t.Helper()
		c := cookieFrom(rec, SessionCookieName)
		if c == nil || c.Value == "" {
			t.Fatalf("no session: %d %s", rec.Code, truncate(rec.Body.String(), 300))
		}
		sid, _, err := store.ResolveSessionCookie(context.Background(), f.pool, store.HashToken(c.Value))
		if err != nil || sid == "" {
			t.Fatal(err)
		}
		var amr []string
		if err := f.pool.QueryRow(context.Background(), `SELECT amr FROM core.sessions WHERE sid = $1`, sid).Scan(&amr); err != nil {
			t.Fatal(err)
		}
		return amr
	}
	setup := func(t *testing.T) (*signInFixture, *captureMailer) {
		f := newSignInFixture(t)
		root, err := keys.NewRootKey("test", make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		f.srv.cfg.Root = root // an authenticator's secret is sealed under it
		mailer := &captureMailer{}
		f.srv.mailer = mailer
		t.Cleanup(func() {
			_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
				store.AccountNoticeTopic, f.userID)
		})
		f.applyFlow(t, emailThenSecondFactorFlow)
		clearSignInBucket(t, f.pool)
		giveEmailFactor(t, f)
		// Proving the address just sent a code, and the resend floor would hide a
		// second-factor code the challenge sent now.
		if _, err := f.pool.Exec(context.Background(),
			`UPDATE core.email_otp_credentials SET last_sent_at = NULL WHERE user_id = $1::uuid`, f.userID); err != nil {
			t.Fatal(err)
		}
		return f, mailer
	}

	t.Run("email is the only second factor", func(t *testing.T) {
		f, mailer := setup(t)
		rec := f.emailSignIn(t, mailer)
		if n := len(mailer.messages()); n != 1 {
			t.Errorf("%d mails, want only the sign-in code: a second went to the same mailbox", n)
		}
		if amr := sessionAMR(t, f, rec); oauth.ACRFromAMR(amr) != oauth.ACRSingleFactor {
			t.Errorf("the session says amr %v, which is %s; one mailbox is one factor", amr, oauth.ACRFromAMR(amr))
		}
	})

	t.Run("email and an authenticator", func(t *testing.T) {
		f, mailer := setup(t)
		secret := giveTOTP(t, f)
		page := f.emailSignIn(t, mailer)
		if cookieFrom(page, PendingCookieName) == nil || cookieFrom(page, SessionCookieName) != nil {
			t.Fatalf("the flow's mfa stage did not ask for the authenticator: %d", page.Code)
		}
		if n := len(mailer.messages()); n != 1 {
			t.Errorf("%d mails, want only the sign-in code", n)
		}
		// A second-factor email code in the mailbox anyway -- from a password
		// sign-in, say -- is still the mailbox.
		ctx := context.Background()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE core.email_otp_credentials SET last_sent_at = NULL WHERE user_id = $1::uuid`, f.userID); err != nil {
			t.Fatal(err)
		}
		code, _, err := store.IssueEmailOTP(ctx, tx, f.userID)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if rec := f.postCode(t, page, code); cookieFrom(rec, SessionCookieName) != nil {
			t.Fatal("an email code was taken as the second factor after an emailed sign-in")
		}
		amr := sessionAMR(t, f, f.answerCode(t, page, secret, 0, false))
		if oauth.ACRFromAMR(amr) != oauth.ACRMultiFactor || primaryProof(amr) != flow.StageEmailOTP {
			t.Errorf("the mailbox and an authenticator gave amr %v", amr)
		}
	})
}

// The page is the same for a name nobody has, and nothing is queued.
func TestAnEmailedCodeForNobodyLooksTheSameAndSendsNothing(t *testing.T) {
	f := newSignInFixture(t)
	f.applyFlow(t, emailOrPasswordFlow)
	clearSignInBucket(t, f.pool)
	page := f.emailStart(t, "nobody-"+f.email)
	if !strings.Contains(page.Body.String(), "If that is the name of an account here") ||
		cookieFrom(page, EmailCodeCookieName) == nil {
		t.Fatalf("a name nobody has got a different page: %s", truncate(page.Body.String(), 300))
	}
	if n := len(f.signInCodeNotices(t)); n != 0 {
		t.Errorf("%d code(s) queued for the fixture's person when somebody else's name was asked for", n)
	}
}

// The code page's token is not a pending sign-in: the second-factor page
// refuses it, or a second factor alone would sign in.
func TestTheEmailedCodesTokenIsNotAPendingSignIn(t *testing.T) {
	f := newSignInFixture(t)
	f.applyFlow(t, emailOrPasswordFlow)
	clearSignInBucket(t, f.pool)
	page := f.emailStart(t, f.email)
	held := cookieFrom(page, EmailCodeCookieName)
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if held == nil || m == nil {
		t.Fatal("no code page")
	}
	form := url.Values{"code": {"123456"}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: PendingCookieName, Value: held.Value})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	// A wrong code on a pending sign-in is a 401 too, so the status does not
	// say which happened; the page does. Taken, the token reaches the code check
	// ("not valid"); refused, there is no sign-in to continue ("expired").
	if body := rec.Body.String(); !strings.Contains(body, "sign-in session expired") || strings.Contains(body, "not valid") {
		t.Errorf("the second-factor page took the code page's token: %d %s", rec.Code, truncate(body, 300))
	}
}

// amr and acr for each way in: an emailed code alone is the email route and one
// factor; the same `otp` after a password is a password sign-in with a second.
func TestTheEmailedCodesAMRAndACR(t *testing.T) {
	for _, c := range []struct {
		amr   []string
		route flow.StageName
		acr   string
	}{
		{[]string{oauth.AMROTP}, flow.StageEmailOTP, oauth.ACRSingleFactor},
		{[]string{oauth.AMRPassword}, flow.StagePassword, oauth.ACRSingleFactor},
		{[]string{oauth.AMRPassword, oauth.AMROTP, oauth.AMRMFA}, flow.StagePassword, oauth.ACRMultiFactor},
	} {
		if got := primaryProof(c.amr); got != c.route {
			t.Errorf("primaryProof(%v) = %q, want %q", c.amr, got, c.route)
		}
		if got := oauth.ACRFromAMR(c.amr); got != c.acr {
			t.Errorf("ACRFromAMR(%v) = %q, want %q", c.amr, got, c.acr)
		}
	}
}

// The sessions page says how each sign-in was made, and a code to the mailbox
// is not a password: that page is where somebody looks for a sign-in that was
// not theirs.
func TestASessionSignedInByEmailedCodeSaysSo(t *testing.T) {
	for amr, want := range map[string]string{
		oauth.AMROTP:      "sessions.how.emailcode",
		oauth.AMRPassword: "sessions.how.password",
	} {
		if got := describeAuth([]string{amr}); got != want {
			t.Errorf("describeAuth([%s]) = %q, want %q", amr, got, want)
		}
	}
	if got := describeAuth([]string{oauth.AMRPassword, oauth.AMROTP, oauth.AMRMFA}); got != "sessions.how.mfa" {
		t.Errorf("a password and an authenticator code read %q", got)
	}
}
