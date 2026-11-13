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

// Each sign-in is sent a code of its own, the minute between codes being a
// resend's within one sign-in; what stops somebody holding the password from
// filling the person's inbox is emailCodesPerHour.
func TestSignInCodesToOneInboxAreCappedEachHour(t *testing.T) {
	f := newSignInFixture(t)
	giveEmailFactor(t, f)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	key := "mfa:email:user:hour:" + f.userID
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.rate_limits WHERE bucket_key = $1`, key)
	})

	for i := 0; i < emailCodesPerHour+3; i++ {
		f.srv.sendEmailOTPIfEnrolled(context.Background(), f.userID, []byte(newAttempt()))
	}
	if n := len(mailer.messages()); n != emailCodesPerHour {
		t.Fatalf("%d sign-ins in a row were mailed %d codes, want %d", emailCodesPerHour+3, n, emailCodesPerHour)
	}
}

// ASVS 5.0.0 V6.6.2 (specs/asvs-5.0.0.txt:2528-2530): an out-of-band code is
// "bound to the original authentication request for which [it was] generated"
// and "not usable for a previous or subsequent one". Ours were bound to the
// person: a code sent for one sign-in finished another, and a bind or a desktop
// sign-in, which send none, took one sent for something else.

// The code step: a code sent for one sign-in does not finish another of the
// same person's, earlier or later, and is still there for its own.
func TestASignInCodeFinishesOnlyTheSignInItWasSentFor(t *testing.T) {
	for _, c := range []struct {
		factor string
		give   func(t *testing.T, f *signInFixture)
		issue  issuer
	}{
		{factorEmailOTP, giveEmailFactor, issueEmailOTP},
		{factorSMSOTP, giveSMSFactor, issueSMS},
	} {
		t.Run(c.factor, func(t *testing.T) {
			f := newSignInFixture(t)
			clearSecondFactorBucket(t, f)
			c.give(t, f)
			earlier, later := newMFAStep(t, f), newMFAStep(t, f)

			code := issueCode(t, f, c.issue, earlier.attempt)
			if rec := later.submit(code); sessionSet(rec) {
				t.Fatal("a code sent for one sign-in finished a later one")
			}
			if rec := earlier.submit(code); !sessionSet(rec) {
				t.Fatalf("the code did not finish the sign-in it was sent for (status %d)", rec.Code)
			}

			// And the other way: a later sign-in's code is not the earlier one's.
			first, second := newMFAStep(t, f), newMFAStep(t, f)
			code = issueCode(t, f, c.issue, second.attempt)
			if rec := first.submit(code); sessionSet(rec) {
				t.Fatal("a code sent for a later sign-in finished an earlier one")
			}
			if rec := second.submit(code); !sessionSet(rec) {
				t.Fatalf("the later sign-in's own code was refused (status %d)", rec.Code)
			}
		})
	}
}

// A bind or RADIUS request sends no code, so a texted code that arrives with one
// was sent for some sign-in. It was taken until November 2026, and spent: the
// sign-in it was sent for then failed too.
func TestABindTakesNoCodeSentForASignIn(t *testing.T) {
	f := newSignInFixture(t)
	clearSecondFactorBucket(t, f)
	giveSMSFactor(t, f)
	step := newMFAStep(t, f)
	code := issueCode(t, f, issueSMS, step.attempt)

	ok, err := f.srv.BindCodeOK(context.Background(), f.orgID, f.userID, code)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a bind was let in on a code texted for a sign-in")
	}
	if rec := step.submit(code); !sessionSet(rec) {
		t.Fatalf("the bind spent the sign-in's code (status %d)", rec.Code)
	}
}

// The desktop sign-in sends no code either.
func TestTheDesktopSignInTakesNoCodeSentForASignIn(t *testing.T) {
	for _, c := range []struct {
		factor string
		give   func(t *testing.T, f *signInFixture)
		issue  issuer
	}{
		{factorEmailOTP, giveEmailFactor, issueEmailOTP},
		{factorSMSOTP, giveSMSFactor, issueSMS},
	} {
		t.Run(c.factor, func(t *testing.T) {
			f := newSignInFixture(t)
			clearSecondFactorBucket(t, f)
			c.give(t, f)
			step := newMFAStep(t, f)
			code := issueCode(t, f, c.issue, step.attempt)

			ctx := context.Background()
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			res, err := f.srv.verifySecondFactor(ctx, tx, f.userID, code)
			_ = tx.Rollback(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if res.OK {
				t.Fatal("the desktop sign-in took a code sent for a browser's sign-in")
			}
		})
	}
}

// The emailed sign-in code: another browser asking for the same name while the
// pace holds is sent nothing, and the code the first browser asked for is not
// its to use. The browser that asked, asking again, keeps its code.
func TestAnEmailedSignInCodeIsOnlyForTheBrowserThatAsked(t *testing.T) {
	f := emailFixture(t)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, f.userID)
	})
	f.applyFlow(t, emailOrPasswordFlow)
	clearSignInBucket(t, f.pool)

	asked := f.emailStart(t, f.email)
	notices := f.signInCodeNotices(t)
	if len(notices) != 1 {
		t.Fatalf("%d codes queued, want 1", len(notices))
	}
	if err := f.srv.DeliverAccountNotice(ctx, notices[0]); err != nil {
		t.Fatal(err)
	}
	code := sixDigits.FindString(mailer.messages()[0].Body)

	other := f.emailStart(t, f.email) // within the minute: paced, nothing sent
	if n := len(f.signInCodeNotices(t)); n != 1 {
		t.Fatalf("the paced request queued another code (%d)", n)
	}
	if rec := f.emailVerify(t, other, code); cookieFrom(rec, SessionCookieName) != nil {
		t.Fatal("a code another browser asked for signed this one in")
	}

	// The browser that asked, asking again while paced, keeps its attempt.
	again := f.emailStartHolding(t, f.email, cookieFrom(asked, EmailCodeCookieName))
	if rec := f.emailVerify(t, again, code); cookieFrom(rec, SessionCookieName) == nil {
		t.Fatalf("asking again in the same browser lost the code it was sent (status %d): %s",
			rec.Code, truncate(rec.Body.String(), 200))
	}
}

// emailStartHolding is emailStart from a browser already holding held, the code
// page's cookie from an earlier request.
func (f *signInFixture) emailStartHolding(t *testing.T, identifier string, held *http.Cookie) *httptest.ResponseRecorder {
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
	r.AddCookie(held)
	r.RemoteAddr = uniqueTestAddr(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}
