package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// The email second factor through the real routes: what the send step may
// change, and who is told when the factor moves.

// formSession is a signed-in browser that can post the account forms.
type formSession struct {
	f          *signInFixture
	cookie     string
	csrfField  string
	csrfCookie string
}

func newFormSession(t *testing.T, f *signInFixture, cookie, page string) *formSession {
	t.Helper()
	rec := accountGET(f, cookie, page)
	m := csrfValue.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("%s carries no CSRF field", page)
	}
	fs := &formSession{f: f, cookie: cookie, csrfField: m[1]}
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			fs.csrfCookie = c.Value
		}
	}
	return fs
}

func (fs *formSession) post(path string, form url.Values) *httptest.ResponseRecorder {
	form.Set(csrfFormField, fs.csrfField)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: fs.cookie})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: fs.csrfCookie})
	rec := httptest.NewRecorder()
	fs.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// codeSentTo returns the last code mailed to address.
func codeSentTo(t *testing.T, m *captureMailer, address string) string {
	t.Helper()
	msgs := m.messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].To == address {
			if c := sixDigits.FindString(msgs[i].Body); c != "" {
				return c
			}
		}
	}
	t.Fatalf("no code was mailed to %s", address)
	return ""
}

func emailFactorAddress(t *testing.T, f *signInFixture) (address string, verified bool) {
	t.Helper()
	var at *string
	if err := f.pool.QueryRow(context.Background(), `
		SELECT address, verified_at::text FROM core.email_otp_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&address, &at); err != nil {
		t.Fatalf("reading the email factor: %v", err)
	}
	return address, at != nil
}

func clearEmailResendFloor(t *testing.T, f *signInFixture) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.email_otp_credentials SET last_sent_at = NULL WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
}

func TestTheEmailSendStepCannotMoveTheFactorAndMovingItTellsTheOldAddress(t *testing.T) {
	f, cookie := enrolFixture(t)
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	fs := newFormSession(t, f, cookie, "/account/mfa/email")

	// Enrol the owner's address properly.
	if rec := fs.post("/account/mfa/email", url.Values{"address": {"owner@example.test"}}); rec.Code != http.StatusOK {
		t.Fatalf("sending the first enrolment code gave %d", rec.Code)
	}
	if rec := fs.post("/account/mfa/email", url.Values{
		"step": {"verify"}, "code": {codeSentTo(t, mailer, "owner@example.test")},
	}); rec.Code != http.StatusOK {
		t.Fatalf("verifying the first enrolment code gave %d", rec.Code)
	}
	if addr, ok := emailFactorAddress(t, f); addr != "owner@example.test" || !ok {
		t.Fatalf("after enrolment the factor is %q (verified=%v)", addr, ok)
	}

	// One POST to the send step, never followed by a code: the factor stays put.
	clearEmailResendFloor(t, f)
	if rec := fs.post("/account/mfa/email", url.Values{"address": {"intruder@example.test"}}); rec.Code != http.StatusOK {
		t.Fatalf("the second send step gave %d", rec.Code)
	}
	if addr, ok := emailFactorAddress(t, f); addr != "owner@example.test" || !ok {
		t.Fatalf("one POST to the send step moved the email factor to %q (verified=%v); "+
			"anybody holding the session could take the account's sign-in codes", addr, ok)
	}
	if has, _ := store.HasSecondFactor(context.Background(), f.pool, f.userID); !has {
		t.Fatal("an abandoned re-enrolment removed the second factor")
	}

	// Proving a new address does move it, and the owner's old address hears.
	clearEmailResendFloor(t, f)
	if rec := fs.post("/account/mfa/email", url.Values{"address": {"new@example.test"}}); rec.Code != http.StatusOK {
		t.Fatalf("sending the re-enrolment code gave %d", rec.Code)
	}
	before := len(mailer.messages())
	if rec := fs.post("/account/mfa/email", url.Values{
		"step": {"verify"}, "code": {codeSentTo(t, mailer, "new@example.test")},
	}); rec.Code != http.StatusOK {
		t.Fatalf("verifying the re-enrolment code gave %d", rec.Code)
	}
	if addr, ok := emailFactorAddress(t, f); addr != "new@example.test" || !ok {
		t.Fatalf("a proved re-enrolment left the factor at %q (verified=%v)", addr, ok)
	}
	warned := false
	for _, m := range mailer.messages()[before:] {
		if m.To == "owner@example.test" && strings.Contains(m.Subject, "no longer") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("moving the email factor did not tell the address that stops receiving codes")
	}
}
