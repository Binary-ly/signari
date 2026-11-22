package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// An organisation that keeps only a keyed hash of each SMS number (4.28): no
// number is stored, the person types theirs on the code page to be texted a
// code, a wrong one is told the same as the right one, and a number already
// stored is hashed at the person's next sign-in.

type hashedSMS struct {
	f      *signInFixture
	cookie string
	texter *captureTexter
}

func newHashedSMS(t *testing.T) *hashedSMS {
	t.Helper()
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	texter := &captureTexter{}
	f.srv.texter = texter
	f.srv.SetSMSPolicy(smsPolicy(t, map[string]string{"SIGNARI_SMS_ALLOWED_PREFIXES": "+44"}))
	return &hashedSMS{f: f, cookie: cookie, texter: texter}
}

func (h *hashedSMS) setHashed(t *testing.T, hashed bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := h.f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetSMSNumbers(ctx, tx, h.f.orgID, hashed); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// codeTo is the last code texted to number, and how many texts there were.
func (h *hashedSMS) codeTo(number string) (string, int) {
	msgs := h.texter.messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].To == number {
			if c := sixDigits.FindString(msgs[i].Body); c != "" {
				return c, len(msgs)
			}
		}
	}
	return "", len(msgs)
}

func (h *hashedSMS) clearResend(t *testing.T) {
	t.Helper()
	if _, err := h.f.pool.Exec(context.Background(), `UPDATE core.sms_otp_credentials
		SET last_sent_at = now() - interval '2 minutes' WHERE user_id = $1::uuid`, h.f.userID); err != nil {
		t.Fatal(err)
	}
}

func (h *hashedSMS) stored(t *testing.T) (number, pending *string, hashed, pendingHashed bool) {
	t.Helper()
	if err := h.f.pool.QueryRow(context.Background(), `SELECT number, pending_number,
		number_hash IS NOT NULL, pending_hash IS NOT NULL FROM core.sms_otp_credentials
		WHERE user_id = $1::uuid`, h.f.userID).Scan(&number, &pending, &hashed, &pendingHashed); err != nil {
		t.Fatal(err)
	}
	return
}

// postNumber submits a number on the code page's form.
func (h *hashedSMS) postNumber(t *testing.T, page *httptest.ResponseRecorder, number string) *httptest.ResponseRecorder {
	t.Helper()
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("the code page carries no CSRF field: %d", page.Code)
	}
	form := url.Values{"number": {number}, csrfFormField: {m[1]}}
	r := httptest.NewRequest(http.MethodPost, "/login/mfa/sms", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookieFrom(page, PendingCookieName))
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	h.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func (h *hashedSMS) amr(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var amr []string
	if err := h.f.pool.QueryRow(context.Background(), `SELECT amr FROM core.sessions WHERE cookie_hash = $1`,
		store.HashToken(cookieFrom(rec, SessionCookieName).Value)).Scan(&amr); err != nil {
		t.Fatal(err)
	}
	return amr
}

func smsTestNumber(offset int64) string {
	return fmt.Sprintf("+447%09d", (time.Now().UnixNano()+offset)%1_000_000_000)
}

func TestAHashedNumberIsTypedAndNeverKept(t *testing.T) {
	h := newHashedSMS(t)
	h.setHashed(t, true)
	number, other := smsTestNumber(0), smsTestNumber(7)

	h.f.formPost(t, h.cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"send"}, "number": {number}})
	if n, p, _, ph := h.stored(t); n != nil || p != nil || !ph {
		t.Fatalf("enrolling stored number %v, pending %v, pending hash %v", n, p, ph)
	}
	code, _ := h.codeTo(number)
	if code == "" {
		t.Fatal("no enrolment code was texted to the number typed")
	}
	page := h.f.formPost(t, h.cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"verify"}, "code": {code}})
	if n, p, hashed, ph := h.stored(t); n != nil || p != nil || !hashed || ph {
		t.Fatalf("after proving: number %v, pending %v, hash %v, pending hash %v", n, p, hashed, ph)
	}
	if strings.Contains(page.Body.String(), number[len(number)-2:]+"<") {
		t.Error("the enrolment page shows the number it does not keep")
	}

	h.clearResend(t)
	_, before := h.codeTo(number)
	page = h.f.signInWith(t, "")
	if _, after := h.codeTo(number); after != before {
		t.Fatal("a number kept only as a hash was texted without being typed")
	}
	if !strings.Contains(page.Body.String(), `action="/login/mfa/sms"`) {
		t.Fatal("the code page offers no place to type the number")
	}
	wrong := h.postNumber(t, page, other)
	right := h.postNumber(t, page, number)
	if c, _ := h.codeTo(other); c != "" {
		t.Error("another number was texted a code")
	}
	strip := func(s string) string { return regexp.MustCompile(`value="[^"]*"`).ReplaceAllString(s, "") }
	if strip(wrong.Body.String()) != strip(right.Body.String()) {
		t.Error("the page says whether the number typed is the one on the account")
	}
	signin, _ := h.codeTo(number)
	if signin == "" || signin == code {
		t.Fatal("the number typed was not texted a sign-in code")
	}
	rec := h.f.postCode(t, page, signin)
	if !sessionSet(rec) {
		t.Fatalf("the code texted to the typed number did not sign in: %d", rec.Code)
	}
	if amr := h.amr(t, rec); !slices.Contains(amr, "sms") {
		t.Errorf("amr %v", amr)
	}
}

func TestAStoredNumberIsHashedAtTheNextSignIn(t *testing.T) {
	h := newHashedSMS(t)
	number := smsTestNumber(13)
	h.f.formPost(t, h.cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"send"}, "number": {number}})
	code, _ := h.codeTo(number)
	h.f.formPost(t, h.cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"verify"}, "code": {code}})
	if n, _, hashed, _ := h.stored(t); n == nil || *n != number || hashed {
		t.Fatalf("a stored-mode enrolment kept %v, hash %v", n, hashed)
	}

	h.setHashed(t, true)
	h.clearResend(t)
	page := h.f.signInWith(t, "")
	signin, _ := h.codeTo(number)
	if signin == "" || signin == code {
		t.Fatal("the stored number was not texted at the sign-in that hashes it")
	}
	if n, _, hashed, _ := h.stored(t); n != nil || !hashed {
		t.Fatalf("after the sign-in: number %v, hash %v", n, hashed)
	}
	if !sessionSet(h.f.postCode(t, page, signin)) {
		t.Fatal("the code did not sign in")
	}
	h.clearResend(t)
	_, before := h.codeTo(number)
	page = h.f.signInWith(t, "")
	if _, after := h.codeTo(number); after != before || !strings.Contains(page.Body.String(), `action="/login/mfa/sms"`) {
		t.Fatal("after hashing, the number was texted untyped or the form not offered")
	}
}

// With a delegated service, a number kept only as a hash is checked by the
// service's id alone.
func TestAHashedNumberIsCheckedByTheServicesID(t *testing.T) {
	h := newHashedSMS(t)
	h.setHashed(t, true)
	v := &fakeVerifier{}
	h.f.srv.texter = nil
	h.f.srv.SetSMSVerifier(v)
	number := smsTestNumber(29)

	h.f.formPost(t, h.cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"send"}, "number": {number}})
	h.f.formPost(t, h.cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"verify"}, "code": {v.code(number)}})
	if v.lastTo != "" || v.lastID != "v-"+number {
		t.Fatalf("the enrolment check was given number %q, id %q", v.lastTo, v.lastID)
	}
	if n, _, hashed, _ := h.stored(t); n != nil || !hashed {
		t.Fatalf("number %v, hash %v", n, hashed)
	}
	h.clearResend(t)
	page := h.f.signInWith(t, "")
	h.postNumber(t, page, number)
	rec := h.f.postCode(t, page, v.code(number))
	if !sessionSet(rec) || v.lastTo != "" {
		t.Fatalf("signed in %v; the check was given number %q", sessionSet(rec), v.lastTo)
	}
}
