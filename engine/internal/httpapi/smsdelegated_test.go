package httpapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// fakeVerifier is a delegated verification service: it makes a code per
// number and approves only that one, once.
type fakeVerifier struct {
	mu     sync.Mutex
	codes  map[string]string
	starts int
	checks int
	down   bool
	next   int
}

func (v *fakeVerifier) Describe() string { return "fake" }

func (v *fakeVerifier) Start(_ context.Context, to string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.starts++
	v.next++
	if v.codes == nil {
		v.codes = map[string]string{}
	}
	v.codes[to] = fmt.Sprintf("%06d", 314159+v.next)
	return nil
}

func (v *fakeVerifier) Check(_ context.Context, to, code string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.checks++
	if v.down {
		return false, errors.New("the service is down")
	}
	if v.codes[to] != "" && v.codes[to] == code {
		delete(v.codes, to)
		return true, nil
	}
	return false, nil
}

func (v *fakeVerifier) code(to string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.codes[to]
}

// With a delegated verification service the engine never holds a code: the
// service makes, sends and checks it, through enrolment and sign-in, under the
// engine's own allowances, and an outage refuses the code without charging it
// (4.13).
func TestADelegatedServiceMakesSendsAndChecksEveryCode(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	v := &fakeVerifier{}
	f.srv.texter = nil
	f.srv.SetSMSVerifier(v)
	f.srv.SetSMSPolicy(smsPolicy(t, map[string]string{"SIGNARI_SMS_ALLOWED_PREFIXES": "+44"}))
	ctx := context.Background()
	number := fmt.Sprintf("+447%09d", time.Now().UnixNano()%1_000_000_000)
	row := func() (hash []byte, delegated bool, attempts, failed int) {
		t.Helper()
		if err := f.pool.QueryRow(ctx, `SELECT code_hash, code_delegated, attempts, failed_attempts
			FROM core.sms_otp_credentials WHERE user_id = $1::uuid`, f.userID).
			Scan(&hash, &delegated, &attempts, &failed); err != nil {
			t.Fatal(err)
		}
		return
	}

	f.formPost(t, cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"send"}, "number": {number}})
	sent := v.code(number)
	if v.starts != 1 || sent == "" {
		t.Fatalf("enrolment asked the service to start %d times", v.starts)
	}
	hash, delegated, _, _ := row()
	if sum := sha256.Sum256([]byte(sent)); !delegated || slices.Equal(hash, sum[:]) {
		t.Fatalf("the stored code is delegated=%v, and its hash is the service's code: %v", delegated,
			slices.Equal(hash, sum[:]))
	}
	f.formPost(t, cookie, "/account/mfa/sms", "/account/mfa/sms", url.Values{"step": {"verify"}, "code": {sent}})
	if c, err := store.LoadSMSOTP(ctx, f.pool, f.userID); err != nil || !c.Verified || c.Number != number {
		t.Fatalf("the service's code did not prove the number: %+v %v", c, err)
	}

	clearResend := func() {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `UPDATE core.sms_otp_credentials SET last_sent_at = now() - interval '2 minutes'
			WHERE user_id = $1::uuid`, f.userID); err != nil {
			t.Fatal(err)
		}
	}
	clearResend()
	page := f.signInWith(t, "")
	code := v.code(number)
	if v.starts != 2 || code == "" {
		t.Fatalf("the code page asked the service to start %d times in all", v.starts)
	}

	// Not a code the service could have sent: not asked, not counted.
	checks := v.checks
	f.postCode(t, page, "ABCD-EFGH-JKLM")
	if v.checks != checks {
		t.Error("a recovery-code-shaped submission was sent to the service")
	}
	// The service down: refused, not charged, and the code still good after.
	v.down = true
	if rec := f.postCode(t, page, code); sessionSet(rec) {
		t.Fatal("a code the service could not check signed in")
	}
	if _, _, attempts, failed := row(); attempts != 0 || failed != 0 {
		t.Errorf("an outage was charged: %d attempts, %d failures", attempts, failed)
	}
	v.down = false
	// Wrong: charged, as an engine-made code is.
	f.postCode(t, page, "000000")
	if _, _, attempts, failed := row(); attempts != 1 || failed != 1 {
		t.Errorf("a wrong code was charged %d attempts, %d failures", attempts, failed)
	}
	rec := f.postCode(t, page, code)
	if !sessionSet(rec) {
		t.Fatalf("the service's code did not sign in: %d", rec.Code)
	}
	var amr []string
	if err := f.pool.QueryRow(ctx, `SELECT amr FROM core.sessions WHERE cookie_hash = $1`,
		store.HashToken(cookieFrom(rec, SessionCookieName).Value)).Scan(&amr); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(amr, "sms") {
		t.Errorf("the session's amr %v does not say sms", amr)
	}
	// Spent: the same code again is no code.
	if _, delegated, _, _ := row(); delegated {
		t.Error("a spent delegated code is still outstanding")
	}
}
