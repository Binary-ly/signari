package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// Enrolling another number leaves the proved one as the factor until a code
// sent to the new one comes back, and an enrolment code is never a sign-in
// code. The send step rewrote the number and cleared verified_at, so one POST
// from any live session switched the factor off; and one function verified
// every code, whatever it had been sent for.
func TestAnotherNumberIsPendingUntilProved(t *testing.T) {
	f, cookie := enrolFixture(t)
	texter := &captureTexter{}
	f.srv.texter = texter
	f.srv.SetSMSPolicy(smsPolicy(t, map[string]string{"SIGNARI_SMS_ALLOWED_PREFIXES": "+44"}))
	ctx := context.Background()
	base := time.Now().UnixNano() % 100_000_000
	first := fmt.Sprintf("+447%09d", base)
	second := fmt.Sprintf("+447%09d", (base+1)%100_000_000)
	digits := regexp.MustCompile(`\b(\d{6})\b`)
	lastCodeTo := func(number string) string {
		t.Helper()
		msgs := texter.messages()
		for i := len(msgs) - 1; i >= 0; i-- {
			if msgs[i].To == number {
				if m := digits.FindStringSubmatch(msgs[i].Body); m != nil {
					return m[1]
				}
			}
		}
		t.Fatalf("no code was texted to %s", number)
		return ""
	}
	step := func(form url.Values) {
		t.Helper()
		f.formPost(t, cookie, "/account/mfa/sms", "/account/mfa/sms", form)
	}
	// The resend floor applies per account; earlier sends in this test are not
	// what is being exercised.
	clearResendFloor := func() {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `UPDATE core.sms_otp_credentials
			SET last_sent_at = now() - interval '2 minutes' WHERE user_id = $1::uuid`, f.userID); err != nil {
			t.Fatal(err)
		}
	}
	state := func() *store.SMSOTPCredential {
		t.Helper()
		c, err := store.LoadSMSOTP(ctx, f.pool, f.userID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	step(url.Values{"step": {"send"}, "number": {first}})
	step(url.Values{"step": {"verify"}, "code": {lastCodeTo(first)}})
	if c := state(); !c.Verified || c.Number != first {
		t.Fatalf("the first number was not proved: %+v", c)
	}

	clearResendFloor()
	step(url.Values{"step": {"send"}, "number": {second}})
	c := state()
	if !c.Verified || c.Number != first || c.Pending != second {
		t.Fatalf("sending a code to another number disturbed the proved factor: %+v", c)
	}
	if has, err := store.HasSecondFactor(ctx, f.pool, f.userID); err != nil || !has {
		t.Fatalf("the proved number stopped counting as a second factor (%v, %v)", has, err)
	}
	enrolCode := lastCodeTo(second)

	// The enrolment code does not pass as a sign-in code.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := store.VerifySMSOTP(ctx, tx, f.userID, enrolCode)
	_ = tx.Rollback(ctx)
	if err != nil || ok {
		t.Fatalf("an enrolment code passed as a sign-in code (%v, %v)", ok, err)
	}

	// Sign-in codes still go to the proved number.
	clearResendFloor()
	tx, err = f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, to, err := store.IssueSMSOTP(ctx, tx, f.userID)
	_ = tx.Rollback(ctx)
	if err != nil || to != first {
		t.Fatalf("a sign-in code would go to %q (%v), want the proved number", to, err)
	}

	// Proving the new number moves the factor, and the old number is told.
	step(url.Values{"step": {"verify"}, "code": {enrolCode}})
	if c := state(); !c.Verified || c.Number != second || c.Pending != "" {
		t.Fatalf("proving the new number did not move the factor: %+v", c)
	}
	told := false
	for _, m := range texter.messages() {
		if m.To == first && strings.Contains(m.Body, "no longer") {
			told = true
		}
	}
	if !told {
		t.Error("the number codes used to go to was not told they had moved")
	}
}
