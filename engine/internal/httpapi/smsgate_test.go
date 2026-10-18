package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/sms"
)

// Every text message passes the country list and the daily ceilings, which
// before this did not exist: any number could be enrolled and every challenge
// cost the operator a message (SMS pumping).

func smsPolicy(t *testing.T, env map[string]string) sms.Policy {
	t.Helper()
	p, err := sms.PolicyFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestATextMessageOutsideTheCountryListIsNotSent(t *testing.T) {
	f := newSignInFixture(t)
	texter := &captureTexter{}
	f.srv.texter = texter
	f.srv.SetSMSPolicy(smsPolicy(t, map[string]string{"SIGNARI_SMS_ALLOWED_PREFIXES": "+44, +1"}))
	ctx := context.Background()

	err := f.srv.sendSMS(ctx, f.userID, smsCode, sms.Message{To: "+88212345678", Body: "code"})
	if !errors.Is(err, errSMSRefused) || len(texter.messages()) != 0 {
		t.Fatalf("a number outside the list gave %v and %d message(s) sent", err, len(texter.messages()))
	}
	// A number of this run's own: the daily ceiling now holds for the whole day,
	// so a fixed number is spent by earlier runs.
	listed := fmt.Sprintf("+4477%09d", time.Now().UnixNano()%1_000_000_000)
	if err := f.srv.sendSMS(ctx, f.userID, smsCode, sms.Message{To: listed, Body: "code"}); err != nil {
		t.Fatalf("a listed number was refused: %v", err)
	}
	var audited int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events
		 WHERE event_type = 'sms.refused' AND subject_id = $1::uuid`, f.userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited == 0 {
		t.Error("the refusal was not audited")
	}
}

func TestOneNumberGetsAtMostItsDailyAllowance(t *testing.T) {
	f := newSignInFixture(t)
	texter := &captureTexter{}
	f.srv.texter = texter
	f.srv.SetSMSPolicy(smsPolicy(t, map[string]string{"SIGNARI_SMS_NUMBER_DAILY_LIMIT": "3"}))
	ctx := context.Background()
	number := fmt.Sprintf("+4477%09d", time.Now().UnixNano()%1_000_000_000)

	for i := 0; i < 3; i++ {
		if err := f.srv.sendSMS(ctx, f.userID, smsCode, sms.Message{To: number, Body: "code"}); err != nil {
			t.Fatalf("message %d within the allowance was refused: %v", i+1, err)
		}
	}
	if err := f.srv.sendSMS(ctx, f.userID, smsCode, sms.Message{To: number, Body: "code"}); !errors.Is(err, errSMSRefused) {
		t.Fatalf("the fourth message to one number in a day gave %v, want a refusal", err)
	}
	if n := len(texter.messages()); n != 3 {
		t.Fatalf("%d messages reached the gateway, want 3", n)
	}
}

// Notices draw on an allowance of their own. A reset request, which anybody
// can make for anybody, texts a notice; sharing the allowance let enough of
// them stop a person -- or, through the organisation's ceiling, everybody --
// receiving a sign-in code.
func TestNoticesCannotSpendTheAllowanceCodesComeFrom(t *testing.T) {
	f := newSignInFixture(t)
	texter := &captureTexter{}
	f.srv.texter = texter
	f.srv.SetSMSPolicy(smsPolicy(t, map[string]string{
		"SIGNARI_SMS_NUMBER_DAILY_LIMIT": "2", "SIGNARI_SMS_ORG_DAILY_LIMIT": "1000000"}))
	ctx := context.Background()
	number := fmt.Sprintf("+4479%09d", time.Now().UnixNano()%1_000_000_000)

	for i := 0; i < 2; i++ {
		if err := f.srv.sendSMS(ctx, f.userID, smsNotice, sms.Message{To: number, Body: "notice"}); err != nil {
			t.Fatalf("notice %d within its allowance was refused: %v", i+1, err)
		}
	}
	if err := f.srv.sendSMS(ctx, f.userID, smsNotice, sms.Message{To: number, Body: "notice"}); !errors.Is(err, errSMSRefused) {
		t.Fatalf("a notice past its own allowance gave %v, want a refusal", err)
	}
	if err := f.srv.sendSMS(ctx, f.userID, smsCode, sms.Message{To: number, Body: "code"}); err != nil {
		t.Fatalf("a sign-in code after the notices' allowance was spent was refused: %v", err)
	}
}

func TestAnOrganisationGetsAtMostItsDailyAllowance(t *testing.T) {
	f := newSignInFixture(t)
	texter := &captureTexter{}
	f.srv.texter = texter
	f.srv.SetSMSPolicy(smsPolicy(t, map[string]string{"SIGNARI_SMS_ORG_DAILY_LIMIT": "2"}))
	ctx := context.Background()
	base := time.Now().UnixNano() % 1_000_000_000

	for i := 0; i < 2; i++ {
		to := fmt.Sprintf("+4478%09d", (base+int64(i))%1_000_000_000)
		if err := f.srv.sendSMS(ctx, f.userID, smsCode, sms.Message{To: to, Body: "code"}); err != nil {
			t.Fatalf("message %d within the organisation's allowance was refused: %v", i+1, err)
		}
	}
	to := fmt.Sprintf("+4478%09d", (base+7)%1_000_000_000)
	if err := f.srv.sendSMS(ctx, f.userID, smsCode, sms.Message{To: to, Body: "code"}); !errors.Is(err, errSMSRefused) {
		t.Fatalf("a third message for the organisation, to a fresh number, gave %v, want a refusal", err)
	}
}

func TestANumberOutsideTheCountryListCannotBeEnrolled(t *testing.T) {
	f := newSignInFixture(t)
	clearSignInBucket(t, f.pool)
	f.srv.texter = &captureTexter{}
	f.srv.SetSMSPolicy(smsPolicy(t, map[string]string{"SIGNARI_SMS_ALLOWED_PREFIXES": "+44"}))

	out := f.attempt(t, f.email, signInTestPassword)
	if out.sessionCookie == "" {
		t.Fatal("the fixture user could not sign in")
	}
	rec := f.formPost(t, out.sessionCookie, "/account/mfa/sms", "/account/mfa/sms",
		url.Values{"step": {"send"}, "number": {"+882 1234 5678"}})
	if !strings.Contains(rec.Body.String(), "not available here") {
		t.Fatalf("enrolling an off-list number did not say why: %d %.300s", rec.Code, rec.Body.String())
	}
	var stored int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.sms_otp_credentials WHERE user_id = $1::uuid`, f.userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatal("the off-list number was stored, building a factor that can never deliver a code")
	}
}

// The gate is the only caller of the gateway.
func TestNoTextMessageBypassesTheGate(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	direct := regexp.MustCompile(`\.texter\.Send\(`)
	found := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		n := len(direct.FindAllIndex(b, -1))
		found += n
		if n > 0 && e.Name() != "smsgate.go" {
			t.Errorf("%s sends a text message without sendSMS, so the country list and "+
				"the daily ceilings do not apply to it", e.Name())
		}
	}
	if found != 1 {
		t.Fatalf("found %d calls to the gateway; the gate's own should be the only one", found)
	}
}
