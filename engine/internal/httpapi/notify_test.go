package httpapi

import (
	"context"
	"sync"
	"testing"

	"signari.dev/engine/internal/sms"
)

// captureTexter records SMS that would have been sent.
type captureTexter struct {
	mu   sync.Mutex
	sent []sms.Message
	err  error
}

func (c *captureTexter) Describe() string { return "capture" }
func (c *captureTexter) Send(_ context.Context, m sms.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.sent = append(c.sent, m)
	return nil
}
func (c *captureTexter) messages() []sms.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sms.Message(nil), c.sent...)
}

// NIST SP 800-63B-4, Account Notifications: "CSPs SHALL support at least two
// notification addresses per subscriber account... Notifications SHALL be sent to
// all notification addresses except postal addresses."
//
// The point is a channel INDEPENDENT of the mailbox an attacker may hold. A
// verified SMS number is that second channel, and a security notice must reach
// both it and the email.
func TestAnAccountSecurityNoticeReachesEveryChannel(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	const email = "two-channel@example.test"
	const number = "+15005550006"
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET email = $2 WHERE id = $1::uuid`, f.userID, email); err != nil {
		t.Fatal(err)
	}
	// A VERIFIED SMS number, which is what makes it a usable notification address.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sms_otp_credentials (user_id, org_id, number, verified_at)
		VALUES ($1::uuid, $2::uuid, $3, now())
		ON CONFLICT (user_id) DO UPDATE SET number = EXCLUDED.number, verified_at = now()`,
		f.userID, f.orgID, number); err != nil {
		t.Fatal(err)
	}

	mailer := &captureMailer{}
	texter := &captureTexter{}
	f.srv.mailer = mailer
	f.srv.texter = texter

	if err := f.srv.notifyAccount(ctx, f.userID, "Test notice",
		"the full email body", "the short sms body"); err != nil {
		t.Fatalf("notifyAccount: %v", err)
	}

	if got := mailer.messages(); len(got) != 1 || got[0].To != email {
		t.Errorf("email channel: got %+v, want one message to %q", got, email)
	}
	sms := texter.messages()
	if len(sms) != 1 || sms[0].To != number {
		t.Fatalf("sms channel: got %+v, want one message to %q", sms, number)
	}
	// The SMS carries the short body, not the long email one: a 160-char medium
	// must not be handed two tokenised URLs.
	if sms[0].Body != "the short sms body" {
		t.Errorf("sms body = %q, want the short form", sms[0].Body)
	}
}

// An UNVERIFIED number is not a notification address: it may be a typo or
// somebody else's phone, and warning a stranger while failing the owner is worse
// than having one channel.
func TestAnUnverifiedNumberIsNotANotificationChannel(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET email = $2 WHERE id = $1::uuid`,
		f.userID, "only-email@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sms_otp_credentials (user_id, org_id, number, verified_at)
		VALUES ($1::uuid, $2::uuid, $3, NULL)
		ON CONFLICT (user_id) DO UPDATE SET number = EXCLUDED.number, verified_at = NULL`,
		f.userID, f.orgID, "+15005550007"); err != nil {
		t.Fatal(err)
	}

	chans, err := f.srv.accountChannels(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chans) != 1 || chans[0].Kind != "email" {
		t.Fatalf("got %+v, want exactly the email channel; an unverified number "+
			"must not count", chans)
	}
	if second, err := f.srv.hasSecondChannel(ctx, f.userID); err != nil || second {
		t.Errorf("hasSecondChannel = %v (err %v); an unverified number is not a "+
			"second channel", second, err)
	}
}
