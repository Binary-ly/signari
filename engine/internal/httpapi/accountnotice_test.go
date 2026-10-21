package httpapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/store"
)

// A notice the Admin API or the CLI queued reaches the holder by email, in
// their language, naming the method (4.14); one for an account deleted since
// says so, for the outbox to close rather than retry.
func TestAnAccountNoticeReachesTheHolder(t *testing.T) {
	f := newSignInFixture(t)
	cap := &captureMailer{}
	f.srv.mailer = cap
	ctx := context.Background()

	for _, c := range []struct {
		n       store.AccountNotice
		subject string
		body    string
	}{
		{store.AccountNotice{UserID: f.userID, Notice: store.NoticeFactorRemoved, Factor: "webauthn"},
			"A sign-in method was removed from your account", "passkey or security key"},
		{store.AccountNotice{UserID: f.userID, Notice: store.NoticeFactorAssigned, Factor: "totp"},
			"A security token was added to your account", "hardware token"},
	} {
		before := len(cap.messages())
		if err := f.srv.DeliverAccountNotice(ctx, c.n); err != nil {
			t.Fatalf("%s: %v", c.n.Notice, err)
		}
		msgs := cap.messages()
		if len(msgs) != before+1 {
			t.Fatalf("%s: %d emails", c.n.Notice, len(msgs)-before)
		}
		m := msgs[len(msgs)-1]
		if m.To != f.email || m.Subject != c.subject || !strings.Contains(m.Body, c.body) ||
			strings.Contains(m.Body, "{") {
			t.Errorf("%s: to %s, subject %q, body %q", c.n.Notice, m.To, m.Subject, m.Body)
		}
	}

	gone := store.AccountNotice{UserID: "00000000-0000-4000-8000-000000000000", Notice: store.NoticeFactorRemoved}
	if err := f.srv.DeliverAccountNotice(ctx, gone); !errors.Is(err, outbox.ErrNoSuchAccount) {
		t.Errorf("a notice for nobody: %v, want ErrNoSuchAccount", err)
	}
}
