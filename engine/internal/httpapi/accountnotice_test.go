package httpapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/store"
)

// queuedNotices counts the notices of one kind waiting for a person.
func queuedNotices(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID, notice string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM core.outbox
		WHERE topic = $1 AND payload->>'user_id' = $2 AND payload->>'notice' = $3`,
		store.AccountNoticeTopic, userID, notice).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

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
		{store.AccountNotice{UserID: f.userID, Notice: store.NoticePasswordChanged},
			"Your password was changed", "every signed-in session was ended"},
		{store.AccountNotice{UserID: f.userID, Notice: store.NoticePasswordSet},
			"An administrator set a new password for your account", "every signed-in session was ended"},
		{store.AccountNotice{UserID: f.userID, Notice: store.NoticeProviderLinked, Provider: "Acme SSO"},
			"Acme SSO can now sign you in", "Your Acme SSO account was just linked"},
		{store.AccountNotice{UserID: f.userID, Notice: store.NoticeProviderUnlinked, Provider: "Acme SSO"},
			"Acme SSO can no longer sign you in", "unlinked"},
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

	// An address an administrator changed: the new one hears through the
	// account's own channels, and the old one is written to as well.
	before := len(cap.messages())
	if err := f.srv.DeliverAccountNotice(ctx, store.AccountNotice{UserID: f.userID,
		Notice: store.NoticeEmailChanged, OldAddress: "was-" + f.email}); err != nil {
		t.Fatal(err)
	}
	to := map[string]bool{}
	for _, m := range cap.messages()[before:] {
		if m.Subject == "The email address on your account was changed" &&
			!strings.Contains(m.Body, f.email) {
			to[m.To] = true
		}
	}
	if !to[f.email] || !to["was-"+f.email] {
		t.Errorf("an address change told %v, want the new address and the old, neither named", to)
	}

	gone := store.AccountNotice{UserID: "00000000-0000-4000-8000-000000000000", Notice: store.NoticeFactorRemoved}
	if err := f.srv.DeliverAccountNotice(ctx, gone); !errors.Is(err, outbox.ErrNoSuchAccount) {
		t.Errorf("a notice for nobody: %v, want ErrNoSuchAccount", err)
	}
}
