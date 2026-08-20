package httpapi

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"signari.dev/engine/internal/mail"
)

// captureMailer records what would have been sent.
type captureMailer struct {
	mu   sync.Mutex
	sent []mail.Message
	err  error
}

func (c *captureMailer) From() string { return "noreply@test.invalid" }
func (c *captureMailer) Send(_ context.Context, m mail.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.sent = append(c.sent, m)
	return nil
}
func (c *captureMailer) messages() []mail.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]mail.Message(nil), c.sent...)
}

// NIST SP 800-63B-4, Binding an Additional Authenticator:
//
//	"When an authenticator is added, the CSP SHALL notify the subscriber via a
//	mechanism independent of the transaction binding the new authenticator"
//
// and Account Notifications:
//
//	"The notification SHALL provide clear instructions, including contact
//	information, in case the recipient repudiates the event associated with the
//	notification."
//
// This was an unmet SHALL. The threat is specific: an attacker with momentary
// control of a session — a borrowed laptop, a stolen cookie — registers their own
// passkey and gains durable access that outlives the session they took. Nothing
// told the account's owner, and the credential list is a page nobody visits.
func TestBindingAnAuthenticatorNotifiesTheSubscriber(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	const addr = "bind-notice@example.test"
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET email = $2 WHERE id = $1::uuid`, f.userID, addr); err != nil {
		t.Fatal(err)
	}

	cap := &captureMailer{}
	f.srv.mailer = cap

	f.srv.notifyAuthenticatorBound(ctx, f.userID, f.orgID, "Work Laptop")

	msgs := cap.messages()
	if len(msgs) != 1 {
		t.Fatalf("got %d notifications, want exactly 1: adding an authenticator is "+
			"a SHALL-notify event", len(msgs))
	}
	m := msgs[0]
	if m.To != addr {
		t.Errorf("sent to %q, want the account's address %q", m.To, addr)
	}
	// It must name the thing that was added, or the recipient cannot tell which
	// of their devices it was.
	if !strings.Contains(m.Body, "Work Laptop") {
		t.Errorf("the notice does not name the authenticator: %q", m.Body)
	}
	// "clear instructions, including contact information, in case the recipient
	// repudiates the event"
	lower := strings.ToLower(m.Body)
	if !strings.Contains(lower, "did not") {
		t.Errorf("the notice gives no instructions for the case where the "+
			"recipient did not do this: %q", m.Body)
	}
	if !strings.Contains(m.Body, f.srv.cfg.Issuer) {
		t.Errorf("the notice carries no contact information: %q", m.Body)
	}
}

// A send failure must not be silent, and must not undo the registration.
//
// The credential is real by this point. Refusing it because an email bounced
// would leave the user holding an authenticator the server has forgotten, which
// is a worse outcome than a notification an operator can see failed.
func TestAFailedNoticeIsAuditedRatherThanSwallowed(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET email = $2 WHERE id = $1::uuid`,
		f.userID, "fails@example.test"); err != nil {
		t.Fatal(err)
	}
	f.srv.mailer = &captureMailer{err: os.ErrDeadlineExceeded}

	// Must not panic and must return; the registration stands.
	f.srv.notifyAuthenticatorBound(ctx, f.userID, f.orgID, "Doomed Key")

	var n int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM core.audit_events
		WHERE subject_id = $1::uuid AND event_type = 'mfa.passkey_notice_failed'`,
		f.userID).Scan(&n); err != nil {
		t.Fatalf("counting audit events: %v", err)
	}
	if n == 0 {
		t.Error("a required notification failed to send and left no audit trace; " +
			"an operator has no way to learn that a SHALL was not met")
	}
}

// The registration handler must actually call it, after the commit.
//
// The unit tests above prove the notice is correct; they cannot prove it is
// reached. This session has already found one defect that was exactly a correct
// function nothing invoked with the right data, so the call site is asserted
// too — narrowly, and it fails on the edit that would remove it.
func TestTheRegistrationHandlerSendsTheNotice(t *testing.T) {
	src, err := os.ReadFile("passkey.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	i := strings.Index(body, "func (s *Server) handlePasskeyRegisterFinish")
	if i < 0 {
		t.Skip("the registration handler was renamed; update this test alongside it")
	}
	end := strings.Index(body[i:], "\nfunc ")
	if end < 0 {
		end = len(body) - i
	}
	handler := body[i : i+end]

	call := strings.Index(handler, "notifyAuthenticatorBound(")
	if call < 0 {
		t.Fatal("the registration handler does not notify the subscriber; " +
			"NIST SP 800-63B-4 makes that a SHALL when an authenticator is bound")
	}
	commit := strings.Index(handler, "tx.Commit(ctx)")
	if commit >= 0 && call < commit {
		t.Error("the notice is sent BEFORE the commit, so a registration that " +
			"then rolls back still tells the user it happened — which teaches " +
			"recipients that these messages are noise")
	}
}
