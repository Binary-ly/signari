package mail

import (
	"strings"
	"testing"
)

// Header injection. A newline in a subject or address lets an attacker append
// their own headers -- Bcc: themselves on every password reset, for instance.
// The display name and subject are the fields most likely to carry user input.
func TestHeaderInjectionIsNeutralised(t *testing.T) {
	s := &SMTPSender{
		FromAddr: "noreply@example.com",
		FromName: "Signari\r\nBcc: attacker@evil.test",
	}
	msg := s.build(Message{
		To:      "user@example.com",
		Subject: "Reset\r\nBcc: attacker@evil.test",
		Body:    "hello",
	})

	// The property is that no NEW HEADER LINE was created. "Bcc:" appearing as
	// literal text inside a Subject value is harmless -- it is one header whose
	// value happens to contain a colon. What must never happen is a line of its
	// own, which is what a surviving CRLF would produce.
	headers, _, _ := strings.Cut(msg, "\r\n\r\n")
	for _, line := range strings.Split(headers, "\r\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "bcc", "cc", "to", "from", "subject", "mime-version", "content-type",
			"auto-submitted", "x-auto-response-suppress":
			// Expected headers only; a "bcc" here would mean injection succeeded.
			if strings.EqualFold(strings.TrimSpace(name), "bcc") {
				t.Fatalf("an injected Bcc became a real header:\n%s", headers)
			}
		default:
			t.Errorf("unexpected header %q -- injection may have created it", name)
		}
	}
	// And no bare CR or LF may survive anywhere in the header block.
	if strings.Contains(headers, "\n\n") || strings.Count(headers, "\r") != strings.Count(headers, "\n") {
		t.Error("unbalanced line endings in the header block")
	}
	for _, want := range []string{"From: ", "To: ", "Subject: ", "Content-Type: text/plain"} {
		if !strings.Contains(headers, want) {
			t.Errorf("missing header %q", want)
		}
	}
}

// The body is text only. HTML mail from an identity provider teaches users that
// a message about their account can contain a styled button they should click --
// which is the exact shape of the attack we are trying to make them resistant to.
func TestMessagesAreTextOnly(t *testing.T) {
	s := &SMTPSender{FromAddr: "noreply@example.com"}
	msg := s.build(Message{To: "u@example.com", Subject: "s", Body: "b"})
	if strings.Contains(msg, "text/html") {
		t.Error("the message declares an HTML part")
	}
	if !strings.Contains(msg, "Auto-Submitted: auto-generated") {
		t.Error("transactional mail must not invite auto-replies")
	}
}

func TestRefusesMalformedRecipients(t *testing.T) {
	s := &SMTPSender{Host: "127.0.0.1", Port: 1, FromAddr: "noreply@example.com"}
	for _, bad := range []string{"", "not-an-address", "a@b@c", "user@example.com\r\nBcc: x@y.z"} {
		if err := s.Send(t.Context(), Message{To: bad, Subject: "s", Body: "b"}); err == nil {
			t.Errorf("accepted recipient %q", bad)
		}
	}
}

// A report with any Fail must not claim deliverability.
func TestReportDeliverability(t *testing.T) {
	r := Report{Findings: []Finding{{Severity: Pass}, {Severity: Warn}}}
	if !r.Deliverable() {
		t.Error("warnings alone should not mark mail undeliverable")
	}
	r.Findings = append(r.Findings, Finding{Severity: Fail})
	if r.Deliverable() {
		t.Error("a failing check was reported as deliverable")
	}
}
