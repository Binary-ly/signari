package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Message is one outgoing email.
type Message struct {
	To      string
	Subject string
	// Text only. HTML mail from an identity provider is a phishing lesson: it
	// trains users that a message about their account can contain a styled button
	// they should click, which is the exact shape of the attack.
	Body string
}

// Sender delivers a message. An interface so the dev driver, the SMTP driver and
// a test double are interchangeable, and so nothing else in the codebase learns
// what SMTP is.
type Sender interface {
	Send(ctx context.Context, m Message) error
	// From is the envelope sender, needed by Preflight to know which domain to
	// check.
	From() string
}

// LogSender writes messages to the log instead of sending them.
//
// The development driver, and deliberately NOT a silent no-op: a developer must
// be able to complete a password reset locally, which means seeing the link. It
// logs at WARN so nobody mistakes a dev deployment for a configured one.
type LogSender struct {
	log  *slog.Logger
	from string
}

func NewLogSender(log *slog.Logger, from string) *LogSender {
	return &LogSender{log: log, from: from}
}

func (l *LogSender) From() string { return l.from }

func (l *LogSender) Send(_ context.Context, m Message) error {
	l.log.Warn("EMAIL NOT SENT -- no SMTP configured; message logged instead",
		"to", m.To, "subject", m.Subject, "body", m.Body)
	return nil
}

// SMTPSender delivers over SMTP.
type SMTPSender struct {
	Host     string
	Port     int
	Username string
	Password string
	FromAddr string
	FromName string
	Timeout  time.Duration
}

func (s *SMTPSender) From() string { return s.FromAddr }

// Send delivers one message.
//
// STARTTLS is REQUIRED, not attempted. SMTP credentials sent in the clear are
// credentials given away, and "fall back to plaintext if the server does not
// offer TLS" is indistinguishable from a downgrade attack -- which is why it is
// refused rather than warned about.
func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	if _, err := mail.ParseAddress(m.To); err != nil {
		return fmt.Errorf("mail: refusing to send to %q: %w", m.To, err)
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mail: connecting to %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return fmt.Errorf("mail: SMTP handshake with %s: %w", addr, err)
	}
	defer func() { _ = c.Close() }()

	ok, _ := c.Extension("STARTTLS")
	if !ok {
		return fmt.Errorf("mail: %s does not offer STARTTLS; refusing to send credentials "+
			"or account links over an unencrypted connection", addr)
	}
	if err := c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("mail: STARTTLS with %s: %w", addr, err)
	}

	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("mail: authenticating to %s: %w", addr, err)
		}
	}
	if err := c.Mail(s.FromAddr); err != nil {
		return fmt.Errorf("mail: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(m.To); err != nil {
		return fmt.Errorf("mail: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: DATA: %w", err)
	}
	if _, err := w.Write([]byte(s.build(m))); err != nil {
		return fmt.Errorf("mail: writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: completing message: %w", err)
	}
	return c.Quit()
}

// build renders the message.
//
// Headers are constructed rather than interpolated, and the subject is RFC 2047
// encoded. A newline in a subject or recipient is header injection -- an
// attacker-chosen display name could otherwise append Bcc: and turn every
// password reset into a copy sent to them.
func (s *SMTPSender) build(m Message) string {
	from := s.FromAddr
	if s.FromName != "" {
		from = (&mail.Address{Name: s.FromName, Address: s.FromAddr}).String()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", sanitiseHeader(from))
	fmt.Fprintf(&b, "To: %s\r\n", sanitiseHeader(m.To))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", stripNewlines(m.Subject)))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	// Transactional mail must never be auto-replied to or filed as bulk.
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("X-Auto-Response-Suppress: All\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(m.Body, "\n", "\r\n"))
	return b.String()
}

func stripNewlines(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func sanitiseHeader(s string) string { return stripNewlines(s) }
