// Package sms sends one-time codes over SMS.
//
// # SMS is the weakest second factor, and this package says so
//
// NIST withdrew its recommendation of SMS for authentication in 2016 (SP
// 800-63B), and the reasons have only got easier since:
//
//	SIM swap    somebody persuades a mobile operator to move a number to their
//	            own SIM. No technical exploit is involved, and it is the single
//	            most common way an SMS second factor is defeated.
//	SS7         the signalling network between operators has no authentication
//	            worth the name, and access to it is purchasable.
//	forwarding  many operators will forward messages to an email address or a
//	            second device, configured through a web portal.
//
// So why is it here? Because the alternative deployments choose is not a
// passkey; it is nothing at all. A large share of real users will enrol SMS and
// will not enrol anything else, and SMS defeats the credential-stuffing attack
// that is by far the most common one. The honest position is: offer it, rank it
// below everything else, and never let it silently satisfy a policy that asked
// for phishing-resistant authentication.
//
// That last part is enforced elsewhere -- the `amr` value this factor produces
// is `sms`, and a policy requiring a phishing-resistant factor does not accept
// it. A factor whose weakness is documented and then treated as equivalent in
// code is worse than one nobody wrote down, because the documentation buys the
// confidence and the code spends it.
package sms

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// Message is one text to send.
type Message struct {
	// To is E.164, with the leading +.
	To   string
	Body string
}

// Sender delivers a message.
//
// An interface because every deployment has a different provider, and because
// the tests must not need one. The same shape as mail.Sender, deliberately: two
// delivery channels with two different abstractions is one more thing to hold
// in your head for no benefit.
type Sender interface {
	Send(ctx context.Context, m Message) error
	// Describe names the gateway for logs and for `signari doctor`.
	Describe() string
}

// LogSender writes the message to the log instead of sending it.
//
// The default, and it is a REFUSAL to send rather than a quiet fallback: with
// no gateway configured, enrolling SMS is refused up front rather than
// accepted and then silently undeliverable. A second factor nobody receives
// locks people out of their own accounts.
type LogSender struct{ log *slog.Logger }

func NewLogSender(log *slog.Logger) *LogSender { return &LogSender{log: log} }

func (l *LogSender) Describe() string { return "log (no gateway configured)" }

func (l *LogSender) Send(_ context.Context, m Message) error {
	// The code is NOT logged. A log file is read by more people than a phone,
	// and an operator debugging a delivery problem does not need the secret to
	// know whether the message was built.
	l.log.Warn("SMS gateway not configured; message not sent",
		"to", RedactNumber(m.To), "length", len(m.Body))
	return fmt.Errorf("no SMS gateway is configured (set SIGNARI_SMS_GATEWAY)")
}

// e164 is deliberately strict: a leading +, a country code that cannot start
// with zero, and 7 to 15 digits in total (ITU-T E.164 caps at 15).
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// NormaliseNumber puts a number into E.164, or explains why it cannot.
//
// Strictness here is a security property, not tidiness. Two spellings of one
// number that both "work" mean a person can enrol +447700900123 and be
// challenged on 07700900123 -- or, worse, that a lookup for one fails to find
// the other and a second credential is silently created for the same phone.
func NormaliseNumber(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	// Punctuation people actually type.
	for _, c := range []string{" ", "-", "(", ")", ".", " "} {
		s = strings.ReplaceAll(s, c, "")
	}
	// 00 is the international prefix in much of the world.
	if strings.HasPrefix(s, "00") {
		s = "+" + s[2:]
	}
	if s == "" {
		return "", fmt.Errorf("no number given")
	}
	if !strings.HasPrefix(s, "+") {
		// NOT guessed. Assuming a country code is how a number in one country
		// gets a code for another, and the person then never receives a message
		// and cannot tell why.
		return "", fmt.Errorf("give the number in international form, starting with "+
			"a + and the country code (got %q). A national-format number cannot be "+
			"dialled without knowing which country it is in, and guessing wrong "+
			"means the code goes to somebody else's phone", raw)
	}
	if !e164.MatchString(s) {
		return "", fmt.Errorf("%q is not a valid international number: expected a + "+
			"followed by 7 to 15 digits", raw)
	}
	return s, nil
}

// RedactNumber keeps the last two digits, which is what a person needs to
// recognise their own number and what an attacker cannot use.
//
// Showing the whole number on a sign-in screen tells anybody who has stolen a
// password exactly which number to attack at the mobile operator -- and SIM
// swap is the way this factor is actually defeated.
func RedactNumber(n string) string {
	if len(n) < 3 {
		return "•••"
	}
	return "••• ••• " + n[len(n)-2:]
}
