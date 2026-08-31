package httpapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/i18n"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/sms"
	"signari.dev/engine/internal/store"
)

// Account notification channels.
//
// A notification channel is where an account-SECURITY notice is sent -- "a
// passkey was added", "a password reset was requested". It is a different thing
// from an authentication factor: a factor proves who you are, a notification
// address tells you when something happened to your account.
//
// NIST SP 800-63B-4, Account Notifications, makes this a SHALL:
//
//	"CSPs SHALL support at least two notification addresses per subscriber
//	account... Notifications SHALL be sent to all notification addresses except
//	postal addresses."
//
// The reason is the whole design: if the only channel is the mailbox an attacker
// has taken over, the notice reaches nobody who can act on it. A second,
// independent channel -- a phone, not another inbox -- is what makes the notice
// worth sending. So this supports two kinds, `email` and a VERIFIED `sms`
// number, and every security notice fans out to all of them.

// notifyChannel is one place a notice is sent.
type notifyChannel struct {
	// Kind is "email" or "sms".
	Kind string
	// Address is the email address or the E.164 phone number.
	Address string
}

// accountChannels returns every notification address for a user, the account
// email first and a verified SMS number second.
//
// Only VERIFIED channels. An unverified number is a typo or somebody else's
// phone until a code sent to it comes back, and a notification address the
// account does not control is worse than none -- it leaks that something
// happened to a stranger and still fails to warn the owner.
func (s *Server) accountChannels(ctx context.Context, userID string) ([]notifyChannel, error) {
	var chans []notifyChannel

	var email string
	err := s.db.QueryRow(ctx,
		`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid AND status = 'active'`,
		userID).Scan(&email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if email != "" {
		chans = append(chans, notifyChannel{Kind: "email", Address: email})
	}

	// The verified SMS number is the independent second channel. A number that is
	// merely enrolled but not verified is excluded for the reason above.
	cred, err := store.LoadSMSOTP(ctx, s.db, userID)
	switch {
	case err == nil:
		if cred.Verified && cred.Number != "" {
			chans = append(chans, notifyChannel{Kind: "sms", Address: cred.Number})
		}
	case errors.Is(err, store.ErrNoSMSOTP):
		// No SMS factor enrolled. The account simply has one channel.
	default:
		return nil, err
	}

	return chans, nil
}

// notifyAccount sends a security notice to every notification channel.
//
// emailBody is the full message; smsBody is the short form for the 160-character
// medium and falls back to the subject when empty. A long, URL-heavy body
// belongs in email; the SMS channel's job is to ALERT the independent address,
// pointing at the email for any action -- so a compromised mailbox still cannot
// keep the owner from learning something happened.
//
// One failing channel does not stop the others: reaching the OTHER channel is
// the entire point when the requester controls one. The first error is returned
// so a caller that needs to know "did anything get through" still can, while the
// delivery to every reachable channel is attempted regardless.
// # The language is the ACCOUNT HOLDER's, never the request's
//
// This is the half that looks like a detail and is a security property.
//
// These notices exist to reach the account holder on a channel whoever
// triggered the action may not control. When the trigger is an attacker --
// which is the case the notice is FOR -- the request carries the attacker's
// browser language. Rendering the warning from `Accept-Language` would send the
// victim "your password was changed" in a language they may not read, on the
// one message whose entire job is to be understood immediately. The notice
// arrives, says the right thing, and is useless, while the deployment records
// that the person was told.
//
// So the language comes from `core.users.locale`, falling back to the
// deployment default when the account has no preference recorded. Interactive
// messages are the opposite case and deliberately use the request instead: a
// sign-in code is read by whoever just submitted the form.
func (s *Server) notifierFor(ctx context.Context, userID string) *i18n.Printer {
	bundle := s.pageSet().Bundle()
	var locale *string
	if err := s.db.QueryRow(ctx,
		`SELECT locale FROM core.users WHERE id = $1::uuid`, userID).Scan(&locale); err != nil {
		// A notice in the default language beats no notice. This runs on the
		// path that tells somebody their account was touched, and failing it
		// over a missing preference would be the wrong trade every time.
		s.log.Warn("reading a user's locale for a notice", "user_id", userID, "err", err)
		return bundle.For(i18n.Default)
	}
	if locale == nil || *locale == "" {
		return bundle.For(i18n.Default)
	}
	return bundle.For(*locale)
}

func (s *Server) notifyAccount(ctx context.Context, userID, subject, emailBody, smsBody string) error {
	chans, err := s.accountChannels(ctx, userID)
	if err != nil {
		return err
	}
	if len(chans) == 0 {
		return fmt.Errorf("user %s has no notification channel", userID)
	}

	var firstErr error
	for _, ch := range chans {
		var sendErr error
		switch ch.Kind {
		case "email":
			sendErr = s.mailer.Send(ctx, mail.Message{
				To: ch.Address, Subject: subject, Body: emailBody,
			})
		case "sms":
			if s.texter == nil {
				// No gateway configured, so the number cannot be reached. Not an
				// error for this call -- the email channel still carried the notice
				// -- but worth a line so an operator who expected SMS delivery sees
				// why it did not happen.
				s.log.Warn("account notice not sent by SMS: no SMS gateway configured",
					"user_id", userID)
				continue
			}
			body := smsBody
			if body == "" {
				body = subject
			}
			sendErr = s.texter.Send(ctx, sms.Message{To: ch.Address, Body: body})
		}
		if sendErr != nil {
			s.log.Error("sending account notice", "kind", ch.Kind, "err", sendErr)
			if firstErr == nil {
				firstErr = sendErr
			}
		}
	}
	return firstErr
}

// hasSecondChannel reports whether an account has the two independent
// notification addresses NIST SP 800-63B-4 asks a CSP to support.
//
// Used by the self-service console to prompt for a second channel and by the
// doctor to count accounts that have only one, so the SHALL is visible per
// deployment rather than assumed.
func (s *Server) hasSecondChannel(ctx context.Context, userID string) (bool, error) {
	chans, err := s.accountChannels(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(chans) >= 2, nil
}
