package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/sms"
	"signari.dev/engine/internal/store"
)

// sendSMS is the only way this package sends a text message.
//
// Enrolment, the sign-in challenge and account notices each called the gateway
// directly, with no country list and no ceiling. Any E.164 number could be
// enrolled from a signup, and each challenge cost the operator a message. A
// number on a high-cost range earns whoever leases the range a share of every
// one, so the sign-in form was a way to bill the deployment (SMS pumping).
//
// Here, in order: the number must be in a country the deployment serves
// (SIGNARI_SMS_ALLOWED_PREFIXES), it may be sent at most so many messages a
// day, and so may its organisation. A refusal is audited, counted and returned
// as errSMSRefused, and nothing is sent. TestNoTextMessageBypassesTheGate keeps
// this the only caller of the gateway.
//
// Codes and notices draw on separate allowances of the same size. They shared
// one, and a reset request -- which anybody can make for anybody, and which
// texts a notice -- spent the allowance a person's sign-in codes come from:
// enough requests and the person could not receive a code, and enough across
// an organisation and nobody in it could. A notice can no longer cost anybody
// a code; what it costs the operator is still capped, by its own ceiling.
//
// With a delegated verification service (SIGNARI_SMS_GATEWAY=verify-webhook) a
// code is the service's to make and send: m.Body is not sent, the service is
// asked to start, under the same checks. It sends nothing else, so a notice
// has no gateway.
func (s *Server) sendSMS(ctx context.Context, userID string, kind smsKind, m sms.Message) error {
	delegated := kind == smsCode && s.smsVerifier != nil
	if s.texter == nil && !delegated {
		return errors.New("no SMS gateway is configured")
	}
	if !s.smsPolicy.Permits(m.To) {
		return s.refuseSMS(ctx, userID, "refused_country", "the number is outside "+
			"SIGNARI_SMS_ALLOWED_PREFIXES")
	}

	var orgID string
	if err := s.db.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id = $1::uuid`,
		userID).Scan(&orgID); err != nil {
		return fmt.Errorf("finding the organisation for a text message: %w", err)
	}
	perNumber, perOrg := s.smsPolicy.Limits()
	prefix := "sms:"
	if kind == smsNotice {
		prefix = "sms:notice:"
	}
	for _, b := range []struct {
		key, outcome, why string
		limit             int
	}{
		{prefix + "number:" + m.To, "refused_number_budget", "this number's daily allowance is spent", perNumber},
		{prefix + "org:" + orgID, "refused_org_budget", "the organisation's daily allowance is spent " +
			"(SIGNARI_SMS_ORG_DAILY_LIMIT)", perOrg},
	} {
		res, err := store.AllowRate(ctx, s.db, b.key, b.limit, 24*time.Hour)
		if err != nil {
			// Refused, not sent: an unmetered window opened by a database fault
			// is the bill this exists to cap.
			return fmt.Errorf("checking the SMS allowance: %w", err)
		}
		if !res.Allowed {
			return s.refuseSMS(ctx, userID, b.outcome, b.why)
		}
	}

	send := func() error { return s.texter.Send(ctx, m) }
	if delegated {
		send = func() error {
			id, err := s.smsVerifier.Start(ctx, m.To)
			if err == nil && id != "" {
				// What its check is made with where the number is not kept.
				err = store.SetSMSCodeRef(ctx, s.db, userID, id)
			}
			return err
		}
	}
	if err := send(); err != nil {
		s.countSMS("failed")
		return err
	}
	s.countSMS("sent")
	return nil
}

// smsAvailable reports whether a code can reach a phone: a gateway that sends
// what this engine makes, or a service that makes and sends its own.
func (s *Server) smsAvailable() bool { return s.texter != nil || s.smsVerifier != nil }

// smsNumberHash is the keyed hash kept for a number in an organisation that
// keeps only hashes, under the person's own subject key.
func (s *Server) smsNumberHash(ctx context.Context, tx pgx.Tx, userID, number string) ([]byte, error) {
	if s.cfg.Root == nil {
		return nil, errors.New("no root key, so no subject key to hash a number under")
	}
	sk, err := keys.LoadOrCreateSubjectKey(ctx, tx, userID, s.cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("the subject key for an SMS number: %w", err)
	}
	return store.SMSNumberMAC(sk, number), nil
}

// smsDelegate is the delegated service's check, nil without one; codes issued
// while there is one are its own (store.IssueSMSOTP's delegated).
func (s *Server) smsDelegate() store.SMSDelegate {
	if s.smsVerifier == nil {
		return nil
	}
	return s.smsVerifier.Check
}

// smsKind says which allowance a text message draws on.
type smsKind int

const (
	// smsCode is a one-time code: the sign-in challenge or enrolment.
	smsCode smsKind = iota
	// smsNotice tells the person something happened to their account.
	smsNotice
)

var errSMSRefused = errors.New("the text message was refused")

func (s *Server) refuseSMS(ctx context.Context, userID, outcome, why string) error {
	s.countSMS(outcome)
	s.log.Warn("text message refused", "reason", why, "user_id", userID)
	s.auditDetached(ctx, audit.Event{
		Type: "sms.refused", SubjectID: userID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"reason": outcome},
	})
	return fmt.Errorf("%w: %s", errSMSRefused, why)
}

func (s *Server) countSMS(outcome string) {
	if s.metrics != nil {
		s.metrics.SMS.Inc(outcome)
	}
}
