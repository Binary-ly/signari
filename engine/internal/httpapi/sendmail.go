package httpapi

import (
	"context"

	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/store"
)

// Every message the engine sends leaves through here or sendMailTo, so each one
// carries its organisation's sender and look, and no new message can forget them.
// TestEveryMessageLeavesThroughSendMail holds that.

// sendMail sends a message for an organisation. For one whose person has gone,
// or who never had an account: a deleted account's last notice, an invitation.
func (s *Server) sendMail(ctx context.Context, orgID string, m mail.Message) error {
	sender, err := store.OrgMailSender(ctx, s.db, orgID)
	if err != nil {
		// The deployment's address is a worse sender and a better outcome than a
		// sign-in code that never left.
		s.log.WarnContext(ctx, "reading an organisation's mail sender", "org_id", orgID, "err", err)
	}
	return s.sendAs(ctx, orgID, sender, m)
}

// sendMailTo sends a message to or about a person, from their organisation.
func (s *Server) sendMailTo(ctx context.Context, userID string, m mail.Message) error {
	sender, orgID, err := store.UserMailSender(ctx, s.db, userID)
	if err != nil {
		s.log.WarnContext(ctx, "reading a person's mail sender", "user_id", userID, "err", err)
	}
	return s.sendAs(ctx, orgID, sender, m)
}

func (s *Server) sendAs(ctx context.Context, orgID string, sender store.MailSender, m mail.Message) error {
	m.From, m.FromName = sender.From, sender.Name
	if b := s.brandOf(ctx, orgID); b != nil {
		m.Look = mail.Look{Product: b.ProductName, Background: b.Background, Text: b.Text, Link: b.Primary}
	}
	return s.mailer.Send(ctx, m)
}
