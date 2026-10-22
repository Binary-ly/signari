package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"signari.dev/engine/internal/i18n"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/store"
)

// DeliverAccountNotice tells an account's holder what the Admin API or the
// CLI did to their account (store.AccountNotice), in their language and by
// every channel a notice uses: email, and a verified number. Installed on the
// outbox worker, which retries a failure; a channel that succeeded before one
// failed is sent again, the at-least-once every outbox topic accepts.
func (s *Server) DeliverAccountNotice(ctx context.Context, n store.AccountNotice) error {
	if n.Notice == store.NoticeInvitation {
		// For an account that does not exist yet.
		return s.deliverInvitation(ctx, n)
	}
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE id = $1::uuid)`,
		n.UserID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return outbox.ErrNoSuchAccount
	}
	var key string
	switch n.Notice {
	case store.NoticeFactorRemoved:
		key = "factor.removed"
	case store.NoticeFactorAssigned:
		key = "factor.assigned"
	case store.NoticePasskeyLink:
		return s.deliverPasskeyLink(ctx, n)
	case store.NoticeSignInCode:
		return s.deliverSignInCode(ctx, n)
	case store.NoticePasswordChanged:
		key = "password.changed"
	case store.NoticePasswordSet:
		key = "password.set"
	case store.NoticeEmailChanged:
		key = "email.changed"
	case store.NoticeProviderLinked:
		key = "federation.linked"
	case store.NoticeProviderUnlinked:
		key = "federation.unlinked"
	default:
		return fmt.Errorf("an account notice of no known kind %q", n.Notice)
	}
	tr := s.notifierFor(ctx, n.UserID)
	data := map[string]any{"Factor": tr.Text("factor.kind." + n.Factor), "Provider": n.Provider}
	subject, body := tr.Text("mail."+key+".subject", data), tr.Text("mail."+key+".body", data)
	err := s.notifyAccount(ctx, n.UserID, subject, body, tr.Text("sms."+key, data))
	if n.Notice == store.NoticeEmailChanged && n.OldAddress != "" {
		// The old address too: if the change was not the holder's, it is the
		// one they still read. Neither address is named in the message.
		if merr := s.mailer.Send(ctx, mail.Message{To: n.OldAddress, Subject: subject, Body: body}); err == nil {
			err = merr
		}
	}
	return err
}

// deliverInvitation mails an invitation's link to the address it is bound to,
// minting its token now, in the deployment's language: nobody has an account
// to have chosen one with.
func (s *Server) deliverInvitation(ctx context.Context, n store.AccountNotice) error {
	token, email, orgID, expires, err := store.MintInvitationToken(ctx, s.db, n.LinkID)
	if errors.Is(err, store.ErrInvitationNotUsable) {
		return nil // used, revoked or expired before it went out
	}
	if err != nil {
		return err
	}
	var org string
	if err := s.db.QueryRow(ctx, `SELECT display_name FROM core.organizations WHERE id = $1::uuid`,
		orgID).Scan(&org); err != nil {
		return err
	}
	tr := s.pageSet().Bundle().For(i18n.Default)
	return s.mailer.Send(ctx, mail.Message{
		To:      email,
		Subject: tr.Text("mail.invitation.subject", map[string]any{"Org": org}),
		Body: tr.Text("mail.invitation.body", map[string]any{
			"Org":  org,
			"URL":  s.cfg.Issuer + "/signup?invite=" + url.QueryEscape(token),
			"Date": expires.UTC().Format("2 January 2006"),
		}),
	})
}
