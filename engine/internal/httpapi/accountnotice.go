package httpapi

import (
	"context"
	"fmt"

	"signari.dev/engine/internal/outbox"
	"signari.dev/engine/internal/store"
)

// DeliverAccountNotice tells an account's holder what the Admin API or the
// CLI did to their account (store.AccountNotice), in their language and by
// every channel a notice uses: email, and a verified number. Installed on the
// outbox worker, which retries a failure; a channel that succeeded before one
// failed is sent again, the at-least-once every outbox topic accepts.
func (s *Server) DeliverAccountNotice(ctx context.Context, n store.AccountNotice) error {
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
	default:
		return fmt.Errorf("an account notice of no known kind %q", n.Notice)
	}
	tr := s.notifierFor(ctx, n.UserID)
	data := map[string]any{"Factor": tr.Text("factor.kind." + n.Factor)}
	return s.notifyAccount(ctx, n.UserID, tr.Text("mail."+key+".subject"),
		tr.Text("mail."+key+".body", data), tr.Text("sms."+key, data))
}
