package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Notices to an account's holder raised where there is no mailer: the Admin
// API and the CLI (4.14). A factor an administrator removed or replaced is
// exactly what the holder must hear about on an independent channel, and it
// was told nothing. Queued in the transaction that made the change, so the
// notice and the change commit together, and delivered by serve's outbox
// worker through the same channels every other notice uses.

// AccountNoticeTopic is their outbox topic.
const AccountNoticeTopic = "account_notice"

// The notices there are.
const (
	// NoticeFactorRemoved: an administrator removed a sign-in method.
	NoticeFactorRemoved = "factor_removed"
	// NoticeFactorAssigned: an administrator gave the person a hardware token.
	NoticeFactorAssigned = "factor_assigned"
	// NoticePasskeyLink: the link to register a passkey (IssuePasskeyLink),
	// emailed to the account's address alone; its token is minted as it is sent.
	NoticePasskeyLink = "passkey_link"
	// NoticePasswordChanged: the person changed their password, by choice or
	// because the sign-in required it, and every session ended.
	NoticePasswordChanged = "password_changed"
	// NoticePasswordSet: an administrator set the password.
	NoticePasswordSet = "password_set"
	// NoticeEmailChanged: an administrator changed the address. Sent to the
	// new one and to the old (OldAddress), which is the one the holder may
	// still be reading if the change was not theirs.
	NoticeEmailChanged = "email_changed"
	// NoticeProviderLinked and NoticeProviderUnlinked: a provider (Provider,
	// its display name) can now, or can no longer, sign the person in.
	NoticeProviderLinked   = "provider_linked"
	NoticeProviderUnlinked = "provider_unlinked"
)

// AccountNotice is one queued notice.
type AccountNotice struct {
	UserID string `json:"user_id"`
	Notice string `json:"notice"`
	// Factor is the kind concerned, as the Admin API names it.
	Factor string `json:"factor,omitempty"`
	// LinkID is the passkey link a NoticePasskeyLink carries. Its id, never
	// its token.
	LinkID string `json:"link_id,omitempty"`
	// OldAddress is the address a NoticeEmailChanged also goes to.
	OldAddress string `json:"old_address,omitempty"`
	// Provider is the provider a NoticeProviderLinked or Unlinked names.
	Provider string `json:"provider,omitempty"`
}

// EnqueueAccountNotice queues a notice in tx.
func EnqueueAccountNotice(ctx context.Context, tx pgx.Tx, n AccountNotice) error {
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.outbox (topic, payload) VALUES ($1, $2)`,
		AccountNoticeTopic, raw); err != nil {
		return fmt.Errorf("queueing a notice to the account's holder: %w", err)
	}
	return nil
}
