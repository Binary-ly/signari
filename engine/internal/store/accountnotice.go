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
	// NoticeSignInCode: a code to sign in with, emailed to the account's
	// address (5.16). LinkID names the email_sign_in_codes row; the code is
	// minted as it is sent, so it never sits in the outbox.
	NoticeSignInCode = "sign_in_code"
	// NoticeInvitation: an invitation's link, mailed to the address it is
	// bound to (5.18). There is no account yet, so UserID is empty; LinkID
	// names the invitation, and the token is minted as the mail goes out.
	NoticeInvitation = "invitation"
	// NoticeAccountApproved: a self-sign-up an administrator approved can now
	// sign in (5.19); its sign-up page said a message would come.
	NoticeAccountApproved = "account_approved"
	// NoticeNewDevice: a sign-in from a browser and system none of the
	// person's recent sessions used (5.21); Device names it.
	NoticeNewDevice = "new_device"
)

// ApproveUser activates a pending account in tx and queues the notice telling
// its holder, reporting whether it was pending. Any other status is left for
// the caller: approving is only ever of a self-sign-up waiting for it.
func ApproveUser(ctx context.Context, tx pgx.Tx, userID string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE core.users SET status = 'active', updated_at = now()
		WHERE id = $1::uuid AND status = 'pending'`, userID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	return true, EnqueueAccountNotice(ctx, tx, AccountNotice{UserID: userID, Notice: NoticeAccountApproved})
}

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
	// Device is the browser and system a NoticeNewDevice names.
	Device string `json:"device,omitempty"`
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
