package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Emailed links to register a passkey without a session (migration 0176). The
// token is minted when the email is sent and only its hash kept, so nothing at
// rest -- this table, the outbox, a log -- holds the credential the link is.

const (
	// DefaultPasskeyLinkTTL is how long a link lives unless told otherwise.
	DefaultPasskeyLinkTTL = 24 * time.Hour
	// MaxPasskeyLinkTTL is the schema's own bound: a credential sitting in
	// somebody's inbox for weeks is one more way into the account.
	MaxPasskeyLinkTTL = 7 * 24 * time.Hour
)

// ErrPasskeyLinkInvalid is a link used, expired, superseded or never issued:
// one answer for all, since telling them apart helps only a guesser.
var ErrPasskeyLinkInvalid = errors.New("this link has been used, has expired or was never issued")

// PasskeyLink is a live link.
type PasskeyLink struct {
	ID        string
	UserID    string
	OrgID     string
	ExpiresAt time.Time
}

// IssuePasskeyLink creates a link for a person, ending any they had that was
// not used, and queues the email that carries it (NoticePasskeyLink), in tx.
func IssuePasskeyLink(ctx context.Context, tx pgx.Tx, userID, orgID string, ttl time.Duration) (PasskeyLink, error) {
	if ttl == 0 {
		ttl = DefaultPasskeyLinkTTL
	}
	if ttl < time.Minute || ttl > MaxPasskeyLinkTTL {
		return PasskeyLink{}, fmt.Errorf("a passkey link lives from a minute to %s, not %s", MaxPasskeyLinkTTL, ttl)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.passkey_links WHERE user_id = $1::uuid AND used_at IS NULL`,
		userID); err != nil {
		return PasskeyLink{}, fmt.Errorf("ending an earlier passkey link: %w", err)
	}
	l := PasskeyLink{UserID: userID, OrgID: orgID}
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.passkey_links (org_id, user_id, expires_at)
		VALUES ($1::uuid, $2::uuid, now() + $3::interval)
		RETURNING id::text, expires_at`, orgID, userID, ttl.String()).Scan(&l.ID, &l.ExpiresAt); err != nil {
		return PasskeyLink{}, fmt.Errorf("issuing a passkey link: %w", err)
	}
	if err := EnqueueAccountNotice(ctx, tx, AccountNotice{UserID: userID, Notice: NoticePasskeyLink,
		LinkID: l.ID}); err != nil {
		return PasskeyLink{}, err
	}
	return l, nil
}

// MintPasskeyLinkToken gives a live link a fresh token, keeping only its hash,
// for the email about to carry it. A resend mints another, and the one before
// stops working. ErrPasskeyLinkInvalid for a link no longer live.
func MintPasskeyLinkToken(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, linkID string) (token string, expires time.Time, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	err = db.QueryRow(ctx, `
		UPDATE core.passkey_links SET token_hash = $2
		 WHERE id = $1::uuid AND used_at IS NULL AND expires_at > now()
		RETURNING expires_at`, linkID, HashToken(token)).Scan(&expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, ErrPasskeyLinkInvalid
	}
	return token, expires, err
}

// FindPasskeyLink reads the live link a token belongs to. A link for an
// account deactivated since it was issued is no longer live.
func FindPasskeyLink(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, token string) (PasskeyLink, error) {
	var l PasskeyLink
	if token == "" {
		return l, ErrPasskeyLinkInvalid
	}
	err := db.QueryRow(ctx, `
		SELECT l.id::text, l.user_id::text, l.org_id::text, l.expires_at
		  FROM core.passkey_links l JOIN core.users u ON u.id = l.user_id AND u.status = 'active'
		 WHERE l.token_hash = $1 AND l.used_at IS NULL AND l.expires_at > now()
		   AND `+OrgInService("u.org_id"), HashToken(token)).
		Scan(&l.ID, &l.UserID, &l.OrgID, &l.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return l, ErrPasskeyLinkInvalid
	}
	return l, err
}

// SpendPasskeyLink marks a person's link used, in the transaction that stores
// the passkey it was for, so one link registers one passkey even when two
// browsers finish at once.
func SpendPasskeyLink(ctx context.Context, tx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, linkID, userID string) error {
	tag, err := tx.Exec(ctx, `UPDATE core.passkey_links l SET used_at = now()
		WHERE l.id = $1::uuid AND l.user_id = $2::uuid AND l.used_at IS NULL AND l.expires_at > now()
		  AND EXISTS (SELECT 1 FROM core.users u WHERE u.id = l.user_id AND u.status = 'active')`,
		linkID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrPasskeyLinkInvalid
	}
	return nil
}
