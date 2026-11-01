package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Persisted claims tokens (UMA §3.3.5). One stands for "this person told this client
// who they are", so a later request need not ask them.

// PersistedClaimsLifetime is how long a PCT lasts. A month, as an ended session's
// row is kept: long enough to save a person being asked each time, and not so long
// that a token nobody has used for a season still speaks for them.
const PersistedClaimsLifetime = 30 * 24 * time.Hour

// ErrPersistedClaimsUnknown is a PCT that is no use here: unknown, ended, another
// client's, or about somebody no longer active. They are one answer, so that it
// says nothing about a token it is not the holder's to know about.
var ErrPersistedClaimsUnknown = errors.New("no such persisted claims token")

// NewPersistedClaims records a PCT and answers it, once.
func NewPersistedClaims(ctx context.Context, e Execer, orgID, clientID, userID string) (string, error) {
	token, hash, err := NewInvitationToken()
	if err != nil {
		return "", err
	}
	if _, err := e.Exec(ctx, `
		INSERT INTO core.uma_persisted_claims (org_id, client_id, user_id, token_hash, expires_at)
		VALUES ($1::uuid, $2, $3::uuid, $4, now() + $5::interval)`,
		orgID, clientID, userID, hash, fmt.Sprintf("%d seconds", int(PersistedClaimsLifetime.Seconds()))); err != nil {
		return "", fmt.Errorf("recording a persisted claims token: %w", err)
	}
	return token, nil
}

// PersonOfPersistedClaims answers who a PCT speaks for. §5.2: the server "MUST
// maintain the binding between the PCT and the client to which it was issued", and
// the person is read active here on every use, because a token is no reason to take
// somebody's word about an account that has since been closed.
func PersonOfPersistedClaims(ctx context.Context, q rowQuerier, token, clientID string) (string, error) {
	var userID string
	err := q.QueryRow(ctx, `
		SELECT u.id::text FROM core.uma_persisted_claims p
		  JOIN core.users u ON u.id = p.user_id AND u.status = 'active'
		 WHERE p.token_hash = $1 AND p.client_id = $2 AND p.expires_at > now()`,
		HashToken(token), clientID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPersistedClaimsUnknown
	}
	return userID, err
}

// RevokePersistedClaims ends a PCT for the client it was issued to, and answers
// whether it did and whose it was.
func RevokePersistedClaims(ctx context.Context, q rowQuerier, token, clientID string) (string, error) {
	var userID string
	err := q.QueryRow(ctx, `
		DELETE FROM core.uma_persisted_claims WHERE token_hash = $1 AND client_id = $2
		RETURNING user_id::text`, HashToken(token), clientID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return userID, err
}

// SweepExpiredPersistedClaims drops those past their time.
func SweepExpiredPersistedClaims(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.uma_persisted_claims WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.uma_persisted_claims WHERE expires_at < now() LIMIT $1 FOR UPDATE SKIP LOCKED))`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
