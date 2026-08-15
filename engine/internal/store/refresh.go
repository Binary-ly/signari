package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrRefreshReused means the refresh token had already been rotated away. The
// caller MUST revoke the entire family: either the token leaked or the client is
// broken, and rotation without reuse detection is just churn.
var ErrRefreshReused = errors.New("refresh token has already been used")

// ErrRefreshInvalid means unknown, expired, or belonging to a revoked family.
var ErrRefreshInvalid = errors.New("refresh token is invalid")

// RefreshGrant is what a successful rotation yields.
type RefreshGrant struct {
	FamilyID  string
	ClientID  string
	UserID    string
	SessionID string
	OrgID     string
	Scopes    []string
	Resources []string
}

// NewRefreshFamily starts a lineage for one (client, user, session).
//
// The family is the unit of revocation. Revoking only the replayed token would
// leave the thief's successor working, which is the whole reason rotation exists.
func NewRefreshFamily(ctx context.Context, tx pgx.Tx, orgID, clientID, userID, sid string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO core.refresh_token_families (org_id, client_id, user_id, sid)
		VALUES ($1,$2,$3,$4) RETURNING id::text`, orgID, clientID, userID, sid).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("creating refresh family: %w", err)
	}
	return id, nil
}

// IssueRefreshToken stores a token in a family. Only the hash is persisted.
func IssueRefreshToken(ctx context.Context, tx pgx.Tx, familyID string, hash []byte,
	scopes, resources []string, ttl time.Duration) error {

	if resources == nil {
		resources = []string{}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO core.refresh_tokens (token_hash, family_id, scopes, resources, expires_at)
		VALUES ($1,$2,$3,$4, now() + $5::interval)`,
		hash, familyID, scopes, resources, ttl.String())
	if err != nil {
		return fmt.Errorf("issuing refresh token: %w", err)
	}
	return nil
}

// RotateRefreshToken atomically consumes a refresh token and returns its grant.
//
// Same technique as authorization codes: the single-use guarantee lives in the
// WHERE clause, so two concurrent refreshes cannot both succeed. It additionally
// joins the family and the session, because a refresh token must stop working the
// moment its family is revoked, its session ends, or its user is deactivated --
// none of which touch the token row itself.
func RotateRefreshToken(ctx context.Context, tx pgx.Tx, hash []byte) (*RefreshGrant, error) {
	var g RefreshGrant
	err := tx.QueryRow(ctx, `
		UPDATE core.refresh_tokens rt
		SET consumed_at = now()
		FROM core.refresh_token_families f
		JOIN core.users u ON u.id = f.user_id
		LEFT JOIN core.sessions s ON s.sid = f.sid
		WHERE rt.token_hash = $1
		  AND rt.consumed_at IS NULL
		  AND rt.expires_at  > now()
		  AND rt.family_id   = f.id
		  AND f.revoked_at IS NULL
		  AND u.status = 'active'
		  AND (s.sid IS NULL OR (s.revoked_at IS NULL AND s.not_after > now()))
		RETURNING f.id::text, f.client_id, f.user_id::text,
		          COALESCE(f.sid, ''), f.org_id::text, rt.scopes, rt.resources`, hash).
		Scan(&g.FamilyID, &g.ClientID, &g.UserID, &g.SessionID, &g.OrgID, &g.Scopes, &g.Resources)

	if errors.Is(err, pgx.ErrNoRows) {
		// Distinguish "already rotated" from every other failure. Only reuse
		// warrants destroying the lineage; an expired token is just expired.
		var consumed bool
		e := tx.QueryRow(ctx,
			`SELECT consumed_at IS NOT NULL FROM core.refresh_tokens WHERE token_hash = $1`, hash).
			Scan(&consumed)
		if e == nil && consumed {
			return nil, ErrRefreshReused
		}
		return nil, ErrRefreshInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("rotating refresh token: %w", err)
	}
	return &g, nil
}

// LinkSuccessor records which token replaced another, so an audit can walk a
// lineage after the fact and see exactly where a replay entered it.
func LinkSuccessor(ctx context.Context, tx pgx.Tx, oldHash, newHash []byte) error {
	_, err := tx.Exec(ctx,
		`UPDATE core.refresh_tokens SET successor_hash = $2 WHERE token_hash = $1`, oldHash, newHash)
	return err
}

// RevokeFamilyByToken kills the entire lineage a token belongs to. Called on
// reuse detection.
func RevokeFamilyByToken(ctx context.Context, tx pgx.Tx, hash []byte, reason string) (int64, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE core.refresh_token_families f
		SET revoked_at = now(), revocation_reason = $2
		FROM core.refresh_tokens rt
		WHERE rt.token_hash = $1 AND rt.family_id = f.id AND f.revoked_at IS NULL`,
		hash, reason)
	if err != nil {
		return 0, fmt.Errorf("revoking refresh family: %w", err)
	}
	return tag.RowsAffected(), nil
}
