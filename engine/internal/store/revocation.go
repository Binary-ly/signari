package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RevokeJTI denylists one access token by its jti.
//
// Idempotent: revoking twice is not an error. RFC 7009 requires that a client
// revoking an already-revoked token still gets a success, and a client that
// retries after a timeout must not be punished for it.
func RevokeJTI(ctx context.Context, tx pgx.Tx, jti, clientID string, expiresAt time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.revoked_jtis (jti, client_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti) DO NOTHING`, jti, clientID, expiresAt)
	if err != nil {
		return fmt.Errorf("revoking jti: %w", err)
	}
	return nil
}

// JTIRevoked reports whether an access token has been revoked.
//
// On a database error this returns TRUE. That is deliberate and it is the whole
// point of the function: the caller is asking "may I honour this credential",
// and the safe answer when we cannot tell is no. Returning false on error would
// turn a database blip into a window where revoked tokens are accepted -- a
// fail-open on exactly the check that exists to fail closed.
func JTIRevoked(ctx context.Context, db *pgxpool.Pool, jti string) (bool, error) {
	if jti == "" {
		// A token with no jti cannot be individually revoked. Treat it as
		// revoked rather than guess: every token we mint has one, so an absent
		// jti means the token did not come from us in the shape we expect.
		return true, fmt.Errorf("access token has no jti")
	}
	var exists bool
	err := db.QueryRow(ctx,
		`SELECT true FROM core.revoked_jtis WHERE jti = $1`, jti).Scan(&exists)
	switch {
	case err == pgx.ErrNoRows:
		return false, nil
	case err != nil:
		return true, fmt.Errorf("checking revocation: %w", err)
	default:
		return exists, nil
	}
}

// PurgeExpiredRevocations drops denylist rows for tokens that have expired on
// their own. Keeping them would make the table grow forever while proving
// nothing: an expired token is rejected on its expiry regardless.
func PurgeExpiredRevocations(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.revoked_jtis WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeRefreshToken revokes the family a refresh token belongs to, if that
// family belongs to the given client.
//
// The whole family, not the single token: the family IS the grant, and leaving
// siblings alive would mean a "revoked" token whose successor still works. The
// client_id check is what stops one client revoking another's grants by
// presenting a token it happened to obtain.
//
// Returns whether anything was revoked. A miss is not an error -- RFC 7009 §2.2
// requires 200 for an unknown token, because distinguishing "unknown" from
// "revoked" is a token-guessing oracle.
func RevokeRefreshToken(ctx context.Context, tx pgx.Tx, tokenHash []byte, clientID string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE core.refresh_token_families f
		SET revoked_at = now(), revocation_reason = 'revoked_by_client'
		FROM core.refresh_tokens t
		WHERE t.token_hash = $1
		  AND t.family_id = f.id
		  AND f.client_id = $2
		  AND f.revoked_at IS NULL`, tokenHash, clientID)
	if err != nil {
		return false, fmt.Errorf("revoking refresh token family: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// RefreshTokenState is what introspection needs to answer for a refresh token.
type RefreshTokenState struct {
	Found     bool
	Active    bool
	ClientID  string
	UserID    string
	SID       string
	Scopes    []string
	ExpiresAt time.Time
}

// LookupRefreshToken reads a refresh token's state for introspection.
//
// Active requires all four: the row exists, it has not been consumed (rotation
// means a consumed token is spent), its family is live, and it has not expired.
// Reporting active on a consumed token would tell a thief their stolen token is
// still good.
func LookupRefreshToken(ctx context.Context, db *pgxpool.Pool, tokenHash []byte) (RefreshTokenState, error) {
	var st RefreshTokenState
	var consumed *time.Time
	var familyRevoked *time.Time
	var sid *string

	err := db.QueryRow(ctx, `
		SELECT f.client_id, f.user_id::text, f.sid, t.scopes, t.expires_at,
		       t.consumed_at, f.revoked_at
		FROM core.refresh_tokens t
		JOIN core.refresh_token_families f ON f.id = t.family_id
		WHERE t.token_hash = $1`, tokenHash).
		Scan(&st.ClientID, &st.UserID, &sid, &st.Scopes, &st.ExpiresAt, &consumed, &familyRevoked)
	if err == pgx.ErrNoRows {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("looking up refresh token: %w", err)
	}

	st.Found = true
	if sid != nil {
		st.SID = *sid
	}
	st.Active = consumed == nil && familyRevoked == nil && time.Now().Before(st.ExpiresAt)
	return st, nil
}

// SessionLive reports whether a session is still usable.
//
// Introspection consults this so that signing out actually invalidates the
// access tokens issued from that session. Without it, "active" would mean only
// "correctly signed and not yet expired", which is the weak answer that makes
// introspection worth little.
func SessionLive(ctx context.Context, db *pgxpool.Pool, sid string) (bool, error) {
	if sid == "" {
		// Client-credentials tokens have no session. Absence of a session is not
		// evidence of revocation for those, so the caller decides -- this
		// function only answers about tokens that claim one.
		return false, nil
	}
	var live bool
	err := db.QueryRow(ctx, `
		SELECT revoked_at IS NULL AND not_after > now()
		FROM core.sessions WHERE sid = $1`, sid).Scan(&live)
	switch {
	case err == pgx.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("checking session: %w", err)
	default:
		return live, nil
	}
}

// GrantRevoked reports whether the refresh token family an access token was
// minted from has been revoked.
//
// RFC 7009 §2.1's cascade: revoking a refresh token SHOULD invalidate "all
// access tokens based on the same authorization grant". Revocation is otherwise
// recorded per-jti, and nothing links a minted access token back to its grant,
// so the cascade had nowhere to land -- the access tokens simply ran to
// expiry.
//
// Fails CLOSED on a database error, like JTIRevoked beside it: a checkpoint that
// cannot determine whether a grant is live must not answer that it is.
func GrantRevoked(ctx context.Context, db *pgxpool.Pool, grantID string) (bool, error) {
	if grantID == "" {
		// No grant to check. Tokens from an authorization with no refresh token
		// carry no gid, and there is no refresh token whose revocation could
		// cascade to them.
		return false, nil
	}
	var revoked bool
	err := db.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM core.refresh_token_families WHERE id = $1::uuid`,
		grantID).Scan(&revoked)
	switch {
	case err == pgx.ErrNoRows:
		// The family is gone. Treat as revoked: a token naming a grant this
		// server cannot find is not one to honour.
		return true, nil
	case err != nil:
		return true, fmt.Errorf("checking grant revocation: %w", err)
	}
	return revoked, nil
}
