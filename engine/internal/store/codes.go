// Package store is the engine's persistence layer for protocol state.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oauth"
)

// ErrCodeReused means the authorization code had already been consumed. The
// caller MUST revoke the associated token family: either the code leaked or the
// client is broken, and both warrant killing the tokens.
var ErrCodeReused = errors.New("authorization code has already been used")

// ErrCodeUnknown means no such code.
var ErrCodeUnknown = errors.New("authorization code is unknown")

// NewCode returns a fresh authorization code and its storage hash.
//
// Only the hash is stored. A database read -- a backup, a log of a slow query, a
// compromised replica -- must not yield usable codes. Same reasoning as password
// storage, applied to bearer values.
func NewCode() (code string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", nil, fmt.Errorf("generating authorization code: %w", err)
	}
	code = base64.RawURLEncoding.EncodeToString(b)
	return code, HashToken(code), nil
}

// HashToken is the one-way transform applied to every bearer value before it
// touches the database.
//
// SHA-256 with no salt or work factor is correct here and would be wrong for a
// password: these values are 256 bits of uniform entropy, so there is no
// dictionary to attack and a work factor would only slow the hot path.
func HashToken(v string) []byte {
	sum := sha256.Sum256([]byte(v))
	return sum[:]
}

// IssueCode stores an authorization code.
func IssueCode(ctx context.Context, tx pgx.Tx, orgID, clientID, sid, userID string,
	g oauth.GrantRecord, hash []byte, resources []string) error {

	// A nil slice marshals to SQL NULL, which overrides the column's DEFAULT '{}'
	// and trips the NOT NULL constraint. "No resources requested" is an empty
	// array, not an absent value.
	if resources == nil {
		resources = []string{}
	}

	_, err := tx.Exec(ctx, `
		INSERT INTO core.authorization_codes
			(code_hash, org_id, client_id, sid, user_id, redirect_uri, scopes,
			 code_challenge, code_challenge_method, nonce, resources, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		hash, orgID, clientID, sid, userID, g.RedirectURI, g.Scopes,
		// NULL, not "", when the client did not use PKCE. The database enforces
		// that the challenge and its method are both present or both absent.
		nullIfEmpty(g.CodeChallenge), nullIfEmpty(g.CodeChallengeMethod),
		nullIfEmpty(g.Nonce), resources, g.ExpiresAt)
	if err != nil {
		return fmt.Errorf("issuing authorization code: %w", err)
	}
	return nil
}

// ConsumedCode is what a successful redemption yields.
type ConsumedCode struct {
	oauth.GrantRecord
	OrgID     string
	SessionID string
	UserID    string
	Resources []string
}

// ConsumeCode atomically marks a code used and returns it.
//
// The single-use guarantee lives in the WHERE clause, not in application logic:
//
//	UPDATE ... SET consumed_at = now() WHERE code_hash = $1 AND consumed_at IS NULL
//
// Two concurrent redemptions both reach the database; exactly one updates a row.
// A read-then-write in Go would let both pass the check and both mint tokens,
// and the window is exactly as wide as your latency to Postgres.
//
// A zero-row update means the code is either unknown or already spent, and those
// must be distinguished: the second case requires revoking the token family.
func ConsumeCode(ctx context.Context, tx pgx.Tx, hash []byte) (*ConsumedCode, error) {
	var c ConsumedCode
	var challenge, method, nonce *string
	err := tx.QueryRow(ctx, `
		UPDATE core.authorization_codes
		SET consumed_at = now()
		WHERE code_hash = $1 AND consumed_at IS NULL
		RETURNING org_id::text, client_id, sid, user_id::text, redirect_uri, scopes,
		          code_challenge, code_challenge_method, nonce, resources, expires_at`, hash).
		Scan(&c.OrgID, &c.ClientID, &c.SessionID, &c.UserID, &c.RedirectURI, &c.Scopes,
			&challenge, &method, &nonce, &c.Resources, &c.ExpiresAt)

	if errors.Is(err, pgx.ErrNoRows) {
		// Distinguish "never existed" from "already spent". Only the latter is a
		// revocation trigger.
		var exists bool
		if e := tx.QueryRow(ctx,
			`SELECT true FROM core.authorization_codes WHERE code_hash = $1`, hash).
			Scan(&exists); e == nil && exists {
			return nil, ErrCodeReused
		}
		return nil, ErrCodeUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("consuming authorization code: %w", err)
	}
	if challenge != nil {
		c.CodeChallenge = *challenge
	}
	if method != nil {
		c.CodeChallengeMethod = *method
	}
	if nonce != nil {
		c.Nonce = *nonce
	}
	return &c, nil
}

// nullIfEmpty maps "" to SQL NULL. An empty challenge is not a challenge, and
// storing it as "" is what broke the CHECK constraint that 0005 replaced.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// RevokeFamilyForCode kills every refresh-token family descended from a code's
// session and client. Called when ConsumeCode reports reuse.
func RevokeFamilyForCode(ctx context.Context, tx pgx.Tx, hash []byte) (int64, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE core.refresh_token_families f
		SET revoked_at = now(), revocation_reason = 'reuse_detected'
		FROM core.authorization_codes c
		WHERE c.code_hash = $1
		  AND f.client_id = c.client_id
		  AND f.sid = c.sid
		  AND f.revoked_at IS NULL`, hash)
	if err != nil {
		return 0, fmt.Errorf("revoking token families after code reuse: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PurgeExpiredCodes removes spent and expired codes. A singleton job, not
// something every node runs -- see ADR on what must not be horizontal.
func PurgeExpiredCodes(ctx context.Context, tx pgx.Tx, olderThan time.Duration) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.authorization_codes WHERE expires_at < now() - $1::interval`,
		olderThan.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
