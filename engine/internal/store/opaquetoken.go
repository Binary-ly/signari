package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// An opaque access token is a reference to the signed one (9.16): what a client gets is a
// random handle, and the token it stands for is kept here sealed under a key only that
// handle gives. Everything that verifies a token goes on verifying that same token, so
// revocation, audience and binding need nothing new, and neither the handle nor anything
// usable is in the row.

// OpaqueTokenPrefix marks a handle, so a token is told from a JWT without a query and a
// leaked one can be found by what it looks like.
const OpaqueTokenPrefix = "sgo_"

const opaqueTokenContext = "signari opaque access token"

// NewOpaqueToken stores a signed token and answers the handle that stands for it, with
// the signed token's own expiry.
func NewOpaqueToken(ctx context.Context, q Execer, orgID, clientID, signed string, expires time.Time) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	handle := OpaqueTokenPrefix + base64.RawURLEncoding.EncodeToString(random)
	sealed, err := sealUnder([]byte(handle), opaqueTokenContext, []byte(signed), nil)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(handle))
	if _, err := q.Exec(ctx, `
		INSERT INTO core.opaque_access_tokens (token_hash, org_id, client_id, sealed, expires_at)
		VALUES ($1, $2::uuid, $3, $4, $5)`, sum[:], orgID, clientID, sealed, expires); err != nil {
		return "", fmt.Errorf("storing an opaque access token: %w", err)
	}
	return handle, nil
}

// ErrNoOpaqueToken is a handle with nothing behind it: never issued, or past its expiry.
var ErrNoOpaqueToken = errors.New("no such opaque access token")

// OpenOpaqueToken answers the signed token a handle stands for.
func OpenOpaqueToken(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, handle string) (string, error) {
	if !strings.HasPrefix(handle, OpaqueTokenPrefix) {
		return "", ErrNoOpaqueToken
	}
	sum := sha256.Sum256([]byte(handle))
	var sealed []byte
	err := q.QueryRow(ctx, `SELECT sealed FROM core.opaque_access_tokens
		WHERE token_hash = $1 AND expires_at > now()`, sum[:]).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoOpaqueToken
	}
	if err != nil {
		return "", fmt.Errorf("reading an opaque access token: %w", err)
	}
	plain, err := openUnder([]byte(handle), opaqueTokenContext, sealed, nil)
	if err != nil {
		return "", ErrNoOpaqueToken
	}
	return string(plain), nil
}

// PurgeExpiredOpaqueTokens drops handles past their expiry, which refuse anyway.
func PurgeExpiredOpaqueTokens(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.opaque_access_tokens WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.opaque_access_tokens WHERE expires_at < now()
		LIMIT $1 FOR UPDATE SKIP LOCKED))`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
