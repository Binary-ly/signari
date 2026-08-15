package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// TokenPrefix marks an admin token on sight.
//
// Worth the eight characters: it lets a secret scanner recognise one in a commit
// or a log, and it tells whoever finds a loose string what they are holding. A
// credential nobody can identify is one nobody reports.
const TokenPrefix = "sgnadm_"

// NewToken mints an admin token and returns the secret ONCE.
//
// The plaintext is never stored and cannot be recovered. That is not an
// inconvenience to work around: a table of live administrative credentials is
// exactly what a database backup, a replica, or a support dump must not contain.
func NewToken(ctx context.Context, conn interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, name, orgID string, scopes []string, expires *time.Time) (secret, id string, err error) {

	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", fmt.Errorf("give the token a name; it appears in the audit trail, " +
			"and \"which token was that\" is unanswerable without one")
	}
	if len(scopes) == 0 {
		return "", "", fmt.Errorf("give at least one scope: %s",
			strings.Join(KnownScopes, ", "))
	}
	for _, sc := range scopes {
		if sc == ScopeAll {
			return "", "", fmt.Errorf("%q cannot be granted to a stored token. A saved "+
				"credential that can do everything is what scopes exist to replace; if "+
				"you need one, that is the break-glass environment token", ScopeAll)
		}
		if !slices.Contains(KnownScopes, sc) {
			return "", "", fmt.Errorf("unknown scope %q; known scopes are %s",
				sc, strings.Join(KnownScopes, ", "))
		}
	}

	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", fmt.Errorf("generating a token: %w", err)
	}
	secret = TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))

	err = conn.QueryRow(ctx, `
		INSERT INTO core.admin_tokens (org_id, name, token_hash, scopes, expires_at)
		VALUES (NULLIF($1,'')::uuid, $2, $3, $4, $5)
		RETURNING id::text`,
		orgID, name, sum[:], scopes, expires).Scan(&id)
	if err != nil {
		return "", "", err
	}
	return secret, id, nil
}
