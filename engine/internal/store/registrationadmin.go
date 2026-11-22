package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
)

// The writes behind `signari registration` and the Admin API's registration
// routes (6.07), one implementation for both.

// DefaultRegistrationScopes are what a registered client may ask for when the
// policy names none.
var DefaultRegistrationScopes = []string{"openid", "profile", "email"}

// DefaultRegistrationCeiling is how many clients registration may make when
// the policy names no ceiling.
const DefaultRegistrationCeiling = 100

// SetRegistrationPolicy turns dynamic registration on with the whole policy.
// Written whole each time, so confidential registration is off again unless
// asked for again: the safe direction for a setting that hands out secrets.
func SetRegistrationPolicy(ctx context.Context, tx Execer, orgID string, p RegistrationPolicy) error {
	if len(p.AllowedScopes) == 0 {
		p.AllowedScopes = DefaultRegistrationScopes
	}
	if p.MaxClients <= 0 {
		p.MaxClients = DefaultRegistrationCeiling
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO core.registration_policies
			(org_id, enabled, open, max_clients, allowed_scopes, allow_confidential)
		VALUES ($1::uuid, true, $2, $3, $4, $5)
		ON CONFLICT (org_id) DO UPDATE SET
			enabled = true, open = EXCLUDED.open, max_clients = EXCLUDED.max_clients,
			allowed_scopes = EXCLUDED.allowed_scopes,
			allow_confidential = EXCLUDED.allow_confidential, updated_at = now()`,
		orgID, p.Open, p.MaxClients, p.AllowedScopes, p.AllowConfidential)
	return err
}

// DisableRegistration turns dynamic registration off, keeping its policy and
// tokens for when it is turned on again, and reports whether it was on.
func DisableRegistration(ctx context.Context, tx Execer, orgID string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE core.registration_policies SET enabled = false, updated_at = now()
		WHERE org_id = $1::uuid AND enabled`, orgID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RegistrationToken is one initial access token, never its secret.
type RegistrationToken struct {
	ID        string
	Name      string
	Remaining *int
	ExpiresAt *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// RegistrationTokens lists an organisation's initial access tokens, newest
// first.
func RegistrationTokens(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]RegistrationToken, error) {
	rows, err := q.Query(ctx, `SELECT id::text, name, remaining, expires_at, revoked_at, created_at
		FROM core.registration_tokens WHERE org_id = $1::uuid ORDER BY created_at DESC, id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RegistrationToken{}
	for rows.Next() {
		var t RegistrationToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Remaining, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// NewRegistrationToken mints an initial access token, returning its secret,
// which is kept only as a hash. uses 0 is unlimited; expires nil is never.
func NewRegistrationToken(ctx context.Context, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, name string, uses int, expires *time.Time) (secret, id string, err error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", err
	}
	secret = "sgnreg_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	var remaining *int
	if uses > 0 {
		remaining = &uses
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO core.registration_tokens (org_id, name, token_hash, remaining, expires_at)
		VALUES ($1::uuid, $2, $3, $4, $5) RETURNING id::text`,
		orgID, name, sum[:], remaining, expires).Scan(&id)
	return secret, id, err
}

// RevokeRegistrationToken stops one of an organisation's tokens, reporting
// whether there was a live one to stop.
func RevokeRegistrationToken(ctx context.Context, tx Execer, orgID, id string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE core.registration_tokens SET revoked_at = now()
		WHERE org_id = $1::uuid AND id::text = $2 AND revoked_at IS NULL`, orgID, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
