package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/oid4vci"
)

// OID4VCI credential configurations and c_nonce values.

// ErrNonceUnknown means the c_nonce was never issued, has expired, or was used.
var ErrNonceUnknown = errors.New("this c_nonce is not valid")

// CredentialConfigurations loads what an organisation issues.
func CredentialConfigurations(ctx context.Context, db Querier, orgID string) (map[string]oid4vci.Configuration, error) {
	rows, err := db.Query(ctx, `
		SELECT config_id, format, vct, always_claims, selective_claims,
		       COALESCE(EXTRACT(EPOCH FROM lifetime), 0)::bigint,
		       COALESCE(display_name, '')
		FROM core.credential_configurations
		WHERE org_id = $1::uuid
		ORDER BY config_id`, orgID)
	if err != nil {
		return nil, fmt.Errorf("loading credential configurations: %w", err)
	}
	defer rows.Close()

	out := map[string]oid4vci.Configuration{}
	for rows.Next() {
		var c oid4vci.Configuration
		var seconds int64
		if err := rows.Scan(&c.ID, &c.Format, &c.VCT, &c.AlwaysClaims,
			&c.SelectiveClaims, &seconds, &c.DisplayName); err != nil {
			return nil, err
		}
		c.Lifetime = time.Duration(seconds) * time.Second
		out[c.ID] = c
	}
	return out, rows.Err()
}

// NewCredentialNonce mints a c_nonce (§7.2).
//
// Returns the value to hand the wallet; only its hash is stored, for the same
// reason authorization codes are hashed — a nonce is a single-use credential
// against the credential endpoint, and read access to the table must not be
// issuance capability.
func NewCredentialNonce(ctx context.Context, db Execer, ttl time.Duration) (string, error) {

	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)
	if _, err := db.Exec(ctx, `
		INSERT INTO core.credential_nonces (nonce_hash, expires_at)
		VALUES ($1, now() + $2::interval)`,
		HashToken(nonce), ttl.String()); err != nil {
		return "", fmt.Errorf("recording the c_nonce: %w", err)
	}
	return nonce, nil
}

// ClaimCredentialNonce spends a c_nonce, atomically.
//
// Single use, in the statement that reads it. §8.2 has the nonce establish
// freshness, and a nonce that can be presented twice establishes it once.
func ClaimCredentialNonce(ctx context.Context, db Execer, nonce string) error {
	if nonce == "" {
		return ErrNonceUnknown
	}
	tag, err := db.Exec(ctx, `
		UPDATE core.credential_nonces SET used_at = now()
		WHERE nonce_hash = $1 AND used_at IS NULL AND expires_at > now()`,
		HashToken(nonce))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNonceUnknown
	}
	return nil
}

// CredentialSubject loads the claim values for one person.
//
// Deliberately a small, fixed set rather than "whatever is in the row": every
// value here ends up inside a credential the holder can present anywhere, so
// what may appear is a decision, not a projection of the schema.
func CredentialSubject(ctx context.Context, db *pgxpool.Pool, userID string) (map[string]any, error) {
	var email, username string
	var emailVerified bool
	err := db.QueryRow(ctx, `
		SELECT COALESCE(email,''), COALESCE(username, email, ''),
		       email_verified_at IS NOT NULL
		FROM core.users WHERE id = $1::uuid`, userID).
		Scan(&email, &username, &emailVerified)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("no such user")
		}
		return nil, err
	}
	out := map[string]any{"sub": userID}
	if email != "" {
		out["email"] = email
		out["email_verified"] = emailVerified
	}
	if username != "" {
		out["preferred_username"] = username
	}
	return out, nil
}

// AllCredentialConfigurations lists every configuration in the deployment.
//
// Not scoped to an organisation, for the same reason the discovery document's
// `authorization_details_types_supported` is not: metadata is published per
// ISSUER, and a deployment serves one. Scoping it would mean the unauthenticated
// metadata endpoint guessing which tenant is asking, and a wallet reading a
// document that describes only some of what the issuer offers.
func AllCredentialConfigurations(ctx context.Context, db Querier) (map[string]oid4vci.Configuration, error) {
	rows, err := db.Query(ctx, `
		SELECT DISTINCT ON (config_id)
		       config_id, format, vct, always_claims, selective_claims,
		       COALESCE(EXTRACT(EPOCH FROM lifetime), 0)::bigint,
		       COALESCE(display_name, '')
		FROM core.credential_configurations
		ORDER BY config_id`)
	if err != nil {
		return nil, fmt.Errorf("listing credential configurations: %w", err)
	}
	defer rows.Close()

	out := map[string]oid4vci.Configuration{}
	for rows.Next() {
		var c oid4vci.Configuration
		var seconds int64
		if err := rows.Scan(&c.ID, &c.Format, &c.VCT, &c.AlwaysClaims,
			&c.SelectiveClaims, &seconds, &c.DisplayName); err != nil {
			return nil, err
		}
		c.Lifetime = time.Duration(seconds) * time.Second
		out[c.ID] = c
	}
	return out, rows.Err()
}
