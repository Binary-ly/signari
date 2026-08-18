package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Attestation-Based Client Authentication storage:
// draft-ietf-oauth-attestation-based-client-auth-10.

// ChallengeLifetime bounds how long a §6 challenge stays answerable.
//
// Short, because the client fetches one and uses it immediately -- §6.1 has it
// retrieve a challenge and put it straight into the next PoP. Anything longer is
// a window in which a challenge captured from the wire is still usable.
const ChallengeLifetime = 2 * time.Minute

// TrustedAttesters returns the JWKS of every Client Attester an organisation
// trusts, merged into one set.
//
// Merged rather than tried in order: §7.1 rule 4 asks only whether the signature
// verifies with a known and trusted attester, not which. Returning the raw JSON
// so the caller can hand it to go-jose without this package importing JOSE.
func TrustedAttesters(ctx context.Context, db *pgxpool.Pool, orgID string) ([]json.RawMessage, error) {
	rows, err := db.Query(ctx,
		`SELECT jwks FROM core.client_attesters WHERE org_id = $1::uuid ORDER BY name`, orgID)
	if err != nil {
		return nil, fmt.Errorf("reading trusted client attesters: %w", err)
	}
	defer rows.Close()

	var out []json.RawMessage
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(raw))
	}
	return out, rows.Err()
}

// NewAttestationChallenge mints a §6.1 challenge and stores only its hash.
func NewAttestationChallenge(ctx context.Context, db *pgxpool.Pool, orgID string) (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	challenge := base64.RawURLEncoding.EncodeToString(b)

	if _, err := db.Exec(ctx, `
		INSERT INTO core.attestation_challenges (challenge_hash, org_id, expires_at)
		VALUES ($1, $2::uuid, now() + $3::interval)`,
		HashToken(challenge), orgID, ChallengeLifetime.String()); err != nil {
		return "", fmt.Errorf("recording an attestation challenge: %w", err)
	}
	return challenge, nil
}

// ClaimAttestationChallenge consumes a challenge, once.
//
// The check and the claim are one statement, so two requests presenting the same
// challenge cannot both succeed -- the same technique authorization codes and
// credential nonces use here, and for the same reason: single use is what makes a
// captured proof worthless rather than merely short-lived.
//
// Returns false for unknown, expired and already-used alike. The client's remedy
// is identical in all three cases (fetch a fresh challenge), and distinguishing
// them would tell an attacker which of their guesses had ever been valid.
func ClaimAttestationChallenge(ctx context.Context, db *pgxpool.Pool, challenge string) (bool, error) {
	tag, err := db.Exec(ctx, `
		UPDATE core.attestation_challenges SET used_at = now()
		WHERE challenge_hash = $1 AND used_at IS NULL AND expires_at > now()`,
		HashToken(challenge))
	if err != nil {
		return false, fmt.Errorf("claiming an attestation challenge: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// PurgeExpiredAttestationChallenges is the janitor's share of this table.
func PurgeExpiredAttestationChallenges(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.attestation_challenges WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
