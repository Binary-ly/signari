package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SpendCeremonyChallenge records a WebAuthn challenge as used and reports
// whether this was its first use.
//
// One statement, so two requests carrying the same captured ceremony cannot
// both be told they are the first. Migration 0141 explains why the signed
// cookie the challenge travels in is not enough on its own.
func SpendCeremonyChallenge(ctx context.Context, db *pgxpool.Pool, challenge string, expiresAt time.Time) (bool, error) {
	h := sha256.Sum256([]byte(challenge))
	var inserted bool
	err := db.QueryRow(ctx, `
		INSERT INTO core.webauthn_spent_challenges (challenge_hash, expires_at)
		VALUES ($1, $2)
		ON CONFLICT (challenge_hash) DO NOTHING
		RETURNING true`, h[:], expiresAt).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// SweepSpentCeremonies drops challenge records past their window.
func SweepSpentCeremonies(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.webauthn_spent_challenges WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
