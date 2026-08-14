package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MarkDPoPProofSeen records a proof and reports whether it is fresh.
//
// Returns false when this (key, jti) pair has been seen before -- a replay.
// Single statement, so two concurrent requests carrying the same captured proof
// cannot both be told they are the first.
func MarkDPoPProofSeen(ctx context.Context, db *pgxpool.Pool, jkt, jti string, ttl time.Duration) (bool, error) {
	var inserted bool
	err := db.QueryRow(ctx, `
		INSERT INTO core.dpop_seen_jtis (jkt, jti, expires_at)
		VALUES ($1, $2, now() + $3::interval)
		ON CONFLICT (jkt, jti) DO NOTHING
		RETURNING true`, jkt, jti, ttl.String()).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// SweepExpiredDPoPProofs drops proof records past their window.
func SweepExpiredDPoPProofs(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.dpop_seen_jtis WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
