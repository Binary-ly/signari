package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// LockConfigVersion takes core.config_version's row in tx, before anything
// else a configuration write locks.
//
// A transaction that will move the version and write an audit record holds
// two locks: the row, and the audit chain's advisory lock (audit.Write). Taken
// in opposite orders by two transactions, they deadlock. A CLI write takes the
// row at its first statement, through migration 0139's trigger, and the chain
// lock after, so the row-first order is the one every writer keeps: the Admin
// API's mutate, `signari apply` and anything else that bumps the version
// itself call this before they write. The Admin API took the chain lock first
// and the row at the end, and deadlocked with the CLI.
func LockConfigVersion(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM core.config_version WHERE id = true FOR UPDATE`); err != nil {
		return fmt.Errorf("locking the configuration version: %w", err)
	}
	return nil
}

// CurrentConfigVersion reads the version without locking it, for an answer
// computed from what follows: read first, so a write committed in between
// makes the version stale rather than the answer newer than its tag.
func CurrentConfigVersion(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (int64, error) {
	var v int64
	err := q.QueryRow(ctx, `SELECT version FROM core.config_version WHERE id = true`).Scan(&v)
	return v, err
}
