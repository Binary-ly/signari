package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// LockConfigVersion takes core.config_version's row in tx, before anything
// else a configuration write locks.
//
// Every writer that moves the version takes this row before any other lock, so
// no two of them can each hold what the other waits for. A transaction that
// moves the version holds the row and more besides: the rows it writes, an
// organisation's identifier lock (core.users' trigger), the audit chain's
// advisory lock (audit.Write). Two that take the row and one of those in
// opposite orders deadlock, and PostgreSQL ends one of them a second later.
//
// So the Admin API's mutate, `signari apply` and anything else that bumps the
// version itself call this before they write. A CLI statement takes the row
// before it does anything, through migration 0307's trigger, which runs before
// the statement, and core.audit_append takes it before the chain's lock in a
// CLI session. A read fires no trigger: a CLI transaction that locks a row with
// SELECT ... FOR UPDATE, or takes an advisory lock, before its first write
// calls this first too.
//
// Twice it was otherwise. The Admin API took the chain lock inside fn and the
// row at the end (4.25). Then 0139's trigger ran after the statement, when the
// rows it wrote were already held, and a CLI write and an Admin API write to
// the same client, provider or organisation deadlocked.
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
