// Package janitor runs the periodic maintenance every OIDC provider needs and
// most of them forget until the disk fills.
//
// Three jobs, each of which is a real failure if it never runs:
//
//   - Expired sessions are TERMINATED, not merely ignored. A session past
//     not_after is dead to the engine already, but relying parties do not know
//     that until a back-channel logout notice reaches them. Skipping this is how
//     an application keeps a user "signed in" for hours after the IdP stopped
//     agreeing -- the single most common complaint about federated logout.
//   - Spent authorization codes are purged, or the table grows without bound.
//   - Parked logout notices are surfaced. A notice that exhausted its retries is
//     an RP whose session was never ended; nobody finds out unless someone looks.
//
// # Why this is a singleton
//
// Sweeping sessions has an observable side effect: it queues logout notices.
// Running it on every node would multiply that work by the node count and, worse,
// have several transactions racing to terminate the same sessions. A PostgreSQL
// advisory lock makes the pass exclusive across the whole cluster without needing
// a leader election, a scheduler, or a separate deployment unit.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sulimanbenhalim/idp/engine/internal/outbox"
	"github.com/sulimanbenhalim/idp/engine/internal/store"
)

// lockID identifies the janitor's advisory lock. Any constant works as long as
// it is stable and not shared with another job; it is namespaced by database.
const lockID int64 = 0x1D9_1A17

const (
	// DefaultInterval is how often a pass runs. Sessions expire continuously, so
	// the interval is really "how stale may an RP's view of a dead session be".
	// A minute keeps that bounded without making the lock hot.
	DefaultInterval = time.Minute

	// sessionBatch bounds one pass. Each terminated session queues notices inside
	// the same transaction, so an unbounded batch after an outage would build one
	// enormous transaction and hold row locks for the duration of it.
	sessionBatch = 500

	// codeRetention keeps spent codes around well past their expiry ON PURPOSE.
	//
	// Reuse detection reads the row: a replayed code is recognised because its
	// consumed_at is set, and recognising it is what revokes the whole token
	// family. Delete the row promptly and a replay degrades into a plain
	// "unknown code" -- still rejected, but the tokens the thief already holds
	// stay live. The row is tiny; the detection window is worth far more than
	// the storage.
	codeRetention = 24 * time.Hour
)

// Stats is one pass's result, for logging and for tests.
type Stats struct {
	SessionsSwept int
	CodesPurged   int64
	Parked        []string
	// Skipped means another node held the lock. Not an error, and deliberately
	// distinguished from "nothing to do" so a misconfigured cluster where every
	// pass is skipped is visible rather than looking idle.
	Skipped bool
}

// RunOnce performs a single maintenance pass, if this node can take the lock.
func RunOnce(ctx context.Context, db *pgxpool.Pool, log *slog.Logger) (Stats, error) {
	var st Stats

	tx, err := db.Begin(ctx)
	if err != nil {
		return st, fmt.Errorf("beginning janitor transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A TRANSACTION-scoped lock, not a session-scoped one: it is released by the
	// commit or rollback, so a node that dies mid-pass cannot leave the janitor
	// wedged for everyone. pg_try_advisory_lock would require an explicit unlock
	// on a pinned connection, which is exactly the thing that gets skipped on a
	// panic path.
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockID).Scan(&got); err != nil {
		return st, fmt.Errorf("taking janitor lock: %w", err)
	}
	if !got {
		st.Skipped = true
		return st, nil
	}

	if st.SessionsSwept, err = store.SweepExpiredSessions(ctx, tx, sessionBatch); err != nil {
		return st, fmt.Errorf("sweeping expired sessions: %w", err)
	}
	if st.CodesPurged, err = store.PurgeExpiredCodes(ctx, tx, codeRetention); err != nil {
		return st, fmt.Errorf("purging expired codes: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return st, fmt.Errorf("committing janitor pass: %w", err)
	}

	// Read AFTER the commit, on the pool rather than the transaction: this is
	// reporting, and it must not be able to roll back the work above.
	if parked, err := outbox.Parked(ctx, db); err != nil {
		log.Error("reading parked logout notices", "err", err)
	} else {
		st.Parked = parked
	}

	return st, nil
}

// Run loops until ctx is cancelled.
func Run(ctx context.Context, db *pgxpool.Pool, log *slog.Logger, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	log.Info("janitor started", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			log.Info("janitor stopped")
			return
		case <-t.C:
			st, err := RunOnce(ctx, db, log)
			switch {
			case errors.Is(err, context.Canceled):
				// Shutdown, not a fault.
			case err != nil:
				// Logged and retried on the next tick. A failed pass must never
				// take the process down: maintenance falling behind is an
				// operational problem, refusing to serve tokens is an outage.
				log.Error("janitor pass failed", "err", err)
			default:
				st.Log(log)
			}
		}
	}
}

// Log emits a pass at a level matched to whether anyone needs to act.
func (s Stats) Log(log *slog.Logger) {
	if s.Skipped {
		return
	}
	if s.SessionsSwept > 0 || s.CodesPurged > 0 {
		log.Info("janitor pass",
			"sessions_swept", s.SessionsSwept, "codes_purged", s.CodesPurged)
	}
	// WARN, and one line per RP. Each of these is a relying party that still
	// believes a signed-out user is signed in, which is a security fact an
	// operator has to see -- not a debug detail.
	for _, p := range s.Parked {
		log.Warn("back-channel logout gave up; the relying party was never notified", "detail", p)
	}
}
