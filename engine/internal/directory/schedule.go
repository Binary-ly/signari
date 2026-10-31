package directory

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
)

// The shortest and longest wait between scheduled syncs. A directory read whole
// every minute is a load nobody asked for, and a week is as long as somebody who
// left should be able to go on signing in.
const (
	MinSyncInterval = 300
	MaxSyncInterval = 604800
)

// ScheduledSyncTimeout bounds one scheduled sync, so a directory that stalls costs
// that source its turn and not every other's.
const ScheduledSyncTimeout = 30 * time.Minute

// Scheduler syncs the sources that ask for it (7.15), as `dir sync -apply` does and
// with every rule that has: a plan past the ceiling is refused, and that is written
// on the source, where `dir list` shows it. A source in dry run is left alone, as
// is a disabled one and any in a suspended organisation.
type Scheduler struct {
	DB       *pgxpool.Pool
	Root     *keys.RootKey
	Interval time.Duration
	Log      *slog.Logger
}

// Run takes a pass at once and then every Interval until ctx ends. At once, because
// a node restarted more often than Interval would otherwise never take one.
func (s *Scheduler) Run(ctx context.Context) {
	s.Once(ctx)
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Once(ctx)
		}
	}
}

// Once syncs what is due, one source at a time, and says how many it took.
func (s *Scheduler) Once(ctx context.Context) int {
	taken := 0
	for ctx.Err() == nil {
		id, orgID, slug, err := claimDue(ctx, s.DB)
		if err != nil {
			s.Log.Error("claiming a directory sync", "err", err)
			return taken
		}
		if id == "" {
			return taken
		}
		taken++
		s.sync(ctx, id, orgID, slug)
	}
	return taken
}

// claimDue moves the most overdue source's next sync on and names it, in one
// statement, so no two nodes take one. Moved before the sync rather than after, so
// a node that dies part-way costs a turn and not a loop of retries.
func claimDue(ctx context.Context, db *pgxpool.Pool) (id, orgID, slug string, err error) {
	err = db.QueryRow(ctx, `
		UPDATE core.directory_sources d
		   SET next_sync_at = now() + make_interval(secs => d.sync_interval_seconds)
		 WHERE d.id = (SELECT s.id FROM core.directory_sources s
		                 JOIN core.organizations o ON o.id = s.org_id
		                WHERE s.next_sync_at <= now() AND s.enabled AND NOT s.dry_run AND o.status = 'active'
		                ORDER BY s.next_sync_at LIMIT 1
		                  FOR UPDATE OF s SKIP LOCKED)
		RETURNING d.id::text, d.org_id::text, d.slug`).Scan(&id, &orgID, &slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", nil
	}
	return id, orgID, slug, err
}

func (s *Scheduler) sync(ctx context.Context, id, orgID, slug string) {
	syncCtx, cancel := context.WithTimeout(ctx, ScheduledSyncTimeout)
	defer cancel()
	report, cause := Sync(syncCtx, s.DB, s.Root, orgID, slug, true)
	if errors.Is(cause, ErrSourceUnknown) {
		return // Disabled since it was claimed.
	}
	if cause != nil {
		s.Log.Error("scheduled directory sync failed", "org_id", orgID, "slug", slug, "err", cause)
		// With ctx: when the sync ran out of time, its own context cannot say so.
		RecordFailure(ctx, s.DB, id, cause)
	} else {
		s.Log.Info("scheduled directory sync", "org_id", orgID, "slug", slug, "upstream", report.Upstream)
	}
	detail := map[string]any{"source_id": id, "slug": slug, "upstream": report.Upstream, "applied": report.Applied}
	if cause != nil {
		detail["error"] = cause.Error()
	}
	if err := writeScheduledRecord(ctx, s.DB, orgID, detail); err != nil {
		s.Log.Error("recording a scheduled directory sync", "org_id", orgID, "slug", slug, "err", err)
	}
}

func writeScheduledRecord(ctx context.Context, db *pgxpool.Pool, orgID string, detail map[string]any) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := audit.Write(ctx, tx, audit.Event{Type: "directory.scheduled_sync", OrgID: orgID, Detail: detail}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
