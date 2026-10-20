package main

import (
	"context"
	"fmt"
	"math"
	"runtime/debug"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/janitor"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/metrics"
	"signari.dev/engine/internal/migrate"
	"signari.dev/engine/internal/outbox"
)

// registerOperationalGauges adds what the engine's background work looks like
// from outside (3.08): the build, the runtime, the outbox's backlog, how far the
// audit stream lags, when the janitor last finished, how old the signing key
// is, and the workers' pool. Each was visible only by reading a table or a log,
// which nobody does until something has already gone wrong.
//
// The backlog gauges query the database at scrape time through the workers'
// pool, with a short deadline; a scrape that cannot reach the database reports
// NaN rather than a stale number.
func registerOperationalGauges(r *metrics.Registry, db *pgxpool.Pool, set *keys.Set, auditStreaming bool) {
	r.RegisterRuntime()

	goVersion := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		goVersion = bi.GoVersion
	}
	release := version
	if release == "" {
		release = "unreleased"
	}
	schema := "unknown"
	if all, err := migrate.Load(); err == nil {
		schema = fmt.Sprint(all[len(all)-1].Version)
	}
	r.NewInfo("signari_build_info", "The release, toolchain and schema version this process runs.",
		[]string{"version", "go_version", "schema"}, []string{release, goVersion, schema})

	scalar := func(query string, args ...any) func() float64 {
		return func() float64 {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var v float64
			if err := db.QueryRow(ctx, query, args...).Scan(&v); err != nil {
				return math.NaN()
			}
			return v
		}
	}
	// Pending is what the worker will still try; parked is what it gave up on
	// after outbox.MaxAttempts and keeps for an operator to see. Both were one
	// count, so a single parked notice made the oldest "pending" row older by
	// the second, forever, and a backlog alert on it could never clear.
	r.NewGauge("signari_outbox_pending",
		"Logout notices and security events queued and still being retried.",
		scalar(`SELECT count(*)::float8 FROM core.outbox
		        WHERE delivered_at IS NULL AND attempts < $1`, outbox.MaxAttempts))
	r.NewGauge("signari_outbox_oldest_pending_seconds",
		"How long the oldest row still being retried has waited; 0 when none is waiting.",
		scalar(`SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(created_at)), 0)::float8
		        FROM core.outbox WHERE delivered_at IS NULL AND attempts < $1`, outbox.MaxAttempts))
	r.NewGauge("signari_outbox_parked",
		"Notices that exhausted their delivery attempts and will not be retried.",
		scalar(`SELECT count(*)::float8 FROM core.outbox
		        WHERE delivered_at IS NULL AND attempts >= $1`, outbox.MaxAttempts))
	if auditStreaming {
		r.NewGauge("signari_audit_stream_lag_events",
			"Audit events written and not yet accepted by the configured stream.",
			scalar(`SELECT (COALESCE((SELECT max(id) FROM core.audit_events), 0) -
			               COALESCE((SELECT last_id FROM core.audit_stream_state WHERE only_row), 0))::float8`))
	}
	r.NewGauge("signari_janitor_last_pass_timestamp_seconds",
		"When this process last completed a janitor pass; 0 if it has not. Only the node "+
			"holding the janitor's lock runs a pass, so read the newest across nodes.",
		func() float64 {
			if t := janitor.LastPass(); !t.IsZero() {
				return float64(t.Unix())
			}
			return 0
		})
	r.NewGauge("signari_signing_key_active_age_seconds",
		"Age of the oldest active signing key since it was published.",
		func() float64 {
			oldest := 0.0
			for _, k := range set.Keys() {
				if k.State() == keys.StateActive {
					oldest = math.Max(oldest, time.Since(k.PublishedAt()).Seconds())
				}
			}
			return oldest
		})
	r.NewGauge("signari_db_worker_pool_connections_acquired",
		"Connections the background workers currently have checked out.",
		func() float64 { return float64(db.Stat().AcquiredConns()) })
	r.NewGauge("signari_db_worker_pool_connections_max",
		"The background workers' pool ceiling.",
		func() float64 { return float64(db.Stat().MaxConns()) })
}
