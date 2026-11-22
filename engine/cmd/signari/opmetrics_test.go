package main

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/metrics"
	"signari.dev/engine/internal/migrate"
	"signari.dev/engine/internal/outbox"
)

// A scrape shows the background work (3.08): every series is there, and
// those read from the database carry a number, not NaN, against a real one.
func TestTheOperationalSeriesAreScraped(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	set, err := keys.NewSet()
	if err != nil {
		t.Fatal(err)
	}
	r := metrics.NewRegistry()
	registerOperationalGauges(r, pool, set, true)
	var b bytes.Buffer
	r.Render(&b)
	values := map[string]string{}
	for _, line := range strings.Split(b.String(), "\n") {
		if f := strings.Fields(line); len(f) == 2 && !strings.HasPrefix(line, "#") {
			values[f[0][:strings.IndexAny(f[0]+"{", "{")]] = f[1]
		}
	}
	for _, name := range []string{
		"go_goroutines", "go_heap_objects_bytes", "go_memory_total_bytes", "go_gc_cycles_total",
		"process_start_time_seconds", "signari_build_info", "signari_outbox_pending",
		"signari_outbox_oldest_pending_seconds", "signari_outbox_parked", "signari_audit_stream_lag_events",
		"signari_janitor_last_pass_timestamp_seconds", "signari_signing_key_active_age_seconds",
		"signari_db_worker_pool_connections_acquired", "signari_db_worker_pool_connections_max",
	} {
		v, ok := values[name]
		if !ok {
			t.Errorf("%s is not in the scrape", name)
			continue
		}
		if v == "NaN" {
			t.Errorf("%s read NaN from a reachable database", name)
		}
	}
	if !strings.Contains(b.String(), `signari_build_info{version="`) {
		t.Errorf("signari_build_info carries no version label:\n%s", b.String())
	}
}

// A notice the worker gave up on is parked, not pending (3.27): it neither
// counts as backlog nor ages the oldest pending row. Against a database of its
// own, because the counts are exact and other packages queue notices.
func TestAParkedNoticeIsNotPending(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("signari_parkedtest_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create a scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	for _, tier := range []migrate.Tier{migrate.TierBootstrap, migrate.TierCore} {
		if _, err := migrate.Up(ctx, conn, tier, 0, migrate.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.outbox (topic, payload, attempts, created_at) VALUES
		  ('backchannel_logout', '{}', $1, now() - interval '2 days'),
		  ('backchannel_logout', '{}', 1, now() - interval '30 seconds')`, outbox.MaxAttempts); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	set, err := keys.NewSet()
	if err != nil {
		t.Fatal(err)
	}
	r := metrics.NewRegistry()
	registerOperationalGauges(r, pool, set, false)
	var b bytes.Buffer
	r.Render(&b)
	values := map[string]float64{}
	for _, line := range strings.Split(b.String(), "\n") {
		if f := strings.Fields(line); len(f) == 2 && !strings.HasPrefix(line, "#") {
			if v, err := strconv.ParseFloat(f[1], 64); err == nil {
				values[f[0]] = v
			}
		}
	}
	if v := values["signari_outbox_pending"]; v != 1 {
		t.Errorf("signari_outbox_pending = %v, want 1: the parked notice counts as backlog", v)
	}
	if v := values["signari_outbox_parked"]; v != 1 {
		t.Errorf("signari_outbox_parked = %v, want 1", v)
	}
	if v := values["signari_outbox_oldest_pending_seconds"]; v > 3600 {
		t.Errorf("signari_outbox_oldest_pending_seconds = %v, want about 30: the parked notice ages the backlog", v)
	}
}
