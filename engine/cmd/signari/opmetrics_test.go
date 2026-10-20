package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/metrics"
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
		"signari_outbox_oldest_pending_seconds", "signari_audit_stream_lag_events",
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
