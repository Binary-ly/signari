package janitor

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/plancheck"
)

// readWhole are the tables a sweep may read whole, each with why that stays cheap.
var readWhole = map[string]string{
	"instances": "a deployment has a handful, and the head signer's pass asks after each",
}

// A pass runs every minute for as long as the deployment lives, on tables that only
// grow, so a statement with no index under it costs more each month and never shows
// in a test, whose tables are small. Retention read every session on every pass, and
// the audit head read the trail: found at 1,000,000 sessions and 5,000,000 events
// (0.74), and only because those two tables were the ones seeded. So this is not a
// list of statements: it runs a real pass and asks the planner about each thing it
// sent. A sweep added later is covered by having been run.
func TestNoSweepReadsATableWhole(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	seen := &plancheck.Recorder{}
	cfg.ConnConfig.Tracer = seen
	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	SetHeadSigner(func(ctx context.Context, tx pgx.Tx) (bool, error) {
		_, err := audit.HeadToSign(ctx, tx, "https://janitor.test", time.Now(), time.Hour)
		return false, err
	})
	t.Cleanup(func() { SetHeadSigner(nil) })
	if _, err := RunOnce(ctx, pool, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}

	found, checked, err := plancheck.Find(ctx, pool, seen.Take(), func(table, _ string) bool {
		return readWhole[table] != ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("only %d statements came through the pass, so this looked at nothing", checked)
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("no index can serve this sweep, so every pass reads the table: %s", f)
	}
}
