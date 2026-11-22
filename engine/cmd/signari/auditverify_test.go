package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/migrate"
)

// `signari audit verify` says the chain verifies, and names the entry and
// exits non-zero once a row has been altered (3.21). It needed the Go
// toolchain and the test suite. Against a database of its own, because the
// test alters a row.
func TestAuditVerifyNamesTheEntryARowWasAlteredAt(t *testing.T) {
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
	name := fmt.Sprintf("signari_verifytest_%d", time.Now().UnixNano())
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
	scratch := u.String()
	conn, err := pgx.Connect(ctx, scratch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	for _, tier := range []migrate.Tier{migrate.TierBootstrap, migrate.TierCore} {
		if _, err := migrate.Up(ctx, conn, tier, 0, migrate.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := audit.Write(ctx, tx, audit.Event{Type: "test.verify", Detail: map[string]any{"n": i}}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	if err := run([]string{"audit", "verify", "-dsn", scratch}); err != nil {
		t.Fatalf("a chain nobody touched did not verify: %v", err)
	}
	var altered int64
	if err := conn.QueryRow(ctx, `SELECT id FROM core.audit_events WHERE event_type = 'test.verify'
		ORDER BY id OFFSET 1 LIMIT 1`).Scan(&altered); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE core.audit_events SET detail = '{"n": 99}' WHERE id = $1`, altered); err != nil {
		t.Fatal(err)
	}
	err = run([]string{"audit", "verify", "-dsn", scratch})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("broken at entry %d", altered)) {
		t.Fatalf("after entry %d was altered, audit verify said %v", altered, err)
	}
}
