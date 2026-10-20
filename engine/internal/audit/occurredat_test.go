package audit

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/migrate"
)

// A row's time is part of its hash from version 2 (3.19): moving occurred_at,
// or claiming the row was written under version 1 to drop it from the hash,
// breaks the chain at that row, while rows written as version 1 keep
// verifying. occurred_at defaulted to the database's clock outside the hash.
// Against a database of its own, because it alters rows.
func TestARowsTimeIsInItsHash(t *testing.T) {
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
	name := fmt.Sprintf("signari_occurredtest_%d", time.Now().UnixNano())
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

	// One row as a release before this one writes it, then three as this one
	// does, the first with a time of its own.
	var ids []int64
	for i, v := range []int{1, 2, 2, 2} {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		e := Event{Type: "test.occurred", Detail: map[string]any{"n": i}}
		if i == 1 {
			e.OccurredAt = time.Date(2026, 1, 2, 3, 4, 5, 678901234, time.UTC)
		}
		if err := write(ctx, tx, e, v); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var id int64
		if err := conn.QueryRow(ctx, `SELECT max(id) FROM core.audit_events`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	broken := func() int64 {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		at, _, err := Verify(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	var stored time.Time
	if err := conn.QueryRow(ctx, `SELECT occurred_at FROM core.audit_events WHERE id = $1`, ids[1]).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !stored.Equal(time.Date(2026, 1, 2, 3, 4, 5, 678901000, time.UTC)) {
		t.Errorf("the time given was stored as %s", stored)
	}
	if at := broken(); at != 0 {
		t.Fatalf("a chain of one version-1 row and three version-2 rows broke at %d", at)
	}

	// A version-1 row's time was never in its hash; it still verifies.
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE core.audit_events SET occurred_at = occurred_at - interval '1 day' WHERE id = $1`, ids[0])
	if at := broken(); at != 0 {
		t.Errorf("moving a version-1 row's time broke the chain at %d; that row never hashed it", at)
	}

	for _, c := range []struct {
		name, change, undo string
		row                int64
	}{
		{"moving a version-2 row's time",
			`UPDATE core.audit_events SET occurred_at = occurred_at - interval '1 second' WHERE id = $1`,
			`UPDATE core.audit_events SET occurred_at = occurred_at + interval '1 second' WHERE id = $1`, ids[2]},
		{"claiming version 1 for a version-2 row",
			`UPDATE core.audit_events SET hash_version = 1 WHERE id = $1`,
			`UPDATE core.audit_events SET hash_version = 2 WHERE id = $1`, ids[3]},
		{"claiming a version nobody wrote",
			`UPDATE core.audit_events SET hash_version = 3 WHERE id = $1`,
			`UPDATE core.audit_events SET hash_version = 2 WHERE id = $1`, ids[3]},
	} {
		exec(c.change, c.row)
		if at := broken(); at != c.row {
			t.Errorf("%s: the chain broke at %d, want %d", c.name, at, c.row)
		}
		exec(c.undo, c.row)
		if at := broken(); at != 0 {
			t.Fatalf("after undoing %s the chain broke at %d", c.name, at)
		}
	}
}
