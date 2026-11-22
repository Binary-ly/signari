package migrate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
)

// A no-transaction migration may hold only concurrent, repeatable index
// builds and drops (3.01): a plain split on ";" is what runs it, and a failure
// part way must be safe to run again.
func TestANoTransactionMigrationHoldsOnlyRepeatableIndexWork(t *testing.T) {
	set := func(body string) fstest.MapFS {
		fsys := fstest.MapFS{"core/0001_bootstrap.sql": {Data: []byte("SELECT 1;")}}
		fsys["core/0002_probe.sql"] = &fstest.MapFile{Data: []byte(body)}
		return fsys
	}
	for _, ok := range []string{
		noTransactionMarker + "\nCREATE INDEX CONCURRENTLY IF NOT EXISTS a_idx ON core.users (email);",
		noTransactionMarker + "\n-- why\nCREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS b_idx ON core.users (id)\n  WHERE email IS NOT NULL;\n" +
			"DROP INDEX CONCURRENTLY IF EXISTS core.old_idx;",
	} {
		if _, err := LoadFS(set(ok)); err != nil {
			t.Errorf("refused %q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		noTransactionMarker + "\nCREATE INDEX CONCURRENTLY a_idx ON core.users (email);",
		noTransactionMarker + "\nCREATE INDEX IF NOT EXISTS a_idx ON core.users (email);",
		noTransactionMarker + "\nALTER TABLE core.users ADD COLUMN x int;",
		noTransactionMarker + "\nCREATE INDEX CONCURRENTLY IF NOT EXISTS a_idx ON users (email);",
		noTransactionMarker + "\n-- nothing",
	} {
		if _, err := LoadFS(set(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	boot := fstest.MapFS{"core/0001_bootstrap.sql": {Data: []byte(noTransactionMarker + "\nSELECT 1;")}}
	if _, err := LoadFS(boot); err == nil {
		t.Error("a no-transaction bootstrap was accepted")
	}
}

// scratchDB creates an empty database for the test, dropped afterwards, and a
// way to connect to it.
func scratchDB(t *testing.T) func() *pgx.Conn {
	t.Helper()
	connect, _ := scratchDBAt(t)
	return connect
}

// scratchDBAt is scratchDB, with the database's name for a tool that takes
// one.
func scratchDBAt(t *testing.T) (func() *pgx.Conn, string) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("signari_migtest_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create a scratch database: %v", err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = name
	var conns []*pgx.Conn
	var mu sync.Mutex
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close(ctx)
		}
		_, _ = admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name)
		_ = admin.Close(ctx)
	})
	return func() *pgx.Conn {
		t.Helper()
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		return c
	}, name
}

// Two `migrate up` runs at once take turns (3.01): one applies every
// migration, the other waits for it and finds nothing left. Nothing
// serialised them, so both read the same version and raced to apply the next.
func TestTwoMigrationRunsAtOnceTakeTurns(t *testing.T) {
	connect := scratchDB(t)
	ctx := context.Background()
	if _, err := Up(ctx, connect(), TierBootstrap, 0, Options{}); err != nil {
		t.Fatal(err)
	}
	all, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	results := make([]int, 2)
	errs := make([]error, 2)
	var waited sync.Once
	sawWait := false
	for i := range 2 {
		wg.Add(1)
		go func(i int, c *pgx.Conn) {
			defer wg.Done()
			applied, err := Up(ctx, c, TierCore, 0, Options{LockTimeout: 10 * time.Second,
				Waiting: func() { waited.Do(func() { sawWait = true }) }})
			results[i], errs[i] = len(applied), err
		}(i, connect())
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if results[0]+results[1] != len(all)-1 || (results[0] != 0 && results[1] != 0) {
		t.Errorf("the two runs applied %d and %d of %d core migrations; want one to apply all and "+
			"the other none", results[0], results[1], len(all)-1)
	}
	if !sawWait {
		t.Error("neither run reported waiting for the other")
	}
	if v, err := Applied(ctx, connect()); err != nil || v != len(all) {
		t.Errorf("the ledger ends at %d (%v), want %d", v, err, len(all))
	}

	// An index built outside a transaction, as CREATE INDEX CONCURRENTLY needs.
	c := connect()
	probe := Migration{Version: len(all) + 1, Name: "probe", SQL: noTransactionMarker +
		"\nCREATE INDEX CONCURRENTLY IF NOT EXISTS probe_created_idx ON core.users (created_at);"}
	if err := applyOne(ctx, c, probe, TierCore, Options{LockTimeout: 5 * time.Second}); err != nil {
		t.Fatalf("a concurrent index build: %v", err)
	}
	var valid bool
	var owner string
	if err := c.QueryRow(ctx, `SELECT i.indisvalid, pg_get_userbyid(r.relowner) FROM pg_index i
		JOIN pg_class r ON r.oid = i.indexrelid WHERE i.indexrelid = to_regclass('core.probe_created_idx')`).
		Scan(&valid, &owner); err != nil || !valid {
		t.Errorf("the concurrently built index: valid %v (%v)", valid, err)
	}
	if v, _ := Applied(ctx, c); v != probe.Version {
		t.Errorf("the no-transaction migration was not recorded: ledger at %d", v)
	}
	var role string
	if err := c.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil || role == "signari_engine" {
		t.Errorf("the connection kept the migration's role afterwards: %q (%v)", role, err)
	}

	// A migration queued behind a lock fails fast instead of holding the table.
	holder := connect()
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE core.users IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	blocked := Migration{Version: len(all) + 2, Name: "blocked", SQL: `ALTER TABLE core.users ADD COLUMN probe_x int;`}
	start := time.Now()
	// Bounded, so a migration that waits for the lock fails this test rather
	// than hanging it.
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	err = applyOne(bounded, connect(), blocked, TierCore, Options{LockTimeout: 300 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "lock timeout") || time.Since(start) > 5*time.Second {
		t.Errorf("a migration behind a held lock answered %v after %s; want a lock timeout, quickly",
			err, time.Since(start).Round(time.Millisecond))
	}
}
