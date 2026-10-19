package keys

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A refresh through the pool survives its database connection being killed,
// as a failover kills it; one through a single connection never recovers,
// which is how `serve` refreshed until 2.18. Five failures in a row make the
// instance unready.
func TestAKeyRefreshSurvivesItsConnectionBeingKilled(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	tag := fmt.Sprintf("keyrefresh-%d", time.Now().UnixNano())
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = tag
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	root, err := NewRootKey("refresher-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var instanceID string
	if err := pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://keyrefresh-' || gen_random_uuid() || '.test', 'refresher') RETURNING id::text`).
		Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, instanceID)
		_, _ = pool.Exec(c, `DELETE FROM core.instances WHERE id = $1::uuid`, instanceID)
	})
	k, err := Generate(NewKID(), ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := WithState(k, StateActive)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(ctx, tx, instanceID, active, root); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	set, err := LoadSet(ctx, pool, instanceID, root)
	if err != nil {
		t.Fatal(err)
	}

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	kill := func() {
		t.Helper()
		killer, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = killer.Close(ctx) }()
		if _, err := killer.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
			WHERE application_name = $1 AND pid <> pg_backend_pid()`, tag); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The old way: one connection, opened once.
	connCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	connCfg.RuntimeParams["application_name"] = tag
	single, err := pgx.ConnectConfig(ctx, connCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = single.Close(ctx) }()
	old := &Refresher{DB: single, InstanceID: instanceID, Root: root, Live: set, Log: quiet}

	r := &Refresher{DB: pool, InstanceID: instanceID, Root: root, Live: set, Log: quiet}
	r.Once(ctx)
	if r.Missed() != 0 {
		t.Fatal("a refresh failed before anything was killed")
	}

	kill()
	for i := 0; i < 3; i++ {
		old.Once(ctx)
		r.Once(ctx)
	}
	if old.Missed() != 3 {
		t.Errorf("the single-connection refresher missed %d of 3 after its backend was killed; "+
			"this test no longer shows what the pool is for", old.Missed())
	}
	if r.Missed() != 0 {
		t.Errorf("the pool refresher is %d refreshes behind after its connection was killed; "+
			"the next tick after a failover must succeed", r.Missed())
	}

	if err := r.Healthy(); err != nil {
		t.Errorf("a refresher that is keeping up reported %v", err)
	}
	for i := 0; i < MaxMissedRefreshes; i++ {
		old.Once(ctx)
	}
	if err := old.Healthy(); err == nil {
		t.Error("a refresher that missed every refresh still reported itself healthy")
	}
}
