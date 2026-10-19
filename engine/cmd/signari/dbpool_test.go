package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// The pool is sized by the SIGNARI_DB_* variables, which win over the DSN's
// `pool_*` settings, and a value that cannot be what the operator meant
// refuses to start instead of falling back to pgx's max(4, CPUs).
func TestThePoolIsSizedByTheEnvironment(t *testing.T) {
	const dsn = "postgres://u@localhost/db?pool_max_conns=9&pool_min_conns=2"

	cfg, err := poolConfig(dsn, envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != 9 || cfg.MinConns != 2 {
		t.Errorf("the DSN's pool settings gave max %d min %d, want 9 and 2", cfg.MaxConns, cfg.MinConns)
	}

	cfg, err = poolConfig(dsn, envOf(map[string]string{
		"SIGNARI_DB_MAX_CONNS":         "40",
		"SIGNARI_DB_MIN_CONNS":         "4",
		"SIGNARI_DB_MAX_CONN_LIFETIME": "15m",
		"SIGNARI_DB_MAX_CONN_IDLE":     "90s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != 40 || cfg.MinConns != 4 ||
		cfg.MaxConnLifetime != 15*time.Minute || cfg.MaxConnIdleTime != 90*time.Second {
		t.Errorf("the variables gave max %d min %d lifetime %s idle %s, want 40, 4, 15m, 90s",
			cfg.MaxConns, cfg.MinConns, cfg.MaxConnLifetime, cfg.MaxConnIdleTime)
	}

	for _, bad := range []map[string]string{
		{"SIGNARI_DB_MAX_CONNS": "0"},
		{"SIGNARI_DB_MAX_CONNS": "ten"},
		{"SIGNARI_DB_MIN_CONNS": "-1"},
		{"SIGNARI_DB_MAX_CONN_LIFETIME": "30"},
		{"SIGNARI_DB_MAX_CONN_IDLE": "0s"},
		{"SIGNARI_DB_MAX_CONNS": "3", "SIGNARI_DB_MIN_CONNS": "5"},
	} {
		if _, err := poolConfig(dsn, envOf(bad)); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

// A DSN carrying `pool_max_conns` connects, and the pool `serve` opens from it
// has the size it names.
func TestADSNWithPoolSettingsConnects(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	sized := dsn + sep + "pool_max_conns=3&pool_max_conn_idle_time=2m"
	ctx := context.Background()

	if c, err := pgx.Connect(ctx, sized); err == nil {
		_ = c.Close(ctx)
		t.Log("pgx.Connect now accepts pool settings itself; the stripping below is no longer what makes this work")
	}

	conn, err := connectDB(ctx, sized)
	if err != nil {
		t.Fatalf("a DSN carrying pool settings did not connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	pool, err := openPool(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if got := pool.Stat().MaxConns(); got != 3 {
		t.Errorf("the pool's maximum is %d, want the DSN's 3", got)
	}

	t.Setenv("SIGNARI_DB_MAX_CONNS", "7")
	pool2, err := openPool(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool2.Close()
	if got := pool2.Stat().MaxConns(); got != 7 {
		t.Errorf("with SIGNARI_DB_MAX_CONNS=7 the pool's maximum is %d", got)
	}
}
