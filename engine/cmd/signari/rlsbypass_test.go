package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// serve refuses a privileged database role, saying what is wrong, why (powers
// over the database server the engine never needs, not row-level security,
// which lets the engine read every organisation by design), the fix and,
// last, the override; the override admits it with one warning; and
// signari_engine is admitted with neither. A login role that may SET ROLE to a
// superuser is refused as one, and so is SIGNARI_READ_DSN's pool when it signs
// in as a superuser. Through run() as well, where the refusal comes before
// anything listens: with no root key set, a serve the gate let through stops
// at the key instead, so the test cannot hang on a server it started.
func TestServeRefusesAPrivilegedDatabaseRole(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	var super bool
	if err := conn.QueryRow(ctx, `SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = session_user`).
		Scan(&super); err != nil {
		t.Fatal(err)
	}
	if !super {
		t.Skip("SIGNARI_TEST_DSN does not sign in as a superuser; the refusal needs one")
	}

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	err = rlsBypassGate(ctx, conn, "SIGNARI_DSN", false, log)
	if err == nil {
		t.Fatal("a superuser connection was admitted")
	}
	msg := err.Error()
	order := []string{"SIGNARI_DSN", "a superuser", "powers it never needs", "signari_engine", "signari setup",
		"-allow-rls-bypass"}
	at := -1
	for _, want := range order {
		i := strings.Index(msg, want)
		if i < 0 || i < at {
			t.Errorf("the refusal does not say %q after what comes before it: %s", want, msg)
		}
		at = i
	}
	if strings.Contains(msg, "row-level security") {
		t.Errorf("the refusal blames row-level security, which lets the engine read every organisation by design: %s", msg)
	}
	if exitCode(err) != 1 || logs.Len() != 0 {
		t.Errorf("the refusal exits %d and logged %q", exitCode(err), logs.String())
	}

	if err := rlsBypassGate(ctx, conn, "SIGNARI_DSN", true, log); err != nil {
		t.Errorf("the override was refused: %v", err)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 || !strings.Contains(logs.String(), "PRIVILEGED DATABASE ROLE") {
		t.Errorf("the override logged %d warnings: %q", n, logs.String())
	}

	// signari_engine, where the cluster lets the suite sign in as it, is let
	// through without a word.
	engineDSN := ""
	if u, err := url.Parse(dsn); err == nil {
		u.User = url.User(engineRole)
		if engine, err := pgx.Connect(ctx, u.String()); err == nil {
			engineDSN = u.String()
			logs.Reset()
			if err := rlsBypassGate(ctx, engine, "SIGNARI_DSN", false, log); err != nil || logs.Len() != 0 {
				t.Errorf("signari_engine: %v, logged %q", err, logs.String())
			}
			_ = engine.Close(ctx)
		}
	}

	// A login role with nothing of its own that may SET ROLE to a superuser is
	// one statement from being one, and is refused as one.
	const su, reacher = "signari_gate_super_test", "signari_gate_setrole_test"
	for _, r := range []string{reacher, su} {
		_, _ = conn.Exec(ctx, "DROP ROLE IF EXISTS "+r)
	}
	t.Cleanup(func() {
		for _, r := range []string{reacher, su} {
			_, _ = conn.Exec(context.Background(), "DROP ROLE IF EXISTS "+r)
		}
	})
	for _, stmt := range []string{"CREATE ROLE " + su + " NOLOGIN SUPERUSER", "CREATE ROLE " + reacher + " LOGIN",
		"GRANT " + su + " TO " + reacher + " WITH INHERIT FALSE, SET TRUE"} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User = reacher
	if rc, err := pgx.ConnectConfig(ctx, cfg); err == nil {
		err := rlsBypassGate(ctx, rc, "SIGNARI_DSN", false, log)
		if err == nil || !strings.Contains(err.Error(), "may SET ROLE to "+su) {
			t.Errorf("a role that may SET ROLE to a superuser: %v", err)
		}
		if _, err := conn.Exec(ctx, "REVOKE "+su+" FROM "+reacher); err != nil {
			t.Fatal(err)
		}
		if err := rlsBypassGate(ctx, rc, "SIGNARI_DSN", false, log); err != nil {
			t.Errorf("once the membership is revoked: %v", err)
		}
		_ = rc.Close(ctx)
	} else {
		t.Logf("the cluster does not let %s sign in, so the SET ROLE refusal is not exercised here: %v", reacher, err)
	}

	t.Setenv("SIGNARI_ALLOW_RLS_BYPASS", "")
	t.Setenv("SIGNARI_ROOT_KEY", "")
	t.Setenv("SIGNARI_ROOT_KEY_FILE", "")
	t.Setenv("SIGNARI_ADDR", "")
	t.Setenv("SIGNARI_READ_DSN", "")
	err = run([]string{"serve", "-dsn", dsn, "-addr", "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "powers it never needs") {
		t.Errorf("serve with a superuser DSN: %v", err)
	}
	for _, args := range [][]string{{"serve", "-dsn", dsn, "-addr", "127.0.0.1:0", "-allow-rls-bypass"}, nil} {
		if args == nil {
			t.Setenv("SIGNARI_ALLOW_RLS_BYPASS", "1")
			args = []string{"serve", "-dsn", dsn, "-addr", "127.0.0.1:0"}
		}
		err := run(args)
		if err == nil || strings.Contains(err.Error(), "powers it never needs") || !strings.Contains(err.Error(), "SIGNARI_ROOT_KEY") {
			t.Errorf("%v with SIGNARI_ALLOW_RLS_BYPASS=%q: %v; want it past the gate and stopped at the root key",
				args, os.Getenv("SIGNARI_ALLOW_RLS_BYPASS"), err)
		}
	}

	// The Admin API's read replica is a second way into the same data: serving
	// as signari_engine with a superuser's SIGNARI_READ_DSN is refused, naming
	// the read pool, and without it the same serve goes on to the root key.
	if engineDSN == "" {
		t.Log("the cluster does not let the suite sign in as signari_engine, so the read pool's refusal is not exercised here")
		return
	}
	t.Setenv("SIGNARI_ALLOW_RLS_BYPASS", "")
	admin := []string{"serve", "-dsn", engineDSN, "-addr", "127.0.0.1:0", "-admin-addr", "127.0.0.1:0", "-admin-insecure"}
	t.Setenv("SIGNARI_READ_DSN", dsn)
	err = run(admin)
	if err == nil || !strings.Contains(err.Error(), "SIGNARI_READ_DSN") || !strings.Contains(err.Error(), "powers it never needs") {
		t.Errorf("serve with a superuser's SIGNARI_READ_DSN: %v", err)
	}
	t.Setenv("SIGNARI_READ_DSN", "")
	if err := run(admin); err == nil || strings.Contains(err.Error(), "powers it never needs") ||
		!strings.Contains(err.Error(), "SIGNARI_ROOT_KEY") {
		t.Errorf("serve as signari_engine with no read replica: %v; want it stopped at the root key", err)
	}
}
