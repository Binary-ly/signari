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

// serve refuses a database role no organisation's row-level security binds,
// saying what is wrong, why, the fix and, last, the override; the override
// admits it with one warning; and signari_engine is admitted with neither.
// Through run() as well, where the refusal comes before anything listens: with
// no root key set, a serve the gate let through stops at the key instead, so
// the test cannot hang on a server it started.
func TestServeRefusesARoleRowLevelSecurityDoesNotBind(t *testing.T) {
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
	var unbound bool
	if err := conn.QueryRow(ctx, `SELECT bool_or(rolsuper OR rolbypassrls) FROM pg_catalog.pg_roles
		WHERE rolname IN (session_user, current_user)`).Scan(&unbound); err != nil {
		t.Fatal(err)
	}
	if !unbound {
		t.Skip("SIGNARI_TEST_DSN signs in as a role row-level security binds; the refusal needs one it does not")
	}

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	err = rlsBypassGate(ctx, conn, false, log)
	if err == nil {
		t.Fatal("a superuser connection was admitted")
	}
	msg := err.Error()
	order := []string{"row-level security", "every tenant's rows", "signari_engine", "signari setup", "-allow-rls-bypass"}
	at := -1
	for _, want := range order {
		i := strings.Index(msg, want)
		if i < 0 || i < at {
			t.Errorf("the refusal does not say %q after what comes before it: %s", want, msg)
		}
		at = i
	}
	if exitCode(err) != 1 || logs.Len() != 0 {
		t.Errorf("the refusal exits %d and logged %q", exitCode(err), logs.String())
	}

	if err := rlsBypassGate(ctx, conn, true, log); err != nil {
		t.Errorf("the override was refused: %v", err)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 || !strings.Contains(logs.String(), "ROW-LEVEL SECURITY") {
		t.Errorf("the override logged %d warnings: %q", n, logs.String())
	}

	// signari_engine, where the cluster lets the suite sign in as it, is let through
	// without a word.
	if u, err := url.Parse(dsn); err == nil {
		u.User = url.User(engineRole)
		if engine, err := pgx.Connect(ctx, u.String()); err == nil {
			logs.Reset()
			if err := rlsBypassGate(ctx, engine, false, log); err != nil || logs.Len() != 0 {
				t.Errorf("signari_engine: %v, logged %q", err, logs.String())
			}
			_ = engine.Close(ctx)
		}
	}

	t.Setenv("SIGNARI_ALLOW_RLS_BYPASS", "")
	t.Setenv("SIGNARI_ROOT_KEY", "")
	t.Setenv("SIGNARI_ROOT_KEY_FILE", "")
	t.Setenv("SIGNARI_ADDR", "")
	err = run([]string{"serve", "-dsn", dsn, "-addr", "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("serve with a superuser DSN: %v", err)
	}
	for _, args := range [][]string{{"serve", "-dsn", dsn, "-addr", "127.0.0.1:0", "-allow-rls-bypass"}, nil} {
		if args == nil {
			t.Setenv("SIGNARI_ALLOW_RLS_BYPASS", "1")
			args = []string{"serve", "-dsn", dsn, "-addr", "127.0.0.1:0"}
		}
		err := run(args)
		if err == nil || strings.Contains(err.Error(), "row-level security") || !strings.Contains(err.Error(), "SIGNARI_ROOT_KEY") {
			t.Errorf("%v with SIGNARI_ALLOW_RLS_BYPASS=%q: %v; want it past the gate and stopped at the root key",
				args, os.Getenv("SIGNARI_ALLOW_RLS_BYPASS"), err)
		}
	}
}
