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

	"signari.dev/engine/internal/migrate"
)

// serve refuses to start under GODEBUG=fips140=only with RADIUS, the breach
// check, or anybody enrolled in TOTP, naming each and what to do (3.11); and
// refuses nothing when the mode is not enforced. Each used to fail by
// panicking the request that reached it. Against a database of its own, so the
// TOTP count is exactly this test's.
func TestServeRefusesWhatFIPSOnlyCannotRun(t *testing.T) {
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
	name := fmt.Sprintf("signari_fipstest_%d", time.Now().UnixNano())
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

	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	all := env("SIGNARI_RADIUS_ADDR", ":1812", "SIGNARI_PASSWORD_BREACH_CHECK", "1")
	if err := fipsPreflight(ctx, conn, all, false); err != nil {
		t.Errorf("not enforced, serve was refused: %v", err)
	}
	if err := fipsPreflight(ctx, conn, env(), true); err != nil {
		t.Errorf("enforced, with nothing it refuses configured: %v", err)
	}
	err = fipsPreflight(ctx, conn, all, true)
	for _, want := range []string{"SIGNARI_RADIUS_ADDR", "SHA-1"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("enforced, with RADIUS and the breach check: %v, want it to name %s", err, want)
		}
	}

	if _, err := conn.Exec(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name) VALUES ('https://fips.test', 'F') RETURNING id),
		     o AS (INSERT INTO core.organizations (instance_id, slug, display_name)
		           SELECT id, 'fips', 'F' FROM i RETURNING id),
		     u AS (INSERT INTO core.users (org_id, email, user_handle, status)
		           SELECT id, 'totp@fips.test', decode(repeat('ab', 64), 'hex'), 'active' FROM o RETURNING id, org_id)
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		SELECT id, org_id, '\x00', now() FROM u`); err != nil {
		t.Fatal(err)
	}
	if err := fipsPreflight(ctx, conn, env(), true); err == nil ||
		!strings.Contains(err.Error(), "1 people have a SHA-1 one-time-code authenticator") {
		t.Errorf("enforced, with a person enrolled in SHA-1 TOTP: %v", err)
	}
	// A SHA-256 authenticator runs inside the module (migration 0171).
	if _, err := conn.Exec(ctx, `UPDATE core.totp_credentials SET algorithm = 'SHA256'`); err != nil {
		t.Fatal(err)
	}
	if err := fipsPreflight(ctx, conn, env(), true); err != nil {
		t.Errorf("enforced, with a person enrolled in SHA-256 TOTP: %v", err)
	}
}
