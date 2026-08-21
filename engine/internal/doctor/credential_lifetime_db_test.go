package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Exercises the query half against the real schema, because nothing else in this
// repository reads `credential_configurations.lifetime` and nothing else scans a
// Postgres `interval` into a `time.Duration` -- so the two assumptions this check
// rests on are load-bearing and otherwise unproven. The judgement half is tested
// in the package's usual style, on the `Report` alone.
func TestCredentialLifetimeQueryAgainstTheRealSchema(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("no dsn")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skip(err)
	}
	defer conn.Close(ctx)

	// Inside a transaction that is always rolled back: the rows are visible to
	// this connection -- which is the connection the check runs on -- and no
	// residue is left in a database other tests share.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	var org string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'probe-org', 'probe' FROM i RETURNING id`).Scan(&org); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	for _, tc := range []struct {
		id   string
		life string
	}{{"probe-long", "2160 hours"},
		{"probe-short", "10 minutes"},
		{"probe-null", ""},
		// Exactly at the window. Not a violation: the passive window starts at
		// demotion and a demoted key never signs again, so a 24h credential
		// signed at or before demotion is always still verifiable. Flagging it
		// would be a false positive.
		{"probe-boundary", "24 hours"}} {
		var life any
		if tc.life != "" {
			life = tc.life
		}
		if _, err := tx.Exec(ctx, `INSERT INTO core.credential_configurations
			(org_id, config_id, format, vct, always_claims, lifetime)
			VALUES ($1,$2,'dc+sd-jwt','https://x/v',ARRAY['a'],$3::interval)`,
			org, tc.id, life); err != nil {
			t.Fatalf("insert %s: %v", tc.id, err)
		}
	}

	r := &Report{}
	if err := checkCredentialLifetimes(ctx, conn, r); err != nil {
		t.Fatalf("check errored: %v", err)
	}
	t.Logf("findings: %d", len(r.Findings))
	for _, f := range r.Findings {
		t.Logf("  %v", f.Summary)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("want exactly 1 finding, got %d", len(r.Findings))
	}
	s := r.Findings[0].Summary
	if !strings.Contains(s, "probe-long") {
		t.Errorf("the 90-day credential is not named: %q", s)
	}
	if strings.Contains(s, "probe-short") || strings.Contains(s, "probe-null") {
		t.Errorf("a credential inside the window, or with no expiry, was flagged: %q", s)
	}
	if strings.Contains(s, "probe-boundary") {
		t.Errorf("a credential of exactly the window length was flagged; it "+
			"cannot outlive its key, because the window starts at demotion: %q", s)
	}
}
