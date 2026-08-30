package config

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The declarative path must leave the same two records every other write leaves.
//
// `signari apply` wrote clients, groups, SAML providers and RADIUS clients
// straight into its transaction and committed. It bumped no configuration
// version and wrote no audit event, so two of the three invariants this project
// states as non-negotiable did not hold on its own declarative path:
//
//   - ADR-008: every configuration mutation bumps `core.config_version` in the
//     SAME transaction. Without it a caller holding an If-Match precondition
//     from before the apply is told nothing moved, and overwrites it — the exact
//     lost update the precondition exists to refuse, reachable from the CLI.
//   - Every admin API mutation writes an audit event. A change made with
//     `signari apply` left none, so "who changed this client" had no answer for
//     the path most likely to be used in production.
//
// Both tests run inside a transaction that is rolled back, so they need no
// cleanup and cannot disturb another package running beside them.

func applyFixture(t *testing.T) (context.Context, *pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var org string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM core.organizations LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation to apply against: %v", err)
	}
	return ctx, pool, org
}

func TestApplyBumpsTheConfigurationVersion(t *testing.T) {
	ctx, pool, org := applyFixture(t)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var before int64
	if err := tx.QueryRow(ctx,
		`SELECT version FROM core.config_version WHERE id = true`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	f := &File{Groups: []Group{{
		Name:        fmt.Sprintf("cfg-invariant-%d", time.Now().UnixNano()),
		DisplayName: "Configuration invariant test",
	}}}
	plan, err := BuildPlan(ctx, tx, org, f, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Empty() {
		t.Fatal("the plan is empty, so this test would pass without applying anything")
	}
	if err := Apply(ctx, tx, org, f, plan); err != nil {
		t.Fatal(err)
	}

	var after int64
	if err := tx.QueryRow(ctx,
		`SELECT version FROM core.config_version WHERE id = true`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("the version went %d -> %d. A configuration change that commits "+
			"without bumping it is durable and invisible: a caller holding an "+
			"If-Match from before this apply is told nothing moved and overwrites it",
			before, after)
	}
}

func TestApplyWritesAnAuditRecordForEveryChange(t *testing.T) {
	ctx, pool, org := applyFixture(t)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	name := fmt.Sprintf("cfg-audit-%d", time.Now().UnixNano())
	f := &File{Groups: []Group{{Name: name, DisplayName: "Audit test"}}}
	plan, err := BuildPlan(ctx, tx, org, f, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Empty() {
		t.Fatal("nothing planned, so nothing would be audited either way")
	}
	if err := Apply(ctx, tx, org, f, plan); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM core.audit_events
		 WHERE event_type = 'config.applied' AND detail->>'name' = $1`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(plan.Changes) {
		t.Errorf("%d audit event(s) for %d planned change(s). A change made with "+
			"`signari apply` must be answerable by the audit trail, or the CLI is a "+
			"way to edit the deployment with no record of who did it",
			n, len(plan.Changes))
	}
}
