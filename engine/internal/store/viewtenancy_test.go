package store

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// No core_v1 view may return another tenant's row.
//
// # The hole this caught
//
// The console has no grant on `core` at all -- it reads `core_v1`. Those views
// run with the OWNER's privileges, and PostgreSQL lets a table's owner bypass
// row-level security unless FORCE is set. So a view over a table without FORCE
// hands the console every tenant's rows, and inspecting the console's grants
// reveals nothing.
//
// Measured before the fix, as signari_admin scoped to one organisation on a
// database holding 6,896:
//
//	SELECT count(*) FROM core_v1.organizations;  -> 6896
//	SELECT count(*) FROM core_v1.users;          ->   16
//
// 0092 closed this on fifty-eight tables by iterating those carrying an `org_id`
// column. An organisation's tenant key is its own `id`, so the loop never
// matched it. 0110 adds the policy.
//
// # Why this test asks the question directly
//
// The first version checked a proxy: does every table under a core_v1 view FORCE
// row-level security? It reported two more leaks -- core_v1.clients over
// client_redirect_uris, and core_v1.logout_deliveries over outbox -- and both
// were false. Those views are scoped by the OTHER side of a join, to a table
// that does force it: scoped to one organisation they return 17 of 1,135 clients
// and 0 of 3 outbox rows.
//
// So the proxy was wrong in the direction that wastes a reader's time. This asks
// what actually matters instead: with a tenant selected, does any row come back
// belonging to somebody else? That has no false positives, and it also catches a
// leak the proxy would miss -- a view over a FORCE-protected table that filters
// on the wrong column.
func TestNoCoreV1ViewReturnsAnotherTenantsRow(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// Views whose rows are deployment state rather than one tenant's data.
	// Each needs a reason, and the reason must be that the rows are not tenant
	// data at all -- not that the leak is small.
	notTenantScoped := map[string]string{
		"config_status":      "a singleton counter, no tenant data",
		"migration_progress": "applied-migration state, identical for every tenant",
	}

	// A tenant that actually owns rows, so the assertion has something to bite on.
	var org string
	if err := pool.QueryRow(ctx, `
		SELECT org_id::text FROM core.users
		 GROUP BY org_id ORDER BY count(*) DESC LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation with users to scope to: %v", err)
	}

	views, err := pool.Query(ctx, `
		SELECT c.relname, a.attname
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_attribute a ON a.attrelid = c.oid
		 WHERE n.nspname = 'core_v1' AND c.relkind = 'v'
		   AND a.attname IN ('org_id', 'organisation_id')
		   AND a.attnum > 0 AND NOT a.attisdropped
		 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	type target struct{ view, col string }
	var targets []target
	for views.Next() {
		var v, col string
		if err := views.Scan(&v, &col); err != nil {
			t.Fatal(err)
		}
		if _, skip := notTenantScoped[v]; !skip {
			targets = append(targets, target{v, col})
		}
	}
	views.Close()

	// organizations carries the tenant in `id`, which is why the org_id sweep in
	// 0092 never matched it. Checked explicitly for exactly that reason.
	targets = append(targets, target{"organizations", "id"})

	if len(targets) < 5 {
		t.Fatalf("only %d tenant-scoped core_v1 views found; the discovery query is "+
			"not matching and this test would pass over a leak", len(targets))
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	// session_user stays whoever connected, so is_engine() is false here and the
	// policies bind exactly as they do for the console.
	if _, err := conn.Exec(ctx, "SET ROLE signari_admin"); err != nil {
		t.Skipf("cannot become signari_admin: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT set_config('app.org_id', $1, false)", org); err != nil {
		t.Fatal(err)
	}

	for _, tg := range targets {
		var foreign int
		q := fmt.Sprintf(
			`SELECT count(*) FROM core_v1.%s WHERE %s IS NOT NULL AND %s::text <> $1`,
			tg.view, tg.col, tg.col)
		if err := conn.QueryRow(ctx, q, org).Scan(&foreign); err != nil {
			// A view the admin role cannot read at all is not a leak.
			t.Logf("skipping core_v1.%s: %v", tg.view, err)
			continue
		}
		if foreign > 0 {
			t.Errorf("core_v1.%s returned %d row(s) belonging to another tenant while "+
				"scoped to %s. A core_v1 view runs with the owner's privileges, and the "+
				"owner bypasses row-level security unless the table FORCEs it — check "+
				"that every table this view reads has a policy AND the FORCE",
				tg.view, foreign, org)
		}
	}
}
