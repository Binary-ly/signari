package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Every table carrying org_id enforces the tenant boundary, uniformly.
//
// ASVS 5.0.0 V8.4.1: "Verify that multi-tenant applications use cross-tenant
// controls to ensure consumer operations will never affect tenants with which
// they do not have permissions to interact."
//
// An audit found eighteen exceptions among fifty-eight org-scoped tables:
// eleven with no row-level security at all, and seven with a policy but no
// FORCE. Neither was reachable by any role that connects today — the console has
// no grants on core, and the maintenance role's BYPASSRLS is deliberate — so
// this is defence in depth rather than a fix for a live leak.
//
// It is worth a standing test for one reason: the exceptions were not decisions.
// A table gets created, its migration does not copy the four lines the other
// fifty-seven have, and nothing notices. This test notices, and it names the
// table.
//
// The FORCE half matters as much as the ENABLE half and is easier to omit. Core
// tables are owned by signari_engine, and PostgreSQL exempts a table's owner from
// its own policies unless FORCE is set — so ENABLE alone produces a policy that
// reads as protection and does nothing for the engine.
func TestEveryOrgScopedTableEnforcesTenantIsolation(t *testing.T) {
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

	rows, err := pool.Query(ctx, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
		       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'core' AND c.relkind = 'r'
		  AND EXISTS (SELECT 1 FROM pg_attribute a
		              WHERE a.attrelid = c.oid AND a.attname = 'org_id'
		                AND NOT a.attisdropped)
		ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var bad []string
	var total int
	for rows.Next() {
		var name string
		var enabled, forced bool
		var policies int
		if err := rows.Scan(&name, &enabled, &forced, &policies); err != nil {
			t.Fatal(err)
		}
		total++
		switch {
		case !enabled:
			bad = append(bad, name+": row-level security not enabled")
		case !forced:
			bad = append(bad, name+": enabled but not FORCEd, so the owning role "+
				"(signari_engine) bypasses the policy silently")
		case policies == 0:
			bad = append(bad, name+": row-level security enabled with no policy, "+
				"which denies everything rather than isolating anything")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// The query must find the tables, or this passes by looking at nothing.
	if total < 40 {
		t.Fatalf("only %d org-scoped tables found; the query is wrong and this "+
			"test would pass vacuously", total)
	}
	if len(bad) > 0 {
		t.Errorf("%d of %d org-scoped tables do not enforce tenant isolation:\n  %s\n\n"+
			"Every other table carries the same four lines: ENABLE, FORCE, and a "+
			"policy of `core.is_engine() OR org_id = core.current_org_id()` for "+
			"USING and WITH CHECK. A new table that omits them is not a decision, "+
			"it is a migration that did not copy them.",
			len(bad), total, strings.Join(bad, "\n  "))
	}
}
