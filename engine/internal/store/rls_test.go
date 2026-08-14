package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// THE regression this file exists for.
//
// Every tenant table is under FORCE ROW LEVEL SECURITY with an org_id policy.
// The engine connects as signari_engine and NEVER sets app.org_id -- it cannot,
// because it looks a client up before it knows the organisation. So the policy
// evaluated to NULL and the engine saw ZERO ROWS in every table.
//
// Nothing caught it because development connects with a superuser DSN, and
// superusers bypass RLS entirely. The product passed every test and would have
// failed completely on the first correctly-configured deployment.
//
// This test connects AS THE ENGINE ROLE, which is the only way to see it.
func TestEngineRoleCanReadItsOwnTables(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	// Reconnect as signari_engine rather than whoever the test DSN names. A test
	// that runs as a superuser cannot observe this bug at all.
	engineDSN := rewriteUser(dsn, "signari_engine")

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, engineDSN)
	if err != nil {
		t.Skipf("cannot connect as signari_engine (%v); set up local trust auth to run this", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var who string
	if err := conn.QueryRow(ctx, `SELECT session_user`).Scan(&who); err != nil {
		t.Fatal(err)
	}
	if who != "signari_engine" {
		t.Fatalf("connected as %q, not signari_engine -- this test proves nothing", who)
	}

	// No app.org_id is set, exactly as the engine runs.
	for _, table := range []string{"core.users", "core.clients", "core.sessions"} {
		var n int
		if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if n == 0 {
			t.Errorf("%s is EMPTY to the engine role: row-level security is filtering the "+
				"engine's own reads, and every flow will fail with \"unknown client\"", table)
		}
	}
}

// And the fix must not have opened the console up. session_user is the
// discriminator precisely because a connecting role cannot change it.
func TestConsoleRoleStillCannotEscalate(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, rewriteUser(dsn, "signari_admin"))
	if err != nil {
		t.Skipf("cannot connect as signari_admin: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	// SET ROLE changes current_user but NOT session_user, so it must not grant
	// the engine's access.
	if _, err := conn.Exec(ctx, "SET ROLE signari_engine"); err == nil {
		var n int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM core_v1.users`).Scan(&n); err == nil && n > 0 {
			t.Fatalf("SET ROLE let the console read %d users with no org context", n)
		}
	}
}

func rewriteUser(dsn, user string) string {
	i := strings.Index(dsn, "://")
	j := strings.Index(dsn[i+3:], "@")
	if i < 0 || j < 0 {
		return dsn
	}
	return dsn[:i+3] + user + dsn[i+3+j:]
}

// TestEveryRLSTableGrantsTheEngine catches the bug of 0018 BEFORE it can bite
// again, and for tables that are still empty.
//
// The row-counting test above can only fail once a table has rows in it. A
// table added later with an org-only policy is invisible to that test until
// somebody puts data in it and a flow breaks in production. This one reads the
// policies themselves, so a new table with the wrong policy fails the moment it
// is created.
//
// The failure it guards against is silent by construction: row-level security
// does not raise an error when it filters everything, it returns nothing, and
// the engine reports "unknown client" for a client that is sitting right there.
func TestEveryRLSTableGrantsTheEngine(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("cannot connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	rows, err := conn.Query(ctx, `
		SELECT c.relname, p.polname, pg_get_expr(p.polqual, p.polrelid)
		FROM pg_policy p
		JOIN pg_class c ON c.oid = p.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'core'
		ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var checked int
	for rows.Next() {
		var table, policy, qual string
		if err := rows.Scan(&table, &policy, &qual); err != nil {
			t.Fatal(err)
		}
		checked++
		// A policy that does not filter by organisation at all (qual `true`, as
		// revoked_jtis uses -- a global replay list belongs to no tenant) is
		// permissive and the engine reads it fine. The dangerous shape is
		// specifically "filters by org, does not exempt the engine".
		if !strings.Contains(qual, "current_org_id") {
			continue
		}
		if !strings.Contains(qual, "is_engine") {
			t.Errorf("core.%s policy %q does not mention is_engine():\n    %s\n"+
				"  The engine sets no app.org_id, so this table reads as EMPTY to it -- "+
				"silently, with no error anywhere.", table, policy, qual)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no policies found in schema core; this test proves nothing")
	}
	t.Logf("checked %d policies", checked)
}
