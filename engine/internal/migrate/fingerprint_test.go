package migrate

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The schema fingerprint exists for the one case the version counter cannot see.
//
// Verify checks the counter first, so an ordinary "binary is ahead of the
// database" mismatch is caught there. The fingerprint is for what the package
// comment names: "two databases can both claim version 7 and disagree, if someone
// hand-patched one of them."
//
// It had never been tested, and it did not do what its own documentation said. It
// promised "every column, its type, nullability and default, plus every table
// constraint" and hashed only the columns -- so dropping a CHECK, a foreign key
// or a unique constraint produced a byte-identical digest, which is precisely the
// hand-patch it was written to detect.

func fpConn(t *testing.T) (*pgx.Conn, context.Context) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	return conn, ctx
}

// ddlConn takes the role that OWNS schema `core`.
//
// The first version of these tests used signari_maintenance and every DDL step
// failed with "must be owner of table", which t.Skipf turned into a green run
// reporting SKIP. Two tests that proved nothing looked exactly like two tests
// that passed -- so the skip is now reserved for "no database", and a permission
// failure is a hard error.
func ddlConn(t *testing.T) (*pgx.Conn, context.Context) {
	t.Helper()
	conn, ctx := fpConn(t)
	if _, err := conn.Exec(ctx, "SET ROLE signari_engine"); err != nil {
		t.Fatalf("cannot take the role that owns schema core: %v", err)
	}
	return conn, ctx
}

// Same schema, same digest -- otherwise the gate fires on every boot and gets
// switched off, which is worse than not having it.
func TestTheFingerprintIsStable(t *testing.T) {
	conn, ctx := fpConn(t)
	a, err := Fingerprint(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Fingerprint(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("two reads of an unchanged schema disagreed: %s vs %s", a[:12], b[:12])
	}
	if len(a) != 64 {
		t.Errorf("fingerprint is %d chars, want a 64-char sha256", len(a))
	}
}

// A dropped constraint must move the digest. This is the test that fails against
// the columns-only version.
//
// Everything runs inside a transaction that is always rolled back, so the schema
// is never actually altered -- the DDL is visible to this transaction's own
// fingerprint read and to nothing else.
func TestDroppingAConstraintChangesTheFingerprint(t *testing.T) {
	conn, ctx := ddlConn(t)

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	before, err := fingerprintTx(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}

	// A CHECK constraint, because it is the case with no column-level shadow:
	// dropping it leaves data_type, is_nullable and column_default untouched, so
	// a columns-only digest cannot notice.
	if _, err := tx.Exec(ctx,
		`ALTER TABLE core.signing_keys DROP CONSTRAINT signing_keys_state_check`); err != nil {
		t.Fatalf("could not drop the constraint under test: %v", err)
	}

	after, err := fingerprintTx(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("dropping a CHECK constraint left the fingerprint identical; " +
			"a hand-patched database would pass the drift gate")
	}
}

// Widening a constraint must move it too. Migration 0097 does exactly this and
// nothing else, so under a columns-only digest it changed the schema without
// changing the fingerprint at all.
func TestWideningAConstraintChangesTheFingerprint(t *testing.T) {
	conn, ctx := ddlConn(t)

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	before, err := fingerprintTx(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		ALTER TABLE core.signing_keys DROP CONSTRAINT signing_keys_state_check;
		ALTER TABLE core.signing_keys ADD CONSTRAINT signing_keys_state_check
			CHECK (state = ANY (ARRAY['next', 'active', 'passive', 'retired', 'invented']));`); err != nil {
		t.Fatalf("could not rewrite the constraint under test: %v", err)
	}
	after, err := fingerprintTx(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("widening a CHECK constraint left the fingerprint identical")
	}
}

// Every hand change that opens one tenant's rows to another moves the digest
// (3.04). The fingerprint covered columns and constraints, so each of these
// left it identical. Each runs in a savepoint of a transaction that is always
// rolled back, as the superuser, which the role and owner changes need.
func TestEveryChangeToTheTenantBoundaryMovesTheFingerprint(t *testing.T) {
	conn, ctx := fpConn(t)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	before, err := fingerprintTx(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, ddl string }{
		{"a policy dropped", `DROP POLICY users_org_isolation ON core.users`},
		{"row-level security no longer forced", `ALTER TABLE core.users NO FORCE ROW LEVEL SECURITY`},
		{"row-level security disabled", `ALTER TABLE core.users DISABLE ROW LEVEL SECURITY`},
		{"a view handed to the role that bypasses it", `ALTER VIEW core_v1.clients OWNER TO signari_maintenance`},
		{"a view made to run as its caller", `ALTER VIEW core_v1.clients SET (security_invoker = true)`},
		{"a view redefined", `CREATE OR REPLACE VIEW core_v1.config_status AS ` +
			`SELECT * FROM (` + mustViewDef(t, ctx, tx, "core_v1.config_status") + `) v WHERE true`},
		{"a table granted to the console", `GRANT SELECT ON core.users TO signari_admin`},
		{"a column granted to the console", `GRANT SELECT (email) ON core.users TO signari_admin`},
		{"the schema granted to the console", `GRANT USAGE ON SCHEMA core TO signari_admin`},
		{"the engine test rewritten", `CREATE OR REPLACE FUNCTION core.is_engine() RETURNS boolean ` +
			`LANGUAGE sql STABLE AS $$ SELECT true $$`},
		{"a trigger disabled", `ALTER TABLE core.users DISABLE TRIGGER users_identifier_cross_field`},
		// An index rather than a constraint, so no constraint row shadows it.
		{"a unique index dropped", `DROP INDEX core.users_org_email_key`},
		{"the view owner given BYPASSRLS", `ALTER ROLE signari_engine BYPASSRLS`},
		{"the console made a member of the engine role", `GRANT signari_engine TO signari_admin`},
	} {
		if _, err := tx.Exec(ctx, `SAVEPOINT boundary`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, c.ddl); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		after, err := fingerprintTx(ctx, tx)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if after == before {
			t.Errorf("%s: the fingerprint did not move", c.name)
		}
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT boundary`); err != nil {
			t.Fatal(err)
		}
	}
	if again, err := fingerprintTx(ctx, tx); err != nil || again != before {
		t.Fatalf("after rolling every change back the fingerprint is %.12s (%v), want %.12s", again, err, before)
	}
}

func mustViewDef(t *testing.T, ctx context.Context, tx pgx.Tx, view string) string {
	t.Helper()
	var def string
	if err := tx.QueryRow(ctx, `SELECT rtrim(pg_get_viewdef($1::regclass), ';')`, view).Scan(&def); err != nil {
		t.Fatal(err)
	}
	return def
}

// The digest is the same whatever the session's search path. The migrations
// set `search_path = core, public` for the session, the ledger fingerprinted
// under it, and names rendered without their schema there and with it
// everywhere else, so no live read had ever matched the ledger.
func TestTheFingerprintDoesNotDependOnTheSearchPath(t *testing.T) {
	conn, ctx := fpConn(t)
	a, err := Fingerprint(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SET search_path = core, public`); err != nil {
		t.Fatal(err)
	}
	b, err := Fingerprint(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("the fingerprint is %.12s with the default search path and %.12s with core on it", a, b)
	}
}

// An unpinned binary compares the live schema with the ledger (3.04). It used
// to compare nothing, and every shipped build is unpinned. Against a database
// migrated from empty: the ledger matches; each hand change is refused and
// accepted again once undone; a row recorded under another PostgreSQL major is
// not compared; and dropping a policy, the case that row was written for, is
// refused.
func TestVerifyRefusesAHandChangeSinceTheLastMigration(t *testing.T) {
	if ExpectedFingerprint != "" {
		t.Skip("this binary is pinned; the ledger comparison is for unpinned builds")
	}
	connect := scratchDB(t)
	ctx := context.Background()
	conn := connect()
	if _, err := Up(ctx, conn, TierBootstrap, 0, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Up(ctx, conn, TierCore, 0, Options{}); err != nil {
		t.Fatal(err)
	}
	// A fresh connection: the migrations left `search_path = core, public` on
	// the one that ran them.
	conn = connect()
	if err := Verify(ctx, conn); err != nil {
		t.Fatalf("a database migrated from empty does not match its own ledger: %v", err)
	}
	for _, c := range []struct{ name, change, undo string }{
		{"FORCE ROW LEVEL SECURITY turned off",
			`ALTER TABLE core.users NO FORCE ROW LEVEL SECURITY`, `ALTER TABLE core.users FORCE ROW LEVEL SECURITY`},
		{"a table granted to the console",
			`GRANT SELECT ON core.users TO signari_admin`, `REVOKE SELECT ON core.users FROM signari_admin`},
		{"a trigger disabled",
			`ALTER TABLE core.users DISABLE TRIGGER users_identifier_cross_field`,
			`ALTER TABLE core.users ENABLE TRIGGER users_identifier_cross_field`},
	} {
		if _, err := conn.Exec(ctx, c.change); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := Verify(ctx, conn); err == nil || !strings.Contains(err.Error(), "schema drift") {
			t.Errorf("%s: verify said %v, want schema drift", c.name, err)
		}
		if _, err := conn.Exec(ctx, c.undo); err != nil {
			t.Fatalf("undoing %s: %v", c.name, err)
		}
		if err := Verify(ctx, conn); err != nil {
			t.Fatalf("after undoing %s: %v", c.name, err)
		}
	}

	if _, err := conn.Exec(ctx, `UPDATE core.schema_migrations SET server_version_num = 120000
		WHERE version = (SELECT max(version) FROM core.schema_migrations)`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `ALTER TABLE core.users NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	c, err := CompareLedger(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if c.Comparable || !strings.Contains(c.Reason, "PostgreSQL 12") {
		t.Errorf("a ledger row recorded under PostgreSQL 12 was compared: %+v", c)
	}
	if err := Verify(ctx, conn); err != nil {
		t.Errorf("verify refused a ledger row it cannot compare: %v", err)
	}
	if _, err := conn.Exec(ctx, `ALTER TABLE core.users FORCE ROW LEVEL SECURITY;
		UPDATE core.schema_migrations SET server_version_num = current_setting('server_version_num')::int
		WHERE version = (SELECT max(version) FROM core.schema_migrations)`); err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Exec(ctx, `DROP POLICY users_org_isolation ON core.users`); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, conn); err == nil || !strings.Contains(err.Error(), "schema drift") {
		t.Fatalf("a policy dropped by hand: verify said %v, want schema drift", err)
	}
}
