package migrate

import (
	"context"
	"os"
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
