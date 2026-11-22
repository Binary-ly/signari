package store

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The identifier check runs for every row and its plan is made once for a
// statement, so the plan has to be a good one whatever the table looked like when
// it was made (0.70). Two looks made a bad one: never analysed, where every index
// starting with org_id costs the same as the identifier's, and small with
// statistics, where reading the table is cheapest. A first directory sync is one
// statement over either. core.users has neither look here, so the real check runs
// on a copy that does, and what is counted is the rows it touched, which does not
// depend on how busy the machine is. Nobody collides, so a check on its index
// touches none.
func TestTheIdentifierCheckStaysOnItsIndexHoweverTheTableLooked(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	const people = 2000
	for _, tc := range []struct {
		name   string
		before int
	}{
		{"no statistics", 0},
		{"small, with statistics", 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := tx.Exec(ctx, sql, args...); err != nil {
					t.Fatalf("%s: %v", sql, err)
				}
			}
			exec(`CREATE TEMP TABLE users (LIKE core.users INCLUDING ALL) ON COMMIT DROP`)
			var check string
			if err := tx.QueryRow(ctx, `
				SELECT replace(replace(pg_get_functiondef('core.refuse_identifier_cross_collision'::regproc),
				       'core.refuse_identifier_cross_collision', 'pg_temp.refuse_identifier_cross_collision'),
				       'core.users', 'pg_temp.users')`).Scan(&check); err != nil {
				t.Fatal(err)
			}
			exec(check)
			exec(`CREATE TRIGGER copy_cross_field BEFORE INSERT ON pg_temp.users FOR EACH ROW
			      EXECUTE FUNCTION pg_temp.refuse_identifier_cross_collision()`)

			const insert = `
				INSERT INTO pg_temp.users (org_id, user_handle, email, username)
				SELECT '00000000-0000-4000-8000-000000000070'::uuid, sha256(('h' || i)::bytea),
				       'p' || i || '@bulk.test', 'p' || i
				  FROM generate_series($1::int, $2::int) i`
			if tc.before > 0 {
				exec(insert, 1, tc.before)
				exec(`ANALYZE pg_temp.users`)
			}
			touched := func() int64 {
				t.Helper()
				var n int64
				if err := tx.QueryRow(ctx, `
					SELECT COALESCE(seq_tup_read, 0) + COALESCE(idx_tup_fetch, 0)
					  FROM pg_stat_xact_all_tables WHERE relid = 'pg_temp.users'::regclass`).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			was := touched()
			exec(insert, tc.before+1, tc.before+people)
			if n := touched() - was; n >= people {
				t.Errorf("bringing in %d people in one statement touched %d rows of the table: each "+
					"person's check is reading it rather than finding an identifier in its index, "+
					"so the work grows with the square of the people", people, n)
			}
		})
	}
}

// A CLI command's transaction moves the version once however many statements it
// runs (0.70). Each one used to update the one row, a transaction cannot prune its
// own versions of a row, and each update walked past all of them: a realm import
// is several statements a person. Read inside the transaction, because it holds
// the row from its first write and other packages move the version around it.
func TestACLITransactionMovesTheVersionOnce(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, `SELECT set_config('signari.cli_write', 'on', false)`); err != nil {
		t.Fatal(err)
	}
	begin := func() pgx.Tx {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		return tx
	}
	write := func(tx pgx.Tx) {
		t.Helper()
		if _, err := tx.Exec(ctx, `UPDATE core.clients SET display_name = display_name
		                            WHERE client_id = 'no-such-client-bulkwrites'`); err != nil {
			t.Fatal(err)
		}
	}
	version := func(tx pgx.Tx) int64 {
		t.Helper()
		var v int64
		if err := tx.QueryRow(ctx, `SELECT version FROM core.config_version WHERE id = true`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	savepoint := func(tx pgx.Tx, sql string) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}

	tx := begin()
	before := version(tx)
	write(tx)
	first := version(tx)
	if first <= before {
		t.Fatalf("a CLI write left the version at %d", first)
	}
	for range 5 {
		write(tx)
	}
	if v := version(tx); v != first {
		t.Errorf("five more statements moved the version from %d to %d, and it moves once", first, v)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// The next transaction is a change of its own. After a commit, because a
	// rollback undoes a session's settings too and would hide one that outlived
	// its transaction.
	tx = begin()
	before = version(tx)
	write(tx)
	if v := version(tx); v <= before {
		t.Errorf("the transaction after one that wrote left the version at %d", v)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// A rollback to a savepoint takes the bump with it, so what remains has to bump again.
	tx = begin()
	before = version(tx)
	savepoint(tx, `SAVEPOINT bulk`)
	write(tx)
	savepoint(tx, `ROLLBACK TO SAVEPOINT bulk`)
	write(tx)
	if v := version(tx); v <= before {
		t.Errorf("a write after a rolled-back one left the version at %d", v)
	}
}
