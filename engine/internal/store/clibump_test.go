package store

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// An operator CLI write moves core.config_version in its own transaction, and
// nothing else does through this route (migration 0139). The CLI wrote every
// table the Admin API does and moved the version in three commands out of
// sixty, so a conditional write read before a CLI change applied over it.

// notBumped are the core tables that carry no trigger, each with its reason.
var notBumped = map[string]string{
	"config_version":    "the counter itself; the trigger would fire on its own update",
	"audit_events":      "written beside the change it records, never on its own",
	"schema_migrations": "migration bookkeeping, not configuration",
}

func TestEveryCoreTableBumpsTheVersionOnACLIWrite(t *testing.T) {
	pool := rateTestPool(t)
	rows, err := pool.Query(context.Background(), `
		SELECT c.relname
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'core' AND c.relkind IN ('r', 'p')
		   AND NOT EXISTS (
		       SELECT 1 FROM pg_trigger tg JOIN pg_proc p ON p.oid = tg.tgfoid
		        WHERE tg.tgrelid = c.oid AND p.proname = 'bump_config_version_for_cli'
		          -- statement level (bit 0 clear), AFTER (bit 1 clear), and on
		          -- INSERT (bit 2), DELETE (bit 3) and UPDATE (bit 4) alike
		          AND tg.tgtype & 1 = 0 AND tg.tgtype & 2 = 0
		          AND tg.tgtype & 28 = 28)`)
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if notBumped[name] == "" {
			missing = append(missing, name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// And the audit trail notes that a CLI session recorded something, which
	// is how RecordCLICommand tells a command that audited itself (0140).
	var noted bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (SELECT 1 FROM pg_trigger tg JOIN pg_proc p ON p.oid = tg.tgfoid
		                WHERE tg.tgrelid = 'core.audit_events'::regclass
		                  AND p.proname = 'note_cli_audit')`).Scan(&noted); err != nil {
		t.Fatal(err)
	}
	if !noted {
		t.Error("core.audit_events carries no trigger calling core.note_cli_audit(), so every " +
			"CLI command that audits itself is recorded a second time")
	}

	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("core.%s carries no statement-level AFTER INSERT OR UPDATE OR DELETE trigger "+
			"calling core.bump_config_version_for_cli(), so a CLI edit to it moves no "+
			"version and a stale conditional write applies over it. Add one in the "+
			"migration that creates the table, or list it in notBumped with the reason", m)
	}
}

// A CLI command that changed something and recorded nothing gets one audit
// record naming it; one that recorded its own change does not get a second;
// one that changed nothing gets none (migration 0140). About 115 commands
// wrote and audited nothing.
func TestACLICommandThatWroteIsAuditedOnce(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	session := func() *pgx.Conn {
		t.Helper()
		c, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(ctx) })
		if _, err := c.Exec(ctx, `SELECT set_config('signari.cli_write', 'on', false)`); err != nil {
			t.Fatal(err)
		}
		return c
	}
	write := func(c *pgx.Conn) {
		t.Helper()
		if _, err := c.Exec(ctx, `UPDATE core.clients SET display_name = display_name
		                           WHERE client_id = 'no-such-client-cliaudit'`); err != nil {
			t.Fatal(err)
		}
	}
	marker := fmt.Sprintf("cliaudit-%d", time.Now().UnixNano())
	recorded := func() int {
		t.Helper()
		var n int
		if err := rateTestPool(t).QueryRow(ctx, `
			SELECT count(*) FROM core.audit_events
			 WHERE event_type = 'admin.cli_command' AND detail->>'command' = $1`, marker).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Wrote, recorded nothing: one record, naming the command and the flags.
	c := session()
	write(c)
	if did, err := RecordCLICommand(ctx, c, marker, []string{"client-id", "client-secret"}, "", "op@host"); err != nil || !did {
		t.Fatalf("a command that wrote was not recorded: %v %v", did, err)
	}
	if n := recorded(); n != 1 {
		t.Fatalf("%d records for the command, want 1", n)
	}

	// Wrote and recorded its own change: nothing more.
	c = session()
	write(c)
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "admin.test_own_record"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if did, err := RecordCLICommand(ctx, c, marker, nil, "", "op@host"); err != nil || did {
		t.Errorf("a command that audited its own change was recorded again: %v %v", did, err)
	}

	// Wrote nothing: nothing.
	if did, err := RecordCLICommand(ctx, session(), marker, nil, "", "op@host"); err != nil || did {
		t.Errorf("a command that wrote nothing was recorded: %v %v", did, err)
	}
	if n := recorded(); n != 1 {
		t.Errorf("%d records after all three, want still 1", n)
	}
}

func TestOnlyACLISessionsWriteMovesTheVersion(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	// Never hand a marked session back to the pool.
	defer func() { _, _ = conn.Exec(ctx, `SELECT set_config('signari.cli_write', '', false)`) }()

	write := func(marked bool) (before, after int64) {
		t.Helper()
		// Repeatable read for the unmarked case, so another package's bump
		// committing meanwhile cannot look like ours; read committed for the
		// marked one, whose own bump it then sees on top of whatever is there.
		iso := pgx.ReadCommitted
		if !marked {
			iso = pgx.RepeatableRead
		}
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		mark := ""
		if marked {
			mark = "on"
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('signari.cli_write', $1, false)`, mark); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT version FROM core.config_version`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		// Any write to a configuration table; it touches no row, which a
		// statement-level trigger fires for all the same.
		if _, err := tx.Exec(ctx, `UPDATE core.clients SET display_name = display_name
		                            WHERE client_id = 'no-such-client-clibump'`); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT version FROM core.config_version`).Scan(&after); err != nil {
			t.Fatal(err)
		}
		return before, after
	}
	if before, after := write(false); after != before {
		t.Errorf("a write from an unmarked session moved the version %d -> %d; the request "+
			"path and background jobs would then refuse every conditional write", before, after)
	}
	if before, after := write(true); after <= before {
		t.Errorf("a write from the operator CLI left the version at %d", after)
	}
}
