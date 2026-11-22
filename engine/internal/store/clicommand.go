package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// RecordCLICommand writes one `admin.cli_command` audit record for an operator
// CLI command that changed something and recorded nothing itself, and reports
// whether it did.
//
// Migration 0140's triggers mark the session: `signari.cli_wrote` when a CLI
// session's statement changed a core table, `signari.cli_audited` when it
// wrote an audit record. A command that wrote and audited gets no second
// record; one that wrote nothing gets none.
//
// The record names the command and the flags it was given, never their
// values: `-client-secret`, `-password` and an admin token's value all arrive
// as flags. The operator is the operating-system account and host.
//
// Written after the command, in a transaction of its own, because a command may
// commit several. The version moved inside each of those (0139), so a
// conditional write already sees the change; this is the record of who.
func RecordCLICommand(ctx context.Context, conn interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}, command string, flags []string, orgID, operator string) (bool, error) {
	var wrote, audited string
	if err := conn.QueryRow(ctx, `
		SELECT COALESCE(current_setting('signari.cli_wrote', true), ''),
		       COALESCE(current_setting('signari.cli_audited', true), '')`).
		Scan(&wrote, &audited); err != nil {
		return false, err
	}
	if wrote != "yes" || audited == "yes" {
		return false, nil
	}
	org, ok := CanonicalUUID(orgID)
	if !ok {
		org = ""
	}
	if flags == nil {
		flags = []string{}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.cli_command", OrgID: org,
		Detail: map[string]any{"command": command, "flags": flags, "operator": operator},
	}); err != nil {
		return false, fmt.Errorf("auditing the command: %w", err)
	}
	return true, tx.Commit(ctx)
}
