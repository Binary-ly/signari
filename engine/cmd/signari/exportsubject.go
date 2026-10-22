package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// exportSubjectCmd writes everything kept about one person (5.08), the document
// they download themselves from /account/export, for an operator answering
// their request for it. A read, so no version moves and no admin.cli_command is
// written for it; the export records itself, because who was handed a person's
// data is what an inquiry into a disclosure asks.
func exportSubjectCmd(ctx context.Context, conn *pgx.Conn, subjectID, out string) error {
	if subjectID == "" {
		return fmt.Errorf("-subject-id is required (the subject uuid to export)")
	}
	root, err := rootKey()
	if err != nil {
		return fmt.Errorf("personal attributes are sealed, so exporting needs SIGNARI_ROOT_KEY: %w", err)
	}

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	exp, err := store.ExportSubject(ctx, tx, subjectID, root)
	_ = tx.Rollback(ctx)
	if errors.Is(err, store.ErrSubjectUnknown) {
		return fmt.Errorf("%s has neither a subject key nor an account; check the identifier", subjectID)
	}
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return err
	}

	// Recorded before it is written, in a transaction of its own: see
	// store.ExportSubject on why not in the snapshot.
	orgID := ""
	if len(exp.Tables["users"]) == 1 {
		orgID, _ = exp.Tables["users"][0]["org_id"].(string)
	}
	atx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = atx.Rollback(ctx) }()
	if err := audit.Write(ctx, atx, audit.Event{
		Type: "admin.subject_exported", OrgID: orgID, SubjectID: exp.SubjectID,
		Detail: map[string]any{"via": "cli", "operator": cliOperator(), "rows": exp.Rows()},
	}); err != nil {
		return err
	}
	if err := atx.Commit(ctx); err != nil {
		return err
	}

	var w io.Writer = os.Stdout
	if out != "" {
		// Readable by the operator alone: it is all of one person.
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if _, err := w.Write(append(body, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "exported %s: %d rows across %d tables, %d attributes; credentials' values withheld\n",
		exp.SubjectID, exp.Rows(), len(exp.Tables), len(exp.Attributes))
	return nil
}
