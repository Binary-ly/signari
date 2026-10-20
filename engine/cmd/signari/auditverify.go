package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// auditVerify says whether the audit chain verifies, the way an export would
// say it, and exits non-zero when it does not (3.21). Verifying the chain
// needed the Go toolchain and the test suite, which a restored database on a
// production host does not have.
func auditVerify(ctx context.Context, conn *pgx.Conn) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s, err := audit.JudgeChain(ctx, tx)
	if err != nil {
		return err
	}
	switch {
	case s.Verified && s.Checkpoint != nil:
		fmt.Printf("chain verified over %d entries since the checkpoint declared on %s by %s.\n"+
			"The %d entries before it are not asserted:\n  %s\n",
			s.Checked, s.Checkpoint.At.Format("2006-01-02"), s.Checkpoint.DeclaredBy,
			s.Checkpoint.SkippedEntries, s.Checkpoint.Reason)
		return nil
	case s.Verified:
		fmt.Printf("chain verified over all %d entries.\n", s.Checked)
		return nil
	case s.Checkpoint != nil:
		return fmt.Errorf("the audit chain is broken at entry %d, after the checkpoint declared on %s, "+
			"so that declaration does not cover it", s.BrokenAt, s.Checkpoint.At.Format("2006-01-02"))
	}
	return fmt.Errorf("the audit chain is broken at entry %d (after checking %d)", s.BrokenAt, s.Checked)
}
