package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// auditVerify says whether the audit chain verifies, the way an export would
// say it, and exits non-zero when it does not (3.21). Verifying the chain
// needed the Go toolchain and the test suite, which a restored database on a
// production host does not have.
//
// With -head it also holds the chain against a signed head kept outside the
// database (3.20): one the audit stream delivered, or an export carried. A
// rewrite recomputed to verify, with every head in the database removed, still
// fails against a head kept elsewhere.
func auditVerify(ctx context.Context, conn *pgx.Conn, head string) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if head != "" {
		if path, ok := strings.CutPrefix(head, "@"); ok {
			b, err := os.ReadFile(path) // #nosec G304 -- the operator names the file
			if err != nil {
				return fmt.Errorf("-head: %w", err)
			}
			head = strings.TrimSpace(string(b))
		}
		c, err := audit.CheckHead(ctx, tx, head)
		if err != nil {
			return fmt.Errorf("the signed head does not match the chain: %w", err)
		}
		fmt.Printf("the signed head matches: entry %d has the hash signed at %s.\n",
			c.ThroughID, time.Unix(c.IssuedAt, 0).UTC().Format(time.RFC3339))
	}
	s, err := audit.JudgeChain(ctx, tx)
	if err != nil {
		return err
	}
	switch {
	case s.HeadFailure != "":
		return fmt.Errorf("the audit chain's hashes agree with each other but not with the signed head "+
			"recorded at entry %d: %s", s.BrokenAt, s.HeadFailure)
	case s.Verified && s.Checkpoint != nil:
		fmt.Printf("chain verified over %d entries since the checkpoint declared on %s by %s, "+
			"and %d signed head(s).\n"+
			"The %d entries before it are not asserted:\n  %s\n",
			s.Checked, s.Checkpoint.At.Format("2006-01-02"), s.Checkpoint.DeclaredBy, s.HeadsChecked,
			s.Checkpoint.SkippedEntries, s.Checkpoint.Reason)
		return nil
	case s.Verified:
		fmt.Printf("chain verified over all %d entries, and %d signed head(s).\n", s.Checked, s.HeadsChecked)
		return nil
	case s.Checkpoint != nil:
		return fmt.Errorf("the audit chain is broken at entry %d, after the checkpoint declared on %s, "+
			"so that declaration does not cover it", s.BrokenAt, s.Checkpoint.At.Format("2006-01-02"))
	}
	return fmt.Errorf("the audit chain is broken at entry %d (after checking %d)", s.BrokenAt, s.Checked)
}
