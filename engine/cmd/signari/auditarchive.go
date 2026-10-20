package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// auditArchive writes the audit trail before a date to a file and removes it
// from the database, recording in the chain what went where (3.18). The trail
// only grew: a DELETE was the one way to shrink it, and broke the chain at the
// first row left, for good.
//
// The file is written and synced before anything is removed, and is opened
// exclusively, so an earlier archive is never overwritten. If the removal then
// fails, the file stays and the trail is as it was.
func auditArchive(ctx context.Context, conn *pgx.Conn, until, out, by string) error {
	switch {
	case until == "":
		return fmt.Errorf("give -until YYYY-MM-DD: the entries before that date are archived")
	case out == "":
		return fmt.Errorf("give -out: the file the archived entries are written to")
	case by == "":
		return fmt.Errorf("give -by: who is archiving, recorded in the trail")
	}
	before, err := time.Parse("2006-01-02", until)
	if err != nil {
		return fmt.Errorf("-until %q: want YYYY-MM-DD", until)
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the operator names the file
	if err != nil {
		return fmt.Errorf("-out: %w (an archive is never written over a file that exists)", err)
	}
	snap, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		_ = f.Close()
		_ = os.Remove(out)
		return err
	}
	a, err := audit.WriteArchive(ctx, snap, f, before)
	_ = snap.Rollback(ctx)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		return err
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w; %s holds the entries and nothing was removed", err, out)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := audit.CommitArchive(ctx, tx, a, by); err != nil {
		return fmt.Errorf("%w; %s holds the entries and nothing was removed", err, out)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w; %s holds the entries and nothing was removed", err, out)
	}

	fmt.Printf("archived %d audit entries, %d to %d, to %s\n", a.Entries, a.FirstID, a.ThroughID, out)
	fmt.Printf("  sha256 of the file : %s\n", a.SHA256)
	fmt.Printf("  last entry's hash  : %s\n", hex.EncodeToString(a.LastHash))
	if len(a.FirstPrev) == 0 {
		fmt.Println("  starts at          : the beginning of the trail")
	} else {
		fmt.Printf("  continues from     : %s, the last hash of the archive before\n", hex.EncodeToString(a.FirstPrev))
	}
	fmt.Println("\n  The file is now the only copy of those entries; keep it as you keep backups.")
	fmt.Printf("  `signari audit verify -file %s` checks it, on any machine, without the database.\n", out)
	return nil
}

// auditVerifyFile checks an archive file with nothing but the file.
func auditVerifyFile(path string) error {
	f, err := os.Open(path) // #nosec G304 -- the operator names the file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	v, err := audit.VerifyArchiveFile(f)
	if err != nil {
		return err
	}
	if v.Entries == 0 {
		return errors.New("the archive holds no entries")
	}
	if v.BrokenAt != 0 {
		return fmt.Errorf("the archive does not verify: entry %d does not follow from the one before it", v.BrokenAt)
	}
	fmt.Printf("archive verified: %d entries, %d to %d\n", v.Entries, v.FirstID, v.LastID)
	fmt.Printf("  sha256 of the file : %s\n", v.SHA256)
	fmt.Printf("  last entry's hash  : %s\n", hex.EncodeToString(v.LastHash))
	if len(v.FirstPrev) == 0 {
		fmt.Println("  starts at          : the beginning of the trail")
	} else {
		fmt.Printf("  continues from     : %s, the last hash of the archive before\n", hex.EncodeToString(v.FirstPrev))
	}
	if v.PreviousArchiveSum != "" {
		fmt.Printf("  names the archive before it, sha256 %s\n", v.PreviousArchiveSum)
	}
	return nil
}
