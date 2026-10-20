package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/migrate"
	"signari.dev/engine/internal/store"
)

// restoreFinalize ends every session and refresh family a restored database
// brought back (3.10). The restore runbook used to stop at "check the
// signing keys open", and every session ended after the backup was taken --
// by logout, by an administrator, by deactivating somebody -- was live again.
//
// It asks for the database's name, because it signs everybody out: run
// against the production database instead of the restored one by mistake,
// that is an outage.
func restoreFinalize(ctx context.Context, conn *pgx.Conn, confirm string) error {
	var name string
	if err := conn.QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		return err
	}
	if confirm != name {
		return fmt.Errorf("this ends every session in %q and signs everybody out; to confirm, "+
			"repeat the database's name:\n  signari restore finalize -confirm %s", name, name)
	}
	// The schema first: a restore of an older backup is behind this binary,
	// and finalizing it before `migrate up` failed part way, on a reason the
	// older schema does not know.
	if err := migrate.Verify(ctx, conn); err != nil {
		return fmt.Errorf("not finalizing: %w", err)
	}
	pool, err := openPool(ctx, conn)
	if err != nil {
		return err
	}
	defer pool.Close()
	f, err := store.FinalizeRestore(ctx, pool)
	if err != nil {
		if f != nil {
			fmt.Printf("ended %d sessions of %d people before stopping; running it again ends the rest\n",
				f.Sessions, f.People)
		}
		return err
	}
	fmt.Printf("ended every session and refresh family created before %s:\n"+
		"  %d sessions of %d people, %d logout notices queued for their applications\n"+
		"  %d refresh families revoked\n"+
		"Everybody signs in again. Recorded as restore.finalized.\n",
		f.Before.UTC().Format("2006-01-02 15:04:05 MST"), f.Sessions, f.People, f.Notices,
		f.RefreshFamilies)
	return nil
}
