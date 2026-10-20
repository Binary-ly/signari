package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
)

// Finalized is what FinalizeRestore ended.
type Finalized struct {
	Before          time.Time
	People          int
	Sessions        int
	Notices         int
	RefreshFamilies int
}

// FinalizeRestore ends every session and refresh family a restored database
// brought back (3.10). A backup holds sessions as they were when it was taken:
// one ended since -- a logout, a revocation, a deactivated person's -- is live
// again after the restore, and nothing in the database can say which. So every
// one created before now is ended, through TerminateSessions, so each
// application is told by back-channel logout and each event stream by a CAEP
// session-revoked event, and every refresh family is revoked whatever session
// it belonged to. Everyone signs in again; that is the price of not
// resurrecting a session somebody ended.
//
// One person per transaction, so a failure part way leaves what it finished,
// and running it again ends only what is still live. Run it before the
// engine serves the restored database.
func FinalizeRestore(ctx context.Context, db *pgxpool.Pool) (*Finalized, error) {
	f := &Finalized{}
	if err := db.QueryRow(ctx, `SELECT now()`).Scan(&f.Before); err != nil {
		return nil, err
	}
	rows, err := db.Query(ctx, `
		SELECT DISTINCT user_id::text FROM core.sessions
		WHERE revoked_at IS NULL AND created_at < $1`, f.Before)
	if err != nil {
		return nil, fmt.Errorf("listing live sessions: %w", err)
	}
	var people []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		people = append(people, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, id := range people {
		tx, err := db.Begin(ctx)
		if err != nil {
			return f, err
		}
		t, err := TerminateSessions(ctx, tx, "", id, ReasonRestored)
		if err == nil {
			err = tx.Commit(ctx)
		}
		_ = tx.Rollback(ctx)
		if err != nil {
			return f, fmt.Errorf("ending subject %s's sessions: %w", id, err)
		}
		f.People++
		f.Sessions += t.Sessions
		f.Notices += t.Notices
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return f, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE core.refresh_token_families SET revoked_at = now(), revocation_reason = $2
		WHERE revoked_at IS NULL AND created_at < $1`, f.Before, string(ReasonRestored))
	if err != nil {
		return f, fmt.Errorf("revoking refresh families: %w", err)
	}
	f.RefreshFamilies = int(tag.RowsAffected())
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "restore.finalized",
		Detail: map[string]any{
			"before": f.Before.UTC().Format(time.RFC3339), "people": f.People,
			"sessions": f.Sessions, "logout_notices": f.Notices, "refresh_families": f.RefreshFamilies,
		},
	}); err != nil {
		return f, fmt.Errorf("auditing the restore: %w", err)
	}
	return f, tx.Commit(ctx)
}
