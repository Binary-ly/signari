package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Checkpoints: living with a chain that is already broken.
//
// # The problem
//
// The chain is append-only and hash-linked, so a break anywhere makes every
// later verification fail. That is the whole point when the break is a
// deletion. It is a serious operational problem when the break is a bug that
// has since been fixed -- as one was: audit appends forked whenever two events
// were written at once, until an advisory lock replaced a row lock that did not
// serialise them.
//
// A deployment that ran the buggy version can never produce a verified export
// again, of any period, including entries written correctly years later. The
// log stops being evidence.
//
// # What a checkpoint is NOT
//
// It is not a repair. Nothing rewrites, re-links, or removes an entry, because
// rewriting entries to close a break is exactly the operation the chain exists
// to make detectable. A tool that did that would be a tool for laundering a
// deletion.
//
// # What it is
//
// A DECLARATION, recorded in the chain itself, that says: everything before
// this point is not asserted, and verification of what follows starts here.
//
// The distinction matters and the export states it in those terms. A reader is
// told there is a disclaimed segment, how large it is, when it was disclaimed,
// by whom, and why. They are never told the log is fine.
//
// # The obvious abuse, and why this does not enable it
//
// If a checkpoint restored trust, then anybody who deleted entries could
// checkpoint after them and the export would verify again. Three things prevent
// that from being a quiet operation:
//
//	the checkpoint IS an audit entry, so declaring one is itself recorded, in
//	the very chain it starts -- it cannot be created without leaving a mark
//
//	an export that crosses one says so prominently and reports the size of the
//	disclaimed segment, so a reader sees history was written off rather than
//	verified
//
//	the reason is mandatory and is carried into the export, so "we upgraded
//	past a known bug" and a blank line are visibly different documents
//
// It is still true that somebody with database access and the will to use it
// can destroy evidence. A hash chain never prevented that; it makes it visible.
// A checkpoint keeps it visible while letting the honest case carry on.

// CheckpointEvent is the event type a checkpoint is recorded under.
//
// A real audit event rather than a row in a side table: a side table can be
// deleted without breaking anything, whereas removing this entry breaks the
// chain at its successor like any other.
const CheckpointEvent = "audit.checkpoint"

// Checkpoint is a declared restart point.
type Checkpoint struct {
	// EntryID is the audit entry that records the declaration. Verification of
	// the current segment starts AT this entry.
	EntryID int64
	// At is when it was declared.
	At time.Time
	// DeclaredBy is the operator who ran the command.
	DeclaredBy string
	// Reason is why, and it is required.
	Reason string
	// SkippedEntries is how many entries precede it -- the size of what is no
	// longer asserted.
	SkippedEntries int64
}

// DeclareCheckpoint records a restart point in the chain.
//
// It refuses when the chain is INTACT. A checkpoint on a sound chain has no
// purpose except to shorten what a later verification covers, which is the
// abuse this is shaped to avoid -- and an operator reaching for it on a healthy
// log has misunderstood what it does.
func DeclareCheckpoint(ctx context.Context, tx pgx.Tx, orgID, declaredBy,
	reason string) (*Checkpoint, error) {

	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, fmt.Errorf("a checkpoint needs a reason: it is carried into " +
			"every export that crosses it, and an unexplained gap in an audit log " +
			"is worse than an explained one")
	}
	if strings.TrimSpace(declaredBy) == "" {
		return nil, fmt.Errorf("a checkpoint needs to name who declared it")
	}

	brokenAt, checked, err := Verify(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("checking the chain before declaring a checkpoint: %w", err)
	}
	if brokenAt == 0 {
		return nil, fmt.Errorf("the audit chain verifies over all %d entries, so "+
			"there is nothing to check point past. A checkpoint only ever narrows "+
			"what a later verification covers; on a sound chain that is a loss and "+
			"nothing else", checked)
	}

	var before int64
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM core.audit_events`).Scan(&before); err != nil {
		return nil, err
	}

	// Written through the ordinary path, so it takes the same chain lock and is
	// linked like any other entry.
	if err := Write(ctx, tx, Event{
		Type:  CheckpointEvent,
		OrgID: orgID,
		Detail: map[string]any{
			"declared_by":     declaredBy,
			"reason":          reason,
			"broken_at":       brokenAt,
			"entries_before":  before,
			"entries_checked": checked,
		},
	}); err != nil {
		return nil, fmt.Errorf("recording the checkpoint: %w", err)
	}

	var id int64
	var at time.Time
	if err := tx.QueryRow(ctx, `
		SELECT id, occurred_at FROM core.audit_events
		WHERE event_type = $1 ORDER BY id DESC LIMIT 1`, CheckpointEvent).
		Scan(&id, &at); err != nil {
		return nil, err
	}

	return &Checkpoint{
		EntryID: id, At: at, DeclaredBy: declaredBy, Reason: reason,
		SkippedEntries: before,
	}, nil
}

// LatestCheckpoint returns the most recent declaration, if there is one.
func LatestCheckpoint(ctx context.Context, tx pgx.Tx) (*Checkpoint, error) {
	var c Checkpoint
	var detail map[string]any
	err := tx.QueryRow(ctx, `
		SELECT id, occurred_at, detail
		FROM core.audit_events WHERE event_type = $1
		ORDER BY id DESC LIMIT 1`, CheckpointEvent).
		Scan(&c.EntryID, &c.At, &detail)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.DeclaredBy, _ = detail["declared_by"].(string)
	c.Reason, _ = detail["reason"].(string)
	if n, ok := detail["entries_before"].(float64); ok {
		c.SkippedEntries = int64(n)
	}
	return &c, nil
}

// VerifyFrom walks the chain starting at an entry, rather than at the
// beginning.
//
// Used with the latest checkpoint so a deployment that hit a historical break
// can still assert the integrity of everything since. The starting entry's own
// prev_hash is NOT checked against its predecessor -- that link is precisely
// what is being disclaimed -- and every link after it is checked exactly as
// before.
func VerifyFrom(ctx context.Context, tx pgx.Tx, startID int64) (
	brokenAt int64, checked int, err error) {

	rows, err := tx.Query(ctx, `
		SELECT id, event_type, COALESCE(org_id::text,''), COALESCE(subject_id::text,''),
		       COALESCE(actor_id::text,''), COALESCE(client_id,''),
		       COALESCE(correlation_id::text,''), retention_class,
		       detail::text, prev_hash, entry_hash,
		       COALESCE(admin_token_id::text,'')
		FROM core.audit_events WHERE id >= $1 ORDER BY id`, startID)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	var expectedPrev []byte
	first := true
	for rows.Next() {
		var id int64
		var e Event
		var detail string
		var prev, entry []byte
		if err := rows.Scan(&id, &e.Type, &e.OrgID, &e.SubjectID, &e.ActorID,
			&e.ClientID, &e.CorrelationID, &e.Retention, &detail, &prev, &entry,
			&e.AdminTokenID); err != nil {
			return 0, checked, err
		}
		checked++

		if first {
			// Adopt this entry's predecessor rather than checking it. Its own
			// hash IS still checked below, so the entry cannot have been altered
			// -- only its link to what came before is left unasserted.
			expectedPrev = prev
			first = false
		}
		if !equalBytes(prev, expectedPrev) {
			return id, checked, nil
		}
		if !equalBytes(chainHash(prev, e, detail), entry) {
			return id, checked, nil
		}
		expectedPrev = entry
	}
	return 0, checked, rows.Err()
}
