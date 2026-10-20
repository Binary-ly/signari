package audit

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
)

// Exporting the audit trail, for the compliance requests that arrive by email
// and expect a spreadsheet.
//
// # What makes this one different
//
// Any system can produce a CSV. The question a compliance reviewer cannot
// normally answer is whether the export is complete and unedited -- a CSV is a
// text file, and one row deleted between the database and the reviewer looks
// exactly like a row that never existed.
//
// This trail is hash-chained: each entry commits to its predecessor. So an
// export can carry the chain with it. The verification runs BEFORE the rows are
// written, the entry hash is a column, and the summary states the range's
// endpoints -- which together let a reviewer confirm the file they hold is the
// trail the database has, and lets a later dispute be settled by recomputation
// rather than by trust.
//
// # What is deliberately not in it
//
// Nothing that identifies a person by name. The trail stores `subject_id`, never
// an email address or an IP treated as identity, so an export is pseudonymous by
// construction: it says what happened to which account, and resolving that
// account to a human is a separate, deliberate step somebody has to take.

// ExportOptions bounds an export.
type ExportOptions struct {
	// OrgID limits to one organisation. Empty exports every organisation, which
	// is what a deployment-wide compliance request asks for.
	OrgID string
	From  time.Time
	To    time.Time
}

// ExportResult is what the operator is told afterwards.
type ExportResult struct {
	Rows int
	// ChainVerified is whether the WHOLE trail verified, not just the exported
	// range. A range can look internally consistent while the chain is broken
	// before it, so the claim has to be about the chain.
	ChainVerified bool
	BrokenAt      int64
	Checked       int
	FirstHash     string
	LastHash      string

	// Checkpoint is set when verification started from a declared restart point
	// rather than from the beginning of the trail.
	//
	// A caller that reports ChainVerified without also reporting this would be
	// making a stronger claim than the data supports: everything before the
	// checkpoint is not asserted, and a reader has to be told so.
	Checkpoint *Checkpoint

	// HeadsChecked and HeadFailure are JudgeChain's (3.20). LatestHead is the
	// newest signed head, carried so the export can be checked later against
	// the chain as it is then, and LatestHeadAt when it was signed.
	HeadsChecked int
	HeadFailure  string
	LatestHead   string
	LatestHeadAt time.Time
}

// ExportCSV writes the trail and reports whether it can be trusted.
//
// The chain is verified first and the result is reported whatever it says. An
// export that silently omits a failed verification would be worse than no export
// at all: it would carry the appearance of integrity without the fact.
func ExportCSV(ctx context.Context, tx pgx.Tx, w io.Writer, opt ExportOptions) (*ExportResult, error) {
	state, err := JudgeChain(ctx, tx)
	if err != nil {
		return nil, err
	}
	res := &ExportResult{ChainVerified: state.Verified, BrokenAt: state.BrokenAt,
		Checked: state.Checked, Checkpoint: state.Checkpoint,
		HeadsChecked: state.HeadsChecked, HeadFailure: state.HeadFailure}
	if res.LatestHead, res.LatestHeadAt, err = LatestHead(ctx, tx); err != nil {
		return nil, err
	}
	return res, writeCSV(ctx, tx, w, opt, res)
}

// ChainState is what the chain can be said to prove.
type ChainState struct {
	// Verified is whether the chain verified: the whole of it, or everything
	// since Checkpoint when that is set.
	Verified bool
	// BrokenAt is the first entry that does not verify, 0 when none.
	BrokenAt int64
	Checked  int
	// Checkpoint is the declared restart point the judgement relied on, if
	// any. A caller that reports Verified without it claims more than the data
	// supports.
	Checkpoint *Checkpoint
	// HeadsChecked is how many signed heads were checked against the chain
	// (3.20); HeadFailure says why one did not match, and BrokenAt is then the
	// head's entry. A chain recomputed after a rewrite verifies by its hashes
	// and fails here.
	HeadsChecked int
	HeadFailure  string
}

// JudgeChain verifies the chain the way every reader of it does (3.21): the
// whole of it, or, when that fails, everything from the latest declared
// checkpoint provided the break is before it. The export, `signari audit
// verify` and doctor all ask through this, so they cannot disagree. It must
// run in one snapshot, since it may read the chain twice.
func JudgeChain(ctx context.Context, tx pgx.Tx) (*ChainState, error) {
	// The verification and the rows have to come from one snapshot. Under READ
	// COMMITTED each statement takes its own, so a row appended between the two
	// was exported under a verification that never read it, and a row changed
	// between them was exported changed under a verification of the original.
	var isolation string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&isolation); err != nil {
		return nil, err
	}
	if isolation != "repeatable read" && isolation != "serializable" {
		return nil, fmt.Errorf("verifying the audit chain, and exporting it, must read one snapshot: "+
			"begin the transaction REPEATABLE READ (this one is %s)", isolation)
	}
	res := &ChainState{}

	// The whole trail first. If it verifies, nothing else is needed and no
	// disclaimer is made.
	brokenAt, checked, err := Verify(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("verifying the chain: %w", err)
	}
	res.BrokenAt, res.Checked = brokenAt, checked
	res.Verified = brokenAt == 0

	// Only when it does not: fall back to a declared checkpoint, if an operator
	// has recorded one.
	//
	// This is deliberately the second attempt rather than the first. A
	// checkpoint narrows what is being asserted, so it must never be used while
	// a wider claim is available -- otherwise an export would quietly assert
	// less than it could, every time, and nobody would notice.
	if !res.Verified {
		cp, cerr := LatestCheckpoint(ctx, tx)
		if cerr != nil {
			return nil, fmt.Errorf("reading the audit checkpoint: %w", cerr)
		}
		if cp != nil && brokenAt < cp.EntryID {
			// The break is BEFORE the checkpoint, which is what a checkpoint is
			// for. A break after it is a live problem and no declaration covers
			// it.
			fromBroken, fromChecked, verr := VerifyFrom(ctx, tx, cp.EntryID)
			if verr != nil {
				return nil, fmt.Errorf("verifying from the checkpoint: %w", verr)
			}
			if fromBroken == 0 {
				res.Verified = true
				res.Checkpoint = cp
				res.Checked = fromChecked
				res.BrokenAt = 0
			} else {
				// A break AFTER the checkpoint. Report THAT one, not the old
				// disclaimed break the first pass happened to reach first.
				//
				// The first version reported entry 136 -- a fork from a fixed bug,
				// already written off by the declaration -- while the real problem
				// was a row deleted at 5635. An operator who knew about 136 would
				// have recognised it and moved on, which is precisely the wrong
				// outcome for a report that a row has gone missing.
				res.BrokenAt = fromBroken
				res.Checked = fromChecked
				res.Checkpoint = cp
			}
		}
	}

	// The hashes agree with each other; the signed heads say whether they
	// still agree with what was signed (3.20).
	if res.Verified {
		var from int64
		if res.Checkpoint != nil {
			from = res.Checkpoint.EntryID
		}
		n, at, why, err := VerifyHeads(ctx, tx, from)
		if err != nil {
			return nil, fmt.Errorf("checking the signed heads: %w", err)
		}
		res.HeadsChecked = n
		if at != 0 {
			res.Verified, res.BrokenAt, res.HeadFailure = false, at, why
		}
	}
	return res, nil
}

// writeCSV writes the rows the export covers, in the transaction JudgeChain
// read, recording the first and last hash on res.
func writeCSV(ctx context.Context, tx pgx.Tx, w io.Writer, opt ExportOptions, res *ExportResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"id", "occurred_at", "event_type", "org_id", "subject_id", "actor_id",
		"client_id", "admin_token_id", "correlation_id", "retention_class",
		"detail", "entry_hash",
	}); err != nil {
		return err
	}

	rows, err := tx.Query(ctx, `
		SELECT id, occurred_at, event_type, COALESCE(org_id::text,''),
		       COALESCE(subject_id::text,''), COALESCE(actor_id::text,''),
		       COALESCE(client_id,''), COALESCE(admin_token_id::text,''),
		       COALESCE(correlation_id::text,''), retention_class,
		       detail::text, entry_hash
		FROM core.audit_events
		WHERE ($1::uuid IS NULL OR org_id = $1::uuid)
		  AND ($2::timestamptz IS NULL OR occurred_at >= $2)
		  AND ($3::timestamptz IS NULL OR occurred_at < $3)
		ORDER BY id`,
		nullUUID(opt.OrgID), nullTime(opt.From), nullTime(opt.To))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var occurred time.Time
		var eventType, orgID, subjectID, actorID, clientID, tokenID string
		var correlationID, retention, detail string
		var entryHash []byte
		if err := rows.Scan(&id, &occurred, &eventType, &orgID, &subjectID, &actorID,
			&clientID, &tokenID, &correlationID, &retention, &detail, &entryHash); err != nil {
			return err
		}

		h := hex.EncodeToString(entryHash)
		if res.FirstHash == "" {
			res.FirstHash = h
		}
		res.LastHash = h

		if err := cw.Write([]string{
			fmt.Sprint(id),
			// RFC 3339 in UTC. A spreadsheet reformats dates according to whoever
			// opens it, so the file has to be unambiguous before it gets there.
			occurred.UTC().Format(time.RFC3339Nano),
			eventType, orgID, subjectID, actorID, clientID, tokenID,
			correlationID, retention, detail, h,
		}); err != nil {
			return err
		}
		res.Rows++
	}
	if err := rows.Err(); err != nil {
		return err
	}

	cw.Flush()
	return cw.Error()
}

func nullUUID(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
