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
}

// ExportCSV writes the trail and reports whether it can be trusted.
//
// The chain is verified first and the result is reported whatever it says. An
// export that silently omits a failed verification would be worse than no export
// at all: it would carry the appearance of integrity without the fact.
func ExportCSV(ctx context.Context, tx pgx.Tx, w io.Writer, opt ExportOptions) (*ExportResult, error) {
	res := &ExportResult{}

	brokenAt, checked, err := Verify(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("verifying the chain before export: %w", err)
	}
	res.BrokenAt, res.Checked = brokenAt, checked
	res.ChainVerified = brokenAt == 0

	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"id", "occurred_at", "event_type", "org_id", "subject_id", "actor_id",
		"client_id", "admin_token_id", "correlation_id", "retention_class",
		"detail", "entry_hash",
	}); err != nil {
		return nil, err
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
		return nil, err
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
			return nil, err
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
			return nil, err
		}
		res.Rows++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	cw.Flush()
	return res, cw.Error()
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
