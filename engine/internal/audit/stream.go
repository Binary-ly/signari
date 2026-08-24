package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Streaming the audit trail to a logically separate system.
//
// The chain lives in one PostgreSQL table and is verifiable there. What it did
// not do is LEAVE: a breach of the host puts the evidence and the incident in the
// same blast radius. OWASP ASVS V16.4.3 makes forwarding logs to a separate
// system a requirement for exactly that reason, and a SIEM is where detection and
// alerting actually happen.
//
// What is streamed is the METADATA, never the crypto-shredded plaintext.
// `detail` is the non-sensitive detail already stored in the clear; `detail_enc`
// (the wrapped plaintext) is not sent, because a SIEM is a copy an erasure
// request cannot reach, and shipping the plaintext there would defeat the shred.
// The `entry_hash` is included so a receiver can tie a streamed line back to the
// verifiable chain.

// StreamRecord is one audit event as it goes to an external sink.
type StreamRecord struct {
	ID             int64          `json:"id"`
	OccurredAt     time.Time      `json:"occurred_at"`
	EventType      string         `json:"event_type"`
	OrgID          string         `json:"org_id,omitempty"`
	SubjectID      string         `json:"subject_id,omitempty"`
	ActorID        string         `json:"actor_id,omitempty"`
	ClientID       string         `json:"client_id,omitempty"`
	CorrelationID  string         `json:"correlation_id,omitempty"`
	RetentionClass string         `json:"retention_class"`
	Detail         map[string]any `json:"detail,omitempty"`
	// EntryHash is the hex of the chain hash, so a receiver can correlate a
	// streamed line with the verifiable trail.
	EntryHash string `json:"entry_hash,omitempty"`
}

// FetchAfter reads up to limit events with an id greater than afterID, oldest
// first. The id column is a bigint sequence, so this is exactly the set not yet
// streamed, in the order they were written.
func FetchAfter(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, afterID int64, limit int) ([]StreamRecord, error) {
	rows, err := q.Query(ctx, `
		SELECT id, occurred_at, event_type,
		       COALESCE(org_id::text,''), COALESCE(subject_id::text,''),
		       COALESCE(actor_id::text,''), COALESCE(client_id,''),
		       COALESCE(correlation_id::text,''), retention_class,
		       detail, entry_hash
		FROM core.audit_events
		WHERE id > $1
		ORDER BY id ASC
		LIMIT $2`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("fetching audit events to stream: %w", err)
	}
	defer rows.Close()

	var out []StreamRecord
	for rows.Next() {
		var r StreamRecord
		var detail []byte
		var entryHash []byte
		if err := rows.Scan(&r.ID, &r.OccurredAt, &r.EventType, &r.OrgID,
			&r.SubjectID, &r.ActorID, &r.ClientID, &r.CorrelationID,
			&r.RetentionClass, &detail, &entryHash); err != nil {
			return nil, err
		}
		if len(detail) > 0 {
			_ = json.Unmarshal(detail, &r.Detail)
		}
		if len(entryHash) > 0 {
			r.EntryHash = hex.EncodeToString(entryHash)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StreamCursor reads how far the forwarder has got.
func StreamCursor(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (int64, error) {
	var last int64
	err := q.QueryRow(ctx,
		`SELECT last_id FROM core.audit_stream_state WHERE only_row`).Scan(&last)
	if err != nil {
		return 0, fmt.Errorf("reading the audit stream cursor: %w", err)
	}
	return last, nil
}

// AdvanceStreamCursor moves the cursor forward, never backward.
//
// The GREATEST guard makes a stale or out-of-order call harmless: a forwarder
// that retried a batch and reports an id lower than one already recorded cannot
// rewind the cursor and cause a replay.
func AdvanceStreamCursor(ctx context.Context, e interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, to int64) error {
	_, err := e.Exec(ctx, `
		UPDATE core.audit_stream_state
		SET last_id = GREATEST(last_id, $1), updated_at = now()
		WHERE only_row`, to)
	if err != nil {
		return fmt.Errorf("advancing the audit stream cursor: %w", err)
	}
	return nil
}
