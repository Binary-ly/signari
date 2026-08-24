package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Poll-based SET delivery (RFC 8936).
//
// A poll stream holds its Security Event Tokens here until the receiver pulls
// them and acknowledges each one. Everything is keyed by stream, and the caller
// has already authenticated as the stream's client, so these functions do not
// re-check ownership -- they operate on the one stream that authentication
// resolved.

// QueuedPollEvent is one SET waiting on a poll stream, in the form it is minted
// from. It is the event, not the signed token: the token is minted at poll time.
type QueuedPollEvent struct {
	JTI       string
	EventType string
	Subject   string
	SID       string
	Reason    string
	QueuedAt  time.Time
}

// PollStreamForClient returns the id of the enabled poll stream a client owns.
//
// ok is false when the client has no stream, has a push stream, or has one that
// is paused or disabled -- all of which are "nothing to poll", answered
// identically so a caller cannot distinguish them and learn about another
// client's configuration.
func PollStreamForClient(ctx context.Context, q Querier, clientID string) (streamID string, ok bool, err error) {
	rows, err := q.Query(ctx, `
		SELECT id::text FROM core.ssf_streams
		WHERE client_id = $1 AND delivery_method = 'poll' AND status = 'enabled'`, clientID)
	if err != nil {
		return "", false, fmt.Errorf("finding a poll stream: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, rows.Err()
	}
	if err := rows.Scan(&streamID); err != nil {
		return "", false, err
	}
	return streamID, true, nil
}

// PollAck removes the SETs a receiver has acknowledged.
//
// Acknowledgement is what lets us drop a SET: until then it is redelivered on
// every poll, because a SET handed over but not stored by the receiver must not
// be lost. Scoped to the stream, so one receiver's ack can never delete another's
// queued events even if it names their jti.
func PollAck(ctx context.Context, tx pgx.Tx, streamID string, jtis []string) (int, error) {
	if len(jtis) == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM core.ssf_poll_queue
		WHERE stream_id = $1::uuid AND jti = ANY($2)`, streamID, jtis)
	if err != nil {
		return 0, fmt.Errorf("acknowledging polled events: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// PollFetch returns up to max queued events for a stream, oldest first, and
// whether more remain beyond what it returned.
//
// It reads max+1 to answer moreAvailable without a second COUNT: if the extra row
// exists, there is more, and it is dropped from the result. Rows are NOT deleted
// here -- they leave the queue only when the receiver acknowledges them.
func PollFetch(ctx context.Context, tx pgx.Tx, streamID string, max int) (events []QueuedPollEvent, more bool, err error) {
	if max < 1 {
		max = 1
	}
	rows, err := tx.Query(ctx, `
		SELECT jti, event_type,
		       payload->>'subject', COALESCE(payload->>'sid',''), COALESCE(payload->>'reason',''),
		       queued_at
		FROM core.ssf_poll_queue
		WHERE stream_id = $1::uuid
		ORDER BY id
		LIMIT $2`, streamID, max+1)
	if err != nil {
		return nil, false, fmt.Errorf("reading queued events: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e QueuedPollEvent
		if err := rows.Scan(&e.JTI, &e.EventType, &e.Subject, &e.SID, &e.Reason, &e.QueuedAt); err != nil {
			return nil, false, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(events) > max {
		return events[:max], true, nil
	}
	return events, false, nil
}

// PurgeStalePollEvents drops queued events older than age, so a poll stream whose
// receiver has stopped polling cannot grow the table without bound.
//
// The age is generous by design: dropping a security event the receiver has not
// yet seen is a real loss, so this is a backstop against an ABANDONED stream, not
// a delivery deadline for a slow one.
func PurgeStalePollEvents(ctx context.Context, tx pgx.Tx, age time.Duration) (int, error) {
	tag, err := tx.Exec(ctx, `
		DELETE FROM core.ssf_poll_queue
		WHERE queued_at < now() - $1::interval`, age.String())
	if err != nil {
		return 0, fmt.Errorf("purging stale poll events: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
