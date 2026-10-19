package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/ssf"
)

// ErrStreamUnknown is a status change for a client with no stream.
var ErrStreamUnknown = errors.New("that client has no Shared Signals stream in the organisation")

// SetStreamStatus pauses, disables or re-enables a Shared Signals stream, with
// what SSF 1.0 requires of a transmitter that does so (2.29). There was no way
// to pause one at all.
//
//   - A stream leaving enabled is told so first: "If a Transmitter decides to
//     change the status of an Event Stream from "enabled" to either "paused" or
//     "disabled", then the Transmitter MUST send this event to the Receiver
//     before stopping the stream" (specs/ssf-1_0.txt:3381-3383). The
//     stream-updated event is queued in the same transaction, and delivery
//     sends a stream-updated event whatever the status.
//   - A stream returning to enabled is told so too (3384-3386), and the events
//     held while it was paused are released at once rather than at the next
//     hold interval.
//   - Moving between paused and disabled sends nothing: neither may transmit.
//   - Disabling deletes what the stream holds, because a disabled stream "will
//     not hold any events for later transmission" (2607-2611). The
//     stream-updated notices stay.
//
// It returns the status the stream had, so the caller can say what changed.
func SetStreamStatus(ctx context.Context, tx pgx.Tx, orgID, clientID, status, reason string) (string, error) {
	switch status {
	case "enabled", "paused", "disabled":
	default:
		return "", fmt.Errorf("a stream's status is enabled, paused or disabled, not %q", status)
	}
	var id, prev, method string
	var endpoint *string
	err := tx.QueryRow(ctx, `
		SELECT id::text, status, delivery_method, endpoint_url FROM core.ssf_streams
		WHERE org_id = $1::uuid AND client_id = $2 FOR UPDATE`, orgID, clientID).
		Scan(&id, &prev, &method, &endpoint)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrStreamUnknown
	}
	if err != nil {
		return "", err
	}
	if prev == status {
		return prev, nil
	}

	if prev == "enabled" {
		// Queued before the status changes, as the specification orders it.
		if err := queueStreamUpdated(ctx, tx, id, clientID, method, endpoint, status, reason); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE core.ssf_streams SET status = $2 WHERE id = $1::uuid`, id, status); err != nil {
		return "", err
	}
	switch status {
	case "disabled":
		if _, err := tx.Exec(ctx, `
			DELETE FROM core.outbox
			WHERE topic = 'ssf_event' AND delivered_at IS NULL
			  AND payload->>'stream_id' = $1 AND payload->>'event' <> $2`, id, ssf.StreamUpdated); err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM core.ssf_poll_queue WHERE stream_id = $1::uuid AND event_type <> $2`,
			id, ssf.StreamUpdated); err != nil {
			return "", err
		}
	case "enabled":
		if err := queueStreamUpdated(ctx, tx, id, clientID, method, endpoint, status, reason); err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE core.outbox SET next_attempt_at = now()
			WHERE topic = 'ssf_event' AND delivered_at IS NULL AND payload->>'stream_id' = $1`, id); err != nil {
			return "", err
		}
	}
	return prev, nil
}

// queueStreamUpdated puts a stream-updated event where the stream's receiver
// will find it: the push outbox, or the poll queue.
func queueStreamUpdated(ctx context.Context, tx pgx.Tx, streamID, clientID, method string,
	endpoint *string, status, reason string) error {
	if method == "poll" {
		_, err := tx.Exec(ctx, `
			INSERT INTO core.ssf_poll_queue (stream_id, jti, event_type, payload)
			VALUES ($1::uuid, gen_random_uuid()::text, $2,
			        jsonb_build_object('client_id', $3::text, 'status', $4::text, 'reason', $5::text))`,
			streamID, ssf.StreamUpdated, clientID, status, reason)
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO core.outbox (topic, payload)
		VALUES ('ssf_event', jsonb_build_object(
			'stream_id', $1::text, 'client_id', $2::text, 'endpoint', $3::text,
			'event', $4::text, 'status', $5::text, 'reason', $6::text))`,
		streamID, clientID, endpoint, ssf.StreamUpdated, status, reason)
	return err
}
