package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/ssf"
)

// MinVerificationInterval is how often a stream may ask for a verification:
// once in each window of this length. It is the stream configuration's
// min_verification_interval (§8.1.1, specs/ssf-1_0.txt:1742-1751), which the
// stream management endpoint serves. The windows are the clock's (AllowRate),
// so two requests this far apart are never refused, as the section's SHOULD NOT
// asks, and two a moment apart either side of a window's edge are both
// answered, which its MAY allows.
const MinVerificationInterval = 30 * time.Second

var (
	// ErrStreamDisabled: a disabled stream "will not hold any events for later
	// transmission", so a promise to send one would be false.
	ErrStreamDisabled = errors.New("the stream is disabled")
	// ErrVerificationTooSoon: asked again in a window that has had its one.
	ErrVerificationTooSoon = errors.New("a verification was asked for too recently")
)

// VerificationTooSoon is ErrVerificationTooSoon with how long the window that
// refused it has left, so a Retry-After can say when asking again succeeds
// rather than the whole interval.
type VerificationTooSoon struct{ RetryAfter time.Duration }

func (e *VerificationTooSoon) Error() string { return ErrVerificationTooSoon.Error() }

func (e *VerificationTooSoon) Unwrap() error { return ErrVerificationTooSoon }

// QueueVerification puts a Verification Event on a receiver's own stream, for
// the worker or the next poll. A paused stream holds it with everything else
// and sends it on resuming.
//
// The stream is found by id and client together, so a stream that exists and is
// somebody else's is ErrStreamUnknown, which is §8.1.4.2's 404 "if there is no
// Event Stream with the given "stream_id" for this Event Receiver".
func QueueVerification(ctx context.Context, tx pgx.Tx, clientID, streamID, state string) error {
	var status, method string
	var endpoint *string
	err := tx.QueryRow(ctx, `
		SELECT status, delivery_method, endpoint_url FROM core.ssf_streams
		WHERE id::text = $1 AND client_id = $2`, streamID, clientID).Scan(&status, &method, &endpoint)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrStreamUnknown
	}
	if err != nil {
		return fmt.Errorf("finding the stream to verify: %w", err)
	}
	if status == "disabled" {
		return ErrStreamDisabled
	}

	// One event per window, counted after the lookup: a mistyped id spends none.
	rate, err := AllowRate(ctx, tx, "ssf-verify:"+streamID, 1, MinVerificationInterval)
	if err != nil {
		return err
	}
	if !rate.Allowed {
		return &VerificationTooSoon{RetryAfter: rate.RetryAfter}
	}

	if method == "poll" {
		_, err = tx.Exec(ctx, `
			INSERT INTO core.ssf_poll_queue (stream_id, jti, event_type, payload)
			VALUES ($1::uuid, gen_random_uuid()::text, $2,
			        jsonb_build_object('client_id', $3::text, 'state', $4::text))`,
			streamID, ssf.Verification, clientID, state)
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO core.outbox (topic, payload)
		VALUES ('ssf_event', jsonb_build_object(
			'stream_id', $1::text, 'client_id', $2::text, 'endpoint', $3::text,
			'event', $4::text, 'state', $5::text))`,
		streamID, clientID, endpoint, ssf.Verification, state)
	return err
}
