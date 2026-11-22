package outbox

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The shape every outbox drain has, in one place.
//
// # Why this is shared when the drains deliberately are not
//
// The two drains -- logout notices and security events -- were written
// independently on purpose, with a comment saying a shared helper would invite
// one to be tuned for the other. That reasoning is sound about POLICY: how long
// to back off, what to log, which receiver to call.
//
// It was not sound about MECHANISM, and the cost showed up immediately. When
// the transaction boundary in the logout drain turned out to be wrong -- every
// HTTP call made with row locks held and a pooled connection checked out, up to
// 250 seconds for a batch of 25 against dead receivers -- the fix went into one
// drain and not its twin. Duplicated mechanism means a correctness fix has to
// be remembered twice.
//
// So the boundaries live here and the policy stays with each caller.
//
// # The three phases, and why each transaction ends where it does
//
//	claim    a short transaction: take rows FOR UPDATE SKIP LOCKED, push
//	         next_attempt_at forward by a lease, commit. SKIP LOCKED divides
//	         work between instances; the lease is what keeps it divided AFTER
//	         the locks are released, which they must be in order to...
//
//	deliver  ...make the network calls with NO transaction open. This is the
//	         whole point. Concurrency is bounded so one hanging receiver does
//	         not delay every notice queued behind it.
//
//	record   one short statement per kind of result, however many there are.
//
// The cost is that a crash between claiming and recording leaves rows hidden
// for the lease before another instance retries them: a delay, not a loss.

// drainSpec is one topic's policy. The mechanism is drainTopic's.
type drainSpec struct {
	topic string
	batch int
	// deliver sends one payload. It runs with no transaction open.
	deliver func(ctx context.Context, raw []byte) error
	// backoff decides how long to wait after a failure. Per-topic, so a
	// receiver of one kind can be tuned without touching the other.
	backoff func(attempts int) time.Duration
	// onFailure reports a failed delivery in whatever terms suit the topic.
	onFailure func(raw []byte, attempts int, err error)
}

// heldError is a delivery deliberately not attempted yet: the row waits for
// wait and is tried again, with no attempt charged, because nothing failed. A
// paused Shared Signals stream is the case: its events are held, not sent, and
// charging each look as a failure would park them before the stream resumed.
type heldError struct {
	reason string
	wait   time.Duration
}

func (e *heldError) Error() string { return e.reason }

// droppedError is a delivery that will never be attempted: the row is closed
// with the reason recorded, as the webhook drain closes one for a deleted
// subscription, rather than retried against nothing.
type droppedError struct{ reason string }

func (e *droppedError) Error() string { return e.reason }

// claimed is one row taken for delivery.
type claimed struct {
	id       int64
	raw      []byte
	attempts int
}

// drainTopic claims a batch, delivers it, and records what happened.
func (w *Worker) drainTopic(ctx context.Context, spec drainSpec) (int, error) {
	batch, err := w.claimTopic(ctx, spec.topic, spec.batch)
	if err != nil || len(batch) == 0 {
		return 0, err
	}

	results := make([]error, len(batch))
	inParallel(len(batch), func(i int) { results[i] = spec.deliver(ctx, batch[i].raw) })

	var delivered []int64
	var held, dropped, failed resultRows
	for i, err := range results {
		row := batch[i]
		var hold *heldError
		var drop *droppedError
		switch {
		case err == nil:
			delivered = append(delivered, row.id)
		case errors.As(err, &hold):
			held.add(row.id, hold.wait, hold.reason)
		case errors.As(err, &drop):
			dropped.add(row.id, 0, drop.reason)
		default:
			failed.add(row.id, spec.backoff(row.attempts), err.Error())
		}
	}

	if len(delivered) > 0 {
		if _, err := w.db.Exec(ctx,
			`UPDATE core.outbox SET delivered_at = now(), last_error = NULL WHERE id = ANY($1)`,
			delivered); err != nil {
			return 0, err
		}
	}
	if len(held.ids) > 0 {
		if _, err := w.db.Exec(ctx, `
			UPDATE core.outbox o SET next_attempt_at = now() + v.wait::interval, last_error = v.reason
			  FROM unnest($1::bigint[], $2::text[], $3::text[]) AS v(id, wait, reason)
			 WHERE o.id = v.id`, held.ids, held.waits, held.reasons); err != nil {
			return len(delivered), err
		}
	}
	if len(dropped.ids) > 0 {
		if _, err := w.db.Exec(ctx, `
			UPDATE core.outbox o SET delivered_at = now(), last_error = v.reason
			  FROM unnest($1::bigint[], $2::text[]) AS v(id, reason)
			 WHERE o.id = v.id`, dropped.ids, dropped.reasons); err != nil {
			return len(delivered), err
		}
	}
	if len(failed.ids) > 0 {
		if _, err := w.db.Exec(ctx, `
			UPDATE core.outbox o SET attempts = o.attempts + 1, next_attempt_at = now() + v.wait::interval,
			       last_error = v.reason
			  FROM unnest($1::bigint[], $2::text[], $3::text[]) AS v(id, wait, reason)
			 WHERE o.id = v.id`, failed.ids, failed.waits, failed.reasons); err != nil {
			return len(delivered), err
		}
		if spec.onFailure != nil {
			for i, err := range results {
				var hold *heldError
				var drop *droppedError
				if err != nil && !errors.As(err, &hold) && !errors.As(err, &drop) {
					spec.onFailure(batch[i].raw, batch[i].attempts, err)
				}
			}
		}
	}
	return len(delivered), nil
}

// resultRows are rows that went one way, for a statement to record together.
type resultRows struct {
	ids     []int64
	waits   []string
	reasons []string
}

func (r *resultRows) add(id int64, wait time.Duration, reason string) {
	r.ids = append(r.ids, id)
	r.waits = append(r.waits, wait.String())
	r.reasons = append(r.reasons, reason)
}

// claimTopic takes a batch and hides it from other instances.
//
// attempts is deliberately NOT incremented here. A crash between claiming and
// recording is not the receiver failing to answer, and charging it as one would
// march a perfectly reachable endpoint toward MaxAttempts and park it.
func (w *Worker) claimTopic(ctx context.Context, topic string, batch int) ([]claimed, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id, payload, attempts
		FROM core.outbox
		WHERE topic = $1
		  AND delivered_at IS NULL
		  AND attempts < $2
		  AND next_attempt_at <= now()
		ORDER BY id
		LIMIT $3
		FOR UPDATE SKIP LOCKED`, topic, MaxAttempts, batch)
	if err != nil {
		return nil, err
	}

	var out []claimed
	var ids []int64
	for rows.Next() {
		var c claimed
		if err := rows.Scan(&c.id, &c.raw, &c.attempts); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
		ids = append(ids, c.id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE core.outbox SET next_attempt_at = now() + $2::interval
		WHERE id = ANY($1)`, ids, claimLease.String()); err != nil {
		return nil, fmt.Errorf("leasing %s rows: %w", topic, err)
	}
	return out, tx.Commit(ctx)
}
