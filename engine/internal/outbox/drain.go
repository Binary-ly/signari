package outbox

import (
	"context"
	"fmt"
	"sync"
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
//	record   one short statement per result.
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

	type outcome struct {
		row claimed
		err error
	}
	results := make([]outcome, len(batch))

	sem := make(chan struct{}, deliveryConcurrency)
	var wg sync.WaitGroup
	for i, row := range batch {
		wg.Add(1)
		go func(i int, row claimed) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = outcome{row: row, err: spec.deliver(ctx, row.raw)}
		}(i, row)
	}
	wg.Wait()

	delivered := 0
	for _, r := range results {
		if r.err == nil {
			if _, e := w.db.Exec(ctx,
				`UPDATE core.outbox SET delivered_at = now(), last_error = NULL WHERE id = $1`,
				r.row.id); e != nil {
				return delivered, e
			}
			delivered++
			continue
		}

		wait := spec.backoff(r.row.attempts)
		if _, e := w.db.Exec(ctx, `
			UPDATE core.outbox
			SET attempts = attempts + 1,
			    next_attempt_at = now() + $2::interval,
			    last_error = $3
			WHERE id = $1`, r.row.id, wait.String(), r.err.Error()); e != nil {
			return delivered, e
		}
		if spec.onFailure != nil {
			spec.onFailure(r.row.raw, r.row.attempts, r.err)
		}
	}
	return delivered, nil
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
