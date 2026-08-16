package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Rate limits shared by every instance.
//
// The counters live in the database rather than in process memory, because a
// limit held per process is not a limit on the deployment: with two instances
// behind a load balancer, 40 sign-in attempts that produced 26 allowed and 14
// refused on one instance produced 40 allowed and 0 refused across two. Every
// instance added for availability multiplied the brute-force budget.
//
// # Cost
//
// One round trip per check. On the login path that sits next to an Argon2
// evaluation costing a hundred times more, so the limiter is not what makes
// signing in slow. Where that trade does not hold -- a high-volume endpoint
// with no expensive work behind it -- a process-local bucket is still the right
// answer, and JWKS keeps one for exactly that reason.

// RateResult is the outcome of one check.
type RateResult struct {
	Allowed bool
	// Count is how many requests this window has now seen, including this one.
	Count int
	// Limit and RetryAfter let a caller answer honestly rather than guess.
	Limit      int
	RetryAfter time.Duration
}

// AllowRate counts one request against a keyed limit.
//
// The increment happens INSIDE the UPDATE, referencing the stored row, so two
// concurrent requests cannot both read the same value and both write their own
// result. That is the whole reason this is a fixed window rather than a token
// bucket: a bucket needs read-then-write, and under exactly the load a limiter
// exists for, one of the decrements is lost.
//
// The boundary property is real and worth stating: a caller can spend a full
// window at the end of one and again at the start of the next, so the worst
// case is 2x the limit across a moment. Bounded and known, as against a
// multiple that grew with the number of instances.
func AllowRate(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, key string, limit int, window time.Duration) (RateResult, error) {

	if limit <= 0 || window <= 0 {
		return RateResult{}, fmt.Errorf("rate limit for %q is not configured "+
			"(limit %d, window %s)", key, limit, window)
	}

	res := RateResult{Limit: limit}
	// The window start is derived from the clock, not stored per caller, so
	// every instance agrees on which window it is in without coordinating.
	err := q.QueryRow(ctx, `
		INSERT INTO core.rate_limits (bucket_key, window_start, count)
		VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / $2) * $2), 1)
		ON CONFLICT (bucket_key, window_start)
		DO UPDATE SET count = core.rate_limits.count + 1
		RETURNING count,
		          to_timestamp(floor(extract(epoch FROM now()) / $2) * $2 + $2) - now()`,
		key, window.Seconds()).Scan(&res.Count, &res.RetryAfter)
	if err != nil {
		return res, fmt.Errorf("checking the rate limit for %q: %w", key, err)
	}

	res.Allowed = res.Count <= limit
	return res, nil
}

// PurgeRateLimits drops windows that have passed.
//
// Housekeeping rather than a security control -- an old window can no longer
// permit anything, since the current window is computed from the clock. It is
// here because a table that only grows is how a deployment discovers its disk
// on a Sunday.
func PurgeRateLimits(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.rate_limits WHERE window_start < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
