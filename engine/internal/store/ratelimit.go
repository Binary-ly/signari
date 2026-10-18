package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// Reservation is one place in a window taken by ReserveRate, to be given back
// with Release when what it guarded turns out not to count.
type Reservation struct {
	key   string
	start time.Time
}

// ReserveRate takes one place in a keyed window only while the window is below
// limit, and reports whether it did. A caller refused is NOT counted, so its
// own retries cannot extend its refusal.
//
// It exists for a check that has to come before something expensive. A
// failure budget read beforehand and charged afterwards admits every request
// that arrives during the expensive part: a burst of parallel guesses each
// read a count below the limit and each paid for an Argon2 evaluation before
// the first of them was charged. Taking the place first, and handing it back
// when the attempt succeeds, closes that window: the burst stops at the limit.
func ReserveRate(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, key string, limit int, window time.Duration) (Reservation, bool, error) {

	if limit <= 0 || window <= 0 {
		return Reservation{}, false, fmt.Errorf("rate limit for %q is not configured "+
			"(limit %d, window %s)", key, limit, window)
	}
	if window > MaxRateWindow {
		return Reservation{}, false, fmt.Errorf("rate limit for %q has a %s window, longer "+
			"than the %s PurgeRateLimits keeps", key, window, MaxRateWindow)
	}
	r := Reservation{key: key}
	err := q.QueryRow(ctx, `
		INSERT INTO core.rate_limits (bucket_key, window_start, count)
		VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / $2) * $2), 1)
		ON CONFLICT (bucket_key, window_start)
		DO UPDATE SET count = core.rate_limits.count + 1
		WHERE core.rate_limits.count < $3
		RETURNING window_start`, key, window.Seconds(), limit).Scan(&r.start)
	if err == pgx.ErrNoRows {
		return Reservation{}, false, nil
	}
	if err != nil {
		return Reservation{}, false, fmt.Errorf("reserving against the rate limit for %q: %w", key, err)
	}
	return r, true, nil
}

// Release gives a reservation's place back, in the window it was taken from.
// A zero Reservation releases nothing.
func (r Reservation) Release(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}) error {
	if r.key == "" {
		return nil
	}
	_, err := q.Exec(ctx, `
		UPDATE core.rate_limits SET count = count - 1
		 WHERE bucket_key = $1 AND window_start = $2 AND count > 0`, r.key, r.start)
	return err
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
	if window > MaxRateWindow {
		return RateResult{}, fmt.Errorf("rate limit for %q has a %s window, longer than "+
			"the %s PurgeRateLimits keeps; its counter would be deleted while live", key,
			window, MaxRateWindow)
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

// MaxRateWindow is the longest window a limit may use, and how far back
// PurgeRateLimits keeps rows. The two are one number so they cannot disagree:
// a row that started before it has ended, whatever its own length.
//
// The purge used to delete everything that started over an hour ago. The SMS
// ceilings count per day in windows starting at midnight UTC, so from 01:00
// the janitor deleted each live counter on its next pass, and "ten a day per
// number" became ten a minute.
const MaxRateWindow = 24 * time.Hour

// PurgeRateLimits drops windows that have passed.
//
// Housekeeping rather than a security control -- an old window can no longer
// permit anything, since the current window is computed from the clock. It is
// here because a table that only grows is how a deployment discovers its disk
// on a Sunday. It keeps every row that could still be a live window.
func PurgeRateLimits(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.rate_limits WHERE window_start < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(MaxRateWindow.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CountRate reads a window's counter without charging anything to it.
//
// Separate from AllowRate because some callers ask a different question. A rate
// limiter asks "may this proceed", which is a decision that costs a request; an
// adaptive CAPTCHA asks "has this address been failing", which is a reading
// taken on every page render and must not itself count as an attempt.
//
// Merging the two would mean the sign-in page escalated its own challenge by
// being displayed.
func CountRate(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, key string, window time.Duration) (int, error) {

	if window <= 0 || window > MaxRateWindow {
		return 0, fmt.Errorf("no usable window given for %q (%s; at most %s)", key, window,
			MaxRateWindow)
	}
	var n int
	err := q.QueryRow(ctx, `
		SELECT COALESCE(count, 0) FROM core.rate_limits
		WHERE bucket_key = $1
		  AND window_start = to_timestamp(floor(extract(epoch FROM now()) / $2) * $2)`,
		key, window.Seconds()).Scan(&n)
	if err != nil {
		if err == pgx.ErrNoRows {
			// No row is a real answer: nothing has happened in this window.
			return 0, nil
		}
		return 0, fmt.Errorf("reading the counter for %q: %w", key, err)
	}
	return n, nil
}

// ClearRate forgets a counter, for a caller that has a reason to.
//
// A successful sign-in clears the adaptive CAPTCHA pressure for that address:
// somebody who mistyped their password four times and then got it right is not
// an attacker, and leaving them challenged for the rest of the window teaches
// them the challenge is noise.
//
// Deliberately NOT used by the rate limiter. There, "I eventually succeeded"
// is exactly what an attacker also does.
func ClearRate(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, key string) error {

	_, err := q.Exec(ctx, `DELETE FROM core.rate_limits WHERE bucket_key = $1`, key)
	return err
}
