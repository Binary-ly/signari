package store

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Per-account login throttling.
//
// See migration 0011 for why this is a decaying delay rather than a lockout. The
// short version: a hard lockout gives an attacker a button that disables any
// account they can name, which is worse than the guessing it prevents.

const (
	// FreeAttempts before any delay applies. People mistype passwords; charging
	// the first few costs real users far more than it costs an attacker.
	FreeAttempts = 3

	// MaxLoginDelay caps the backoff. Uncapped exponential growth is a permanent
	// lockout with extra steps, and it is how "temporary" throttling becomes a
	// support ticket.
	MaxLoginDelay = 15 * time.Minute

	// FailureDecay is how long a failure counts for. Without decay, an account
	// carries typos from months ago and eventually throttles a legitimate user
	// who has done nothing wrong.
	FailureDecay = 1 * time.Hour
)

// LoginDelay is the backoff after n failures: 1s, 2s, 4s, 8s ... capped.
//
// Doubling is chosen because it makes guessing infeasible quickly while staying
// invisible to someone who fumbled a password twice. Ten failures is already
// past the cap; a thousand is no worse, which is the point -- the attacker gains
// nothing by continuing.
func LoginDelay(failures int) time.Duration {
	if failures <= FreeAttempts {
		return 0
	}
	d := time.Second * time.Duration(math.Pow(2, float64(failures-FreeAttempts-1)))
	if d > MaxLoginDelay || d <= 0 {
		return MaxLoginDelay
	}
	return d
}

// ThrottleState is what the login path needs before spending an Argon2 hash.
type ThrottleState struct {
	Throttled bool
	// RetryAfter is how long until the next attempt is allowed. Reported to the
	// user, because "try again" with no interval is advice nobody can follow.
	RetryAfter time.Duration
	Failures   int
}

// CheckLoginThrottle reads the current state for a user.
//
// Called BEFORE password verification, so a throttled account costs an attacker
// a lookup rather than an Argon2 evaluation -- which is the difference between
// rate limiting and a memory-exhaustion amplifier.
func CheckLoginThrottle(ctx context.Context, db *pgxpool.Pool, userID string) (ThrottleState, error) {
	var failures int
	var throttledUntil, lastFailure *time.Time

	err := db.QueryRow(ctx, `
		SELECT failed_attempts, throttled_until, last_failure_at
		FROM core.password_credentials WHERE user_id = $1::uuid`, userID).
		Scan(&failures, &throttledUntil, &lastFailure)
	if err == pgx.ErrNoRows {
		return ThrottleState{}, nil
	}
	if err != nil {
		return ThrottleState{}, fmt.Errorf("checking login throttle: %w", err)
	}

	// Stale failures do not count. Read-side decay rather than a sweep job: it is
	// exact at the moment it matters and needs nothing scheduled.
	if lastFailure != nil && time.Since(*lastFailure) > FailureDecay {
		return ThrottleState{}, nil
	}

	st := ThrottleState{Failures: failures}
	if throttledUntil != nil && time.Now().Before(*throttledUntil) {
		st.Throttled = true
		st.RetryAfter = time.Until(*throttledUntil).Round(time.Second)
	}
	return st, nil
}

// RecordLoginFailure increments the counter and sets the next backoff window.
func RecordLoginFailure(ctx context.Context, db *pgxpool.Pool, userID string) error {
	// The decay is applied in SQL so the counter cannot be inflated by an
	// attacker who spaces attempts out beyond the decay window: each burst starts
	// from a clean count, which is correct, and each burst is still throttled.
	var failures int
	err := db.QueryRow(ctx, `
		UPDATE core.password_credentials
		SET failed_attempts = CASE
				WHEN last_failure_at IS NULL OR last_failure_at < now() - $2::interval
				THEN 1 ELSE failed_attempts + 1 END,
		    last_failure_at = now()
		WHERE user_id = $1::uuid
		RETURNING failed_attempts`, userID, FailureDecay.String()).Scan(&failures)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("recording login failure: %w", err)
	}

	if d := LoginDelay(failures); d > 0 {
		if _, err := db.Exec(ctx, `
			UPDATE core.password_credentials SET throttled_until = now() + $2::interval
			WHERE user_id = $1::uuid`, userID, d.String()); err != nil {
			return fmt.Errorf("setting throttle window: %w", err)
		}
	}
	return nil
}

// ClearLoginThrottle resets everything after a successful sign-in.
//
// A correct password is proof the person is who they say they are, so carrying
// their earlier typos forward would throttle the one user we now know is
// legitimate.
func ClearLoginThrottle(ctx context.Context, db *pgxpool.Pool, userID string) error {
	_, err := db.Exec(ctx, `
		UPDATE core.password_credentials
		SET failed_attempts = 0, throttled_until = NULL, last_failure_at = NULL
		WHERE user_id = $1::uuid AND (failed_attempts <> 0 OR throttled_until IS NOT NULL)`,
		userID)
	if err != nil {
		return fmt.Errorf("clearing login throttle: %w", err)
	}
	return nil
}
