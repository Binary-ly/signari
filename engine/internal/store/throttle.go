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

// LoginDelay is the backoff after n failures under the defaults.
func LoginDelay(failures int) time.Duration {
	return LoginDelayFor(failures, FreeAttempts, MaxLoginDelay)
}

// LoginDelayFor is the backoff after n failures when free are free and the
// delay is capped at max: 1s, 2s, 4s, 8s ... The organisation sets both
// (migration 0169); FreeAttempts and MaxLoginDelay are their defaults.
//
// Doubling is chosen because it makes guessing infeasible quickly while staying
// invisible to someone who fumbled a password twice. Ten failures is already
// past the cap; a thousand is no worse, which is the point -- the attacker gains
// nothing by continuing.
func LoginDelayFor(failures, free int, max time.Duration) time.Duration {
	if failures <= free {
		return 0
	}
	d := time.Second * time.Duration(math.Pow(2, float64(failures-free-1)))
	if d > max || d <= 0 {
		return max
	}
	return d
}

// The bounds the organisation's settings take (0169).
const (
	MinFreeAttempts  = 1
	MaxFreeAttempts  = 20
	MinMaxLoginDelay = time.Minute
	MaxMaxLoginDelay = 24 * time.Hour
)

// ErrLoginThrottle is a setting outside the bounds.
var ErrLoginThrottle = fmt.Errorf("free attempts must be %d to %d, and the longest delay whole "+
	"seconds from %s to %s", MinFreeAttempts, MaxFreeAttempts, MinMaxLoginDelay, MaxMaxLoginDelay)

// SetLoginThrottle sets an organisation's backoff. Zero leaves a value as it is.
func SetLoginThrottle(ctx context.Context, tx pgx.Tx, orgID string, free int, max time.Duration) error {
	if (free != 0 && (free < MinFreeAttempts || free > MaxFreeAttempts)) ||
		(max != 0 && (max < MinMaxLoginDelay || max > MaxMaxLoginDelay || max%time.Second != 0)) {
		return ErrLoginThrottle
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.organizations
		   SET login_free_attempts = CASE WHEN $2 = 0 THEN login_free_attempts ELSE $2 END,
		       login_max_delay_s   = CASE WHEN $3 = 0 THEN login_max_delay_s ELSE $3 END
		 WHERE id = $1::uuid`, orgID, free, int(max.Seconds()))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrOrganizationNotFound
	}
	return nil
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
	var failures, free, maxSeconds int
	err := db.QueryRow(ctx, `
		UPDATE core.password_credentials pc
		SET failed_attempts = CASE
				WHEN pc.last_failure_at IS NULL OR pc.last_failure_at < now() - $2::interval
				THEN 1 ELSE pc.failed_attempts + 1 END,
		    last_failure_at = now()
		FROM core.organizations o
		WHERE pc.user_id = $1::uuid AND o.id = pc.org_id
		RETURNING pc.failed_attempts, o.login_free_attempts, o.login_max_delay_s`,
		userID, FailureDecay.String()).Scan(&failures, &free, &maxSeconds)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("recording login failure: %w", err)
	}

	if d := LoginDelayFor(failures, free, time.Duration(maxSeconds)*time.Second); d > 0 {
		if _, err := db.Exec(ctx, `
			UPDATE core.password_credentials SET throttled_until = now() + $2::interval
			WHERE user_id = $1::uuid`, userID, d.String()); err != nil {
			return fmt.Errorf("setting throttle window: %w", err)
		}
	}
	return nil
}

// UnlockAccount clears every count a wrong guess at one person charged: the
// password step's backoff, the sign-in form's per-account budget under each
// name they sign in with, and the second-factor step's. What an administrator
// does for somebody who has been sent to wait; the per-address budgets are
// the address's, not the person's, and stay.
func UnlockAccount(ctx context.Context, tx pgx.Tx, userID string) (cleared int, err error) {
	tag, err := tx.Exec(ctx, `
		UPDATE core.password_credentials
		SET failed_attempts = 0, throttled_until = NULL, last_failure_at = NULL
		WHERE user_id = $1::uuid AND (failed_attempts <> 0 OR throttled_until IS NOT NULL)`, userID)
	if err != nil {
		return 0, fmt.Errorf("clearing the sign-in delay: %w", err)
	}
	cleared = int(tag.RowsAffected())
	tag, err = tx.Exec(ctx, `
		DELETE FROM core.rate_limits
		 WHERE bucket_key IN (
		     SELECT 'signin:fail:user:' || lower(u.email) FROM core.users u
		      WHERE u.id = $1::uuid AND u.email IS NOT NULL
		     UNION ALL
		     SELECT 'signin:fail:user:' || lower(u.username) FROM core.users u
		      WHERE u.id = $1::uuid AND u.username IS NOT NULL
		     UNION ALL
		     SELECT 'mfa:fail:user:' || $1::text)`, userID)
	if err != nil {
		return 0, fmt.Errorf("clearing the sign-in budgets: %w", err)
	}
	return cleared + int(tag.RowsAffected()), nil
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
