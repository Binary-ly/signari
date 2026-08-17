package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Account recovery. See migration 0012 for why this is delay-and-notify.

const (
	// RecoveryDelay is the window in which a real owner can cancel a reset they
	// did not ask for. Long enough that a notification sent at 3am is seen before
	// it matters; short enough that a locked-out user is not stuck for a day.
	//
	// Waived entirely by proving a second factor -- see 0012.
	RecoveryDelay = 30 * time.Minute

	// RecoveryLifetime is how long the whole request stays usable. A reset link
	// that works next week is a credential sitting in a mailbox.
	RecoveryLifetime = 24 * time.Hour
)

var (
	ErrRecoveryNotFound = errors.New("store: no such recovery request")
	// ErrRecoveryPending means the token is valid but the delay has not elapsed.
	// Distinguished from invalid so the user can be told exactly when it will
	// work -- "try again later" with no time is not usable advice.
	ErrRecoveryPending = errors.New("store: recovery request is not effective yet")
)

// RecoveryRequest is a pending reset.
type RecoveryRequest struct {
	ID          string
	UserID      string
	OrgID       string
	EffectiveAt time.Time
	ExpiresAt   time.Time
	WaivedBy    string
}

// CreateRecoveryRequest supersedes any pending request and returns the new one.
//
// waivedBy names the second factor that was proven, or "" for the delayed path.
// Supersedes rather than rejects: a user who clicks "forgot password" twice must
// not be told they already have a request they cannot see, but two live tokens
// would double an attacker's chances.
func CreateRecoveryRequest(ctx context.Context, tx pgx.Tx, userID, orgID string,
	tokenHash, cancelHash []byte, waivedBy string, now time.Time) (*RecoveryRequest, error) {

	if _, err := tx.Exec(ctx, `
		UPDATE core.recovery_requests SET cancelled_at = now()
		WHERE user_id = $1::uuid AND cancelled_at IS NULL AND consumed_at IS NULL`,
		userID); err != nil {
		return nil, fmt.Errorf("superseding earlier recovery requests: %w", err)
	}

	effective := now.Add(RecoveryDelay)
	if waivedBy != "" {
		// A proven second factor is something the mailbox thief does not have, so
		// the delay defends against nothing here and only hurts the real user.
		effective = now
	}

	r := &RecoveryRequest{UserID: userID, OrgID: orgID, EffectiveAt: effective,
		ExpiresAt: now.Add(RecoveryLifetime), WaivedBy: waivedBy}
	err := tx.QueryRow(ctx, `
		INSERT INTO core.recovery_requests
			(user_id, org_id, token_hash, cancel_hash, effective_at, expires_at, waived_by)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)
		RETURNING id::text`,
		userID, orgID, tokenHash, cancelHash, effective, r.ExpiresAt,
		nullIfEmpty(waivedBy)).Scan(&r.ID)
	if err != nil {
		return nil, fmt.Errorf("creating recovery request: %w", err)
	}
	return r, nil
}

// LookupRecovery resolves a reset token.
//
// Returns ErrRecoveryPending when the token is genuine but the delay has not
// elapsed, so the caller can say when it will work rather than implying it is
// wrong.
func LookupRecovery(ctx context.Context, tx pgx.Tx, tokenHash []byte, now time.Time) (*RecoveryRequest, error) {
	var r RecoveryRequest
	var cancelled, consumed *time.Time
	var waived *string

	err := tx.QueryRow(ctx, `
		SELECT id::text, user_id::text, org_id::text, effective_at, expires_at,
		       cancelled_at, consumed_at, waived_by
		FROM core.recovery_requests WHERE token_hash = $1
		FOR UPDATE`, tokenHash).
		Scan(&r.ID, &r.UserID, &r.OrgID, &r.EffectiveAt, &r.ExpiresAt,
			&cancelled, &consumed, &waived)
	if err == pgx.ErrNoRows {
		return nil, ErrRecoveryNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up recovery request: %w", err)
	}
	if waived != nil {
		r.WaivedBy = *waived
	}

	// Cancelled, spent and expired are all reported identically. Telling a caller
	// "this was cancelled" confirms the token was real, which is exactly what an
	// attacker holding a guess wants to learn.
	if cancelled != nil || consumed != nil || now.After(r.ExpiresAt) {
		return nil, ErrRecoveryNotFound
	}
	if now.Before(r.EffectiveAt) {
		return &r, ErrRecoveryPending
	}
	return &r, nil
}

// CancelRecovery kills a pending request by its cancel token.
//
// Idempotent and deliberately quiet: the link is clicked from an email, possibly
// twice, possibly by a mail scanner that prefetches links. Reporting an error on
// the second click would alarm someone who did exactly the right thing.
func CancelRecovery(ctx context.Context, tx pgx.Tx, cancelHash []byte) (userID string, ok bool, err error) {
	err = tx.QueryRow(ctx, `
		UPDATE core.recovery_requests SET cancelled_at = now()
		WHERE cancel_hash = $1 AND cancelled_at IS NULL AND consumed_at IS NULL
		RETURNING user_id::text`, cancelHash).Scan(&userID)
	if err == pgx.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cancelling recovery request: %w", err)
	}
	return userID, true, nil
}

// ConsumeRecovery spends a request, sets the new password, and ends every
// existing session.
//
// All three in one transaction, because a reset that changes the password while
// leaving the attacker's session live has changed nothing they care about --
// which is the most commonly missed half of "reset the password".
func ConsumeRecovery(ctx context.Context, tx pgx.Tx, requestID, userID, newHash string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE core.recovery_requests SET consumed_at = now()
		WHERE id = $1::uuid AND cancelled_at IS NULL AND consumed_at IS NULL`, requestID)
	if err != nil {
		return fmt.Errorf("consuming recovery request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Someone cancelled or spent it between lookup and now.
		return ErrRecoveryNotFound
	}

	if _, err := tx.Exec(ctx, `
		UPDATE core.password_credentials
		SET hash = $2, algorithm = 'argon2id', is_current = true, updated_at = now(),
		    failed_attempts = 0, throttled_until = NULL, last_failure_at = NULL,
		    -- A recovery reset satisfies a required change: the new password went
		    -- through the same policy. Leaving the flag set would demand a second
		    -- change immediately after the first.
		    must_change = false, must_change_reason = NULL, last_breach_check = NULL
		WHERE user_id = $1::uuid`, userID, newHash); err != nil {
		return fmt.Errorf("setting the new password: %w", err)
	}

	// Every session, through the one termination path, so relying parties are
	// told. A password reset that leaves the thief signed in is theatre.
	if _, err := TerminateSessions(ctx, tx, "", userID, ReasonPasswordChange); err != nil {
		return fmt.Errorf("ending sessions after recovery: %w", err)
	}
	return nil
}

// PurgeExpiredRecoveries drops requests nobody can use any more.
func PurgeExpiredRecoveries(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.recovery_requests WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
