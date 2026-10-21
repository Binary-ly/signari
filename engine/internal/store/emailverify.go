package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Proving an address before a person is signed in (migration 0177). Written by
// self-sign-up under a rule that requires it; the sign-in flow's verify_email
// stage sends a code and holds the sign-in until it comes back.

// EmailVerificationCeiling is how many wrong codes one verification takes, across
// codes, before it accepts none. Whoever reaches the code holds the password,
// and for an account made by self-sign-up that may be somebody who typed
// another person's address; so the guessing is bounded in total, not only per
// code. Past it the address can still be proved by resetting the password from
// the email, which proves the same mailbox.
const EmailVerificationCeiling = 20

var (
	// ErrEmailVerificationClosed is a verification past its ceiling, or one for
	// an account with no address to send to.
	ErrEmailVerificationClosed = errors.New("this address can no longer be confirmed with a code")
)

// RequireEmailVerification records that a person must prove their address
// before they are signed in.
func RequireEmailVerification(ctx context.Context, tx pgx.Tx, userID, orgID string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.email_verifications (user_id, org_id) VALUES ($1::uuid, $2::uuid)
		ON CONFLICT (user_id) DO NOTHING`, userID, orgID); err != nil {
		return fmt.Errorf("requiring the address be confirmed: %w", err)
	}
	return nil
}

// Obligations are what an account must do before a sign-in may finish, read in
// one query because every sign-in through the built-in flow asks both: a
// password change an administrator or a breach flagged, and an address
// self-sign-up has not yet seen proved.
type Obligations struct {
	PasswordChange bool
	ChangeReason   string
	// EmailPending is a verification outstanding for an address not already
	// proved.
	EmailPending bool
}

// AccountObligations reads them.
func AccountObligations(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (Obligations, error) {
	var o Obligations
	err := db.QueryRow(ctx, `
		SELECT COALESCE(p.must_change, false), COALESCE(p.must_change_reason, ''),
		       u.email_verified_at IS NULL
		         AND EXISTS (SELECT 1 FROM core.email_verifications v WHERE v.user_id = u.id)
		  FROM core.users u LEFT JOIN core.password_credentials p ON p.user_id = u.id
		 WHERE u.id = $1::uuid`, userID).Scan(&o.PasswordChange, &o.ChangeReason, &o.EmailPending)
	if errors.Is(err, pgx.ErrNoRows) {
		return Obligations{}, nil
	}
	return o, err
}

// IssueEmailVerification makes a code for the person's current address and
// returns it for sending, replacing any code outstanding. ErrEmailOTPTooSoon
// within the resend interval; ErrEmailVerificationClosed past the ceiling or
// with no address.
func IssueEmailVerification(ctx context.Context, tx pgx.Tx, userID string) (code, address string, err error) {
	var lastSent *time.Time
	var failed int
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(u.email, ''), v.last_sent_at, v.failed_attempts
		  FROM core.email_verifications v JOIN core.users u ON u.id = v.user_id
		 WHERE v.user_id = $1::uuid FOR UPDATE OF v`, userID).Scan(&address, &lastSent, &failed)
	if err != nil {
		return "", "", err
	}
	if address == "" || failed >= EmailVerificationCeiling {
		return "", "", ErrEmailVerificationClosed
	}
	if lastSent != nil && time.Since(*lastSent) < EmailOTPResendInterval {
		return "", "", ErrEmailOTPTooSoon
	}
	if code, err = newNumericCode(EmailOTPDigits); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(code))
	if _, err := tx.Exec(ctx, `
		UPDATE core.email_verifications
		   SET address = $2, code_hash = $3, code_expires_at = now() + $4::interval,
		       attempts = 0, last_sent_at = now()
		 WHERE user_id = $1::uuid`,
		userID, address, sum[:], fmt.Sprintf("%d seconds", int(EmailOTPLifetime.Seconds()))); err != nil {
		return "", "", err
	}
	return code, address, nil
}

// ConfirmEmailVerification checks a submitted code. The right one, for the
// address the person still has, proves it: users.email_verified_at is set and
// the verification removed. guessed reports a wrong guess at a live code, which
// the caller charges to the second-factor budget as well.
func ConfirmEmailVerification(ctx context.Context, tx pgx.Tx, userID, submitted string) (ok, guessed bool, err error) {
	var stored []byte
	var expires *time.Time
	var attempts, failed int
	var sentTo *string
	var current string
	err = tx.QueryRow(ctx, `
		SELECT v.code_hash, v.code_expires_at, v.attempts, v.failed_attempts, v.address, COALESCE(u.email, '')
		  FROM core.email_verifications v JOIN core.users u ON u.id = v.user_id
		 WHERE v.user_id = $1::uuid FOR UPDATE OF v`, userID).
		Scan(&stored, &expires, &attempts, &failed, &sentTo, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	// A code proves the address it went to, so one sent before the address
	// changed proves nothing about the new one.
	if stored == nil || expires == nil || time.Now().After(*expires) || sentTo == nil ||
		!strings.EqualFold(*sentTo, current) || attempts >= EmailOTPMaxAttempts ||
		failed >= EmailVerificationCeiling {
		return false, false, nil
	}
	sum := sha256.Sum256([]byte(submitted))
	if subtle.ConstantTimeCompare(sum[:], stored) != 1 {
		if _, err := tx.Exec(ctx, `UPDATE core.email_verifications
			SET attempts = attempts + 1, failed_attempts = failed_attempts + 1 WHERE user_id = $1::uuid`,
			userID); err != nil {
			return false, false, err
		}
		return false, true, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE core.users SET email_verified_at = now() WHERE id = $1::uuid`,
		userID); err != nil {
		return false, false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.email_verifications WHERE user_id = $1::uuid`,
		userID); err != nil {
		return false, false, err
	}
	return true, false, nil
}

// EmailVerificationClosed reports whether a person's verification has taken
// its ceiling of wrong codes.
func EmailVerificationClosed(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (bool, error) {
	var closed bool
	err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.email_verifications
		WHERE user_id = $1::uuid AND failed_attempts >= $2)`, userID, EmailVerificationCeiling).Scan(&closed)
	return closed, err
}

// AddressProvedByRecovery records what a completed password reset proved: the
// address its link was sent to, if the account still has it. That address is
// verified and any outstanding verification ends. An address changed since
// the link went out is left as it was.
func AddressProvedByRecovery(ctx context.Context, tx pgx.Tx, requestID, userID string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE core.users u SET email_verified_at = COALESCE(u.email_verified_at, now())
		  FROM core.recovery_requests r
		 WHERE u.id = $2::uuid AND r.id = $1::uuid AND r.user_id = u.id
		   AND r.sent_to IS NOT NULL AND lower(r.sent_to) = lower(u.email)`, requestID, userID)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM core.email_verifications WHERE user_id = $1::uuid`, userID)
	return err
}
