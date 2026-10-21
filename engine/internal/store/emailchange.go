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
	"github.com/jackc/pgx/v5/pgconn"
)

// A person moving their account to another address (migration 0178): the
// address stays until a code sent to the new one comes back.

var (
	// ErrAddressInUse is an address another account in the organisation has.
	ErrAddressInUse = errors.New("another account already uses that address")
	// ErrSameAddress is the address the account already has.
	ErrSameAddress = errors.New("that is already the address on your account")
	// ErrNoEmailChange is no change outstanding, or one past its ceiling.
	ErrNoEmailChange = errors.New("no change of address is waiting for a code")
)

// EmailChange is a change waiting for its code.
type EmailChange struct {
	NewAddress string
	// Closed is past the ceiling of wrong codes: it accepts none.
	Closed bool
}

// PendingEmailChange reads the change waiting for a person, if any.
func PendingEmailChange(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (*EmailChange, error) {
	var c EmailChange
	var failed int
	err := db.QueryRow(ctx, `SELECT new_address, failed_attempts FROM core.email_changes
		WHERE user_id = $1::uuid`, userID).Scan(&c.NewAddress, &failed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Closed = failed >= EmailVerificationCeiling
	return &c, nil
}

// StartEmailChange records the address a person wants and returns the code to
// send to it, replacing any code outstanding. ErrEmailOTPTooSoon for the same
// address within the resend interval; a different address starts afresh.
func StartEmailChange(ctx context.Context, tx pgx.Tx, userID, orgID, address string) (string, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	var current string
	var taken bool
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(u.email, ''),
		       EXISTS (SELECT 1 FROM core.users o WHERE o.org_id = u.org_id AND o.id <> u.id
		                AND lower(o.email) = $2)
		  FROM core.users u WHERE u.id = $1::uuid`, userID, address).Scan(&current, &taken); err != nil {
		return "", err
	}
	switch {
	case strings.EqualFold(current, address):
		return "", ErrSameAddress
	case taken:
		return "", ErrAddressInUse
	}
	var prior string
	var lastSent time.Time
	err := tx.QueryRow(ctx, `SELECT new_address, last_sent_at FROM core.email_changes
		WHERE user_id = $1::uuid FOR UPDATE`, userID).Scan(&prior, &lastSent)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if err == nil && prior == address && time.Since(lastSent) < EmailOTPResendInterval {
		return "", ErrEmailOTPTooSoon
	}
	code, err := newNumericCode(EmailOTPDigits)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(code))
	// The count of wrong codes follows the address: asking again for the same
	// one keeps it, naming another starts afresh.
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.email_changes (user_id, org_id, new_address, code_hash, code_expires_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, now() + $5::interval)
		ON CONFLICT (user_id) DO UPDATE SET
			failed_attempts = CASE WHEN core.email_changes.new_address = EXCLUDED.new_address
			                       THEN core.email_changes.failed_attempts ELSE 0 END,
			new_address = EXCLUDED.new_address, code_hash = EXCLUDED.code_hash,
			code_expires_at = EXCLUDED.code_expires_at, attempts = 0, last_sent_at = now()`,
		userID, orgID, address, sum[:], fmt.Sprintf("%d seconds", int(EmailOTPLifetime.Seconds()))); err != nil {
		return "", fmt.Errorf("recording the change of address: %w", err)
	}
	return code, nil
}

// ConfirmEmailChange checks a submitted code. The right one moves the account to
// the new address, verified by that proof, and returns the old one; guessed is
// a wrong guess at a live code, for the caller to charge.
func ConfirmEmailChange(ctx context.Context, tx pgx.Tx, userID, submitted string) (old, moved string, guessed bool, err error) {
	var stored []byte
	var expires time.Time
	var attempts, failed int
	err = tx.QueryRow(ctx, `SELECT new_address, code_hash, code_expires_at, attempts, failed_attempts
		FROM core.email_changes WHERE user_id = $1::uuid FOR UPDATE`, userID).
		Scan(&moved, &stored, &expires, &attempts, &failed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, ErrNoEmailChange
	}
	if err != nil {
		return "", "", false, err
	}
	if failed >= EmailVerificationCeiling {
		return "", "", false, ErrNoEmailChange
	}
	if time.Now().After(expires) || attempts >= EmailOTPMaxAttempts {
		return "", "", false, nil
	}
	sum := sha256.Sum256([]byte(submitted))
	if subtle.ConstantTimeCompare(sum[:], stored) != 1 {
		if _, err := tx.Exec(ctx, `UPDATE core.email_changes
			SET attempts = attempts + 1, failed_attempts = failed_attempts + 1 WHERE user_id = $1::uuid`,
			userID); err != nil {
			return "", "", false, err
		}
		return "", "", true, nil
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(email, '') FROM core.users WHERE id = $1::uuid`,
		userID).Scan(&old); err != nil {
		return "", "", false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.users SET email = $2, email_verified_at = now(), updated_at = now()
		WHERE id = $1::uuid`, userID, moved); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			// Taken by another account between the request and the code.
			return "", "", false, ErrAddressInUse
		}
		return "", "", false, err
	}
	// The change is done, and the new address is proved, which settles any
	// confirmation the old one was still waiting for.
	if _, err := tx.Exec(ctx, `DELETE FROM core.email_changes WHERE user_id = $1::uuid`, userID); err != nil {
		return "", "", false, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.email_verifications WHERE user_id = $1::uuid`, userID); err != nil {
		return "", "", false, err
	}
	return old, moved, false, nil
}

// CancelEmailChange drops a change waiting for its code.
func CancelEmailChange(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `DELETE FROM core.email_changes WHERE user_id = $1::uuid`, userID)
	return err
}
