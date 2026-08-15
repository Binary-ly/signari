package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
)

// Email as a second factor.

var (
	// ErrNoEmailOTP means the user has not enrolled this factor.
	ErrNoEmailOTP = errors.New("no email second factor enrolled")
	// ErrEmailOTPTooSoon throttles resends.
	ErrEmailOTPTooSoon = errors.New("a code was sent very recently")
)

const (
	// EmailOTPLifetime is how long a code is good for. Long enough for mail to
	// arrive and be read on another device, short enough that a code sitting in
	// a mailbox is not a standing key.
	EmailOTPLifetime = 10 * time.Minute
	// EmailOTPResendInterval bounds "send me another": without it the button is
	// a way to flood somebody's inbox.
	EmailOTPResendInterval = 60 * time.Second
	// EmailOTPMaxAttempts against one code. Six digits is a million
	// possibilities; five guesses makes that irrelevant.
	EmailOTPMaxAttempts = 5
	// EmailOTPDigits is what the person types.
	EmailOTPDigits = 6
)

// EmailOTPCredential is an enrolled email factor.
type EmailOTPCredential struct {
	UserID  string
	OrgID   string
	Address string
}

// EnrollEmailOTP records the factor against a specific address.
func EnrollEmailOTP(ctx context.Context, tx pgx.Tx, userID, orgID, address string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.email_otp_credentials (user_id, org_id, address)
		VALUES ($1::uuid, $2::uuid, $3)
		ON CONFLICT (user_id) DO UPDATE SET
			address = EXCLUDED.address,
			-- Changing the address invalidates any code in flight: one sent to
			-- the old address must not unlock the new configuration.
			code_hash = NULL, code_expires_at = NULL, attempts = 0,
			updated_at = now()`,
		userID, orgID, address)
	if err != nil {
		return fmt.Errorf("enrolling the email factor: %w", err)
	}
	return nil
}

// IssueEmailOTP generates a code, stores its hash, and returns the plaintext for
// sending.
//
// Replaces any pending code rather than adding to it. "Send another" must not
// leave the previous one valid, or a patient attacker accumulates guesses
// against a widening set of live codes.
func IssueEmailOTP(ctx context.Context, tx pgx.Tx, userID string) (code, address string, err error) {
	var lastSent *time.Time
	err = tx.QueryRow(ctx, `
		SELECT address, last_sent_at FROM core.email_otp_credentials
		WHERE user_id = $1::uuid FOR UPDATE`, userID).Scan(&address, &lastSent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNoEmailOTP
		}
		return "", "", err
	}
	if lastSent != nil && time.Since(*lastSent) < EmailOTPResendInterval {
		return "", "", ErrEmailOTPTooSoon
	}

	code, err = newNumericCode(EmailOTPDigits)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(code))
	if _, err := tx.Exec(ctx, `
		UPDATE core.email_otp_credentials
		SET code_hash = $2, code_expires_at = now() + $3::interval,
		    attempts = 0, last_sent_at = now(), updated_at = now()
		WHERE user_id = $1::uuid`,
		userID, sum[:], fmt.Sprintf("%d seconds", int(EmailOTPLifetime.Seconds()))); err != nil {
		return "", "", err
	}
	return code, address, nil
}

// VerifyEmailOTP checks a submitted code and consumes it on success.
//
// A correct code is destroyed whether or not the rest of the sign-in succeeds: a
// one-time code that survives its use is not one-time.
func VerifyEmailOTP(ctx context.Context, tx pgx.Tx, userID, submitted string) (bool, error) {
	var storedHash []byte
	var expires *time.Time
	var attempts int
	err := tx.QueryRow(ctx, `
		SELECT code_hash, code_expires_at, attempts
		FROM core.email_otp_credentials WHERE user_id = $1::uuid FOR UPDATE`, userID).
		Scan(&storedHash, &expires, &attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if storedHash == nil || expires == nil || time.Now().After(*expires) {
		return false, nil
	}
	if attempts >= EmailOTPMaxAttempts {
		// Budget gone. The code stays dead until a new one is requested, which is
		// what stops five guesses becoming five hundred.
		return false, nil
	}

	sum := sha256.Sum256([]byte(submitted))
	if subtle.ConstantTimeCompare(sum[:], storedHash) != 1 {
		if _, uerr := tx.Exec(ctx, `
			UPDATE core.email_otp_credentials SET attempts = attempts + 1, updated_at = now()
			WHERE user_id = $1::uuid`, userID); uerr != nil {
			return false, uerr
		}
		return false, nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE core.email_otp_credentials
		SET code_hash = NULL, code_expires_at = NULL, attempts = 0, updated_at = now()
		WHERE user_id = $1::uuid`, userID); err != nil {
		return false, err
	}
	return true, nil
}

// newNumericCode returns n digits, uniformly.
//
// rand.Int rather than modulo over a random byte: modulo biases the low values,
// and a six-digit code has only a million of them, so the distribution IS the
// entropy. Skewing it would be careless in a way nobody would ever notice.
func newNumericCode(n int) (string, error) {
	limit := big.NewInt(1)
	for i := 0; i < n; i++ {
		limit.Mul(limit, big.NewInt(10))
	}
	v, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", fmt.Errorf("generating a numeric code: %w", err)
	}
	return fmt.Sprintf("%0*d", n, v), nil
}
