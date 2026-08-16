package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/sms"
)

// SMS one-time codes.
//
// The same three rules as the email factor, deliberately identical: one live
// code, a resend interval, a bounded attempt count. Two channels with two sets
// of rules means one of them is missing a check, and it is always the second
// one written.
//
// The one structural difference is verified_at. An email address is proven by
// the code arriving in it; a phone number needs the same proof BEFORE the
// factor counts, because a typo during enrolment would otherwise put somebody
// else's phone between a person and their own account.

const (
	// SMSOTPLifetime is shorter than the email equivalent. A text arrives in
	// seconds and is read on the device in the person's hand; ten minutes of
	// validity would be ten minutes of a live code sitting on a lock screen.
	SMSOTPLifetime = 5 * time.Minute
	// SMSOTPResendInterval bounds "send me another". Longer than email's,
	// because every message costs money and a resend button without a floor is
	// a way to spend somebody else's budget.
	SMSOTPResendInterval = 60 * time.Second
	// SMSOTPMaxAttempts against one code.
	SMSOTPMaxAttempts = 5
	// SMSOTPDigits is what the person types.
	SMSOTPDigits = 6
)

var (
	ErrNoSMSOTP      = errors.New("no SMS factor is enrolled")
	ErrSMSOTPTooSoon = errors.New("a code was sent moments ago")
)

// SMSOTPCredential is an enrolled SMS factor.
type SMSOTPCredential struct {
	UserID   string
	OrgID    string
	Number   string
	Verified bool
}

// EnrollSMSOTP records the factor against a number, UNVERIFIED.
//
// Not a second factor yet. It becomes one when VerifySMSOTP succeeds against a
// code sent to that number -- see MarkSMSOTPVerified. Enrolling and trusting in
// one step means a typo enrols somebody else's phone, and the account's owner
// is then locked out by their own security setting.
func EnrollSMSOTP(ctx context.Context, tx pgx.Tx, userID, orgID, rawNumber string) (
	string, error) {

	number, err := sms.NormaliseNumber(rawNumber)
	if err != nil {
		return "", err
	}
	// Re-enrolling a different number clears any verification: the new number
	// has proven nothing.
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.sms_otp_credentials (user_id, org_id, number)
		VALUES ($1::uuid, $2::uuid, $3)
		ON CONFLICT (user_id) DO UPDATE SET
			number = EXCLUDED.number,
			verified_at = CASE WHEN core.sms_otp_credentials.number = EXCLUDED.number
			                   THEN core.sms_otp_credentials.verified_at
			                   ELSE NULL END,
			code_hash = NULL, code_expires_at = NULL, attempts = 0,
			updated_at = now()`,
		userID, orgID, number); err != nil {
		return "", fmt.Errorf("enrolling the SMS factor: %w", err)
	}
	return number, nil
}

// LoadSMSOTP reads the enrolled factor.
func LoadSMSOTP(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (*SMSOTPCredential, error) {

	c := &SMSOTPCredential{UserID: userID}
	var verifiedAt *time.Time
	err := q.QueryRow(ctx, `
		SELECT org_id::text, number, verified_at
		FROM core.sms_otp_credentials WHERE user_id = $1::uuid`, userID).
		Scan(&c.OrgID, &c.Number, &verifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoSMSOTP
		}
		return nil, err
	}
	c.Verified = verifiedAt != nil
	return c, nil
}

// HasVerifiedSMS reports whether SMS is a usable second factor for this user.
//
// Verified, not merely enrolled. The distinction is the whole reason the column
// exists, and a helper that blurred it would put the bug back.
func HasVerifiedSMS(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (bool, error) {

	var ok bool
	err := q.QueryRow(ctx, `
		SELECT verified_at IS NOT NULL FROM core.sms_otp_credentials
		WHERE user_id = $1::uuid`, userID).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ok, err
}

// IssueSMSOTP generates a code and returns it with the number to send it to.
//
// Replaces any pending code rather than adding to it: "send another" must not
// leave the previous one live, or a patient attacker accumulates guesses
// against a widening set of valid codes.
func IssueSMSOTP(ctx context.Context, tx pgx.Tx, userID string) (code, number string, err error) {
	var lastSent *time.Time
	err = tx.QueryRow(ctx, `
		SELECT number, last_sent_at FROM core.sms_otp_credentials
		WHERE user_id = $1::uuid FOR UPDATE`, userID).Scan(&number, &lastSent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNoSMSOTP
		}
		return "", "", err
	}
	if lastSent != nil && time.Since(*lastSent) < SMSOTPResendInterval {
		return "", "", ErrSMSOTPTooSoon
	}

	code, err = newNumericCode(SMSOTPDigits)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(code))
	if _, err := tx.Exec(ctx, `
		UPDATE core.sms_otp_credentials
		SET code_hash = $2, code_expires_at = now() + $3::interval,
		    attempts = 0, last_sent_at = now(), updated_at = now()
		WHERE user_id = $1::uuid`,
		userID, sum[:], fmt.Sprintf("%d seconds", int(SMSOTPLifetime.Seconds()))); err != nil {
		return "", "", err
	}
	return code, number, nil
}

// VerifySMSOTP checks a submitted code and consumes it on success.
//
// A correct code is destroyed whether or not the rest of the sign-in succeeds:
// a one-time code that survives its use is not one-time.
func VerifySMSOTP(ctx context.Context, tx pgx.Tx, userID, submitted string) (bool, error) {
	var storedHash []byte
	var expires *time.Time
	var attempts int
	err := tx.QueryRow(ctx, `
		SELECT code_hash, code_expires_at, attempts
		FROM core.sms_otp_credentials WHERE user_id = $1::uuid FOR UPDATE`, userID).
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
	if attempts >= SMSOTPMaxAttempts {
		// Budget gone. The code stays dead until a new one is requested, which
		// is what stops five guesses becoming five hundred.
		return false, nil
	}

	sum := sha256.Sum256([]byte(submitted))
	if subtle.ConstantTimeCompare(sum[:], storedHash) != 1 {
		if _, uerr := tx.Exec(ctx, `
			UPDATE core.sms_otp_credentials SET attempts = attempts + 1, updated_at = now()
			WHERE user_id = $1::uuid`, userID); uerr != nil {
			return false, uerr
		}
		return false, nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE core.sms_otp_credentials
		SET code_hash = NULL, code_expires_at = NULL, attempts = 0, updated_at = now()
		WHERE user_id = $1::uuid`, userID); err != nil {
		return false, err
	}
	return true, nil
}

// MarkSMSOTPVerified completes enrolment.
//
// Called only after a code sent to the number came back, which is the proof
// that the number belongs to the person enrolling it rather than to whoever
// their typo reached.
func MarkSMSOTPVerified(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE core.sms_otp_credentials SET verified_at = now(), updated_at = now()
		WHERE user_id = $1::uuid AND verified_at IS NULL`, userID)
	return err
}

// RemoveSMSOTP deletes the factor.
func RemoveSMSOTP(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM core.sms_otp_credentials WHERE user_id = $1::uuid`, userID)
	return err
}
