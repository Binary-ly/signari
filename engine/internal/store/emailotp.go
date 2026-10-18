package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
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

// The two jobs a code can do. One slot holds at most one code, and its purpose
// is recorded with it so that neither can stand in for the other (0126).
const (
	emailCodeSignIn = "signin"
	emailCodeEnrol  = "enrol"
)

// StartEmailOTPEnrolment records an address the user wants codes sent to.
//
// It goes into pending_address and nowhere else. The address that already
// works -- if there is one -- stays the factor until a code sent to the new one
// comes back; writing it over on this step, as this function once did, let any
// holder of a session point the account's sign-in codes at their own mailbox
// without entering a single code (0126). A first-time row is created
// unverified, so it is not a second factor yet either.
func StartEmailOTPEnrolment(ctx context.Context, tx pgx.Tx, userID, orgID, address string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.email_otp_credentials (user_id, org_id, address, pending_address)
		VALUES ($1::uuid, $2::uuid, $3, $3)
		ON CONFLICT (user_id) DO UPDATE SET
			pending_address = EXCLUDED.pending_address,
			-- Any code in flight is invalidated: one sent for a different
			-- purpose or address must not complete this enrolment.
			code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, attempts = 0,
			updated_at = now()`,
		userID, orgID, address)
	if err != nil {
		return fmt.Errorf("starting the email factor enrolment: %w", err)
	}
	return nil
}

// IssueEmailOTP generates a SIGN-IN code for the user's proved address and
// returns the plaintext for sending.
//
// Refuses (ErrNoEmailOTP) while the address is unproved: a code for an address
// nobody has shown they read is not a factor. Replaces any pending code rather
// than adding to it. "Send another" must not leave the previous one valid, or a
// patient attacker accumulates guesses against a widening set of live codes.
func IssueEmailOTP(ctx context.Context, tx pgx.Tx, userID string) (code, address string, err error) {
	return issueEmailCode(ctx, tx, userID, emailCodeSignIn)
}

// IssueEmailOTPEnrolment generates an ENROLMENT code for the pending address.
func IssueEmailOTPEnrolment(ctx context.Context, tx pgx.Tx, userID string) (code, address string, err error) {
	return issueEmailCode(ctx, tx, userID, emailCodeEnrol)
}

func issueEmailCode(ctx context.Context, tx pgx.Tx, userID, purpose string) (code, address string, err error) {
	var lastSent, verifiedAt *time.Time
	var proved string
	var pending *string
	err = tx.QueryRow(ctx, `
		SELECT address, pending_address, verified_at, last_sent_at
		FROM core.email_otp_credentials
		WHERE user_id = $1::uuid FOR UPDATE`, userID).Scan(&proved, &pending, &verifiedAt, &lastSent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNoEmailOTP
		}
		return "", "", err
	}
	switch purpose {
	case emailCodeSignIn:
		if verifiedAt == nil {
			return "", "", ErrNoEmailOTP
		}
		address = proved
	case emailCodeEnrol:
		if pending == nil {
			return "", "", ErrNoEmailOTP
		}
		address = *pending
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
		SET code_hash = $2, code_expires_at = now() + $3::interval, code_purpose = $4,
		    attempts = 0, last_sent_at = now(), updated_at = now()
		WHERE user_id = $1::uuid`,
		userID, sum[:], fmt.Sprintf("%d seconds", int(EmailOTPLifetime.Seconds())), purpose); err != nil {
		return "", "", err
	}
	return code, address, nil
}

// VerifyEmailOTP checks a submitted SIGN-IN code and consumes it on success.
//
// A correct code is destroyed whether or not the rest of the sign-in succeeds: a
// one-time code that survives its use is not one-time. An enrolment code is
// refused here, and so is any code while the address is unproved.
func VerifyEmailOTP(ctx context.Context, tx pgx.Tx, userID, submitted string) (bool, error) {
	ok, _, err := checkEmailCode(ctx, tx, userID, submitted, emailCodeSignIn)
	return ok, err
}

// ConfirmEmailOTPEnrolment checks a submitted ENROLMENT code. On success the
// pending address becomes the proved one and the factor counts from then on.
//
// replaced is the previously proved address when the enrolment moved the factor
// somewhere else, so the caller can tell that address it has stopped receiving
// codes -- the one notice an attacker who redirected the factor cannot suppress.
func ConfirmEmailOTPEnrolment(ctx context.Context, tx pgx.Tx, userID, submitted string) (ok bool, replaced string, err error) {
	return checkEmailCode(ctx, tx, userID, submitted, emailCodeEnrol)
}

func checkEmailCode(ctx context.Context, tx pgx.Tx, userID, submitted, purpose string) (bool, string, error) {
	var storedHash []byte
	var expires, verifiedAt *time.Time
	var attempts int
	var codePurpose, pending *string
	var proved string
	err := tx.QueryRow(ctx, `
		SELECT code_hash, code_expires_at, attempts, code_purpose, address, pending_address, verified_at
		FROM core.email_otp_credentials WHERE user_id = $1::uuid FOR UPDATE`, userID).
		Scan(&storedHash, &expires, &attempts, &codePurpose, &proved, &pending, &verifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", nil
		}
		return false, "", err
	}
	if storedHash == nil || expires == nil || time.Now().After(*expires) {
		return false, "", nil
	}
	if codePurpose == nil || *codePurpose != purpose {
		return false, "", nil
	}
	if purpose == emailCodeSignIn && verifiedAt == nil {
		return false, "", nil
	}
	if purpose == emailCodeEnrol && pending == nil {
		return false, "", nil
	}
	if attempts >= EmailOTPMaxAttempts {
		// Budget gone. The code stays dead until a new one is requested, which is
		// what stops five guesses becoming five hundred.
		return false, "", nil
	}

	sum := sha256.Sum256([]byte(submitted))
	if subtle.ConstantTimeCompare(sum[:], storedHash) != 1 {
		if _, uerr := tx.Exec(ctx, `
			UPDATE core.email_otp_credentials SET attempts = attempts + 1, updated_at = now()
			WHERE user_id = $1::uuid`, userID); uerr != nil {
			return false, "", uerr
		}
		return false, "", nil
	}

	if purpose == emailCodeSignIn {
		if _, err := tx.Exec(ctx, `
			UPDATE core.email_otp_credentials
			SET code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, attempts = 0,
			    updated_at = now()
			WHERE user_id = $1::uuid`, userID); err != nil {
			return false, "", err
		}
		return true, "", nil
	}

	var replaced string
	if verifiedAt != nil && !strings.EqualFold(proved, *pending) {
		replaced = proved
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.email_otp_credentials
		SET address = pending_address, pending_address = NULL, verified_at = now(),
		    code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, attempts = 0,
		    updated_at = now()
		WHERE user_id = $1::uuid`, userID); err != nil {
		return false, "", err
	}
	return true, replaced, nil
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
