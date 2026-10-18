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
	var lastSent, verifiedAt, disabledAt *time.Time
	var proved string
	var pending *string
	err = tx.QueryRow(ctx, `
		SELECT address, pending_address, verified_at, last_sent_at, disabled_at
		FROM core.email_otp_credentials
		WHERE user_id = $1::uuid FOR UPDATE`, userID).Scan(&proved, &pending, &verifiedAt, &lastSent, &disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNoEmailOTP
		}
		return "", "", err
	}
	switch purpose {
	case emailCodeSignIn:
		// A disabled factor is sent nothing: a code it would refuse is only
		// more for somebody to guess at.
		if verifiedAt == nil || disabledAt != nil {
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
// refused here, and so is any code while the address is unproved or the factor
// disabled.
//
// guessed reports a wrong guess against a live sign-in code, for the caller to
// charge with RecordEmailOTPFailure once it knows no other factor took the
// code -- as RecordTOTPFailure is charged. A right code resets the count.
func VerifyEmailOTP(ctx context.Context, tx pgx.Tx, userID, submitted string) (ok, guessed bool, err error) {
	ok, _, guessed, err = checkEmailCode(ctx, tx, userID, submitted, emailCodeSignIn)
	return ok, guessed, err
}

// RecordEmailOTPFailure counts one consecutive wrong guess at the email
// factor, and disables it at ceiling (0136).
//
// Each code allowed five guesses and a new one came every minute or so, with
// nothing counting across codes: about 960 guesses a day at a six-digit code,
// indefinitely, where an authenticator app is switched off at the ceiling.
func RecordEmailOTPFailure(ctx context.Context, tx pgx.Tx, userID string, ceiling int) (FactorFailure, error) {
	var f FactorFailure
	err := tx.QueryRow(ctx, `
		UPDATE core.email_otp_credentials
		SET failed_attempts = failed_attempts + 1,
		    disabled_at = CASE WHEN failed_attempts + 1 >= $2 THEN now() END,
		    updated_at = now()
		WHERE user_id = $1::uuid AND disabled_at IS NULL
		RETURNING disabled_at IS NOT NULL`, userID, ceiling).Scan(&f.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return FactorFailure{}, nil
	}
	if err != nil {
		return FactorFailure{}, fmt.Errorf("recording an email code failure: %w", err)
	}
	return f, nil
}

// ConfirmEmailOTPEnrolment checks a submitted ENROLMENT code. On success the
// pending address becomes the proved one and the factor counts from then on.
//
// replaced is the previously proved address when the enrolment moved the factor
// somewhere else, so the caller can tell that address it has stopped receiving
// codes -- the one notice an attacker who redirected the factor cannot suppress.
func ConfirmEmailOTPEnrolment(ctx context.Context, tx pgx.Tx, userID, submitted string) (ok bool, replaced string, err error) {
	ok, replaced, _, err = checkEmailCode(ctx, tx, userID, submitted, emailCodeEnrol)
	return ok, replaced, err
}

func checkEmailCode(ctx context.Context, tx pgx.Tx, userID, submitted, purpose string) (
	ok bool, replaced string, guessed bool, err error) {

	const none = false
	var storedHash []byte
	var expires, verifiedAt, disabledAt *time.Time
	var attempts int
	var codePurpose, pending *string
	var proved string
	err = tx.QueryRow(ctx, `
		SELECT code_hash, code_expires_at, attempts, code_purpose, address, pending_address,
		       verified_at, disabled_at
		FROM core.email_otp_credentials WHERE user_id = $1::uuid FOR UPDATE`, userID).
		Scan(&storedHash, &expires, &attempts, &codePurpose, &proved, &pending, &verifiedAt, &disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", none, nil
		}
		return false, "", none, err
	}
	if storedHash == nil || expires == nil || time.Now().After(*expires) {
		return false, "", none, nil
	}
	if codePurpose == nil || *codePurpose != purpose {
		return false, "", none, nil
	}
	if purpose == emailCodeSignIn && (verifiedAt == nil || disabledAt != nil) {
		return false, "", none, nil
	}
	if purpose == emailCodeEnrol && pending == nil {
		return false, "", none, nil
	}
	if attempts >= EmailOTPMaxAttempts {
		// Budget gone. The code stays dead until a new one is requested, which is
		// what stops five guesses becoming five hundred.
		return false, "", none, nil
	}

	sum := sha256.Sum256([]byte(submitted))
	if subtle.ConstantTimeCompare(sum[:], storedHash) != 1 {
		if _, uerr := tx.Exec(ctx, `
			UPDATE core.email_otp_credentials SET attempts = attempts + 1, updated_at = now()
			WHERE user_id = $1::uuid`, userID); uerr != nil {
			return false, "", none, uerr
		}
		// A guess at the factor itself, for the caller to charge across codes.
		return false, "", purpose == emailCodeSignIn, nil
	}

	if purpose == emailCodeSignIn {
		if _, err := tx.Exec(ctx, `
			UPDATE core.email_otp_credentials
			SET code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, attempts = 0,
			    failed_attempts = 0, updated_at = now()
			WHERE user_id = $1::uuid`, userID); err != nil {
			return false, "", none, err
		}
		return true, "", none, nil
	}

	if verifiedAt != nil && !strings.EqualFold(proved, *pending) {
		replaced = proved
	}
	// Proving an address again is how a disabled factor comes back.
	if _, err := tx.Exec(ctx, `
		UPDATE core.email_otp_credentials
		SET address = pending_address, pending_address = NULL, verified_at = now(),
		    code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, attempts = 0,
		    failed_attempts = 0, disabled_at = NULL, updated_at = now()
		WHERE user_id = $1::uuid`, userID); err != nil {
		return false, "", none, err
	}
	return true, replaced, none, nil
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
