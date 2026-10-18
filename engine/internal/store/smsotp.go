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
	// Pending is a number being enrolled, until a code sent to it comes back.
	Pending string
}

// The two kinds of code, kept apart in code_purpose (0135).
const (
	smsCodeSignIn = "signin"
	smsCodeEnrol  = "enrol"
)

// EnrollSMSOTP records a number the person wants codes sent to.
//
// It goes into pending_number and nowhere else. The number that already works
// -- if there is one -- stays the factor until a code sent to the new one comes
// back. This function once wrote the new number over it and cleared
// verified_at, so one POST from any live session switched the factor off and
// pointed the account at a number of the session holder's choosing (0135). A
// first-time row is created unverified, so it is not a second factor yet
// either: a typo would otherwise enrol somebody else's phone.
func EnrollSMSOTP(ctx context.Context, tx pgx.Tx, userID, orgID, rawNumber string) (
	string, error) {

	number, err := sms.NormaliseNumber(rawNumber)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.sms_otp_credentials (user_id, org_id, number, pending_number)
		VALUES ($1::uuid, $2::uuid, $3, $3)
		ON CONFLICT (user_id) DO UPDATE SET
			pending_number = EXCLUDED.pending_number,
			-- Any code in flight is invalidated: one sent for a different
			-- purpose or number must not complete this enrolment.
			code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, attempts = 0,
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
	var pending *string
	err := q.QueryRow(ctx, `
		SELECT org_id::text, number, verified_at, pending_number
		FROM core.sms_otp_credentials WHERE user_id = $1::uuid`, userID).
		Scan(&c.OrgID, &c.Number, &verifiedAt, &pending)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoSMSOTP
		}
		return nil, err
	}
	c.Verified = verifiedAt != nil
	if pending != nil {
		c.Pending = *pending
	}
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

// IssueSMSOTP generates a SIGN-IN code for the proved number and returns it
// with that number.
//
// Refuses (ErrNoSMSOTP) while no number is proved. Replaces any outstanding code
// rather than adding to it: "send another" must not leave the previous one
// live, or a patient attacker accumulates guesses against a widening set of
// valid codes.
func IssueSMSOTP(ctx context.Context, tx pgx.Tx, userID string) (code, number string, err error) {
	return issueSMSCode(ctx, tx, userID, smsCodeSignIn)
}

// IssueSMSOTPEnrolment generates an ENROLMENT code for the pending number.
func IssueSMSOTPEnrolment(ctx context.Context, tx pgx.Tx, userID string) (code, number string, err error) {
	return issueSMSCode(ctx, tx, userID, smsCodeEnrol)
}

func issueSMSCode(ctx context.Context, tx pgx.Tx, userID, purpose string) (code, number string, err error) {
	var lastSent, verifiedAt *time.Time
	var proved string
	var pending *string
	err = tx.QueryRow(ctx, `
		SELECT number, pending_number, verified_at, last_sent_at FROM core.sms_otp_credentials
		WHERE user_id = $1::uuid FOR UPDATE`, userID).Scan(&proved, &pending, &verifiedAt, &lastSent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNoSMSOTP
		}
		return "", "", err
	}
	switch purpose {
	case smsCodeSignIn:
		if verifiedAt == nil {
			return "", "", ErrNoSMSOTP
		}
		number = proved
	case smsCodeEnrol:
		if pending == nil {
			return "", "", ErrNoSMSOTP
		}
		number = *pending
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
		SET code_hash = $2, code_expires_at = now() + $3::interval, code_purpose = $4,
		    attempts = 0, last_sent_at = now(), updated_at = now()
		WHERE user_id = $1::uuid`,
		userID, sum[:], fmt.Sprintf("%d seconds", int(SMSOTPLifetime.Seconds())), purpose); err != nil {
		return "", "", err
	}
	return code, number, nil
}

// VerifySMSOTP checks a submitted SIGN-IN code and consumes it on success.
//
// A correct code is destroyed whether or not the rest of the sign-in succeeds:
// a one-time code that survives its use is not one-time. An enrolment code is
// refused here, and so is any code while no number is proved.
func VerifySMSOTP(ctx context.Context, tx pgx.Tx, userID, submitted string) (bool, error) {
	ok, _, err := checkSMSCode(ctx, tx, userID, submitted, smsCodeSignIn)
	return ok, err
}

// ConfirmSMSOTPEnrolment checks a submitted ENROLMENT code. On success the
// pending number becomes the proved one, and the factor counts from then on.
//
// replaced is the previously proved number when the enrolment moved the factor
// somewhere else, so the caller can tell that number it has stopped receiving
// codes -- the one notice somebody who redirected the factor cannot suppress.
func ConfirmSMSOTPEnrolment(ctx context.Context, tx pgx.Tx, userID, submitted string) (ok bool, replaced string, err error) {
	return checkSMSCode(ctx, tx, userID, submitted, smsCodeEnrol)
}

func checkSMSCode(ctx context.Context, tx pgx.Tx, userID, submitted, purpose string) (bool, string, error) {
	var storedHash []byte
	var expires, verifiedAt *time.Time
	var attempts int
	var codePurpose, pending *string
	var proved string
	err := tx.QueryRow(ctx, `
		SELECT code_hash, code_expires_at, attempts, code_purpose, number, pending_number, verified_at
		FROM core.sms_otp_credentials WHERE user_id = $1::uuid FOR UPDATE`, userID).
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
	if purpose == smsCodeSignIn && verifiedAt == nil {
		return false, "", nil
	}
	if purpose == smsCodeEnrol && pending == nil {
		return false, "", nil
	}
	if attempts >= SMSOTPMaxAttempts {
		// Budget gone. The code stays dead until a new one is requested, which
		// is what stops five guesses becoming five hundred.
		return false, "", nil
	}

	sum := sha256.Sum256([]byte(submitted))
	if subtle.ConstantTimeCompare(sum[:], storedHash) != 1 {
		if _, uerr := tx.Exec(ctx, `
			UPDATE core.sms_otp_credentials SET attempts = attempts + 1, updated_at = now()
			WHERE user_id = $1::uuid`, userID); uerr != nil {
			return false, "", uerr
		}
		return false, "", nil
	}

	if purpose == smsCodeSignIn {
		if _, err := tx.Exec(ctx, `
			UPDATE core.sms_otp_credentials
			SET code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, attempts = 0,
			    updated_at = now()
			WHERE user_id = $1::uuid`, userID); err != nil {
			return false, "", err
		}
		return true, "", nil
	}

	// The proof that the number belongs to the person enrolling it rather than
	// to whoever their typo reached.
	var replaced string
	if verifiedAt != nil && proved != *pending {
		replaced = proved
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.sms_otp_credentials
		SET number = pending_number, pending_number = NULL, verified_at = now(),
		    code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, attempts = 0,
		    updated_at = now()
		WHERE user_id = $1::uuid`, userID); err != nil {
		return false, "", err
	}
	return true, replaced, nil
}

// RemoveSMSOTP deletes the factor.
func RemoveSMSOTP(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM core.sms_otp_credentials WHERE user_id = $1::uuid`, userID)
	return err
}
