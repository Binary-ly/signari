package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/keys"
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
	// ErrSMSVerifierUnavailable is a delegated code the service could not
	// check. The code is refused, not charged: an outage is not a guess.
	ErrSMSVerifierUnavailable = errors.New("the SMS verification service did not answer")
)

// SMSDelegate checks a code a delegated verification service sent, to number
// or under its id, whichever is known (sms.Verifier.Check); nil where there is
// no service.
type SMSDelegate func(ctx context.Context, number, id, code string) (bool, error)

// plausibleDelegatedCode is what a verification service's code can look like:
// 4 to 10 digits. Anything else is not sent to it, so a recovery code or an
// authenticator code tried first does not spend one of its checks.
func plausibleDelegatedCode(s string) bool {
	if len(s) < 4 || len(s) > 10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// SMSOTPCredential is an enrolled SMS factor.
type SMSOTPCredential struct {
	UserID string
	OrgID  string
	// Number is empty when only its hash is kept (Hashed).
	Number   string
	Verified bool
	// Pending is a number being enrolled, until a code sent to it comes back;
	// empty when only its hash is kept (PendingHashed).
	Pending string
	// Hashed is a proved number kept only as a keyed hash (migration 0173):
	// the person retypes it to be sent a code.
	Hashed        bool
	PendingHashed bool
}

// ErrSMSNumberMismatch is a retyped number whose hash is not the one kept.
var ErrSMSNumberMismatch = errors.New("that is not the number on the account")

// SMSNumberMAC is the keyed hash kept for a number in an organisation that
// keeps only hashes: under the person's own subject key (keys.SubjectKey.MAC).
func SMSNumberMAC(sk *keys.SubjectKey, number string) []byte {
	return sk.MAC([]byte(number), "sms_number")
}

// SMSNumbersHashed reports whether an organisation keeps only hashes of
// numbers (organizations.sms_numbers).
func SMSNumbersHashed(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (bool, error) {
	var mode string
	if err := q.QueryRow(ctx, `SELECT sms_numbers FROM core.organizations WHERE id = $1::uuid`,
		orgID).Scan(&mode); err != nil {
		return false, fmt.Errorf("reading how SMS numbers are kept: %w", err)
	}
	return mode == "hashed", nil
}

// SetSMSNumbers sets whether an organisation keeps numbers or only their
// hashes. The one writer, behind `signari instance sms-numbers`.
func SetSMSNumbers(ctx context.Context, tx pgx.Tx, orgID string, hashed bool) error {
	mode := "stored"
	if hashed {
		mode = "hashed"
	}
	tag, err := tx.Exec(ctx, `UPDATE core.organizations SET sms_numbers = $2 WHERE id = $1::uuid`, orgID, mode)
	if err != nil {
		return fmt.Errorf("setting how SMS numbers are kept: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrOrganizationNotFound
	}
	return nil
}

// HashSMSNumber replaces a proved number with its keyed hash, for a person in
// an organisation that has moved to keeping hashes: done at their next
// sign-in, which is still texted to the stored number.
func HashSMSNumber(ctx context.Context, tx pgx.Tx, userID string, hash []byte) error {
	_, err := tx.Exec(ctx, `
		UPDATE core.sms_otp_credentials SET number_hash = $2, number = NULL, updated_at = now()
		 WHERE user_id = $1::uuid AND number IS NOT NULL AND verified_at IS NOT NULL`, userID, hash)
	if err != nil {
		return fmt.Errorf("hashing the SMS number: %w", err)
	}
	return nil
}

// SetSMSCodeRef records a delegated service's id for the outstanding code.
func SetSMSCodeRef(ctx context.Context, db interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, userID, ref string) error {
	_, err := db.Exec(ctx, `UPDATE core.sms_otp_credentials SET code_ref = $2
		 WHERE user_id = $1::uuid AND code_delegated AND code_purpose IS NOT NULL`, userID, ref)
	return err
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
//
// hash, for an organisation that keeps only hashes, is the number's keyed
// hash, and the number itself is not stored at all: the code that proves it
// is sent to the number from the same request (IssueSMSOTPEnrolmentTo).
func EnrollSMSOTP(ctx context.Context, tx pgx.Tx, userID, orgID, rawNumber string, hash []byte) (
	string, error) {

	number, err := sms.NormaliseNumber(rawNumber)
	if err != nil {
		return "", err
	}
	var kept *string
	if hash == nil {
		kept = &number
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.sms_otp_credentials (user_id, org_id, number, pending_number, pending_hash)
		VALUES ($1::uuid, $2::uuid, $3, $3, $4)
		ON CONFLICT (user_id) DO UPDATE SET
			pending_number = EXCLUDED.pending_number,
			pending_hash = EXCLUDED.pending_hash,
			-- Any code in flight is invalidated: one sent for a different
			-- purpose or number must not complete this enrolment.
			code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, code_delegated = false,
			code_ref = NULL, attempts = 0,
			updated_at = now()`,
		userID, orgID, kept, hash); err != nil {
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
	var number, pending *string
	err := q.QueryRow(ctx, `
		SELECT org_id::text, number, verified_at, pending_number,
		       number IS NULL AND number_hash IS NOT NULL, pending_hash IS NOT NULL
		FROM core.sms_otp_credentials WHERE user_id = $1::uuid`, userID).
		Scan(&c.OrgID, &number, &verifiedAt, &pending, &c.Hashed, &c.PendingHashed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoSMSOTP
		}
		return nil, err
	}
	c.Verified = verifiedAt != nil
	if number != nil {
		c.Number = *number
	}
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
//
// delegated records a code a verification service will make and send
// instead, and returns no code: the caller asks the service to start.
func IssueSMSOTP(ctx context.Context, tx pgx.Tx, userID string, delegated bool) (code, number string, err error) {
	return issueSMSCode(ctx, tx, userID, smsCodeSignIn, delegated, "", nil)
}

// IssueSMSOTPTo is IssueSMSOTP for a number kept only as a hash: to is the
// number the person retyped and toHash its keyed hash, and a hash that is not
// the kept one is ErrSMSNumberMismatch, with nothing sent.
func IssueSMSOTPTo(ctx context.Context, tx pgx.Tx, userID, to string, toHash []byte, delegated bool) (
	code, number string, err error) {
	return issueSMSCode(ctx, tx, userID, smsCodeSignIn, delegated, to, toHash)
}

// IssueSMSOTPEnrolment generates an ENROLMENT code for the pending number.
func IssueSMSOTPEnrolment(ctx context.Context, tx pgx.Tx, userID string, delegated bool) (code, number string, err error) {
	return issueSMSCode(ctx, tx, userID, smsCodeEnrol, delegated, "", nil)
}

// IssueSMSOTPEnrolmentTo is IssueSMSOTPEnrolment for a pending number kept
// only as a hash, sent to the number from the enrolling request.
func IssueSMSOTPEnrolmentTo(ctx context.Context, tx pgx.Tx, userID, to string, toHash []byte, delegated bool) (
	code, number string, err error) {
	return issueSMSCode(ctx, tx, userID, smsCodeEnrol, delegated, to, toHash)
}

func issueSMSCode(ctx context.Context, tx pgx.Tx, userID, purpose string, delegated bool, to string,
	toHash []byte) (code, number string, err error) {

	var lastSent, verifiedAt, disabledAt *time.Time
	var proved, pending *string
	var provedHash, pendingHash []byte
	err = tx.QueryRow(ctx, `
		SELECT number, pending_number, number_hash, pending_hash, verified_at, last_sent_at, disabled_at
		  FROM core.sms_otp_credentials
		WHERE user_id = $1::uuid FOR UPDATE`, userID).
		Scan(&proved, &pending, &provedHash, &pendingHash, &verifiedAt, &lastSent, &disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNoSMSOTP
		}
		return "", "", err
	}
	// The kept number, or the retyped one when its hash is the kept hash.
	choose := func(kept *string, keptHash []byte) (string, error) {
		switch {
		case kept != nil:
			return *kept, nil
		case keptHash == nil:
			return "", ErrNoSMSOTP
		case toHash == nil || subtle.ConstantTimeCompare(toHash, keptHash) != 1:
			return "", ErrSMSNumberMismatch
		}
		return to, nil
	}
	switch purpose {
	case smsCodeSignIn:
		// A disabled factor is sent nothing: a code it would refuse is only
		// more for somebody to guess at, and costs a message.
		if verifiedAt == nil || disabledAt != nil {
			return "", "", ErrNoSMSOTP
		}
		if number, err = choose(proved, provedHash); err != nil {
			return "", "", err
		}
	case smsCodeEnrol:
		if number, err = choose(pending, pendingHash); err != nil {
			return "", "", err
		}
	}
	if lastSent != nil && time.Since(*lastSent) < SMSOTPResendInterval {
		return "", "", ErrSMSOTPTooSoon
	}

	// A delegated code is the service's, so what is stored is the hash of no
	// code: random bytes, which keep the purpose-and-hash constraint and which
	// an engine that does not know the column refuses every code against.
	hash := make([]byte, sha256.Size)
	if delegated {
		if _, err := rand.Read(hash); err != nil {
			return "", "", err
		}
	} else {
		if code, err = newNumericCode(SMSOTPDigits); err != nil {
			return "", "", err
		}
		sum := sha256.Sum256([]byte(code))
		hash = sum[:]
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.sms_otp_credentials
		SET code_hash = $2, code_delegated = $5, code_ref = NULL, code_expires_at = now() + $3::interval,
		    code_purpose = $4, attempts = 0, last_sent_at = now(), updated_at = now()
		WHERE user_id = $1::uuid`,
		userID, hash, fmt.Sprintf("%d seconds", int(SMSOTPLifetime.Seconds())), purpose, delegated); err != nil {
		return "", "", err
	}
	return code, number, nil
}

// VerifySMSOTP checks a submitted SIGN-IN code and consumes it on success.
//
// A correct code is destroyed whether or not the rest of the sign-in succeeds:
// a one-time code that survives its use is not one-time. An enrolment code is
// refused here, and so is any code while no number is proved or the factor is
// disabled.
//
// guessed reports a wrong guess against a live sign-in code, for the caller to
// charge with RecordSMSOTPFailure, as VerifyEmailOTP does.
//
// A code the delegated service made (code_delegated) is checked by delegate.
func VerifySMSOTP(ctx context.Context, tx pgx.Tx, userID, submitted string, delegate SMSDelegate) (ok, guessed bool, err error) {
	ok, _, guessed, err = checkSMSCode(ctx, tx, userID, submitted, smsCodeSignIn, delegate)
	return ok, guessed, err
}

// RecordSMSOTPFailure counts one consecutive wrong guess at the SMS factor, and
// disables it at ceiling (0136), as RecordEmailOTPFailure does for email.
func RecordSMSOTPFailure(ctx context.Context, tx pgx.Tx, userID string, ceiling int) (FactorFailure, error) {
	var f FactorFailure
	err := tx.QueryRow(ctx, `
		UPDATE core.sms_otp_credentials
		SET failed_attempts = failed_attempts + 1,
		    disabled_at = CASE WHEN failed_attempts + 1 >= $2 THEN now() END,
		    updated_at = now()
		WHERE user_id = $1::uuid AND disabled_at IS NULL
		RETURNING disabled_at IS NOT NULL`, userID, ceiling).Scan(&f.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return FactorFailure{}, nil
	}
	if err != nil {
		return FactorFailure{}, fmt.Errorf("recording an SMS code failure: %w", err)
	}
	return f, nil
}

// ConfirmSMSOTPEnrolment checks a submitted ENROLMENT code. On success the
// pending number becomes the proved one, and the factor counts from then on.
//
// replaced is the previously proved number when the enrolment moved the factor
// somewhere else, so the caller can tell that number it has stopped receiving
// codes -- the one notice somebody who redirected the factor cannot suppress.
func ConfirmSMSOTPEnrolment(ctx context.Context, tx pgx.Tx, userID, submitted string, delegate SMSDelegate) (
	ok bool, replaced string, err error) {
	ok, replaced, _, err = checkSMSCode(ctx, tx, userID, submitted, smsCodeEnrol, delegate)
	return ok, replaced, err
}

func checkSMSCode(ctx context.Context, tx pgx.Tx, userID, submitted, purpose string, delegate SMSDelegate) (
	ok bool, replaced string, guessed bool, err error) {

	const none = false
	var storedHash, pendingHash []byte
	var delegated bool
	var expires, verifiedAt, disabledAt *time.Time
	var attempts int
	var codePurpose, pending, proved, ref *string
	err = tx.QueryRow(ctx, `
		SELECT code_hash, code_delegated, code_ref, code_expires_at, attempts, code_purpose, number,
		       pending_number, pending_hash, verified_at, disabled_at
		FROM core.sms_otp_credentials WHERE user_id = $1::uuid FOR UPDATE`, userID).
		Scan(&storedHash, &delegated, &ref, &expires, &attempts, &codePurpose, &proved, &pending, &pendingHash,
			&verifiedAt, &disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", none, nil
		}
		return false, "", none, err
	}
	// A delegated code is the service's to check; with no service to ask, it
	// is no code.
	if storedHash == nil || (delegated && delegate == nil) || expires == nil || time.Now().After(*expires) {
		return false, "", none, nil
	}
	if codePurpose == nil || *codePurpose != purpose {
		return false, "", none, nil
	}
	if purpose == smsCodeSignIn && (verifiedAt == nil || disabledAt != nil) {
		return false, "", none, nil
	}
	if purpose == smsCodeEnrol && pending == nil && pendingHash == nil {
		return false, "", none, nil
	}
	if attempts >= SMSOTPMaxAttempts {
		// Budget gone. The code stays dead until a new one is requested, which
		// is what stops five guesses becoming five hundred.
		return false, "", none, nil
	}

	var match bool
	if delegated {
		if !plausibleDelegatedCode(submitted) {
			return false, "", none, nil
		}
		// The number where it is kept, and the service's id where it gave one:
		// a number kept only as a hash is checked by the id alone.
		var number, id string
		kept := proved
		if purpose == smsCodeEnrol {
			kept = pending
		}
		if kept != nil {
			number = *kept
		}
		if ref != nil {
			id = *ref
		}
		if number == "" && id == "" {
			return false, "", none, fmt.Errorf("%w: the number is kept only as a hash and the service "+
				"gave no id for the code", ErrSMSVerifierUnavailable)
		}
		approved, derr := delegate(ctx, number, id, submitted)
		if derr != nil {
			return false, "", none, fmt.Errorf("%w: %v", ErrSMSVerifierUnavailable, derr)
		}
		match = approved
	} else {
		sum := sha256.Sum256([]byte(submitted))
		match = subtle.ConstantTimeCompare(sum[:], storedHash) == 1
	}
	if !match {
		if _, uerr := tx.Exec(ctx, `
			UPDATE core.sms_otp_credentials SET attempts = attempts + 1, updated_at = now()
			WHERE user_id = $1::uuid`, userID); uerr != nil {
			return false, "", none, uerr
		}
		// A guess at the factor itself, for the caller to charge across codes.
		return false, "", purpose == smsCodeSignIn, nil
	}

	if purpose == smsCodeSignIn {
		if _, err := tx.Exec(ctx, `
			UPDATE core.sms_otp_credentials
			SET code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, code_delegated = false,
			    code_ref = NULL, attempts = 0, failed_attempts = 0, updated_at = now()
			WHERE user_id = $1::uuid`, userID); err != nil {
			return false, "", none, err
		}
		return true, "", none, nil
	}

	// The proof that the number belongs to the person enrolling it rather than
	// to whoever their typo reached. Proving a number again is also how a
	// disabled factor comes back. The number it moved from is told only where
	// it is kept, and the new one compared only where it is too.
	if verifiedAt != nil && proved != nil && (pending == nil || *proved != *pending) {
		replaced = *proved
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.sms_otp_credentials
		SET number = pending_number, number_hash = pending_hash, pending_number = NULL, pending_hash = NULL,
		    verified_at = now(),
		    code_hash = NULL, code_expires_at = NULL, code_purpose = NULL, code_delegated = false,
		    code_ref = NULL, attempts = 0,
		    failed_attempts = 0, disabled_at = NULL, updated_at = now()
		WHERE user_id = $1::uuid`, userID); err != nil {
		return false, "", none, err
	}
	return true, replaced, none, nil
}

// RemoveSMSOTP deletes the factor.
func RemoveSMSOTP(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM core.sms_otp_credentials WHERE user_id = $1::uuid`, userID)
	return err
}
