package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// The AEAD context binding TOTP ciphertext to its purpose. A blob moved to
// another column will not decrypt, rather than silently becoming another secret.
const totpContext = "totp_secret"

const (
	// MaxTOTPFailures before the credential locks. A 6-digit code is a million
	// possibilities; without a per-credential limit an attacker walks it in
	// hours. Deliberately per credential, not global: a global limiter cannot
	// tell a slow attack on one account from ordinary traffic.
	MaxTOTPFailures = 5
	// TOTPLockout is short on purpose. The goal is to make guessing infeasible,
	// not to hand an attacker a way to lock a victim out by failing on their
	// behalf -- a long lockout turns a defence into a denial of service.
	TOTPLockout = 5 * time.Minute

	// MaxConsecutiveFactorFailures is where a pause becomes a switch-off. The
	// lockout above re-arms on every failure after the fifth, so on its own it
	// allowed about 288 guesses a day for as long as anybody cared to keep
	// going. NIST SP 800-63B §3.2.2: "The verifier SHALL limit consecutive
	// failed authentication attempts using a specific authenticator on a single
	// subscriber account to no more than 100 by disabling that authenticator".
	//
	// A deployment may set it lower (SIGNARI_MFA_FAILURE_LIMIT), never higher.
	// Only someone who already passed the password step can spend these, so
	// unlike a password counter it is not a way to lock a stranger out.
	MaxConsecutiveFactorFailures = 100
	// MinConsecutiveFactorFailures is the lowest that may be configured. Below
	// it, a phone with a drifting clock and a user retyping the same stale code
	// switches their own authenticator off.
	MinConsecutiveFactorFailures = 10
)

// FactorFailureLimit returns the ceiling to apply, given what was configured:
// zero means the default, and anything outside the allowed range is refused.
func FactorFailureLimit(configured int) (int, error) {
	if configured == 0 {
		return MaxConsecutiveFactorFailures, nil
	}
	if configured < MinConsecutiveFactorFailures || configured > MaxConsecutiveFactorFailures {
		return 0, fmt.Errorf("the second-factor failure limit must be between %d and %d, not %d",
			MinConsecutiveFactorFailures, MaxConsecutiveFactorFailures, configured)
	}
	return configured, nil
}

var (
	ErrNoTOTP           = errors.New("store: no TOTP credential")
	ErrTOTPLocked       = errors.New("store: TOTP credential is locked")
	ErrTOTPDisabled     = errors.New("store: TOTP credential was disabled after repeated failures")
	ErrNoTOTPEnrolment  = errors.New("store: no TOTP enrolment in progress")
	ErrTOTPEnrolmentOld = errors.New("store: the TOTP enrolment has expired; start again")
)

// TOTPEnrolmentTTL bounds how long a shown-but-unconfirmed secret stays
// confirmable. Long enough to find a phone and scan; short enough that an
// abandoned enrolment does not linger as a second secret for the account.
const TOTPEnrolmentTTL = 15 * time.Minute

// TOTPCredential is an enrolled authenticator.
type TOTPCredential struct {
	Secret      []byte
	Digits      int
	Period      time.Duration
	Confirmed   bool
	LastCounter int64
	LockedUntil *time.Time
}

// StartTOTPEnrolment stores a secret the user is about to scan, APART from any
// credential they already have.
//
// It used to write straight into core.totp_credentials with confirmed_at NULL,
// which kept an unscanned authenticator from locking anyone out -- by
// overwriting the confirmed credential the moment enrolment was opened. Opening
// it was a GET, so one cross-site link turned a user's second factor off
// (migration 0125). The confirmed credential is now replaced only by
// CompleteTOTPEnrolment, after the user proves their app holds the new secret.
//
// Starting again replaces an earlier unfinished enrolment, never a credential.
func StartTOTPEnrolment(ctx context.Context, tx pgx.Tx, userID, orgID string, secret []byte,
	digits int, period time.Duration, root *keys.RootKey) error {

	sk, err := keys.LoadOrCreateSubjectKey(ctx, tx, userID, root)
	if err != nil {
		return fmt.Errorf("subject key for TOTP enrolment: %w", err)
	}
	// Same context as the credential, so completion moves the ciphertext rather
	// than unsealing and resealing it.
	sealed, err := sk.Seal(secret, totpContext)
	if err != nil {
		return fmt.Errorf("sealing TOTP secret: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.totp_enrolments (user_id, org_id, secret_enc, digits, period_secs)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET
			org_id = EXCLUDED.org_id,
			secret_enc = EXCLUDED.secret_enc,
			digits = EXCLUDED.digits,
			period_secs = EXCLUDED.period_secs,
			created_at = now()`,
		userID, orgID, sealed, digits, int(period.Seconds())); err != nil {
		return fmt.Errorf("storing the TOTP enrolment: %w", err)
	}
	return nil
}

// LoadTOTPEnrolment reads the secret shown for enrolment, refusing one older
// than TOTPEnrolmentTTL.
func LoadTOTPEnrolment(ctx context.Context, tx pgx.Tx, userID string, root *keys.RootKey) (*TOTPCredential, error) {
	var sealed []byte
	var digits, period int
	var createdAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT secret_enc, digits, period_secs, created_at
		FROM core.totp_enrolments WHERE user_id = $1::uuid
		FOR UPDATE`, userID).Scan(&sealed, &digits, &period, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoTOTPEnrolment
	}
	if err != nil {
		return nil, fmt.Errorf("loading the TOTP enrolment: %w", err)
	}
	if time.Since(createdAt) > TOTPEnrolmentTTL {
		return nil, ErrTOTPEnrolmentOld
	}
	sk, err := keys.LoadOrCreateSubjectKey(ctx, tx, userID, root)
	if err != nil {
		return nil, fmt.Errorf("subject key for TOTP enrolment: %w", err)
	}
	secret, err := sk.Open(sealed, totpContext)
	if err != nil {
		return nil, fmt.Errorf("decrypting the TOTP enrolment secret: %w", err)
	}
	return &TOTPCredential{Secret: secret, Digits: digits, Period: time.Duration(period) * time.Second}, nil
}

// CompleteTOTPEnrolment makes the enrolment the user's confirmed credential,
// replacing any previous one, and records the counter of the code that proved
// it so that code cannot be replayed. Reports whether a confirmed credential was
// replaced, so the caller can tell the account holder.
//
// Replacement is deliberate: a user who re-enrols has decided the previous
// authenticator is lost, and leaving it live would be a second, forgotten way
// into the account.
func CompleteTOTPEnrolment(ctx context.Context, tx pgx.Tx, userID string, counter int64) (replaced bool, err error) {
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.totp_credentials
		                WHERE user_id = $1::uuid AND confirmed_at IS NOT NULL)`,
		userID).Scan(&replaced); err != nil {
		return false, fmt.Errorf("checking for an existing TOTP credential: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.totp_credentials
			(user_id, org_id, secret_enc, digits, period_secs, confirmed_at, last_used_counter)
		SELECT user_id, org_id, secret_enc, digits, period_secs, now(), $2
		  FROM core.totp_enrolments WHERE user_id = $1::uuid
		ON CONFLICT (user_id) DO UPDATE SET
			org_id = EXCLUDED.org_id,
			secret_enc = EXCLUDED.secret_enc,
			digits = EXCLUDED.digits,
			period_secs = EXCLUDED.period_secs,
			confirmed_at = now(),
			last_used_counter = EXCLUDED.last_used_counter,
			failed_attempts = 0,
			locked_until = NULL,
			disabled_at = NULL`, userID, counter)
	if err != nil {
		return false, fmt.Errorf("confirming the TOTP credential: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, ErrNoTOTPEnrolment
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.totp_enrolments WHERE user_id = $1::uuid`, userID); err != nil {
		return false, fmt.Errorf("clearing the TOTP enrolment: %w", err)
	}
	return replaced, nil
}

// LoadTOTP reads and decrypts a credential.
func LoadTOTP(ctx context.Context, tx pgx.Tx, userID string, root *keys.RootKey) (*TOTPCredential, error) {
	var sealed []byte
	var digits, period int
	var confirmedAt, lockedUntil, disabledAt *time.Time
	var lastCounter int64

	err := tx.QueryRow(ctx, `
		SELECT secret_enc, digits, period_secs, confirmed_at, last_used_counter, locked_until,
		       disabled_at
		FROM core.totp_credentials WHERE user_id = $1::uuid
		FOR UPDATE`, userID).
		Scan(&sealed, &digits, &period, &confirmedAt, &lastCounter, &lockedUntil, &disabledAt)
	if err == pgx.ErrNoRows {
		return nil, ErrNoTOTP
	}
	if err != nil {
		return nil, fmt.Errorf("loading TOTP credential: %w", err)
	}

	// Checked before decrypting: a locked credential should cost an attacker a
	// lookup, not an unwrap.
	if disabledAt != nil {
		return nil, ErrTOTPDisabled
	}
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		return nil, ErrTOTPLocked
	}

	sk, err := keys.LoadOrCreateSubjectKey(ctx, tx, userID, root)
	if err != nil {
		return nil, fmt.Errorf("subject key for TOTP: %w", err)
	}
	secret, err := sk.Open(sealed, totpContext)
	if err != nil {
		return nil, fmt.Errorf("decrypting TOTP secret: %w", err)
	}

	return &TOTPCredential{
		Secret: secret, Digits: digits, Period: time.Duration(period) * time.Second,
		Confirmed: confirmedAt != nil, LastCounter: lastCounter, LockedUntil: lockedUntil,
	}, nil
}

// RecordTOTPSuccess advances the counter and clears the failure state.
//
// The counter is what makes replay protection real, so this MUST be called and
// MUST commit. A verification that succeeds without recording leaves the code
// spendable again for the rest of its window.
func RecordTOTPSuccess(ctx context.Context, tx pgx.Tx, userID string, counter int64) error {
	_, err := tx.Exec(ctx, `
		UPDATE core.totp_credentials
		SET last_used_counter = GREATEST(last_used_counter, $2),
		    failed_attempts = 0, locked_until = NULL,
		    confirmed_at = COALESCE(confirmed_at, now())
		WHERE user_id = $1::uuid`, userID, counter)
	if err != nil {
		return fmt.Errorf("recording TOTP success: %w", err)
	}
	return nil
}

// FactorFailure is what one failed code did to a factor.
type FactorFailure struct {
	// Locked is the short TOTP pause; recovery codes have no pause, only the
	// ceiling.
	Locked bool
	// Disabled is true only for the failure that switched the factor off, so
	// the account holder is told once rather than on every later attempt.
	Disabled bool
}

// RecordTOTPFailure increments the counter, locks on the threshold, and
// disables the credential on the ceiling (see MaxConsecutiveFactorFailures).
//
// failed_attempts is reset only by a success, so it is the CONSECUTIVE count
// §3.2.2 asks for. A credential already disabled is left alone: nothing tries
// it, so nothing should be counting against it.
func RecordTOTPFailure(ctx context.Context, tx pgx.Tx, userID string, ceiling int) (FactorFailure, error) {
	var f FactorFailure
	err := tx.QueryRow(ctx, `
		UPDATE core.totp_credentials
		SET failed_attempts = failed_attempts + 1,
		    locked_until = CASE WHEN failed_attempts + 1 >= $2
		                        THEN now() + $3::interval ELSE locked_until END,
		    disabled_at = CASE WHEN failed_attempts + 1 >= $4 THEN now() END
		WHERE user_id = $1::uuid AND disabled_at IS NULL
		RETURNING locked_until IS NOT NULL AND locked_until > now(), disabled_at IS NOT NULL`,
		userID, MaxTOTPFailures, TOTPLockout.String(), ceiling).Scan(&f.Locked, &f.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return FactorFailure{}, nil
	}
	if err != nil {
		return FactorFailure{}, fmt.Errorf("recording TOTP failure: %w", err)
	}
	return f, nil
}

// recoveryAlphabet excludes characters people confuse when reading a code they
// wrote down: no 0/O, no 1/I/L.
const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// GenerateRecoveryCodes replaces a user's codes and returns the plaintext ONCE.
//
// Returned, never re-readable: only hashes are stored. A system that can show a
// user their recovery codes again can also show them to whoever reads the
// database, and these are password-equivalent -- one alone gets past MFA.
//
// Generating replaces the previous set. A user asking for new codes has decided
// the old ones are compromised or lost, and leaving them valid would defeat the
// point of asking.
func GenerateRecoveryCodes(ctx context.Context, tx pgx.Tx, userID, orgID string, count int) ([]string, error) {
	if count <= 0 {
		count = 10
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM core.recovery_codes WHERE user_id = $1::uuid`, userID); err != nil {
		return nil, fmt.Errorf("clearing old recovery codes: %w", err)
	}
	// A new set starts with a clean count. The failures were guesses at codes
	// that no longer exist, and a set disabled for them is the set being
	// replaced.
	if err := ClearRecoveryCodeFailures(ctx, tx, userID); err != nil {
		return nil, err
	}

	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.recovery_codes (user_id, org_id, code_hash)
			VALUES ($1::uuid, $2::uuid, $3)`, userID, orgID, hashRecoveryCode(code)); err != nil {
			return nil, fmt.Errorf("storing recovery code: %w", err)
		}
		out = append(out, code)
	}
	return out, nil
}

// ConsumeRecoveryCode spends a code, returning whether it was valid.
//
// Single use, enforced by the UPDATE's own WHERE clause rather than a read
// followed by a write: two simultaneous attempts with the same code must not
// both succeed, and only the atomic form guarantees that.
//
// A set disabled by RecordRecoveryCodeFailure accepts nothing, the right code
// included: after a hundred consecutive wrong ones the next right one is as
// likely to be the hundred-and-first guess as the account holder.
func ConsumeRecoveryCode(ctx context.Context, tx pgx.Tx, userID, code string) (bool, error) {
	normalised := normaliseRecoveryCode(code)
	if normalised == "" {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.recovery_codes
		SET used_at = now()
		WHERE user_id = $1::uuid AND code_hash = $2 AND used_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM core.recovery_code_failures f
		                   WHERE f.user_id = $1::uuid AND f.disabled_at IS NOT NULL)`,
		userID, hashRecoveryCode(normalised))
	if err != nil {
		return false, fmt.Errorf("consuming recovery code: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	// Consecutive failures: an accepted code ends the run.
	if err := ClearRecoveryCodeFailures(ctx, tx, userID); err != nil {
		return false, err
	}
	return true, nil
}

// RecordRecoveryCodeFailure counts one wrong recovery code against the account
// and disables the set on the ceiling (see MaxConsecutiveFactorFailures).
// Disabled is true only for the failure that disabled it.
//
// Counted per account rather than per code because the guess is not at a code:
// a submission is checked against every unused code at once, so the set is the
// authenticator §3.2.2 is talking about. An account with no unused code has no
// set to guess at, and nothing is counted -- or announced as disabled.
func RecordRecoveryCodeFailure(ctx context.Context, tx pgx.Tx, userID string, ceiling int) (FactorFailure, error) {
	var f FactorFailure
	err := tx.QueryRow(ctx, `
		INSERT INTO core.recovery_code_failures (user_id, org_id, failed_attempts, disabled_at)
		SELECT u.id, u.org_id, 1, CASE WHEN 1 >= $2 THEN now() END
		  FROM core.users u
		 WHERE u.id = $1::uuid
		   AND EXISTS (SELECT 1 FROM core.recovery_codes c
		                WHERE c.user_id = u.id AND c.used_at IS NULL)
		ON CONFLICT (user_id) DO UPDATE SET
			failed_attempts = core.recovery_code_failures.failed_attempts + 1,
			disabled_at = CASE WHEN core.recovery_code_failures.failed_attempts + 1 >= $2
			                   THEN now() END,
			updated_at = now()
		WHERE core.recovery_code_failures.disabled_at IS NULL
		RETURNING disabled_at IS NOT NULL`, userID, ceiling).Scan(&f.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		// Already disabled (or no such user): nothing is counting.
		return FactorFailure{}, nil
	}
	if err != nil {
		return FactorFailure{}, fmt.Errorf("recording a recovery code failure: %w", err)
	}
	return f, nil
}

// ClearRecoveryCodeFailures forgets the count and re-enables the set: called
// when a code is accepted, when the set is regenerated, and when an operator
// removes it.
func ClearRecoveryCodeFailures(ctx context.Context, tx pgx.Tx, userID string) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM core.recovery_code_failures WHERE user_id = $1::uuid`, userID); err != nil {
		return fmt.Errorf("clearing recovery code failures: %w", err)
	}
	return nil
}

// RemainingRecoveryCodes drives the "you have N codes left" warning. Running out
// silently is how a lost phone becomes a support ticket.
func RemainingRecoveryCodes(ctx context.Context, tx pgx.Tx, userID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM core.recovery_codes
		WHERE user_id = $1::uuid AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// newRecoveryCode returns 20 characters from a 31-symbol alphabet, printed in
// four groups of five.
//
// That is 20 x log2(31) = 99.1 bits. The comment here used to say "128 bits, in
// two readable groups" and both halves were wrong: 128 bits would need 26 of
// these characters, and the separator goes in every five, which makes four
// groups. 99 bits is ample for a code that is hashed at rest, rate limited on
// presentation and single use -- but a number in a comment is what somebody
// quotes in a risk assessment, so it should be the real one.
//
// # Drawn without modulo bias
//
// The previous version did `recoveryAlphabet[int(v)%31]` over a uniform byte.
// 256 is not a multiple of 31 -- it leaves 8 -- so the first eight symbols came
// up about 3.5% more often than the rest. That costs a fraction of a bit rather
// than breaking anything, and it is still the kind of thing that has no reason
// to be here: rejection sampling removes it for a loop nobody will notice.
func newRecoveryCode() (string, error) {
	const chars = recoveryCodeLength
	// The largest multiple of the alphabet that fits in a byte. Anything at or
	// above it is redrawn rather than folded, which is what removes the bias.
	const limit = 256 - (256 % len(recoveryAlphabet)) // 248 for 31 symbols

	var sb strings.Builder
	buf := make([]byte, 1)
	for i := 0; i < chars; i++ {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		for {
			if _, err := io.ReadFull(rand.Reader, buf); err != nil {
				return "", fmt.Errorf("no entropy for a recovery code: %w", err)
			}
			if int(buf[0]) < limit {
				sb.WriteByte(recoveryAlphabet[int(buf[0])%len(recoveryAlphabet)])
				break
			}
		}
	}
	return sb.String(), nil
}

// recoveryCodeLength is how many alphabet characters a code has, separators
// not counted.
const recoveryCodeLength = 20

// CouldBeRecoveryCode reports whether a submission has the shape of a recovery
// code once normalised, so a failure is charged to the recovery codes only when
// it could have been one. A mistyped six-digit authenticator code is not a guess
// at a recovery code, and charging it as one would let ordinary typing errors
// disable the codes a person keeps for the day the authenticator is gone.
func CouldBeRecoveryCode(s string) bool {
	return len(normaliseRecoveryCode(s)) == recoveryCodeLength
}

// normaliseRecoveryCode accepts what a person actually types: any case, with or
// without the separators, with stray spaces.
func normaliseRecoveryCode(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToUpper(s) {
		if strings.ContainsRune(recoveryAlphabet, r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// hashRecoveryCode hashes for lookup.
//
// A fast hash, deliberately. Argon2id is the right answer for a user-CHOSEN
// secret, where the threat is a dictionary. These are 99 bits of our own
// randomness (see newRecoveryCode): there is no dictionary, and no user
// reusing them elsewhere. What
// matters is that the stored form is not the code.
func hashRecoveryCode(code string) []byte {
	sum := sha256.Sum256([]byte(normaliseRecoveryCode(code)))
	return sum[:]
}

// HasFactorOtherThanDuo reports whether a user could present something else.
//
// Used only on the Duo fail-open path: when Duo is unreachable and the
// deployment has chosen to fail open, somebody with an authenticator app should
// be asked for THAT rather than waved through. Somebody with nothing else has
// to be waved through or the fail-open setting means nothing.
func HasFactorOtherThanDuo(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (bool, error) {
	var any bool
	err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM core.totp_credentials
			WHERE user_id = $1::uuid AND confirmed_at IS NOT NULL
		) OR EXISTS (
			SELECT 1 FROM core.email_otp_credentials
			WHERE user_id = $1::uuid AND verified_at IS NOT NULL
		) OR EXISTS (
			SELECT 1 FROM core.sms_otp_credentials
			WHERE user_id = $1::uuid AND verified_at IS NOT NULL
		)`, userID).Scan(&any)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	return any, nil
}

// HasSecondFactor reports whether a user has any usable second factor.
//
// Was HasConfirmedTOTP, and checked only TOTP while its own comment claimed to
// report "a usable second factor". That was harmless until email codes existed
// and then immediately was not: a user whose only factor was email would have
// been waved straight through with a password alone, having explicitly turned
// on a second factor. The name and the query now agree.
//
// EVERY factor must be listed here. This function is the single gate between a
// correct password and a session, so a factor missing from it is a factor that
// silently does not apply -- the user turned on MFA, sees it in their account
// settings, and is waved through on a password alone. TestEveryFactorTableIsChecked
// fails when a credential table exists that this query does not mention.
//
// Checked on the pool, not in a transaction, and deliberately cheap: it runs on
// every password sign-in. Every factor here has a half state, and the proved
// half is the only one that counts: `confirmed_at` for TOTP, `verified_at` for
// email and SMS. An enrolment the user never proved must not lock them out of
// their own account. (This comment once said email had no half state because
// "the row exists only after a code sent to that address was entered". The row
// was written on the send step; see 0126.)
func HasSecondFactor(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (bool, error) {
	var any bool
	err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM core.totp_credentials
			WHERE user_id = $1::uuid AND confirmed_at IS NOT NULL
		) OR EXISTS (
			-- VERIFIED, for the same reason as SMS below: an address is
			-- somebody's typo until a code sent to it comes back.
			SELECT 1 FROM core.email_otp_credentials
			WHERE user_id = $1::uuid AND verified_at IS NOT NULL
		) OR EXISTS (
			-- VERIFIED, not merely enrolled. An unverified number is somebody's
			-- typo until a code sent to it comes back, and treating it as a
			-- factor would lock the account's owner out with a phone they do
			-- not have.
			SELECT 1 FROM core.sms_otp_credentials
			WHERE user_id = $1::uuid AND verified_at IS NOT NULL
		) OR EXISTS (
			-- Duo, only while its integration is enabled. An enrollment whose
			-- integration has been switched off is not a factor anybody can
			-- present, and treating it as one would lock every enrolled user out
			-- the moment an administrator disabled Duo.
			SELECT 1 FROM core.duo_enrollments e
			JOIN core.duo_integrations i ON i.org_id = e.org_id AND i.enabled
			WHERE e.user_id = $1::uuid
		) OR EXISTS (
			-- A security key or passkey, presented on the code page after a
			-- password. It has no half state: a row is written only once a
			-- registration's attestation has verified.
			SELECT 1 FROM core.webauthn_credentials
			WHERE user_id = $1::uuid
		)`, userID).Scan(&any)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("checking for a second factor: %w", err)
	}
	return any, nil
}
