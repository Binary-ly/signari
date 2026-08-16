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
)

var (
	ErrNoTOTP     = errors.New("store: no TOTP credential")
	ErrTOTPLocked = errors.New("store: TOTP credential is locked")
)

// TOTPCredential is an enrolled authenticator.
type TOTPCredential struct {
	Secret      []byte
	Digits      int
	Period      time.Duration
	Confirmed   bool
	LastCounter int64
	LockedUntil *time.Time
}

// EnrollTOTP stores an UNCONFIRMED credential.
//
// Unconfirmed matters: enrolment is only complete once the user proves the app
// holds the same secret. Marking it usable at generation time is how people end
// up locked out by an authenticator that silently failed to scan -- the server
// believes MFA is on, the phone has nothing, and the account is unreachable.
func EnrollTOTP(ctx context.Context, tx pgx.Tx, userID, orgID string, secret []byte,
	digits int, period time.Duration, root *keys.RootKey) error {

	sk, err := keys.LoadOrCreateSubjectKey(ctx, tx, userID, root)
	if err != nil {
		return fmt.Errorf("subject key for TOTP enrolment: %w", err)
	}
	sealed, err := sk.Seal(secret, totpContext)
	if err != nil {
		return fmt.Errorf("sealing TOTP secret: %w", err)
	}

	// Re-enrolling REPLACES the credential and resets its counter and lock. The
	// old secret is gone; a user who re-enrols has decided the previous
	// authenticator is lost, and leaving it live would be a second, forgotten
	// way into the account.
	_, err = tx.Exec(ctx, `
		INSERT INTO core.totp_credentials
			(user_id, org_id, secret_enc, digits, period_secs)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET
			secret_enc = EXCLUDED.secret_enc,
			digits = EXCLUDED.digits,
			period_secs = EXCLUDED.period_secs,
			confirmed_at = NULL,
			last_used_counter = 0,
			failed_attempts = 0,
			locked_until = NULL`,
		userID, orgID, sealed, digits, int(period.Seconds()))
	if err != nil {
		return fmt.Errorf("storing TOTP credential: %w", err)
	}
	return nil
}

// LoadTOTP reads and decrypts a credential.
func LoadTOTP(ctx context.Context, tx pgx.Tx, userID string, root *keys.RootKey) (*TOTPCredential, error) {
	var sealed []byte
	var digits, period int
	var confirmedAt, lockedUntil *time.Time
	var lastCounter int64

	err := tx.QueryRow(ctx, `
		SELECT secret_enc, digits, period_secs, confirmed_at, last_used_counter, locked_until
		FROM core.totp_credentials WHERE user_id = $1::uuid
		FOR UPDATE`, userID).
		Scan(&sealed, &digits, &period, &confirmedAt, &lastCounter, &lockedUntil)
	if err == pgx.ErrNoRows {
		return nil, ErrNoTOTP
	}
	if err != nil {
		return nil, fmt.Errorf("loading TOTP credential: %w", err)
	}

	// Checked before decrypting: a locked credential should cost an attacker a
	// lookup, not an unwrap.
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

// RecordTOTPFailure increments the counter and locks on the threshold.
func RecordTOTPFailure(ctx context.Context, tx pgx.Tx, userID string) (locked bool, err error) {
	err = tx.QueryRow(ctx, `
		UPDATE core.totp_credentials
		SET failed_attempts = failed_attempts + 1,
		    locked_until = CASE WHEN failed_attempts + 1 >= $2
		                        THEN now() + $3::interval ELSE locked_until END
		WHERE user_id = $1::uuid
		RETURNING locked_until IS NOT NULL AND locked_until > now()`,
		userID, MaxTOTPFailures, TOTPLockout.String()).Scan(&locked)
	if err != nil {
		return false, fmt.Errorf("recording TOTP failure: %w", err)
	}
	return locked, nil
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
func ConsumeRecoveryCode(ctx context.Context, tx pgx.Tx, userID, code string) (bool, error) {
	normalised := normaliseRecoveryCode(code)
	if normalised == "" {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.recovery_codes
		SET used_at = now()
		WHERE user_id = $1::uuid AND code_hash = $2 AND used_at IS NULL`,
		userID, hashRecoveryCode(normalised))
	if err != nil {
		return false, fmt.Errorf("consuming recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
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

func newRecoveryCode() (string, error) {
	// 128 bits, in two readable groups.
	const chars = 20
	b := make([]byte, chars)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("no entropy for a recovery code: %w", err)
	}
	var sb strings.Builder
	for i, v := range b {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(recoveryAlphabet[int(v)%len(recoveryAlphabet)])
	}
	return sb.String(), nil
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
// secret, where the threat is a dictionary. These are 128 bits of our own
// randomness: there is no dictionary, and no user reusing them elsewhere. What
// matters is that the stored form is not the code.
func hashRecoveryCode(code string) []byte {
	sum := sha256.Sum256([]byte(normaliseRecoveryCode(code)))
	return sum[:]
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
// every password sign-in. For TOTP, `confirmed_at` is what matters -- an
// enrolment the user never proved must not lock them out of their own account.
// Email enrolment has no such half state: the row exists only after a code sent
// to that address was entered.
func HasSecondFactor(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (bool, error) {
	var any bool
	err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM core.totp_credentials
			WHERE user_id = $1::uuid AND confirmed_at IS NOT NULL
		) OR EXISTS (
			SELECT 1 FROM core.email_otp_credentials WHERE user_id = $1::uuid
		) OR EXISTS (
			-- VERIFIED, not merely enrolled. An unverified number is somebody's
			-- typo until a code sent to it comes back, and treating it as a
			-- factor would lock the account's owner out with a phone they do
			-- not have.
			SELECT 1 FROM core.sms_otp_credentials
			WHERE user_id = $1::uuid AND verified_at IS NOT NULL
		)`, userID).Scan(&any)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("checking for a second factor: %w", err)
	}
	return any, nil
}
