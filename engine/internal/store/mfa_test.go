package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
)

func mfaFixture(t *testing.T) (pgx.Tx, string, string, *keys.RootKey) {
	t.Helper()
	conn := connect(t)
	ctx := context.Background()
	orgID, userID, _, _ := fixture(t, conn)

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return tx, orgID, userID, root
}

func enrol(t *testing.T, tx pgx.Tx, userID, orgID string, root *keys.RootKey) []byte {
	t.Helper()
	secret, _, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := EnrollTOTP(context.Background(), tx, userID, orgID, secret,
		mfa.DefaultDigits, mfa.DefaultPeriod, root); err != nil {
		t.Fatal(err)
	}
	return secret
}

// The secret must survive the encryption round trip, or every code is wrong and
// the failure looks like a clock problem.
func TestTOTPSecretRoundTripsThroughEncryption(t *testing.T) {
	tx, orgID, userID, root := mfaFixture(t)
	ctx := context.Background()

	secret := enrol(t, tx, userID, orgID, root)

	cred, err := LoadTOTP(ctx, tx, userID, root)
	if err != nil {
		t.Fatal(err)
	}
	if string(cred.Secret) != string(secret) {
		t.Fatal("the decrypted secret does not match the enrolled one")
	}
	if cred.Confirmed {
		t.Error("a freshly enrolled credential is already confirmed; a failed scan would lock the user out")
	}

	// The stored form must not be the secret.
	var stored []byte
	if err := tx.QueryRow(ctx,
		`SELECT secret_enc FROM core.totp_credentials WHERE user_id = $1::uuid`, userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), string(secret)) {
		t.Fatal("the TOTP secret is recoverable from the stored column")
	}
}

// The full replay defence, store and verifier together: a code that worked once
// must not work again, because the counter was persisted.
func TestReplayIsRefusedAcrossTheStore(t *testing.T) {
	tx, orgID, userID, root := mfaFixture(t)
	ctx := context.Background()

	secret := enrol(t, tx, userID, orgID, root)
	now := time.Now()
	code := mfa.Code(secret, mfa.Counter(now, mfa.DefaultPeriod), mfa.DefaultDigits)

	cred, _ := LoadTOTP(ctx, tx, userID, root)
	counter, err := mfa.Verify(secret, code, now, cred.Digits, cred.Period, mfa.DefaultSkew, cred.LastCounter)
	if err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	if err := RecordTOTPSuccess(ctx, tx, userID, counter); err != nil {
		t.Fatal(err)
	}

	// Reload: the counter must have been persisted, and confirmation set.
	cred2, err := LoadTOTP(ctx, tx, userID, root)
	if err != nil {
		t.Fatal(err)
	}
	if cred2.LastCounter != counter {
		t.Fatalf("counter was not persisted: got %d, want %d", cred2.LastCounter, counter)
	}
	if !cred2.Confirmed {
		t.Error("a successful verification did not confirm the credential")
	}

	if _, err := mfa.Verify(secret, code, now, cred2.Digits, cred2.Period, mfa.DefaultSkew, cred2.LastCounter); !errors.Is(err, mfa.ErrReplay) {
		t.Fatalf("the same code was accepted twice (err = %v)", err)
	}
}

// A six-digit code is a million guesses. Only a per-credential limit makes that
// a real number.
func TestFailuresLockTheCredential(t *testing.T) {
	tx, orgID, userID, root := mfaFixture(t)
	ctx := context.Background()
	enrol(t, tx, userID, orgID, root)

	for i := 1; i <= MaxTOTPFailures; i++ {
		locked, err := RecordTOTPFailure(ctx, tx, userID)
		if err != nil {
			t.Fatal(err)
		}
		if i < MaxTOTPFailures && locked {
			t.Fatalf("locked after only %d failures", i)
		}
		if i == MaxTOTPFailures && !locked {
			t.Fatalf("still unlocked after %d failures", i)
		}
	}

	// A locked credential must refuse to load at all -- not decrypt and then
	// reject, which would let an attacker keep the unwrap cost running.
	if _, err := LoadTOTP(ctx, tx, userID, root); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("a locked credential loaded anyway: %v", err)
	}

	// A success clears the lock, so a legitimate user is not stuck after the
	// window passes.
	if err := RecordTOTPSuccess(ctx, tx, userID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTOTP(ctx, tx, userID, root); err != nil {
		t.Fatalf("the lock was not cleared by a success: %v", err)
	}
}

// Single use is the whole property. A recovery code that works twice is a
// password that never expires.
func TestRecoveryCodesAreSingleUse(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()

	codes, err := GenerateRecoveryCodes(ctx, tx, userID, orgID, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 5 {
		t.Fatalf("got %d codes, want 5", len(codes))
	}

	ok, err := ConsumeRecoveryCode(ctx, tx, userID, codes[0])
	if err != nil || !ok {
		t.Fatalf("a valid code was refused (ok=%v err=%v)", ok, err)
	}
	if ok, _ := ConsumeRecoveryCode(ctx, tx, userID, codes[0]); ok {
		t.Fatal("a recovery code was accepted twice")
	}

	if n, _ := RemainingRecoveryCodes(ctx, tx, userID); n != 4 {
		t.Errorf("remaining = %d, want 4", n)
	}
	if ok, _ := ConsumeRecoveryCode(ctx, tx, userID, "AAAAA-BBBBB-CCCCC-DDDDD"); ok {
		t.Error("an invented code was accepted")
	}
}

// People type these off paper, in any case, with or without the dashes.
func TestRecoveryCodeEntryIsForgiving(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()

	codes, _ := GenerateRecoveryCodes(ctx, tx, userID, orgID, 3)
	messy := " " + strings.ToLower(strings.ReplaceAll(codes[0], "-", " ")) + " "

	if ok, err := ConsumeRecoveryCode(ctx, tx, userID, messy); err != nil || !ok {
		t.Fatalf("a correctly typed code in messy form was refused: ok=%v err=%v", ok, err)
	}
}

// Regenerating means the old set is compromised or lost. Leaving it valid would
// defeat the reason for asking.
func TestRegeneratingInvalidatesTheOldCodes(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()

	old, _ := GenerateRecoveryCodes(ctx, tx, userID, orgID, 3)
	fresh, _ := GenerateRecoveryCodes(ctx, tx, userID, orgID, 3)

	for _, c := range old {
		if ok, _ := ConsumeRecoveryCode(ctx, tx, userID, c); ok {
			t.Fatal("a superseded recovery code still works")
		}
	}
	if ok, _ := ConsumeRecoveryCode(ctx, tx, userID, fresh[0]); !ok {
		t.Fatal("a freshly generated code does not work")
	}
}

// Crypto-shredding reaching all the way through: erasing the subject must make
// the TOTP secret unrecoverable, not merely unlinked.
func TestErasureDestroysTheTOTPSecret(t *testing.T) {
	tx, orgID, userID, root := mfaFixture(t)
	ctx := context.Background()

	enrol(t, tx, userID, orgID, root)
	if _, err := LoadTOTP(ctx, tx, userID, root); err != nil {
		t.Fatal(err)
	}

	if err := keys.EraseSubject(ctx, tx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTOTP(ctx, tx, userID, root); err == nil {
		t.Fatal("the TOTP secret was still readable after the subject was erased")
	}
}
