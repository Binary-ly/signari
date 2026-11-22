package store

import (
	"context"
	"errors"
	"testing"
)

// NIST SP 800-63B §3.2.2: "The verifier SHALL limit consecutive failed
// authentication attempts using a specific authenticator on a single subscriber
// account to no more than 100 by disabling that authenticator".
//
// The five-minute pause re-armed on every failure after the fifth and never
// ended, so an authenticator could be guessed at about 288 times a day for as
// long as anybody cared to; recovery codes were not counted at all.

func TestTheCeilingFailureDisablesTheAuthenticator(t *testing.T) {
	tx, orgID, userID, root := mfaFixture(t)
	ctx := context.Background()
	enrol(t, tx, userID, orgID, root)

	for i := 1; i <= MaxConsecutiveFactorFailures; i++ {
		f, err := RecordTOTPFailure(ctx, tx, userID, MaxConsecutiveFactorFailures)
		if err != nil {
			t.Fatal(err)
		}
		if i < MaxConsecutiveFactorFailures && f.Disabled {
			t.Fatalf("disabled after %d failures; the ceiling is %d", i, MaxConsecutiveFactorFailures)
		}
		if i == MaxConsecutiveFactorFailures && !f.Disabled {
			t.Fatalf("failure %d did not disable the authenticator", i)
		}
	}

	// Disabled, not paused: the pause would have lapsed by the next window.
	if _, err := LoadTOTP(ctx, tx, userID, root); !errors.Is(err, ErrTOTPDisabled) {
		t.Fatalf("a disabled authenticator loaded as %v, want ErrTOTPDisabled", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE core.totp_credentials SET locked_until = now() - interval '1 second'
		  WHERE user_id = $1::uuid`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTOTP(ctx, tx, userID, root); !errors.Is(err, ErrTOTPDisabled) {
		t.Fatalf("the authenticator came back when the pause lapsed: %v", err)
	}

	// Announced once: the next failure changes nothing and says so.
	f, err := RecordTOTPFailure(ctx, tx, userID, MaxConsecutiveFactorFailures)
	if err != nil {
		t.Fatal(err)
	}
	if f.Disabled {
		t.Error("failure 101 reported disabling the authenticator again; the holder would be told twice")
	}

	// Still the account's second factor. Disabling it must not leave a
	// password that signs in alone.
	has, err := HasSecondFactor(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("disabling the authenticator downgraded the account to password-only")
	}

	// Re-enrolling, once signed in another way, is the way back.
	enrol(t, tx, userID, orgID, root)
	if _, err := LoadTOTP(ctx, tx, userID, root); err != nil {
		t.Fatalf("a re-enrolled authenticator is still refused: %v", err)
	}
}

func TestALowerConfiguredCeilingIsHonoured(t *testing.T) {
	tx, orgID, userID, root := mfaFixture(t)
	ctx := context.Background()
	enrol(t, tx, userID, orgID, root)

	const ceiling = MinConsecutiveFactorFailures
	for i := 1; i <= ceiling; i++ {
		f, err := RecordTOTPFailure(ctx, tx, userID, ceiling)
		if err != nil {
			t.Fatal(err)
		}
		if f.Disabled != (i == ceiling) {
			t.Fatalf("failure %d: disabled = %v with a ceiling of %d", i, f.Disabled, ceiling)
		}
	}
}

// A success ends the run: the count is of consecutive failures.
func TestASuccessEndsTheRunOfFailures(t *testing.T) {
	tx, orgID, userID, root := mfaFixture(t)
	ctx := context.Background()
	enrol(t, tx, userID, orgID, root)

	const ceiling = MinConsecutiveFactorFailures
	for i := 1; i < ceiling; i++ {
		if _, err := RecordTOTPFailure(ctx, tx, userID, ceiling); err != nil {
			t.Fatal(err)
		}
	}
	if err := RecordTOTPSuccess(ctx, tx, userID, 1); err != nil {
		t.Fatal(err)
	}
	f, err := RecordTOTPFailure(ctx, tx, userID, ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if f.Disabled {
		t.Fatal("failures before a success were still counted towards the ceiling")
	}
}

func TestTheFailureLimitIsBoundedBothWays(t *testing.T) {
	for _, c := range []struct {
		in   int
		want int
		ok   bool
	}{
		{0, MaxConsecutiveFactorFailures, true},
		{MinConsecutiveFactorFailures, MinConsecutiveFactorFailures, true},
		{50, 50, true},
		{MaxConsecutiveFactorFailures, MaxConsecutiveFactorFailures, true},
		{MaxConsecutiveFactorFailures + 1, 0, false},
		{MinConsecutiveFactorFailures - 1, 0, false},
		{-1, 0, false},
	} {
		got, err := FactorFailureLimit(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("FactorFailureLimit(%d) = %d, %v; want %d, ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
}

func TestRecoveryCodesAreDisabledAtTheCeiling(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	codes, err := GenerateRecoveryCodes(ctx, tx, userID, orgID, 3)
	if err != nil {
		t.Fatal(err)
	}

	const ceiling = MinConsecutiveFactorFailures
	for i := 1; i <= ceiling; i++ {
		f, err := RecordRecoveryCodeFailure(ctx, tx, userID, ceiling)
		if err != nil {
			t.Fatal(err)
		}
		if f.Disabled != (i == ceiling) {
			t.Fatalf("failure %d: disabled = %v with a ceiling of %d", i, f.Disabled, ceiling)
		}
	}

	// The right code included: after the ceiling it is as likely to be the
	// next guess as the account holder.
	if ok, err := ConsumeRecoveryCode(ctx, tx, userID, codes[0]); err != nil || ok {
		t.Fatalf("a disabled set accepted a code (ok=%v err=%v)", ok, err)
	}
	if f, _ := RecordRecoveryCodeFailure(ctx, tx, userID, ceiling); f.Disabled {
		t.Error("a failure after the ceiling reported disabling the set again")
	}

	// A new set is the way back.
	fresh, err := GenerateRecoveryCodes(ctx, tx, userID, orgID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ConsumeRecoveryCode(ctx, tx, userID, fresh[0]); err != nil || !ok {
		t.Fatalf("a regenerated set is still disabled (ok=%v err=%v)", ok, err)
	}
}

func TestAnAcceptedRecoveryCodeEndsTheRun(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	codes, _ := GenerateRecoveryCodes(ctx, tx, userID, orgID, 3)

	const ceiling = MinConsecutiveFactorFailures
	for i := 1; i < ceiling; i++ {
		if _, err := RecordRecoveryCodeFailure(ctx, tx, userID, ceiling); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := ConsumeRecoveryCode(ctx, tx, userID, codes[0]); !ok {
		t.Fatal("a valid code was refused below the ceiling")
	}
	if f, _ := RecordRecoveryCodeFailure(ctx, tx, userID, ceiling); f.Disabled {
		t.Fatal("failures before an accepted code were still counted")
	}
}

// Nothing to guess at, nothing counted -- and nobody told their codes were
// disabled when they never had any.
func TestAnAccountWithoutRecoveryCodesCountsNothing(t *testing.T) {
	tx, _, userID, _ := mfaFixture(t)
	ctx := context.Background()

	const ceiling = MinConsecutiveFactorFailures
	for i := 1; i <= ceiling; i++ {
		f, err := RecordRecoveryCodeFailure(ctx, tx, userID, ceiling)
		if err != nil {
			t.Fatal(err)
		}
		if f.Disabled {
			t.Fatal("recovery codes the account never had were reported disabled")
		}
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM core.recovery_code_failures WHERE user_id = $1::uuid`,
		userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d failure rows for an account with no recovery codes", n)
	}
}

func TestOnlyARecoveryShapedCodeIsAGuessAtOne(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	codes, _ := GenerateRecoveryCodes(context.Background(), tx, userID, orgID, 1)
	for in, want := range map[string]bool{
		codes[0]:                   true,
		" abcde fghjk mnpqr stuvw": true,
		"123456":                   false,
		"12345678":                 false,
		"AAAAA-BBBBB-CCCCC-DDDD":   false,
		"":                         false,
	} {
		if got := CouldBeRecoveryCode(in); got != want {
			t.Errorf("CouldBeRecoveryCode(%q) = %v, want %v", in, got, want)
		}
	}
}
