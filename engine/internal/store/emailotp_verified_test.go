package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Email as a second factor: what counts, what moves it, and which code does
// what. Each test is one of the failures migration 0126 describes.

// allowResend clears the resend floor so a test can issue a second code at once.
func allowResend(t *testing.T, tx pgx.Tx, userID string) {
	t.Helper()
	if _, err := tx.Exec(context.Background(),
		`UPDATE core.email_otp_credentials SET last_sent_at = NULL WHERE user_id = $1::uuid`, userID); err != nil {
		t.Fatal(err)
	}
}

// proveEmail runs a whole enrolment for address and returns what it replaced.
func proveEmail(t *testing.T, tx pgx.Tx, userID, orgID, address string) string {
	t.Helper()
	ctx := context.Background()
	if err := StartEmailOTPEnrolment(ctx, tx, userID, orgID, address); err != nil {
		t.Fatal(err)
	}
	allowResend(t, tx, userID)
	code, to, err := IssueEmailOTPEnrolment(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if to != address {
		t.Fatalf("the enrolment code went to %q, want %q", to, address)
	}
	ok, replaced, err := ConfirmEmailOTPEnrolment(ctx, tx, userID, code)
	if err != nil || !ok {
		t.Fatalf("a correct enrolment code was refused (ok=%v err=%v)", ok, err)
	}
	return replaced
}

// An address abandoned at the code screen -- a typo, or one somebody else typed
// -- must not become the account's second factor.
func TestAnUnprovedEmailAddressIsNotASecondFactor(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()

	if err := StartEmailOTPEnrolment(ctx, tx, userID, orgID, "typo@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := IssueEmailOTPEnrolment(ctx, tx, userID); err != nil {
		t.Fatal(err)
	}

	has, err := HasSecondFactor(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("an email address nobody proved counts as a second factor; the owner would be " +
			"challenged for codes sent to an address they do not have")
	}
	if other, _ := HasFactorOtherThanDuo(ctx, tx, userID); other {
		t.Fatal("HasFactorOtherThanDuo counts an unproved email address")
	}
	allowResend(t, tx, userID)
	if _, _, err := IssueEmailOTP(ctx, tx, userID); !errors.Is(err, ErrNoEmailOTP) {
		t.Fatalf("a sign-in code was issued for an unproved address (err = %v)", err)
	}
}

// Re-enrolling must not move the factor until the new address is proved, and
// must say where it moved from when it does.
func TestANewEmailAddressDoesNotDisplaceTheProvedOneUntilItIsProved(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()

	if replaced := proveEmail(t, tx, userID, orgID, "owner@example.test"); replaced != "" {
		t.Fatalf("a first enrolment reported replacing %q", replaced)
	}

	// Somebody with the session starts pointing the factor elsewhere and stops.
	if err := StartEmailOTPEnrolment(ctx, tx, userID, orgID, "intruder@example.test"); err != nil {
		t.Fatal(err)
	}
	if has, _ := HasSecondFactor(ctx, tx, userID); !has {
		t.Fatal("starting a re-enrolment removed the proved email factor")
	}
	allowResend(t, tx, userID)
	_, to, err := IssueEmailOTP(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if to != "owner@example.test" {
		t.Fatalf("sign-in codes went to %q after an unproved re-enrolment; they must keep going "+
			"to the proved address", to)
	}

	// Proving the new address is what moves it, and the old one is reported.
	if replaced := proveEmail(t, tx, userID, orgID, "new@example.test"); replaced != "owner@example.test" {
		t.Fatalf("moving the factor reported replacing %q, want the previous address", replaced)
	}
	allowResend(t, tx, userID)
	if _, to, _ := IssueEmailOTP(ctx, tx, userID); to != "new@example.test" {
		t.Fatalf("after proving the new address, sign-in codes go to %q", to)
	}
}

// One code slot, two jobs: neither may stand in for the other.
func TestAnEmailEnrolmentCodeCannotSignInAndASignInCodeCannotEnrol(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	proveEmail(t, tx, userID, orgID, "owner@example.test")

	// An enrolment code for another address must not pass a sign-in check.
	if err := StartEmailOTPEnrolment(ctx, tx, userID, orgID, "elsewhere@example.test"); err != nil {
		t.Fatal(err)
	}
	allowResend(t, tx, userID)
	enrolCode, _, err := IssueEmailOTPEnrolment(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyEmailOTP(ctx, tx, userID, enrolCode); ok {
		t.Fatal("a code sent to an address being enrolled satisfied a sign-in challenge")
	}

	// And a sign-in code must not complete an enrolment.
	allowResend(t, tx, userID)
	signInCode, _, err := IssueEmailOTP(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := ConfirmEmailOTPEnrolment(ctx, tx, userID, signInCode); ok {
		t.Fatal("a sign-in code completed an email enrolment")
	}
}

// A correct sign-in code works once.
func TestAnEmailSignInCodeIsSingleUse(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	proveEmail(t, tx, userID, orgID, "owner@example.test")

	allowResend(t, tx, userID)
	code, _, err := IssueEmailOTP(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyEmailOTP(ctx, tx, userID, code); err != nil || !ok {
		t.Fatalf("a correct sign-in code was refused (ok=%v err=%v)", ok, err)
	}
	if ok, _ := VerifyEmailOTP(ctx, tx, userID, code); ok {
		t.Fatal("a sign-in code was accepted twice")
	}
}
