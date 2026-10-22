package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// An emailed sign-in code: made once, spent once, and ended by guessing.

// askForCode starts an emailed sign-in and returns the row and its code.
func askForCode(t *testing.T, tx pgx.Tx, userID, orgID string) (id, code string) {
	t.Helper()
	ctx := context.Background()
	if err := StartEmailSignIn(ctx, tx, userID, orgID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT id::text FROM core.email_sign_in_codes WHERE user_id = $1::uuid`,
		userID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	code, _, err := MintEmailSignInCode(ctx, tx, id)
	if err != nil {
		t.Fatal(err)
	}
	return id, code
}

func TestAnEmailedSignInCodeIsSpentByUse(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	_, code := askForCode(t, tx, userID, orgID)

	if ok, err := VerifyEmailSignIn(ctx, tx, userID, code); err != nil || !ok {
		t.Fatalf("the right code was refused: %v %v", ok, err)
	}
	if ok, err := VerifyEmailSignIn(ctx, tx, userID, code); err != nil || ok {
		t.Fatalf("the code signed in twice: %v %v", ok, err)
	}
}

func TestFiveWrongEmailedSignInCodesEndIt(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	_, code := askForCode(t, tx, userID, orgID)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < EmailSignInAttempts; i++ {
		if ok, err := VerifyEmailSignIn(ctx, tx, userID, wrong); err != nil || ok {
			t.Fatalf("wrong code %d: %v %v", i+1, ok, err)
		}
	}
	if ok, err := VerifyEmailSignIn(ctx, tx, userID, code); err != nil || ok {
		t.Fatalf("the right code still worked after %d wrong ones: %v %v", EmailSignInAttempts, ok, err)
	}
}

// Minted once, when the notice goes out: delivering the notice again sends no
// second code. Asking again replaces the first, which then neither verifies
// nor can be minted late by its notice.
func TestAnEmailedSignInCodeIsMintedOnceAndReplacedByTheNext(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	first, firstCode := askForCode(t, tx, userID, orgID)
	if _, _, err := MintEmailSignInCode(ctx, tx, first); !errors.Is(err, ErrEmailSignInInvalid) {
		t.Fatalf("a second delivery minted another code: %v", err)
	}

	second, secondCode := askForCode(t, tx, userID, orgID)
	if second == first {
		t.Fatal("asking again kept the first row's id, so its notice would still mint")
	}
	if firstCode != secondCode {
		if ok, err := VerifyEmailSignIn(ctx, tx, userID, firstCode); err != nil || ok {
			t.Fatalf("the replaced code still signed in: %v %v", ok, err)
		}
	}
	if ok, err := VerifyEmailSignIn(ctx, tx, userID, secondCode); err != nil || !ok {
		t.Fatalf("the current code was refused: %v %v", ok, err)
	}
}
