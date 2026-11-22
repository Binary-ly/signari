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
	id, err := StartEmailSignIn(ctx, tx, userID, orgID)
	if err != nil {
		t.Fatal(err)
	}
	var row string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM core.email_sign_in_codes WHERE user_id = $1::uuid`,
		userID).Scan(&row); err != nil || row != id {
		t.Fatalf("the attempt returned is %q, the row is %q (%v)", id, row, err)
	}
	code, _, err = MintEmailSignInCode(ctx, tx, id)
	if err != nil {
		t.Fatal(err)
	}
	return id, code
}

func TestAnEmailedSignInCodeIsSpentByUse(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	attempt, code := askForCode(t, tx, userID, orgID)

	if ok, err := VerifyEmailSignIn(ctx, tx, userID, attempt, code); err != nil || !ok {
		t.Fatalf("the right code was refused: %v %v", ok, err)
	}
	if ok, err := VerifyEmailSignIn(ctx, tx, userID, attempt, code); err != nil || ok {
		t.Fatalf("the code signed in twice: %v %v", ok, err)
	}
}

// V6.6.2: the code is for the request that asked for it. Another browser's
// cookie, which names no request or another one, finishes nothing with it, and
// what it tries is no guess at the code: the browser that asked still has all
// of its tries.
func TestAnEmailedSignInCodeIsOnlyForTheRequestThatAskedForIt(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	attempt, code := askForCode(t, tx, userID, orgID)

	for _, other := range []string{"", "not-a-uuid", "6f0f1b5e-6c0c-4f6c-9a43-0d3c5f4b2a11"} {
		for i := 0; i < EmailSignInAttempts; i++ {
			if ok, err := VerifyEmailSignIn(ctx, tx, userID, other, code); err != nil || ok {
				t.Fatalf("the code finished a sign-in from attempt %q: %v %v", other, ok, err)
			}
		}
	}
	if ok, err := VerifyEmailSignIn(ctx, tx, userID, attempt, code); err != nil || !ok {
		t.Fatalf("after others tried it, the code was refused to the request that asked: %v %v", ok, err)
	}
}

func TestFiveWrongEmailedSignInCodesEndIt(t *testing.T) {
	tx, orgID, userID, _ := mfaFixture(t)
	ctx := context.Background()
	attempt, code := askForCode(t, tx, userID, orgID)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < EmailSignInAttempts; i++ {
		if ok, err := VerifyEmailSignIn(ctx, tx, userID, attempt, wrong); err != nil || ok {
			t.Fatalf("wrong code %d: %v %v", i+1, ok, err)
		}
	}
	if ok, err := VerifyEmailSignIn(ctx, tx, userID, attempt, code); err != nil || ok {
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
		for _, attempt := range []string{first, second} {
			if ok, err := VerifyEmailSignIn(ctx, tx, userID, attempt, firstCode); err != nil || ok {
				t.Fatalf("the replaced code still signed in from %q: %v %v", attempt, ok, err)
			}
		}
	}
	// The earlier request's id with the current code: a previous request is
	// not this code's either.
	if ok, err := VerifyEmailSignIn(ctx, tx, userID, first, secondCode); err != nil || ok {
		t.Fatalf("the current code finished the earlier request: %v %v", ok, err)
	}
	if ok, err := VerifyEmailSignIn(ctx, tx, userID, second, secondCode); err != nil || !ok {
		t.Fatalf("the current code was refused: %v %v", ok, err)
	}
}
