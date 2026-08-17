package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The forced-password-change machinery, against a real database.
//
// Each of these exists because the alternative behaviour is either a lockout or
// a control that silently does nothing, and neither shows up in a build.

const seedHash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$b3JpZ2luYWxoYXNo"

// seedPassword gives the fixture user a credential to change.
func seedPassword(t *testing.T, conn *pgx.Conn, orgID, userID string) {
	t.Helper()
	_, err := conn.Exec(context.Background(), `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, is_current)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id', true)`, userID, orgID, seedHash)
	must(t, err)
}

func TestRequiringAChangeCarriesItsReason(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	seedPassword(t, conn, orgID, userID)

	must, _, err := PasswordChangeRequired(ctx, conn, userID)
	if err != nil {
		t.Fatalf("reading the flag: %v", err)
	}
	if must {
		t.Fatal("a fresh credential must not require a change")
	}

	const why = "Your password appeared in a breach."
	if err := RequirePasswordChange(ctx, conn, userID, why); err != nil {
		t.Fatalf("setting the flag: %v", err)
	}
	must, reason, err := PasswordChangeRequired(ctx, conn, userID)
	if err != nil {
		t.Fatalf("re-reading the flag: %v", err)
	}
	if !must {
		t.Fatal("the flag did not stick")
	}
	// An unexplained demand to change a password is indistinguishable from
	// phishing. Drop the reason and the page has nothing to show but the demand.
	if reason != why {
		t.Fatalf("reason = %q, want %q", reason, why)
	}
}

func TestSettingAPasswordClearsTheDemandToChangeIt(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	seedPassword(t, conn, orgID, userID)

	if err := RequirePasswordChange(ctx, conn, userID, "because"); err != nil {
		t.Fatalf("setting the flag: %v", err)
	}
	if err := SetPassword(ctx, conn, userID, "$argon2id$v=19$m=19456,t=2,p=1$bmV3c2FsdA$bmV3aGFzaA"); err != nil {
		t.Fatalf("setting the password: %v", err)
	}

	// Without this, a user changes their password as instructed and is asked to
	// change it again -- forever, with no exit from their side.
	must, _, err := PasswordChangeRequired(ctx, conn, userID)
	if err != nil {
		t.Fatalf("reading the flag: %v", err)
	}
	if must {
		t.Fatal("changing the password did not clear the demand to change it")
	}
}

func TestBreachRecheckIsBoundedAndResumes(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	seedPassword(t, conn, orgID, userID)

	due, err := BreachCheckDue(ctx, conn, userID, 24*time.Hour)
	if err != nil {
		t.Fatalf("asking whether a check is due: %v", err)
	}
	if !due {
		t.Fatal("a credential that has never been checked must be due")
	}

	if err := RecordBreachCheck(ctx, conn, userID); err != nil {
		t.Fatalf("recording the check: %v", err)
	}

	// Just checked: not due. Without the bound, the corpus is consulted on every
	// sign-in, putting a third party on the critical path of every login.
	due, err = BreachCheckDue(ctx, conn, userID, 24*time.Hour)
	if err != nil {
		t.Fatalf("asking again: %v", err)
	}
	if due {
		t.Fatal("a credential checked a moment ago must not be due again")
	}

	// Zero disables it rather than meaning "always".
	due, err = BreachCheckDue(ctx, conn, userID, 0)
	if err != nil {
		t.Fatalf("asking with a zero interval: %v", err)
	}
	if due {
		t.Fatal("a zero interval must disable re-checking, not force it")
	}

	// And it resumes: an interval that never elapses is a control that ran once.
	_, err = conn.Exec(ctx,
		`UPDATE core.password_credentials SET last_breach_check = now() - interval '10 days'
		  WHERE user_id = $1::uuid`, userID)
	must(t, err)
	due, err = BreachCheckDue(ctx, conn, userID, 24*time.Hour)
	if err != nil {
		t.Fatalf("asking after the interval: %v", err)
	}
	if !due {
		t.Fatal("re-checking never resumed; the control would run once and stop")
	}
}

func TestRetiringBeforeReplacingIsWhatMakesHistoryWork(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	seedPassword(t, conn, orgID, userID)

	original, err := CurrentPasswordHash(ctx, conn, userID)
	if err != nil || original != seedHash {
		t.Fatalf("reading the current hash: %v (%q)", err, original)
	}

	if err := RetirePassword(ctx, conn, userID, orgID); err != nil {
		t.Fatalf("retiring: %v", err)
	}
	const replacement = "$argon2id$v=19$m=19456,t=2,p=1$bmV3c2FsdA$bmV3aGFzaA"
	if err := SetPassword(ctx, conn, userID, replacement); err != nil {
		t.Fatalf("replacing: %v", err)
	}

	prev, err := RecentPasswordHashes(ctx, conn, userID, 5)
	if err != nil {
		t.Fatalf("reading history: %v", err)
	}
	// The ORDER is the whole point. Retiring after replacing files the NEW
	// password as a previous one, and the user is refused their own new password
	// at the next change -- a bug that appears only on the second change, long
	// after anyone is watching.
	for _, h := range prev {
		if h == replacement {
			t.Fatal("the new password was filed as a previous one; " +
				"the next change would refuse it")
		}
	}
	found := false
	for _, h := range prev {
		if h == original {
			found = true
		}
	}
	if !found {
		t.Fatalf("the replaced password was not recorded; history has %d entries", len(prev))
	}
}
