package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func recoveryFixture(t *testing.T) (pgx.Tx, string, string) {
	t.Helper()
	conn := connect(t)
	orgID, userID, _, _ := fixture(t, conn)
	tx, err := conn.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx, orgID, userID
}

func hashes(seed byte) ([]byte, []byte) {
	return []byte{seed, 1, 2, 3}, []byte{seed, 9, 8, 7}
}

// THE property. A reset must not work the instant it is requested -- that window
// is the only thing standing between a stolen mailbox and a stolen account.
func TestResetIsNotUsableBeforeTheDelay(t *testing.T) {
	tx, orgID, userID := recoveryFixture(t)
	ctx := context.Background()
	tok, cancel := hashes(0x10)
	now := time.Now()

	r, err := CreateRecoveryRequest(ctx, tx, userID, orgID, tok, cancel, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if !r.EffectiveAt.After(now) {
		t.Fatal("a delayed request was immediately effective")
	}

	_, err = LookupRecovery(ctx, tx, tok, now)
	if !errors.Is(err, ErrRecoveryPending) {
		t.Fatalf("token usable during the delay window (err = %v)", err)
	}

	// After the delay it works.
	got, err := LookupRecovery(ctx, tx, tok, now.Add(RecoveryDelay+time.Second))
	if err != nil {
		t.Fatalf("token unusable after the delay: %v", err)
	}
	if got.UserID != userID {
		t.Errorf("resolved to the wrong user")
	}
}

// Proving a second factor waives the delay: the holder of an authenticator has
// something the mailbox thief does not, so the delay protects nothing and only
// punishes the real user.
func TestSecondFactorWaivesTheDelay(t *testing.T) {
	tx, orgID, userID := recoveryFixture(t)
	ctx := context.Background()
	tok, cancel := hashes(0x20)
	now := time.Now()

	if _, err := CreateRecoveryRequest(ctx, tx, userID, orgID, tok, cancel, "totp", now); err != nil {
		t.Fatal(err)
	}
	got, err := LookupRecovery(ctx, tx, tok, now)
	if err != nil {
		t.Fatalf("a second-factor reset was still delayed: %v", err)
	}
	if got.WaivedBy != "totp" {
		t.Errorf("waiver was not recorded: %q -- an investigation could not tell a fast reset from a suspicious one", got.WaivedBy)
	}
}

// The cancel link is the user's defence, and it must work instantly and twice
// (mail scanners prefetch links; people click again when unsure).
func TestCancelIsImmediateAndIdempotent(t *testing.T) {
	tx, orgID, userID := recoveryFixture(t)
	ctx := context.Background()
	tok, cancel := hashes(0x30)
	now := time.Now()

	if _, err := CreateRecoveryRequest(ctx, tx, userID, orgID, tok, cancel, "", now); err != nil {
		t.Fatal(err)
	}
	who, ok, err := CancelRecovery(ctx, tx, cancel)
	if err != nil || !ok || who != userID {
		t.Fatalf("cancel failed: ok=%v who=%q err=%v", ok, who, err)
	}

	// Cancelled tokens are indistinguishable from invalid ones: saying "this was
	// cancelled" confirms the token was real.
	if _, err := LookupRecovery(ctx, tx, tok, now.Add(RecoveryDelay+time.Second)); !errors.Is(err, ErrRecoveryNotFound) {
		t.Errorf("a cancelled token was still usable (err = %v)", err)
	}

	if _, ok, err := CancelRecovery(ctx, tx, cancel); err != nil || ok {
		t.Errorf("a second cancel should be quietly ignored, got ok=%v err=%v", ok, err)
	}
}

// Two live requests would double an attacker's chances, so a new one supersedes.
func TestNewRequestSupersedesTheOld(t *testing.T) {
	tx, orgID, userID := recoveryFixture(t)
	ctx := context.Background()
	now := time.Now()
	old, oldCancel := hashes(0x40)
	fresh, freshCancel := hashes(0x50)

	if _, err := CreateRecoveryRequest(ctx, tx, userID, orgID, old, oldCancel, "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateRecoveryRequest(ctx, tx, userID, orgID, fresh, freshCancel, "", now); err != nil {
		t.Fatalf("a second request was refused instead of superseding: %v", err)
	}

	after := now.Add(RecoveryDelay + time.Second)
	if _, err := LookupRecovery(ctx, tx, old, after); !errors.Is(err, ErrRecoveryNotFound) {
		t.Errorf("the superseded token still works (err = %v)", err)
	}
	if _, err := LookupRecovery(ctx, tx, fresh, after); err != nil {
		t.Errorf("the newest token does not work: %v", err)
	}
}

// A reset that leaves the attacker's session live has changed nothing they care
// about. This is the half most implementations miss.
func TestConsumingEndsEverySession(t *testing.T) {
	tx, orgID, userID := recoveryFixture(t)
	ctx := context.Background()
	tok, cancel := hashes(0x60)
	now := time.Now()

	r, err := CreateRecoveryRequest(ctx, tx, userID, orgID, tok, cancel, "totp", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ConsumeRecovery(ctx, tx, r.ID, userID, "$argon2id$new"); err != nil {
		t.Fatal(err)
	}

	var live int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM core.sessions WHERE user_id = $1::uuid AND revoked_at IS NULL`,
		userID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Errorf("%d session(s) survived the password reset", live)
	}

	// Single use.
	if err := ConsumeRecovery(ctx, tx, r.ID, userID, "$argon2id$other"); !errors.Is(err, ErrRecoveryNotFound) {
		t.Errorf("a recovery request was spent twice (err = %v)", err)
	}
}
