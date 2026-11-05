package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// Made by libyubikey 1.13's ykgenerate under this key and private ID, as in mfa's tests:
// use counter 1 session 0, use 1 session 1, use 2 session 0.
const (
	yubicoKeyHex       = "47077bb37e5298413989c9ef9fcb1dad"
	yubicoPrivateIDHex = "aa994855e455"
	yubicoOTP0100      = "hfbkfjghgbjibhlvjfibfvujblhgbfnf"
	yubicoOTP0101      = "dvhtenbcidccjcbvrjtheicebfleckuh"
	yubicoOTP0200      = "gfbhkgrbjdghehdgvclijvekcidkdgrk"
)

// randomPublicID is a public ID no other run holds. A token has one holder across the
// instance, and the encrypted part does not depend on what is typed before it.
func randomPublicID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte("cbdefghijklnrtuv"[x>>4])
		sb.WriteByte("cbdefghijklnrtuv"[x&15])
	}
	return sb.String()
}

func assignYubico(t *testing.T, f *signInFixture, publicID string, counter int64) error {
	t.Helper()
	ctx := context.Background()
	key, _ := hex.DecodeString(yubicoKeyHex)
	privateID, _ := hex.DecodeString(yubicoPrivateIDHex)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.AssignYubicoToken(ctx, tx, f.userID, f.orgID, publicID, key, privateID, counter,
		f.srv.cfg.Root); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// A YubiKey's Yubico OTP signs a person in through the same second-factor step as any
// authenticator, once each (4.27). Only an OTP with the token's public ID is a guess at it.
func TestAYubicoOTPSignsInOnce(t *testing.T) {
	f, _ := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	ctx := context.Background()
	publicID := randomPublicID(t)
	// Assigned with the OTP that proved it, use 1 session 0.
	if err := assignYubico(t, f, publicID, 0x0100); err != nil {
		t.Fatal(err)
	}
	state := func() (n int64, failed int) {
		t.Helper()
		if err := f.pool.QueryRow(ctx, `SELECT last_used_counter, failed_attempts FROM core.totp_credentials
			WHERE user_id = $1::uuid`, f.userID).Scan(&n, &failed); err != nil {
			t.Fatal(err)
		}
		return n, failed
	}

	page := f.signInWith(t, "")
	// The OTP that proved the token is spent, and a replay is no guess.
	if rec := f.postCode(t, page, publicID+yubicoOTP0100); sessionSet(rec) {
		t.Fatal("the OTP the token was assigned with signed in")
	}
	if _, failed := state(); failed != 0 {
		t.Errorf("a replayed OTP was charged as a guess (%d)", failed)
	}
	// The next, as typed with the Enter the token sends.
	if rec := f.postCode(t, page, publicID+yubicoOTP0101+"\r\n"); !sessionSet(rec) {
		t.Fatalf("the token's next OTP did not sign in: %d %.300s", rec.Code, rec.Body)
	}
	if n, _ := state(); n != 0x0101 {
		t.Fatalf("the token's counter is %#x after use 1 session 1", n)
	}

	page = f.signInWith(t, "")
	if rec := f.postCode(t, page, publicID+yubicoOTP0101); sessionSet(rec) {
		t.Fatal("an OTP signed in twice")
	}
	// Six digits are no guess at a YubiKey, nor is another token's OTP.
	for _, notOurs := range []string{"123456", randomPublicID(t) + yubicoOTP0200} {
		if rec := f.postCode(t, page, notOurs); sessionSet(rec) {
			t.Fatalf("%q signed in", notOurs)
		}
	}
	if _, failed := state(); failed != 0 {
		t.Errorf("codes that were no guess at the token were charged to it (%d)", failed)
	}
	// Its public ID and anything else is, and is charged.
	if rec := f.postCode(t, page, publicID+strings.Repeat("c", 32)); sessionSet(rec) {
		t.Fatal("a made-up OTP signed in")
	}
	if _, failed := state(); failed != 1 {
		t.Errorf("a made-up OTP with the token's public ID was charged %d times", failed)
	}
	// After a power-up: use 2 session 0.
	if rec := f.postCode(t, page, strings.ToUpper(publicID+yubicoOTP0200)); !sessionSet(rec) {
		t.Fatalf("the OTP after a power-up, typed with caps lock on, did not sign in: %d", rec.Code)
	}
	if n, failed := state(); n != 0x0200 || failed != 0 {
		t.Errorf("after use 2 session 0 the counter is %#x with %d failures", n, failed)
	}
}

// A token has one holder, in any organisation: its counter is kept with the credential, and
// a second credential would accept every OTP the first had spent.
func TestAYubicoTokenHasOneHolder(t *testing.T) {
	f, _ := enrolFixture(t)
	other, _ := enrolFixture(t)
	publicID := randomPublicID(t)
	if err := assignYubico(t, f, publicID, 0x0100); err != nil {
		t.Fatal(err)
	}
	if err := assignYubico(t, other, publicID, 0x0100); !errors.Is(err, store.ErrYubicoTokenHeld) {
		t.Fatalf("the same token assigned to a second person: %v, want ErrYubicoTokenHeld", err)
	}
	// Given to the same person again, it replaces itself.
	if err := assignYubico(t, f, publicID, 0x0101); err != nil {
		t.Fatalf("the same token assigned again to its holder: %v", err)
	}
}

// A person whose YubiKey is replaced by an authenticator app is left with the app, and the
// token's public ID goes with the token: it was kept on the row, which the check on the
// table then refused, so the app could not be enrolled at all.
func TestAnAppReplacesAYubicoToken(t *testing.T) {
	f, _ := enrolFixture(t)
	ctx := context.Background()
	publicID := randomPublicID(t)
	if err := assignYubico(t, f, publicID, 0x0100); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.StartTOTPEnrolment(ctx, tx, f.userID, f.orgID, []byte("12345678901234567890"), "SHA1", 6,
		30*time.Second, f.srv.cfg.Root); err != nil {
		t.Fatal(err)
	}
	if replaced, err := store.CompleteTOTPEnrolment(ctx, tx, f.userID, 1); err != nil || !replaced {
		t.Fatalf("enrolling an app over a Yubico token: replaced %v, %v", replaced, err)
	}
	cred, err := store.LoadTOTP(ctx, tx, f.userID, f.srv.cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Kind != "totp" || cred.Algorithm != "SHA1" || cred.YubicoPublicID != "" {
		t.Errorf("after the app: kind %s, %s, public ID %q", cred.Kind, cred.Algorithm, cred.YubicoPublicID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// And the token is free to be somebody else's.
	other, _ := enrolFixture(t)
	if err := assignYubico(t, other, publicID, 0x0100); err != nil {
		t.Errorf("the token an app replaced could not be given to anyone else: %v", err)
	}
}
