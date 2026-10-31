package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/radius"
	"signari.dev/engine/internal/store"
)

// bindCodes is a person with an authenticator, under a policy refusing a
// password alone, and a code for each step of the clock so none is a replay.
type bindCodes struct {
	f      *signInFixture
	secret []byte
	step   int64
}

func newBindCodes(t *testing.T) *bindCodes {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	secret, _, err := mfa.GenerateSecret(mfa.SHA1)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.StartTOTPEnrolment(ctx, tx, f.userID, f.orgID, secret,
		string(mfa.SHA1), mfa.DefaultDigits, mfa.DefaultPeriod, root); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteTOTPEnrolment(ctx, tx, f.userID, 0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.organizations SET password_only_binds = 'refuse_when_mfa'
		WHERE id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	return &bindCodes{f: f, secret: secret, step: time.Now().Unix() / int64(mfa.DefaultPeriod/time.Second)}
}

// code is a good code for the present step, or the next when asked for again.
func (b *bindCodes) code() string {
	return mfa.Code(b.secret, b.step, mfa.DefaultDigits)
}

func (b *bindCodes) ldap() *LDAPAuthenticator {
	return NewLDAPAuthenticator(b.f.pool, passwords.Shared(), b.f.orgID, b.f.srv.log).
		WithMFAGate(b.f.srv.BindDemandsMFA).WithCodes(b.f.srv.BindCodeOK)
}

// A bind carries a code after its password (7.05, completing 1.07): a right
// password alone is refused for somebody who owes a second factor, a code is
// held to everything the sign-in form holds it to, and each wrong one is
// charged. Protocols with one credential field could not carry a factor at all,
// so an organisation had to choose between no second factor and no VPN.
func TestABindCarriesACodeAfterItsPassword(t *testing.T) {
	b := newBindCodes(t)
	ctx := context.Background()
	auth, password := b.ldap(), signInTestPassword

	if _, err := auth.Authenticate(ctx, b.f.email, password); !errors.Is(err, errMFARequired) {
		t.Fatalf("a password alone answered %v, want it refused for a second factor", err)
	}
	good := b.code()
	if id, err := auth.Authenticate(ctx, b.f.email, password+";"+good); err != nil || id == nil {
		t.Fatalf("the password and its code answered %v", err)
	}
	if _, err := auth.Authenticate(ctx, b.f.email, password+";"+good); !errors.Is(err, errLDAPInvalid) {
		t.Errorf("the same code again answered %v, want it refused as a replay", err)
	}
	if _, err := auth.Authenticate(ctx, b.f.email, "wrong;"+good); !errors.Is(err, errLDAPInvalid) {
		t.Errorf("a good code with a wrong password answered %v", err)
	}

	var failed int
	failures := func() int {
		t.Helper()
		if err := b.f.pool.QueryRow(ctx, `SELECT failed_attempts FROM core.totp_credentials WHERE user_id = $1::uuid`,
			b.f.userID).Scan(&failed); err != nil {
			t.Fatal(err)
		}
		return failed
	}
	before := failures()
	if _, err := auth.Authenticate(ctx, b.f.email, password+";000000"); !errors.Is(err, errLDAPInvalid) {
		t.Errorf("a wrong code answered %v", err)
	}
	if got := failures(); got != before+1 {
		t.Errorf("a wrong code moved the authenticator's failures from %d to %d", before, got)
	}
}

// A code that came with the password has to be right even where a password alone
// would have done; and a password that merely ends like a code is a password.
func TestWhatLooksLikeACodeIsHeldToBeingOne(t *testing.T) {
	b := newBindCodes(t)
	ctx := context.Background()
	if _, err := b.f.pool.Exec(ctx, `UPDATE core.organizations SET password_only_binds = 'allow'
		WHERE id = $1::uuid`, b.f.orgID); err != nil {
		t.Fatal(err)
	}
	auth := b.ldap()
	if _, err := auth.Authenticate(ctx, b.f.email, signInTestPassword); err != nil {
		t.Fatalf("a password alone, where that is allowed, answered %v", err)
	}
	if _, err := auth.Authenticate(ctx, b.f.email, signInTestPassword+";000000"); !errors.Is(err, errLDAPInvalid) {
		t.Errorf("a wrong code where none was needed answered %v, want it refused", err)
	}

	whole := "a-password-of-mine;123456"
	hash, err := passwords.Shared().Hash(ctx, whole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.f.pool.Exec(ctx, `UPDATE core.password_credentials SET hash = $2 WHERE user_id = $1::uuid`,
		b.f.userID, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Authenticate(ctx, b.f.email, whole); err != nil {
		t.Errorf("a password ending in digits answered %v", err)
	}
	for password, code := range map[string]string{
		"pw;123456":    "123456",
		"pw;12345678":  "12345678",
		"pw;12345":     "",
		"pw;123456789": "",
		"pw;12345a":    "",
		";123456":      "",
		"pw":           "",
	} {
		if _, got := splitCode(password); got != code {
			t.Errorf("splitCode(%q) found %q, want %q", password, got, code)
		}
	}
}

// RADIUS is the same credential path, and a right password without a code asks
// for one rather than being refused, when the device can show a prompt.
func TestARADIUSPasswordAsksForItsCode(t *testing.T) {
	b := newBindCodes(t)
	ctx := context.Background()
	auth := NewRADIUSAuthenticator(b.f.pool, passwords.Shared(), b.f.orgID, b.f.srv.log).
		WithMFAGate(b.f.srv.BindDemandsMFA).WithCodes(b.f.srv.BindCodeOK)

	if err := auth.Authenticate(ctx, b.f.email, signInTestPassword); !errors.Is(err, radius.ErrSecondFactor) {
		t.Fatalf("a password alone answered %v, want a challenge", err)
	}
	good := b.code()
	if err := auth.VerifyCode(ctx, b.f.email, good); err != nil {
		t.Errorf("the code answered %v", err)
	}
	if err := auth.VerifyCode(ctx, b.f.email, good); err == nil {
		t.Error("the same code twice was accepted")
	}
	if err := auth.VerifyCode(ctx, "nobody@example.test", "123456"); err == nil {
		t.Error("a code for nobody was accepted")
	}
	// And in the one field, for a device that shows no prompt.
	b.step++
	if err := auth.Authenticate(ctx, b.f.email, signInTestPassword+";"+b.code()); err != nil {
		t.Errorf("the password and code together answered %v", err)
	}

	// With no way to check a code it stays what it was: refused.
	plain := NewRADIUSAuthenticator(b.f.pool, passwords.Shared(), b.f.orgID, b.f.srv.log).
		WithMFAGate(b.f.srv.BindDemandsMFA)
	if err := plain.Authenticate(ctx, b.f.email, signInTestPassword); err == nil || errors.Is(err, radius.ErrSecondFactor) {
		t.Errorf("without codes a password alone answered %v", err)
	}

	// Somebody switched off while the device waits for their code is not let
	// in by the password they had already proved (ADR-007): the challenge holds
	// nothing about them, and they are read again.
	b.step++
	if _, err := b.f.pool.Exec(ctx, `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, b.f.userID); err != nil {
		t.Fatal(err)
	}
	if err := auth.VerifyCode(ctx, b.f.email, b.code()); err == nil {
		t.Error("a good code from a deactivated person was accepted")
	}
}
