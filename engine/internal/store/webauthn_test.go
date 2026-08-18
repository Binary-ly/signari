package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func waFixture(t *testing.T) (pgx.Tx, string, string) {
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

func addCred(t *testing.T, tx pgx.Tx, userID, orgID string, id byte, count uint32) {
	t.Helper()
	if err := SaveCredential(context.Background(), tx, userID, orgID, "localhost",
		[]byte{id}, []byte{0x02}, nil, count, true, []string{"internal"}, "none", "Test key"); err != nil {
		t.Fatal(err)
	}
}

// The counter rules, which are the whole of WebAuthn's cloning detection and are
// routinely implemented backwards.
func TestSignCountCloningRules(t *testing.T) {
	tx, orgID, userID := waFixture(t)
	ctx := context.Background()
	caseIndex := 0

	for _, tc := range []struct {
		name              string
		stored, presented uint32
		wantCloned        bool
	}{
		// The majority of real passkeys. Apple's always report zero, because a
		// credential synced across devices cannot keep a coherent counter.
		// Treating this as suspicious rejects most of the passkeys in the world.
		{"authenticator does not implement counters", 0, 0, false},
		{"first use of a counting authenticator", 0, 5, false},
		{"counter advances normally", 5, 6, false},
		{"counter jumps ahead", 5, 500, false},

		// A stored non-zero counter followed by ZERO is a signal, and this case
		// used to assert the opposite.
		//
		// WebAuthn L3 §7.2 step 21 enters the cloning sub-step when EITHER
		// counter is non-zero, and then flags any value that does not advance --
		// so stored=5, presented=0 is flagged. The old comment justified ignoring
		// it on the grounds that flagging "would lock out a user whose device was
		// replaced". Nothing in this system locks anybody out: the caller in
		// internal/httpapi/passkey.go logs a warning, writes an
		// mfa.passkey_counter_regression audit event, and completes the sign-in.
		//
		// So the deviation was justified by a consequence that does not exist
		// here, which made it a false rationale rather than a considered
		// trade-off. The one case it discarded is the one that cannot be
		// explained by "this authenticator does not count" -- because it did.
		{"counted before, reports zero now", 5, 0, true},

		// The only real signal: a non-zero counter that failed to advance.
		{"counter went backwards", 10, 3, true},
		{"counter repeated", 10, 10, true},
	} {
		i := caseIndex
		caseIndex++
		t.Run(tc.name, func(t *testing.T) {
			// Unique per case. Derived from the name it collides for two names of
			// equal length, and one collision aborts the shared transaction so
			// every later case fails for an unrelated reason.
			credID := byte(0xA0 + i)
			addCred(t, tx, userID, orgID, credID, tc.stored)

			err := UpdateSignCount(ctx, tx, []byte{credID}, tc.stored, tc.presented)
			if got := errors.Is(err, ErrCredentialCloned); got != tc.wantCloned {
				t.Fatalf("cloned=%v, want %v (err=%v)", got, tc.wantCloned, err)
			}

			// The counter advances even on the cloning path: refusing to write it
			// would let an attacker replay the same assertion forever, each
			// attempt raising the same alarm and none of them closing the hole.
			creds, err := CredentialsForUser(ctx, tx, userID)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range creds {
				if len(c.CredentialID) == 1 && c.CredentialID[0] == credID {
					if c.SignCount < tc.stored {
						t.Errorf("sign_count went backwards in storage: %d < %d", c.SignCount, tc.stored)
					}
					if c.LastUsedAt == nil {
						t.Error("last_used_at was not recorded")
					}
				}
			}
		})
	}
}

// One passkey is not enough to drop a password. The credential lives in a secure
// enclave and cannot be exported or recovered, so a single one turns a lost
// device into a permanently dead account.
func TestPasswordlessNeedsTwoCredentials(t *testing.T) {
	tx, orgID, userID := waFixture(t)
	ctx := context.Background()

	if ok, _ := CanGoPasswordless(ctx, tx, userID); ok {
		t.Fatal("passwordless allowed with no credentials at all")
	}

	addCred(t, tx, userID, orgID, 0x11, 0)
	if ok, _ := CanGoPasswordless(ctx, tx, userID); ok {
		t.Fatal("passwordless allowed with ONE credential -- a lost device is now a dead account")
	}

	addCred(t, tx, userID, orgID, 0x12, 0)
	ok, err := CanGoPasswordless(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("passwordless refused with %d credentials", MinCredentialsForPasswordless)
	}
}

// Deleting the last way in must be refused, or self-service becomes a way for a
// user to lock themselves out permanently.
func TestDeletingTheLastCredentialIsRefused(t *testing.T) {
	tx, orgID, userID := waFixture(t)
	ctx := context.Background()

	addCred(t, tx, userID, orgID, 0x21, 0)
	creds, _ := CredentialsForUser(ctx, tx, userID)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	// Give the user a password, so removing their only passkey is safe.
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, is_current)
		VALUES ($1::uuid, $2::uuid, 'x', 'argon2id', true)`, userID, orgID); err != nil {
		t.Fatal(err)
	}
	if err := DeleteCredential(ctx, tx, userID, creds[0].ID); err != nil {
		t.Fatalf("removing a passkey from a password-holding account was refused: %v", err)
	}

	// Now with no password: the last passkey must be undeletable.
	addCred(t, tx, userID, orgID, 0x22, 0)
	if _, err := tx.Exec(ctx,
		`DELETE FROM core.password_credentials WHERE user_id = $1::uuid`, userID); err != nil {
		t.Fatal(err)
	}
	creds, _ = CredentialsForUser(ctx, tx, userID)
	if err := DeleteCredential(ctx, tx, userID, creds[0].ID); !errors.Is(err, ErrWouldLockOut) {
		t.Fatalf("the last authentication method was deletable (err = %v)", err)
	}
}

// One user must not be able to delete another's credential by guessing a uuid.
func TestDeletionIsScopedToTheOwner(t *testing.T) {
	tx, orgID, userID := waFixture(t)
	ctx := context.Background()

	addCred(t, tx, userID, orgID, 0x31, 0)
	addCred(t, tx, userID, orgID, 0x32, 0)
	creds, _ := CredentialsForUser(ctx, tx, userID)

	var stranger string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&stranger); err != nil {
		t.Fatal(err)
	}
	if err := DeleteCredential(ctx, tx, stranger, creds[0].ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("a stranger deleted someone else's credential (err = %v)", err)
	}
	if n, _ := CountCredentials(ctx, tx, userID); n != 2 {
		t.Errorf("credential count changed to %d", n)
	}
}

// The rp_id a credential was created under is recorded per credential, because
// that is what a Related Origin Requests migration needs and what tells an
// operator which passkeys an rp_id change would have destroyed.
func TestCredentialRecordsItsRPID(t *testing.T) {
	tx, orgID, userID := waFixture(t)
	ctx := context.Background()

	addCred(t, tx, userID, orgID, 0x41, 0)
	creds, err := CredentialsForUser(ctx, tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) == 0 || creds[0].RPID != "localhost" {
		t.Fatalf("rp_id was not stored with the credential: %+v", creds)
	}
}
