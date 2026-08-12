package keys

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func subjectTx(t *testing.T) (pgx.Tx, *RootKey, string) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, "SET ROLE signari_maintenance"); err != nil {
		t.Fatal(err)
	}
	// Everything runs in a transaction that is rolled back, so these tests never
	// touch real subject keys.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	root, err := NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	var id string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return tx, root, id
}

func TestSubjectKeyRoundTrips(t *testing.T) {
	tx, root, id := subjectTx(t)
	ctx := context.Background()

	k, err := LoadOrCreateSubjectKey(ctx, tx, id, root)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("a totp secret")
	sealed, err := k.Seal(secret, "totp_secret")
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) == string(secret) {
		t.Fatal("Seal returned the plaintext")
	}

	// The same subject, loaded again, must decrypt what the first load sealed --
	// otherwise the key is regenerated per call and yesterday's data is lost.
	again, err := LoadOrCreateSubjectKey(ctx, tx, id, root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.Open(sealed, "totp_secret")
	if err != nil {
		t.Fatalf("a reloaded subject key could not decrypt its own ciphertext: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("got %q, want %q", got, secret)
	}
}

// The context binds ciphertext to its purpose. Without it, a blob lifted from
// one column and pasted into another decrypts happily and silently becomes a
// different secret.
func TestContextIsAuthenticated(t *testing.T) {
	tx, root, id := subjectTx(t)
	ctx := context.Background()

	k, _ := LoadOrCreateSubjectKey(ctx, tx, id, root)
	sealed, _ := k.Seal([]byte("secret"), "totp_secret")

	if _, err := k.Open(sealed, "audit_detail"); err == nil {
		t.Fatal("ciphertext decrypted under the wrong context")
	}
}

// Two subjects must not be able to read each other's data, which is the entire
// reason the key is per-subject rather than global.
func TestSubjectsAreCryptographicallyIsolated(t *testing.T) {
	tx, root, alice := subjectTx(t)
	ctx := context.Background()

	var bob string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&bob); err != nil {
		t.Fatal(err)
	}

	ka, _ := LoadOrCreateSubjectKey(ctx, tx, alice, root)
	kb, err := LoadOrCreateSubjectKey(ctx, tx, bob, root)
	if err != nil {
		t.Fatal(err)
	}

	sealed, _ := ka.Seal([]byte("alice's totp secret"), "totp_secret")
	if _, err := kb.Open(sealed, "totp_secret"); err == nil {
		t.Fatal("one subject's key decrypted another's ciphertext")
	}
}

// Crypto-shredding: the point of the whole design. After erasure the ciphertext
// must be unreadable by anyone, including us, including from a backup taken
// before the erasure.
func TestErasureMakesCiphertextPermanentlyUnreadable(t *testing.T) {
	tx, root, id := subjectTx(t)
	ctx := context.Background()

	k, _ := LoadOrCreateSubjectKey(ctx, tx, id, root)
	sealed, _ := k.Seal([]byte("a totp secret"), "totp_secret")

	if err := EraseSubject(ctx, tx, id); err != nil {
		t.Fatal(err)
	}

	// Loading again must refuse rather than quietly minting a fresh key, which
	// would make new data readable under the same subject and undo the erasure.
	_, err := LoadOrCreateSubjectKey(ctx, tx, id, root)
	if !errors.Is(err, ErrErased) {
		t.Fatalf("after erasure the key was reloaded (err = %v)", err)
	}

	// The row survives as evidence the erasure happened, with no key in it.
	var hasKey, erased bool
	if err := tx.QueryRow(ctx, `
		SELECT wrapped_dek IS NOT NULL, erased_at IS NOT NULL
		FROM core.subject_keys WHERE subject_id = $1::uuid`, id).Scan(&hasKey, &erased); err != nil {
		t.Fatal(err)
	}
	if hasKey {
		t.Error("the wrapped key is still present after erasure")
	}
	if !erased {
		t.Error("erased_at was not recorded; there is no evidence the erasure happened")
	}
	_ = sealed // the ciphertext remains; nothing can read it, which is the point
}

// An erasure request that arrives twice must not fail the second time.
func TestErasureIsIdempotent(t *testing.T) {
	tx, root, id := subjectTx(t)
	ctx := context.Background()

	if _, err := LoadOrCreateSubjectKey(ctx, tx, id, root); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := EraseSubject(ctx, tx, id); err != nil {
			t.Fatalf("erasure %d failed: %v", i+1, err)
		}
	}
}

// The wrong root key must fail loudly rather than produce garbage that later
// looks like data corruption.
func TestWrongRootKeyIsRejected(t *testing.T) {
	tx, root, id := subjectTx(t)
	ctx := context.Background()

	if _, err := LoadOrCreateSubjectKey(ctx, tx, id, root); err != nil {
		t.Fatal(err)
	}

	other := make([]byte, 32)
	other[0] = 1
	wrongRoot, _ := NewRootKey("test", other)

	if _, err := LoadOrCreateSubjectKey(ctx, tx, id, wrongRoot); err == nil {
		t.Fatal("a subject key was unwrapped with the wrong root key")
	}
}
