package passwords

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

func TestHashAndVerifyRoundTrip(t *testing.T) {
	h := NewHasher(0)
	ctx := context.Background()

	stored, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "$argon2id$") {
		t.Fatalf("unexpected format: %s", stored)
	}

	needsRehash, err := h.Verify(ctx, stored, "correct horse battery staple")
	if err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	if needsRehash {
		t.Error("a freshly written hash should already be at current policy")
	}

	if _, err := h.Verify(ctx, stored, "wrong"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong password: err = %v, want ErrMismatch", err)
	}
}

// Two hashes of the same password must differ, or the salt is not doing its job.
func TestHashesAreSalted(t *testing.T) {
	h := NewHasher(0)
	ctx := context.Background()
	a, _ := h.Hash(ctx, "same")
	b, _ := h.Hash(ctx, "same")
	if a == b {
		t.Fatal("identical hashes for the same password; salt is missing or constant")
	}
}

// The migration wedge: a foreign hash must verify in place and report that it
// needs upgrading, so login can silently rehash without a password reset.
func TestForeignHashesVerifyAndRequestRehash(t *testing.T) {
	h := NewHasher(0)
	ctx := context.Background()
	const pw = "s3cr3t-p@ssw0rd"

	t.Run("bcrypt", func(t *testing.T) {
		raw, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
		if err != nil {
			t.Fatal(err)
		}
		needsRehash, err := h.Verify(ctx, string(raw), pw)
		if err != nil {
			t.Fatalf("a valid bcrypt hash failed to verify: %v", err)
		}
		if !needsRehash {
			t.Error("an imported bcrypt hash must be flagged for rehashing")
		}
		if _, err := h.Verify(ctx, string(raw), "wrong"); !errors.Is(err, ErrMismatch) {
			t.Error("bcrypt accepted a wrong password")
		}
	})

	t.Run("django pbkdf2_sha256", func(t *testing.T) {
		const salt, iter = "abcdefghijkl", 260000
		sum := pbkdf2.Key([]byte(pw), []byte(salt), iter, 32, sha256.New)
		stored := "pbkdf2_sha256$260000$" + salt + "$" + base64.StdEncoding.EncodeToString(sum)

		needsRehash, err := h.Verify(ctx, stored, pw)
		if err != nil {
			t.Fatalf("a valid Django hash failed to verify: %v", err)
		}
		if !needsRehash {
			t.Error("an imported Django hash must be flagged for rehashing")
		}
		if _, err := h.Verify(ctx, stored, "wrong"); !errors.Is(err, ErrMismatch) {
			t.Error("Django PBKDF2 accepted a wrong password")
		}
	})
}

// An unrecognised prefix must be a mismatch, never a pass. Failing open here
// would turn a botched import into an authentication bypass.
func TestUnknownFormatFailsClosed(t *testing.T) {
	h := NewHasher(0)
	ctx := context.Background()
	for _, stored := range []string{
		"", "plaintext", "$1$abc$def", "{SSHA}xyz", "$argon2i$v=19$m=1,t=1,p=1$aaaa$bbbb",
		"pbkdf2_sha512$1$s$h",
	} {
		if _, err := h.Verify(ctx, stored, "anything"); !errors.Is(err, ErrMismatch) {
			t.Errorf("stored %q: err = %v, want ErrMismatch", stored, err)
		}
	}
}

// Malformed Argon2 strings must not panic or pass.
func TestMalformedArgonStrings(t *testing.T) {
	h := NewHasher(0)
	ctx := context.Background()
	for _, stored := range []string{
		"$argon2id$",
		"$argon2id$v=19$m=19456,t=2,p=1$notbase64!!$abc",
		"$argon2id$v=99$m=19456,t=2,p=1$YWJj$YWJj",
		"$argon2id$v=19$garbage$YWJj$YWJj",
	} {
		if _, err := h.Verify(ctx, stored, "x"); !errors.Is(err, ErrMismatch) {
			t.Errorf("stored %q: err = %v, want ErrMismatch", stored, err)
		}
	}
}

// A hash written with weaker-than-policy parameters must still verify, and must
// ask to be upgraded. Refusing it would lock out every user after a parameter bump.
func TestWeakerParametersVerifyButRequestRehash(t *testing.T) {
	h := NewHasher(0)
	ctx := context.Background()

	// Same construction as Hash, at deliberately lower cost.
	weak := buildArgon(t, "pw", 8192, 1, 1)
	needsRehash, err := h.Verify(ctx, weak, "pw")
	if err != nil {
		t.Fatalf("a weaker-parameter hash failed to verify: %v", err)
	}
	if !needsRehash {
		t.Error("a below-policy hash must be flagged for rehashing")
	}
}

// The whole point of the semaphore: concurrency is capped, so a login flood
// queues instead of exhausting memory.
func TestConcurrencyIsBounded(t *testing.T) {
	h := NewHasher(64) // 64 MiB budget -> at most 3 concurrent at 19 MiB each
	if h.Concurrency() < 1 {
		t.Fatal("concurrency must be at least 1")
	}
	if h.Concurrency() > 64*1024/argonMemoryKiB {
		t.Fatalf("concurrency %d exceeds what the memory budget allows", h.Concurrency())
	}

	// And it must still be correct under contention.
	ctx := context.Background()
	stored, err := h.Hash(ctx, "pw")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.Verify(ctx, stored, "pw"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("verification failed under contention: %v", err)
	}
}

// A caller that has already given up must stop occupying hashing budget.
func TestCancelledContextReleasesBudget(t *testing.T) {
	h := NewHasher(19) // exactly one slot
	ctx, cancel := context.WithCancel(context.Background())

	// Occupy the only slot.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.Hash(context.Background(), "occupying")
	}()

	cancel()
	if _, err := h.Hash(ctx, "pw"); err == nil {
		t.Error("a cancelled context still acquired a hashing slot")
	}
	<-done
}

func buildArgon(t *testing.T, pw string, m, time uint32, p uint8) string {
	t.Helper()
	h := NewHasher(0)
	full, err := h.Hash(context.Background(), pw)
	if err != nil {
		t.Fatal(err)
	}
	// Recompute at the weaker parameters, reusing the generated salt.
	parts := strings.Split(full, "$")
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatal(err)
	}
	key := argon2.IDKey([]byte(pw), salt, time, m, p, argonKeyLen)
	return "$argon2id$v=19$m=" + strconv.Itoa(int(m)) + ",t=" + strconv.Itoa(int(time)) + ",p=" + strconv.Itoa(int(p)) +
		"$" + base64.RawStdEncoding.EncodeToString(salt) +
		"$" + base64.RawStdEncoding.EncodeToString(key)
}

// TestSupportedPrefixesMatchesVerify.
//
// SupportedPrefixes named five formats while Verify handled nine. Migration
// tooling reads that list to tell an operator which passwords will transfer, so
// under-reporting means planning a password reset for users who never needed
// one. This asserts every advertised prefix is actually recognised, and that a
// hash Verify would handle is never reported as unsupported.
func TestSupportedPrefixesMatchesVerify(t *testing.T) {
	// Every prefix Verify branches on, read off the switch in passwords.go.
	handled := []string{
		"$argon2id$", "$2a$", "$2b$", "$2y$", "pbkdf2_sha256$",
		"$P$", "$H$", "$S$", "$keycloak$", "$scrypt$",
	}
	advertised := map[string]bool{}
	for _, p := range SupportedPrefixes() {
		advertised[p] = true
	}
	for _, p := range handled {
		if !advertised[p] {
			t.Errorf("Verify handles %q but SupportedPrefixes does not advertise it; "+
				"migration tooling will tell an operator those passwords cannot transfer", p)
		}
		if !CanVerify(p + "whatever") {
			t.Errorf("CanVerify says no to %q, which Verify handles", p)
		}
	}
	if CanVerify("$6$rounds=5000$saltsalt$hash") {
		t.Error("CanVerify claims glibc SHA-crypt works; passwords.go says NOT HANDLED")
	}
	if CanVerify("") {
		t.Error("an empty hash was reported as verifiable")
	}
}
