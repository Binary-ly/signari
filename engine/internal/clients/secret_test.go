package clients

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// Client-secret hashing.
//
// The rule under test is that the FAST path is taken only where entropy has
// been established, because the fast path's whole safety argument is "there is
// no dictionary to run".

func generated(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw) // 43 chars, 256 bits
}

func TestAGeneratedSecretTakesTheFastPath(t *testing.T) {
	secret := generated(t)
	if len(secret) < MinFastSecretLen {
		t.Fatalf("a generated secret is %d chars, below the threshold of %d",
			len(secret), MinFastSecretLen)
	}
	stored, ok := HashSecret(secret)
	if !ok {
		t.Fatal("a 256-bit secret was not eligible for the fast path")
	}
	if !strings.HasPrefix(stored, FastSecretPrefix) {
		t.Fatalf("stored = %q, want the %s prefix", stored, FastSecretPrefix)
	}
	// The secret itself must not be recoverable from what is stored.
	if strings.Contains(stored, secret) {
		t.Fatal("the stored form contains the secret")
	}

	got, err := VerifyFastSecret(stored, secret)
	if err != nil || !got {
		t.Fatalf("the correct secret did not verify: %v %v", got, err)
	}
	wrong, err := VerifyFastSecret(stored, secret[:len(secret)-1]+"X")
	if err != nil {
		t.Fatalf("verifying a wrong secret errored: %v", err)
	}
	if wrong {
		t.Fatal("a wrong secret verified")
	}
}

// A short secret might be human-chosen, and guessing wrong in that direction is
// the expensive mistake. Those must NOT get the fast hash.
func TestAShortSecretIsRefusedTheFastPath(t *testing.T) {
	for _, s := range []string{"", "hunter2", "correct-horse", strings.Repeat("a", MinFastSecretLen-1)} {
		if _, ok := HashSecret(s); ok {
			t.Errorf("%q (%d chars) was given the fast hash; its entropy is not "+
				"established and SHA-256 over a guessable value is guessable",
				s, len(s))
		}
	}
	// And exactly at the threshold it is allowed, so the boundary is not off by one.
	if _, ok := HashSecret(strings.Repeat("a", MinFastSecretLen)); !ok {
		t.Errorf("a secret of exactly %d chars was refused", MinFastSecretLen)
	}
}

// Verification must dispatch on the STORED format, so an Argon2 hash from
// before this change keeps working.
func TestVerificationDispatchesOnTheStoredFormat(t *testing.T) {
	if IsFastSecret("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA") {
		t.Fatal("an argon2 hash was identified as the fast format")
	}
	if !IsFastSecret(FastSecretPrefix + "abc") {
		t.Fatal("a fast hash was not identified")
	}
	// A malformed fast hash is an error, not a silent pass.
	if ok, err := VerifyFastSecret(FastSecretPrefix+"!!!not-base64", "x"); ok || err == nil {
		t.Fatal("a malformed stored hash verified or did not error")
	}
	// The wrong length is malformed too -- a truncated digest must not compare
	// equal to its own prefix.
	short := base64.RawStdEncoding.EncodeToString([]byte("tooshort"))
	if ok, err := VerifyFastSecret(FastSecretPrefix+short, "x"); ok || err == nil {
		t.Fatal("a short digest verified or did not error")
	}
	if _, err := VerifyFastSecret("$argon2id$whatever", "x"); err == nil {
		t.Fatal("verifying an argon2 hash through the fast path did not error")
	}
}
