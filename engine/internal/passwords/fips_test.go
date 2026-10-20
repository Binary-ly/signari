package passwords

import (
	"context"
	"crypto/fips140"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// skipWithoutSHA1 skips a test whose fixture is a SHA-1 digest under
// fips140=only, which refuses SHA-1: the breach check it covers is refused at
// startup in that mode, and TestPasswordsUnderFIPSOnly says what happens.
func skipWithoutSHA1(t *testing.T) {
	t.Helper()
	if fips140.Enforced() {
		t.Skip("the fixture is a SHA-1 digest, which fips140=only refuses")
	}
}

// Under fips140=only (3.11): a new password is PBKDF2-SHA256 through the
// standard library, an Argon2id one verifies once and asks to be rehashed to
// it, MD5-based and short-salted imports are refused by name, and the breach
// check is unavailable; none of them panics. Argon2id was the only hash, and
// MD5, SHA-1 and short salts crashed their request.
func TestPasswordsUnderFIPSOnly(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPasswordsUnderFIPSOnly$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	ctx := context.Background()
	h := NewHasher(0)
	const pw = "correct horse battery staple"

	stored, err := h.Hash(ctx, pw)
	if err != nil || !strings.HasPrefix(stored, pbkdf2Prefix) {
		t.Fatalf("a new password: %q %v, want %s", stored, err, pbkdf2Prefix)
	}
	if rehash, err := h.Verify(ctx, stored, pw); err != nil || rehash {
		t.Errorf("a PBKDF2 hash: rehash %v, %v", rehash, err)
	}
	if _, err := h.Verify(ctx, stored, pw+"x"); !errors.Is(err, ErrMismatch) {
		t.Errorf("the wrong password against PBKDF2: %v", err)
	}

	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt)
	argon := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB, argonTime,
		argonThreads, base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(argon2.IDKey([]byte(pw), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)))
	if rehash, err := h.Verify(ctx, argon, pw); err != nil || !rehash {
		t.Errorf("an Argon2id hash under FIPS: rehash %v, %v; want it verified and moved to PBKDF2", rehash, err)
	}

	for name, imported := range map[string]string{
		"phpass (MD5)":             "$P$Babcdefghz3ByWd5584TNs0JQphRgs1",
		"Django with a short salt": "pbkdf2_sha256$260000$abcdefghijkl$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	} {
		if _, err := h.Verify(ctx, imported, pw); !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "reset the password") {
			t.Errorf("%s under FIPS: %v, want a refusal that says to reset", name, err)
		}
	}

	if _, err := (&BreachChecker{Online: true}).Breached(ctx, pw); !errors.Is(err, ErrUnavailable) {
		t.Errorf("the breach check under FIPS: %v, want ErrUnavailable", err)
	}
}
