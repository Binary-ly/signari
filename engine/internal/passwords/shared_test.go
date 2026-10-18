package passwords

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The memory ceiling belonged to each Hasher and Hashers were built per
// request, so the ceiling was per request. And one evaluation took one slot
// sized for our own Argon2 cost, whatever the stored hash declared.

func TestThereIsOneHasherPerProcess(t *testing.T) {
	if Shared() != Shared() {
		t.Fatal("Shared returned two hashers, so there are two budgets")
	}
}

func TestAnImportedHashIsChargedTheMemoryItDeclares(t *testing.T) {
	for stored, want := range map[string]int64{
		"$argon2id$v=19$m=262144,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g": 262144,
		"$scrypt$ln=15,r=8,p=1$c2FsdA$aGFzaA":                     32768, // 128·2^15·8 bytes
		"$2b$10$abcdefghijklmnopqrstuv":                           argonMemoryKiB,
		"pbkdf2_sha256$600000$salt$hash":                          argonMemoryKiB,
	} {
		if got := memoryKiB(stored); got != want {
			t.Errorf("memoryKiB(%.24s...) = %d KiB, want %d", stored, got, want)
		}
	}
}

func TestTheMemoryBudgetIsSharedAndHonest(t *testing.T) {
	h := NewHasher(64) // 64 MiB
	const forty = 40 * 1024

	if err := h.acquire(context.Background(), forty); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := h.acquire(ctx, forty); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a second 40 MiB evaluation against a 64 MiB budget gave %v; it should "+
			"have waited, because together they exceed what the budget allows", err)
	}
	h.release(forty)
	if err := h.acquire(context.Background(), forty); err != nil {
		t.Fatalf("after the release the budget did not come back: %v", err)
	}
	h.release(forty)

	err := h.acquire(context.Background(), 70*1024)
	if !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "MiB") {
		t.Fatalf("a hash needing more than the whole budget gave %v; it can never fit, and "+
			"must be refused rather than run outside the budget or left waiting", err)
	}
}

// Nothing outside this package builds its own Hasher.
func TestNoPathBuildsItsOwnHasher(t *testing.T) {
	root := filepath.Join("..", "..")
	found := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "internal/passwords/") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "passwords.NewHasher(") {
			t.Errorf("%s builds its own Hasher. Use passwords.Shared(): a Hasher of its own "+
				"has a memory budget of its own, so the process's ceiling stops being one", path)
		}
		if strings.Contains(string(b), "passwords.Shared()") {
			found++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 5 {
		t.Fatalf("only %d files use passwords.Shared(), so this walk is not reading the engine", found)
	}
}
