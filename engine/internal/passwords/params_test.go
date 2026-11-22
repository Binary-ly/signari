package passwords

import (
	"context"
	"crypto/fips140"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The hash's cost and pepper (4.08): set, bounded, named in each hash, and a
// change reaches a stored password at its next sign-in.

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func newPepperKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestTheHashCostAndPepperAreReadAndBounded(t *testing.T) {
	c, err := ConfigFromEnv(env(nil))
	if err != nil || c.Params != Floor || len(c.Peppers) != 0 {
		t.Fatalf("nothing set: %+v %v, want the floor and no pepper", c, err)
	}
	c, err = ConfigFromEnv(env(map[string]string{"SIGNARI_ARGON2_MEMORY_MIB": "64",
		"SIGNARI_ARGON2_ITERATIONS": "3", "SIGNARI_ARGON2_PARALLELISM": "2",
		"SIGNARI_PASSWORD_PEPPERS": "b:" + newPepperKey(t) + ",a:" + newPepperKey(t)}))
	if err != nil || c.Params != (Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2}) ||
		len(c.Peppers) != 2 || c.current().ID != "b" {
		t.Fatalf("set: %+v %v", c, err)
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	for name, e := range map[string]map[string]string{
		"memory below the floor":   {"SIGNARI_ARGON2_MEMORY_MIB": "8"},
		"memory above the ceiling": {"SIGNARI_ARGON2_MEMORY_MIB": "512"},
		"one iteration":            {"SIGNARI_ARGON2_ITERATIONS": "1"},
		"not a number":             {"SIGNARI_ARGON2_PARALLELISM": "two"},
		"a short pepper":           {"SIGNARI_PASSWORD_PEPPERS": "a:" + short},
		"a pepper without an id":   {"SIGNARI_PASSWORD_PEPPERS": newPepperKey(t)},
		"a pepper named twice": {"SIGNARI_PASSWORD_PEPPERS": "a:" + newPepperKey(t) +
			",a:" + newPepperKey(t)},
	} {
		if _, err := ConfigFromEnv(env(e)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestRaisingTheCostRehashesAtTheNextSignIn(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("under FIPS new passwords are PBKDF2; see TestThePepperUnderFIPS")
	}
	ctx := context.Background()
	const pw = "correct horse battery staple"
	old, err := NewHasher(0).Hash(ctx, pw)
	if err != nil {
		t.Fatal(err)
	}
	raised := NewHasherWith(0, &Config{Params: Params{MemoryKiB: 32 * 1024, Time: 3, Threads: 1}})
	rehash, err := raised.Verify(ctx, old, pw)
	if err != nil || !rehash {
		t.Fatalf("a hash at the floor under a raised cost: rehash %v, %v; want it to verify and ask", rehash, err)
	}
	fresh, err := raised.Hash(ctx, pw)
	if err != nil || !strings.Contains(fresh, "m=32768,t=3,p=1") {
		t.Fatalf("a new hash under the raised cost is %q (%v)", fresh, err)
	}
	if rehash, err := raised.Verify(ctx, fresh, pw); err != nil || rehash {
		t.Errorf("a hash at the raised cost: rehash %v, %v", rehash, err)
	}
	// Lowering it again does not rehash downwards.
	if rehash, err := NewHasher(0).Verify(ctx, fresh, pw); err != nil || rehash {
		t.Errorf("a stronger hash under the floor: rehash %v, %v", rehash, err)
	}
}

func TestThePepperIsNamedRotatedAndRequired(t *testing.T) {
	ctx := context.Background()
	const pw = "correct horse battery staple"
	keyA, keyB := newPepperKey(t), newPepperKey(t)
	cfg := func(spec string) *Config {
		c, err := ConfigFromEnv(env(map[string]string{"SIGNARI_PASSWORD_PEPPERS": spec}))
		if err != nil {
			t.Fatal(err)
		}
		return &c
	}
	withA := NewHasherWith(0, cfg("a:"+keyA))
	stored, err := withA.Hash(ctx, pw)
	if err != nil || PepperID(stored) != "a" {
		t.Fatalf("a hash under pepper a is %q (%v); it must name the pepper", stored, err)
	}
	if rehash, err := withA.Verify(ctx, stored, pw); err != nil || rehash {
		t.Errorf("verified under its own pepper: rehash %v, %v", rehash, err)
	}
	if _, err := withA.Verify(ctx, stored, pw+"x"); !errors.Is(err, ErrMismatch) {
		t.Errorf("the wrong password: %v", err)
	}

	// Rotated: b in front, a kept. It verifies, and asks to move to b.
	rotated := NewHasherWith(0, cfg("b:"+keyB+",a:"+keyA))
	if rehash, err := rotated.Verify(ctx, stored, pw); err != nil || !rehash {
		t.Errorf("a pepper-a hash after rotating to b: rehash %v, %v; want it to verify and ask", rehash, err)
	}
	// A hash with no pepper moves to one once one is set.
	plain, err := NewHasher(0).Hash(ctx, pw)
	if err != nil {
		t.Fatal(err)
	}
	if rehash, err := withA.Verify(ctx, plain, pw); err != nil || !rehash {
		t.Errorf("an unpeppered hash under a pepper: rehash %v, %v", rehash, err)
	}

	// The pepper is part of the hash: another key under the same id, or none
	// configured at all, does not verify it.
	if _, err := NewHasherWith(0, cfg("a:"+keyB)).Verify(ctx, stored, pw); !errors.Is(err, ErrMismatch) {
		t.Errorf("another key named a verified the hash: %v", err)
	}
	if _, err := NewHasher(0).Verify(ctx, stored, pw); !errors.Is(err, ErrMismatch) ||
		!strings.Contains(err.Error(), `pepper "a"`) {
		t.Errorf("with no pepper configured a peppered hash gave %v; want a mismatch naming the pepper", err)
	}
}

// The same rules for the PBKDF2 hashes made under FIPS.
func TestThePepperUnderFIPS(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestThePepperUnderFIPS$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	TestThePepperIsNamedRotatedAndRequired(t)
	stored, err := NewHasherWith(0, &Config{Params: Floor,
		Peppers: []Pepper{{ID: "a", Key: make([]byte, 32)}}}).Hash(context.Background(), "x")
	if err != nil || !strings.HasPrefix(stored, pbkdf2Prefix) || PepperID(stored) != "a" {
		t.Errorf("under FIPS a peppered hash is %q (%v)", stored, err)
	}
}

func TestAnImportedScryptHashMayNotAskForMoreThan256MiB(t *testing.T) {
	// ln=18, r=12: 128 × 2^18 × 12 bytes = 384 MiB, inside the format's
	// ceilings and the 512 MiB budget, so only this bound refuses it.
	if err := CostRefusal("$scrypt$ln=18,r=12,p=1$c2FsdA$aGFzaA"); err == nil {
		t.Error("an imported scrypt hash asking for 384 MiB was accepted")
	}
	// ln=17, r=8: 128 MiB.
	if err := CostRefusal("$scrypt$ln=17,r=8,p=1$c2FsdA$aGFzaA"); err != nil {
		t.Errorf("an ordinary scrypt import was refused: %v", err)
	}
}
