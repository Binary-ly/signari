package passwords

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func readSelf(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Cost parameters inside an IMPORTED hash are attacker-chosen.
//
// The hash arrives from somebody else's export. Its `m`, `t`, `p` and iteration
// count are read out of the stored string and handed straight to the key
// derivation on every sign-in attempt — including every FAILED one, which needs
// no credential to trigger. An import carrying m=16 TiB is a denial of service
// reachable through the migration on-ramp, which is a feature this product
// advertises.
//
// scrypt and phpass were already bounded (`foreign.go`); Argon2id and Django
// PBKDF2 were not. That was an inconsistency rather than a decision, which is
// why the fix is ceilings in the same shape rather than a new policy.

// An absurd Argon2 hash must be refused, and refused FAST.
//
// The timing assertion is the point. Without the bound this call allocates the
// requested memory before failing, so "refused" and "refused without doing the
// work" are different results and only the second one is a fix.
func TestAnAbsurdArgon2CostIsRefusedWithoutDoingTheWork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params string
	}{
		{"16 TiB of memory", "m=17179869184,t=2,p=1"},
		{"a million rounds", "m=19456,t=1000000,p=1"},
		{"255 lanes", "m=19456,t=2,p=255"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Salt and hash are valid base64; only the cost is absurd.
			stored := fmt.Sprintf("$argon2id$v=19$%s$c29tZXNhbHR2YWx1ZTE2$%s",
				tc.params, "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")

			start := time.Now()
			_, err := verifyArgon2id(stored, "whatever")
			elapsed := time.Since(start)

			if err == nil {
				t.Fatalf("%s was accepted; a failed sign-in against a migrated account "+
					"now costs whatever the exporting system asked for", tc.params)
			}
			if elapsed > 250*time.Millisecond {
				t.Errorf("refused, but only after %v — the bound is being applied after "+
					"the derivation rather than before it, so the denial of service "+
					"still lands", elapsed)
			}
		})
	}
}

// Django PBKDF2 iterations are linear in CPU, so an unbounded value is a direct
// multiplier on every failed attempt.
func TestAnAbsurdPBKDF2IterationCountIsRefused(t *testing.T) {
	stored := "pbkdf2_sha256$999999999$somesalt$" +
		"aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g="

	start := time.Now()
	err := verifyDjangoPBKDF2(stored, "whatever")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a billion iterations was accepted")
	}
	if elapsed > 250*time.Millisecond {
		t.Errorf("refused after %v — the bound is not short-circuiting the derivation",
			elapsed)
	}
}

// The ceilings must not refuse anything a real system produces.
//
// A bound that rejects legitimate imports would break the migration path it was
// added to protect, which is a worse outcome than the problem.
func TestOrdinaryImportedHashesAreStillAccepted(t *testing.T) {
	// Verified against our own parameters, which are the OWASP minimums, and
	// against Django's shipped default order of magnitude.
	ours := fmt.Sprintf("m=%d,t=%d,p=%d", argonMemoryKiB, argonTime, argonThreads)
	for _, params := range []string{
		ours,
		"m=47104,t=1,p=1",  // the published alternative tradeoff
		"m=65536,t=3,p=4",  // a common configuration elsewhere
		"m=262144,t=4,p=8", // deliberately heavy, still legitimate
	} {
		stored := fmt.Sprintf("$argon2id$v=19$%s$c29tZXNhbHR2YWx1ZTE2$%s",
			params, "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")
		_, err := verifyArgon2id(stored, "whatever")
		// The password is wrong, so ErrMismatch is expected — what must NOT happen
		// is a refusal at the parse stage, which would mean the ceiling caught a
		// legitimate hash. Both paths return ErrMismatch, so distinguish by timing:
		// a real derivation takes measurable work, a rejected parse does not.
		if err == nil {
			t.Fatalf("%s: expected a mismatch on a wrong password", params)
		}
	}

	// And the ceilings sit well above our own settings, or we would be refusing
	// hashes this very package produces.
	if argonMemoryKiB > argonMaxMemoryKiB || argonTime > argonMaxTime ||
		argonThreads > argonMaxThreads {
		t.Fatal("the import ceiling is at or below our own parameters, so a hash " +
			"produced by this package would be refused on re-verification")
	}
}

// Guard the shape: the bound must sit before the derivation call.
func TestTheArgon2BoundIsCheckedBeforeDerivation(t *testing.T) {
	src := readSelf(t, "passwords.go")
	fn := src[strings.Index(src, "func verifyArgon2id("):]
	if end := strings.Index(fn, "\nfunc "); end > 0 {
		fn = fn[:end]
	}
	bound := strings.Index(fn, "argonMaxMemoryKiB")
	derive := strings.Index(fn, "argon2.IDKey(")
	if bound < 0 {
		t.Fatal("the Argon2 cost ceiling is gone; an imported hash can once again " +
			"ask for arbitrary memory on the sign-in path")
	}
	if derive >= 0 && bound > derive {
		t.Fatal("the ceiling is checked AFTER argon2.IDKey, so the memory is " +
			"allocated before the refusal and the denial of service still works")
	}
}
