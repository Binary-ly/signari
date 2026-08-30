// Package passwords hashes and verifies passwords, including foreign hashes
// imported from another identity provider.
//
// Two things here are load-bearing and easy to miss.
//
// FIRST: concurrency is bounded. Argon2id at the OWASP minimum allocates 19 MiB
// per evaluation. A hundred simultaneous logins is ~1.9 GiB of transient
// allocation, and an unauthenticated flood against the login endpoint will OOM
// the process long before it exhausts CPU. Every deployment guide discusses the
// parameters; almost none mention that you must cap how many run at once. The
// semaphore below is the difference between a slow login page and a dead one.
//
// SECOND: foreign hashes verify in place and rehash lazily on success. Being able
// to import another provider's password hashes verbatim -- and upgrade them on
// first login without a password reset -- is the single biggest lever on
// migration cost, because the alternative is asking every user to reset.
package passwords

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/text/unicode/norm"
	"io"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// ErrMismatch means the password did not verify. It is deliberately the only
// failure a caller can distinguish, so nothing upstream can accidentally reveal
// whether an account exists or which algorithm it uses.
var ErrMismatch = errors.New("password does not match")

// Current OWASP Password Storage Cheat Sheet minimums for Argon2id.
// The alternative published tradeoff is m=47104, t=1, p=1; both give equivalent
// defence, trading CPU against RAM.
const (
	argonMemoryKiB = 19456 // 19 MiB
	argonTime      = 2
	argonThreads   = 1
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// Ceilings for cost parameters read out of an IMPORTED hash.
//
// Not a policy about how expensive a hash may be -- they are set far above any
// sane configuration. They bound what a foreign export can make this process do
// on the sign-in path, where the parameters are attacker-supplied in the only
// sense that matters: whoever produced the export chose them, and we verify
// against them on every attempt.
//
// 1 GiB and 16 rounds are roughly fifty times our own settings. A real export
// from any product never approaches them.
const (
	argonMaxMemoryKiB = 1 << 20 // 1 GiB
	argonMaxTime      = 16
	argonMaxThreads   = 16

	// Django's default is on the order of a million; ten million is generous and
	// still bounded. pbkdf2.Key is linear in this, so an unbounded value is a
	// direct multiplier on CPU per failed sign-in.
	pbkdf2MaxIterations = 10_000_000
)

// Hasher owns the concurrency budget for password hashing.
type Hasher struct {
	sem chan struct{}
}

// MemoryBudgetMiB is the default ceiling on concurrent Argon2 memory.
// Deliberately conservative: exceeding it degrades to queuing, which is
// recoverable, whereas exceeding available RAM is not.
const MemoryBudgetMiB = 512

// NewHasher builds a hasher whose concurrency is the smaller of the CPU count
// and what the memory budget allows.
func NewHasher(memoryBudgetMiB int) *Hasher {
	if memoryBudgetMiB <= 0 {
		memoryBudgetMiB = MemoryBudgetMiB
	}
	byMemory := memoryBudgetMiB * 1024 / argonMemoryKiB
	limit := runtime.GOMAXPROCS(0)
	if byMemory < limit {
		limit = byMemory
	}
	if limit < 1 {
		limit = 1
	}
	return &Hasher{sem: make(chan struct{}, limit)}
}

// Concurrency reports the cap, so it can be exported as a metric. Saturation
// here is the first sign of a login flood.
func (h *Hasher) Concurrency() int { return cap(h.sem) }

// acquire blocks for a slot, or returns the context's error. Callers pass a
// request context so a client that has already given up stops occupying budget.
func (h *Hasher) acquire(ctx context.Context) error {
	// Check cancellation FIRST. A bare select over both cases picks at random
	// when both are ready, so an already-abandoned request could still take a
	// free slot and spend 19 MiB plus CPU on an answer nobody will read. Under a
	// flood -- where clients time out constantly and slots churn -- that is
	// exactly when the budget matters most.
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash produces a PHC-format Argon2id string.

// Normalize applies NFC to a password before it becomes bytes.
//
// NIST SP 800-63B-4 §3.1.1.2: "the verifier SHOULD apply the normalization
// process for stabilized strings using the Normalization Form Canonical
// Composition (NFC) normalization... **This process is applied before hashing
// the byte string that represents the password.**"
//
// # Why it lives in the Hasher and not in the Policy
//
// It was first written inside Policy.Check, which takes the candidate BY VALUE:
// the local copy was normalised, the caller went on to hash the original, and
// the normalisation affected nothing that mattered. It looked like the SHOULD
// was implemented. That is the exact shape of defect this codebase keeps
// finding elsewhere, produced here by the fix for a different one.
//
// Hash and Verify are the only two places a password becomes bytes, so
// normalising here cannot be bypassed by a caller that does not know to.
//
// ASCII is unaffected -- NFC is the identity on it -- so existing hashes of
// ASCII passwords, which is nearly all of them, verify exactly as before.
func Normalize(password string) string { return norm.NFC.String(password) }

func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	password = Normalize(password)
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()

	salt := make([]byte, argonSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks a password against a stored hash in any supported format.
//
// It returns needsRehash when the stored hash is not current policy -- a foreign
// format, or Argon2id with weaker parameters. The caller rehashes and updates in
// the SAME transaction as the login, so a successful sign-in silently upgrades
// the credential.
func (h *Hasher) Verify(ctx context.Context, stored, password string) (needsRehash bool, err error) {
	password = Normalize(password)
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()

	switch {
	case strings.HasPrefix(stored, "$argon2id$"):
		current, err := verifyArgon2id(stored, password)
		if err != nil {
			return false, err
		}
		return !current, nil

	case strings.HasPrefix(stored, "$2a$"), strings.HasPrefix(stored, "$2b$"),
		strings.HasPrefix(stored, "$2y$"):
		// bcrypt silently truncates at 72 bytes. Never pre-hash an imported
		// bcrypt password: a hash from a system that did not pre-hash will never
		// verify if we do.
		if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)); err != nil {
			return false, ErrMismatch
		}
		return true, nil

	case strings.HasPrefix(stored, "pbkdf2_sha256$"):
		// Django's format, used by many Python providers.
		if err := verifyDjangoPBKDF2(stored, password); err != nil {
			return false, err
		}
		return true, nil

	// --- imported formats -------------------------------------------------
	// Each returns needsRehash=true unconditionally: a foreign hash is by
	// definition not current policy, so a successful sign-in upgrades it to
	// Argon2id in the same transaction. The foreign format is transitional.

	case strings.HasPrefix(stored, "$P$"), strings.HasPrefix(stored, "$H$"):
		// WordPress, phpBB, Drupal 7 -- the systems most in need of migrating off.
		if err := verifyPHPass(stored, password); err != nil {
			return false, err
		}
		return true, nil

	case strings.HasPrefix(stored, "$S$"):
		if err := verifyDrupal7(stored, password); err != nil {
			return false, err
		}
		return true, nil

	// NOT HANDLED: $5$ and $6$ (glibc SHA-crypt, used by /etc/shadow, FreeIPA and
	// most LDAP directories).
	//
	// An implementation was written and then removed, because it disagreed with
	// PHP's crypt(3) on real vectors. Shipping it would have been worse than
	// having nothing: every user imported from an LDAP directory would have been
	// told their password was wrong, with no indication that the fault was ours.
	//
	// It falls through to the default below and is refused, so such an import
	// fails loudly at sign-in rather than silently accepting anything. Finishing
	// it needs the glibc permutation table checked against published vectors --
	// see internal/passwords/foreign.go.

	case strings.HasPrefix(stored, "$keycloak$"):
		if err := verifyKeycloakPacked(stored, password); err != nil {
			return false, err
		}
		return true, nil

	case strings.HasPrefix(stored, "$scrypt$"):
		if err := verifyScrypt(stored, password); err != nil {
			return false, err
		}
		return true, nil

	default:
		// An unrecognised format is a mismatch, never a pass. Failing open on an
		// unknown prefix would turn a bad import into an authentication bypass.
		return false, ErrMismatch
	}
}

// verifyArgon2id reports whether the hash matched AND whether its parameters are
// current. Parameters are read from the stored string, never assumed, so hashes
// written under older settings still verify.
func verifyArgon2id(stored, password string) (current bool, err error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 {
		return false, ErrMismatch
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrMismatch
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, ErrMismatch
	}
	// Bounded, for the same reason scrypt is bounded in foreign.go: these numbers
	// arrive inside an imported hash, so whoever produced the export chooses them.
	// `m` is memory in KiB and reaches argon2.IDKey directly -- an import carrying
	// m=17179869184 asks for 16 TiB on the sign-in path, and the request that
	// triggers it is an ordinary failed password attempt against a migrated
	// account. That is a denial of service reachable through the migration
	// on-ramp, which is a feature we advertise.
	//
	// The ceilings are far above anything a real deployment configures -- ours is
	// m=19456, t=2, p=1 -- so a legitimate export is unaffected and only an
	// absurd one is refused.
	if m > argonMaxMemoryKiB || t > argonMaxTime || p > argonMaxThreads {
		return false, ErrMismatch
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrMismatch
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrMismatch
	}

	// #nosec G115 -- the length of a decoded Argon2 hash, bounded by the parser
	// that produced it at well under 2^32.
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, ErrMismatch
	}
	return m >= argonMemoryKiB && t >= argonTime, nil
}

// verifyDjangoPBKDF2 handles `pbkdf2_sha256$<iterations>$<salt>$<b64 hash>`.
func verifyDjangoPBKDF2(stored, password string) error {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 {
		return ErrMismatch
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 || iter > pbkdf2MaxIterations {
		return ErrMismatch
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return ErrMismatch
	}
	got := pbkdf2.Key([]byte(password), []byte(parts[2]), iter, len(want), sha256.New)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// SupportedPrefixes lists the import formats recognised today. Used by the
// migration tooling to report, per source system, what will transfer.
//
// This list UNDER-REPORTED for a while: it named five prefixes while Verify
// handled nine, so migration tooling told operators that phpass, Drupal 7,
// Keycloak and scrypt passwords would not transfer when they would. A reporting
// function that disagrees with the code it reports on is worse than none --
// somebody plans a password reset for users who never needed one.
//
// TestSupportedPrefixesMatchesVerify keeps the two in step.
func SupportedPrefixes() []string {
	return []string{
		"$argon2id$",
		"$2a$", "$2b$", "$2y$", // bcrypt
		"pbkdf2_sha256$", // Django, and therefore authentik
		"$P$", "$H$",     // phpass: WordPress, phpBB, Drupal 7
		"$S$", // Drupal 7 native
		"$keycloak$",
		"$scrypt$",
	}
}

// CanVerify reports whether a stored hash is one this engine can check.
//
// The question migration tooling actually asks, and the one an operator needs
// answered BEFORE importing rather than after: an account imported with a hash
// nothing can verify is an account nobody can sign in to.
func CanVerify(stored string) bool {
	for _, p := range SupportedPrefixes() {
		if strings.HasPrefix(stored, p) {
			return true
		}
	}
	return false
}
