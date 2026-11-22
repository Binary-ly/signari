// Package keys is the engine's signing-key layer.
//
// ADR-009: nothing outside this package ever handles a *rsa.PrivateKey or
// *ecdsa.PrivateKey. Everything is a Key, whose private half is reachable only as
// a crypto.Signer. Because crypto.Signer is already the right abstraction, a
// software key, a PKCS#11 token and a cloud KMS are all just implementations --
// products that skip this end up shipping HSM support as a fork.
//
// The rotation state machine, and why the timings are what they are:
//
//	next  --promote-->  active  --demote-->  passive  --retire-->  removed
//	(published,          (published,          (published,           (gone)
//	 not signing)         signing)             verify only)
//
// All three published states appear in the JWKS. Publication timing is dictated
// by the slowest relying party's JWKS cache, not by us: an RP that caches the key
// set and does not refresh on an unknown `kid` will reject tokens signed with a
// key it has never seen. So a key must be visible in the JWKS for a full cache
// lifetime BEFORE it signs anything, and a demoted key must stay published until
// every token it signed has expired.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Algorithm is a JWS signing algorithm we are willing to issue with.
type Algorithm string

const (
	// RS256 is the universal floor. OIDC Core requires it and every relying-party
	// library supports it, so it is always advertised even when it is not default.
	RS256 Algorithm = "RS256"
	// ES256 is the default for new clients: broadly supported, smaller, faster.
	ES256 Algorithm = "ES256"
	// EdDSA is cryptographically the nicest and the worst default. RP support is
	// patchy and the failure is silent and total -- the RP simply cannot verify.
	// Opt-in per client only.
	EdDSA Algorithm = "EdDSA"
	// PS256 is for FAPI profiles.
	PS256 Algorithm = "PS256"
	// The longer hashes are for a relying party or a policy that asks for them.
	// Nothing here signs with one until an operator publishes a key for it.
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
)

// AllAlgorithms is every algorithm a key may be made for, the schema's CHECK on
// core.signing_keys. No symmetric algorithm, ever.
var AllAlgorithms = []Algorithm{ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA}

// isRSA reports the algorithms an RSA key signs.
func isRSA(alg Algorithm) bool {
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
		return true
	}
	return false
}

// curveFor is the one curve each ECDSA algorithm may use, or nil for an
// algorithm that is not ECDSA. RFC 7518 pairs them, and a P-256 key under ES384
// is a key that does not give what its name says.
func curveFor(alg Algorithm) elliptic.Curve {
	switch alg {
	case ES256:
		return elliptic.P256()
	case ES384:
		return elliptic.P384()
	case ES512:
		return elliptic.P521()
	}
	return nil
}

// State is a key's position in the rotation machine.
type State string

const (
	StateNext    State = "next"
	StateActive  State = "active"
	StatePassive State = "passive"
	// StateRetired is a key that has left the JWKS. It is not loaded into a Set
	// and never appears in a published key set, so nothing here can sign or
	// verify with it; the row survives only so an operator can answer "when did
	// this kid stop being served?".
	StateRetired State = "retired"
)

// Timing defaults. These are security parameters with names, not magic numbers.
const (
	// MinPublishBeforeActive is how long a key must be visible in the JWKS before
	// it may sign. Derived from the worst observed RP behaviour (caches measured
	// in the wild range from ~10 minutes to 24 hours, and some fetch only at
	// boot), not from the average.
	MinPublishBeforeActive = 24 * time.Hour

	// MinPassiveBeforeRetire is how long a demoted key stays published. Must
	// exceed the longest lifetime of any token it signed.
	MinPassiveBeforeRetire = 24 * time.Hour

	// JWKSMaxAge is the Cache-Control max-age we serve on the JWKS endpoint so
	// well-behaved clients converge in minutes. Never assume it is honoured.
	JWKSMaxAge = 10 * time.Minute
)

// Key is a signing key. The private half is never exposed as a concrete type.
type Key interface {
	KID() string
	Algorithm() Algorithm
	State() State
	// Signer is the private half. For a KMS- or HSM-backed key this performs a
	// remote or in-token signature; the private material never leaves.
	Signer() crypto.Signer
	// PublicJWK is what is published in the JWKS.
	PublicJWK() jose.JSONWebKey
	// PublishedAt drives the promotion dwell time.
	PublishedAt() time.Time
	// DemotedAt is when the key left active service, and drives the retirement
	// dwell. Zero means it has never been demoted.
	//
	// Separate from PublishedAt because the two clocks measure different things
	// and an earlier comment here conflated them. Retirement measured from
	// publication would retire a key the instant it was demoted -- a key
	// published in January and demoted in June is long past any publication
	// dwell, so the check would pass immediately and the passive window,
	// the entire point of the state, would be zero.
	DemotedAt() time.Time
}

// signingKey is a key with its signer: private material in process memory,
// sealed under the root key when stored, or a key a Backend holds, which this
// process asks to sign (backend.go). Nothing above this package can tell the
// two apart.
type signingKey struct {
	kid         string
	alg         Algorithm
	state       State
	signer      crypto.Signer
	publishedAt time.Time
	demotedAt   time.Time
	// held is the key_ref of a key a Backend holds, empty for one whose
	// material is here.
	held string
}

func (k *signingKey) KID() string            { return k.kid }
func (k *signingKey) Algorithm() Algorithm   { return k.alg }
func (k *signingKey) State() State           { return k.state }
func (k *signingKey) Signer() crypto.Signer  { return k.signer }
func (k *signingKey) PublishedAt() time.Time { return k.publishedAt }
func (k *signingKey) DemotedAt() time.Time   { return k.demotedAt }

func (k *signingKey) PublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       k.signer.Public(),
		KeyID:     k.kid,
		Algorithm: string(k.alg),
		Use:       "sig",
	}
}

// NewSoftwareKey wraps an existing signer. Used when loading key material back
// out of the database or a secret store.
func NewSoftwareKey(kid string, alg Algorithm, state State, signer crypto.Signer, publishedAt time.Time) (Key, error) {
	if err := checkSignerMatchesAlg(alg, signer); err != nil {
		return nil, err
	}
	return &signingKey{kid: kid, alg: alg, state: state, signer: signer, publishedAt: publishedAt}, nil
}

// Generate creates fresh private material for alg. New keys always enter the set
// as StateNext -- never as active, because an unpublished key that signs
// immediately is precisely the rotation outage this package exists to prevent.
// RSABits is the modulus size for RSA keys this server GENERATES.
//
// ASVS 5.0.0 V11.2.3: "Verify that all cryptographic primitives utilize a minimum
// of 128-bits of security based on the algorithm, key size, and configuration.
// For example, a 256-bit ECC key provides roughly 128 bits of security where RSA
// requires a 3072-bit key to achieve the same."
//
// This was 2048, which is roughly 112 bits — the NIST floor for "acceptable
// until 2030", not the 128-bit floor ASVS asks for. P-256 is the default
// algorithm here and already meets it; RS256 exists for clients whose libraries
// do only RSA, and those clients were being handed the weaker key.
//
// # Why raising this is free and raising the ACCEPT floor is not
//
// These are two different numbers and they are pulled in opposite directions by
// two standards we follow.
//
// What we generate is entirely our choice. Clients fetch the modulus from our
// JWKS and verify with whatever we publish; RSA verification is size-agnostic in
// every mainstream library, and the cost is a few hundred microseconds on a path
// that is not hot. Nothing breaks.
//
// What we ACCEPT from a client stays at 2048 — clientauth.MinRSABits — because
// FAPI 2.0 §5.4.1 sets that floor and most clients hold 2048-bit keys. Raising it
// would refuse working integrations to gain 16 bits of security in somebody
// else's key, and the client is the party bearing that risk.
//
// So: strict about our own key, conventional about theirs. The asymmetry is the
// point rather than an inconsistency.
const RSABits = 3072

// MinRSABits is the smallest key this server will make or load. A deployment
// asks for it by name, for a relying party whose library stops at 2048 (`keys
// rotate -rsa-bits 2048`): RSABits above is the default and stays it, and
// `signari doctor` says so of a key below it for as long as there is one.
const MinRSABits = 2048

// RSASizes are the moduli an operator may ask for.
var RSASizes = []int{MinRSABits, RSABits, 4096}

func Generate(kid string, alg Algorithm) (Key, error) {
	return generate(kid, alg, RSABits)
}

// GenerateSized is Generate at a modulus an operator chose.
func GenerateSized(kid string, alg Algorithm, bits int) (Key, error) {
	if err := sizable(alg, bits); err != nil {
		return nil, err
	}
	return generate(kid, alg, bits)
}

func sizable(alg Algorithm, bits int) error {
	if !isRSA(alg) {
		return fmt.Errorf("%s has no modulus to size", alg)
	}
	if !slices.Contains(RSASizes, bits) {
		return fmt.Errorf("an RSA key is one of %v bits, not %d", RSASizes, bits)
	}
	return nil
}

// Successor makes the key that takes over from k. An operator who chose a size
// chose it for a relying party, and a rotation nobody is watching must not
// change it behind them.
func Successor(kid string, k Key) (Key, error) {
	return generate(kid, k.Algorithm(), successorBits(k))
}

func successorBits(k Key) int {
	if pub, ok := k.Signer().Public().(*rsa.PublicKey); ok && slices.Contains(RSASizes, pub.N.BitLen()) {
		return pub.N.BitLen()
	}
	return RSABits
}

func generate(kid string, alg Algorithm, rsaBits int) (Key, error) {
	var (
		signer crypto.Signer
		err    error
	)
	switch {
	case isRSA(alg):
		signer, err = rsa.GenerateKey(rand.Reader, rsaBits)
	case curveFor(alg) != nil:
		signer, err = ecdsa.GenerateKey(curveFor(alg), rand.Reader)
	case alg == EdDSA:
		_, priv, e := ed25519.GenerateKey(rand.Reader)
		signer, err = priv, e
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", alg, err)
	}
	return &signingKey{
		kid:         kid,
		alg:         alg,
		state:       StateNext,
		signer:      signer,
		publishedAt: time.Now().UTC(),
	}, nil
}

// checkSignerMatchesAlg refuses a key whose type cannot produce the declared
// algorithm. Algorithm confusion -- verifying an RS256 token as HS256, or trusting
// the token's own `alg` header to pick the method -- is a recurring JWT CVE class,
// and the defence starts by pinning algorithm to key at construction.
func checkSignerMatchesAlg(alg Algorithm, signer crypto.Signer) error {
	switch {
	case isRSA(alg):
		pub, ok := signer.Public().(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %s requires an RSA key, got %T", alg, signer.Public())
		}
		if n := pub.N.BitLen(); n < MinRSABits {
			return fmt.Errorf("algorithm %s requires at least %d bits, got %d", alg, MinRSABits, n)
		}
	case curveFor(alg) != nil:
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %s requires an ECDSA key, got %T", alg, signer.Public())
		}
		if want := curveFor(alg); pub.Curve != want {
			return fmt.Errorf("algorithm %s requires curve %s, got %s", alg, want.Params().Name,
				pub.Curve.Params().Name)
		}
	case alg == EdDSA:
		if _, ok := signer.Public().(ed25519.PublicKey); !ok {
			return fmt.Errorf("algorithm EdDSA requires an Ed25519 key, got %T", signer.Public())
		}
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
	return nil
}

// Set is the engine's live view of its keys for one instance.
type Set struct {
	// mu guards keys, which is REPLACED while requests are in flight.
	//
	// A set read once at startup and never again defeated the whole rotation
	// design. Rotation publishes a `next` key first so relying parties cache it
	// before anything is signed with it, then promotes it a day later. With no
	// reload, running instances never published the new key at all -- so the
	// waiting period protected nothing, and after a restart they would begin
	// signing with a key no relying party had ever seen.
	//
	// Found by rotating against two running instances and reading their JWKS:
	// the new kid was in the database and in neither response.
	mu   sync.RWMutex
	keys []Key
	now  func() time.Time
}

// Replace swaps the keys this set serves.
//
// The set is shared by every request in flight, so the swap is behind a lock
// rather than by handing out a new pointer: call sites hold the *Set itself,
// and asking each of them to re-read an indirection is a rule that will be
// broken exactly once.
//
// The replacement is VALIDATED first, by building a candidate set. A reload
// that found two active keys for one algorithm, or a duplicate kid, must not
// replace a good set with a bad one -- the running configuration is the one
// thing known to work.
func (s *Set) Replace(next ...Key) error {
	candidate, err := NewSet(next...)
	if err != nil {
		return fmt.Errorf("refusing to load an unsafe key set: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = candidate.keys
	return nil
}

// snapshot returns the current keys under a read lock.
func (s *Set) snapshot() []Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys
}

// NewSet builds a key set, rejecting any arrangement that would be unsafe to
// serve: more than one active key per algorithm, or a duplicate kid.
func NewSet(keys ...Key) (*Set, error) {
	s := &Set{keys: keys, now: func() time.Time { return time.Now().UTC() }}
	seen := make(map[string]struct{}, len(keys))
	active := make(map[Algorithm]string)
	for _, k := range keys {
		if _, dup := seen[k.KID()]; dup {
			return nil, fmt.Errorf("duplicate kid %q", k.KID())
		}
		seen[k.KID()] = struct{}{}
		if k.State() == StateActive {
			if prev, ok := active[k.Algorithm()]; ok {
				return nil, fmt.Errorf(
					"two active keys for %s (%q and %q): signing would be non-deterministic",
					k.Algorithm(), prev, k.KID())
			}
			active[k.Algorithm()] = k.KID()
		}
	}
	return s, nil
}

// Keys returns every published key, whatever its state.
//
// A copy, so a caller building a rotation cannot mutate the live set out from
// under the server that is signing with it.
func (s *Set) Keys() []Key {
	// ONE snapshot, not two. Taking it twice takes the lock twice, and a
	// replacement landing between them would size the slice from one set and
	// fill it from another.
	cur := s.snapshot()
	out := make([]Key, len(cur))
	copy(out, cur)
	return out
}

// WithState returns k in a different state, for persisting a rotation step.
//
// PublishedAt is carried over unchanged, and that is the important part: it is
// what every dwell-time calculation is measured from. Re-stamping it on promotion
// would restart the clock and make the "published long enough" guarantee
// unfalsifiable -- the key would always look freshly published.
func WithState(k Key, state State) (Key, error) {
	switch state {
	case StateNext, StateActive, StatePassive:
	case StateRetired:
		// Retirement does not go through here. A retired key is not a member of
		// any Set -- LoadSetFor does not read one -- so producing a Key in that
		// state would only create something whose only correct use is never to
		// be used. Retire persists the state directly.
		return nil, fmt.Errorf("retirement is not a Set transition; use keys.Retire")
	default:
		return nil, fmt.Errorf("unknown key state %q", state)
	}
	out, err := NewSoftwareKey(k.KID(), k.Algorithm(), state, k.Signer(), k.PublishedAt())
	if err != nil {
		return nil, err
	}
	// A key a module holds stays there. Dropped, a promotion would have Save
	// seal the signer as if it were material, which it is not, and refuse.
	if sk, ok := k.(*signingKey); ok {
		out.(*signingKey).held = sk.held
	}
	// Carry the demotion stamp across the transition. Dropping it would silently
	// reset the retirement clock, and it would reset it in the safe-looking
	// direction: a zero stamp reads as "never demoted", which CanRetire refuses.
	// The bug would therefore be invisible -- keys would simply never retire.
	return withDemotedAt(out, k.DemotedAt()), nil
}

// withDemotedAt returns k carrying a demotion stamp.
func withDemotedAt(k Key, at time.Time) Key {
	sk := k.(*signingKey)
	sk.demotedAt = at
	return sk
}

// Active returns the key currently signing for alg.
func (s *Set) Active(alg Algorithm) (Key, error) {
	for _, k := range s.snapshot() {
		if k.Algorithm() == alg && k.State() == StateActive {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no active key for algorithm %s", alg)
}

// ByKID finds any published key, whatever its state. Verification must accept
// passive keys -- that is the entire point of the passive state.
func (s *Set) ByKID(kid string) (Key, bool) {
	for _, k := range s.snapshot() {
		if k.KID() == kid {
			return k, true
		}
	}
	return nil, false
}

// JWKS is the public key set to publish. It includes next, active and passive:
// next so relying parties have it cached before it signs anything, passive so
// tokens signed before the last rotation still verify.
func (s *Set) JWKS() jose.JSONWebKeySet {
	cur := s.snapshot()
	out := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(cur))}
	for _, k := range cur {
		out.Keys = append(out.Keys, k.PublicJWK())
	}
	return out
}

// Algorithms lists what this set can actually sign with, for the discovery
// document's id_token_signing_alg_values_supported.
//
// Advertising an algorithm with no active key is the single most common reason
// implementations fail OIDF Config OP certification: the metadata claims
// something the server does not honour.
func (s *Set) Algorithms() []Algorithm {
	seen := map[Algorithm]bool{}
	var out []Algorithm
	for _, k := range s.snapshot() {
		if k.State() == StateActive && !seen[k.Algorithm()] {
			seen[k.Algorithm()] = true
			out = append(out, k.Algorithm())
		}
	}
	return out
}

// CanPromote reports whether a `next` key has been published long enough to start
// signing. Promoting early is how a rotation becomes an outage.
func (s *Set) CanPromote(k Key) (bool, time.Duration) {
	if k.State() != StateNext {
		return false, 0
	}
	elapsed := s.now().Sub(k.PublishedAt())
	if elapsed >= MinPublishBeforeActive {
		return true, 0
	}
	return false, MinPublishBeforeActive - elapsed
}

// CanRetire reports whether a passive key has been out of service long enough to
// leave the JWKS, and how long remains if not.
//
// `dwell` is passed in rather than read from MinPassiveBeforeRetire because that
// constant is a floor, not the answer. A verifiable credential is signed with the
// same key and its lifetime is operator-configured with no ceiling, so the real
// dwell is the longest lifetime anything signed by this key can still have. See
// RequiredPassiveDwell, which computes it, and the doctor check that reports the
// configurations driving it.
//
// The comparison is >=, matching the exclusive boundary the doctor already
// documents: the window starts at demotion and Set.Active hands out only active
// keys, so a demoted key never signs again. Anything it signed at time T <= D
// expires by D+dwell, and at exactly D+dwell the key was still published at every
// instant that token was valid.
func (s *Set) CanRetire(k Key, dwell time.Duration) (bool, time.Duration) {
	if k.State() != StatePassive {
		return false, 0
	}
	// A passive key with no demotion stamp is refused rather than treated as
	// demoted at the zero time, which would make it instantly retirable -- the
	// exact inversion that turns a missing timestamp into a deleted key. Rows
	// written before demoted_at was populated land here, and so does any key
	// demoted in memory but not yet reloaded from the database that stamps it.
	if k.DemotedAt().IsZero() {
		return false, 0
	}
	elapsed := s.now().Sub(k.DemotedAt())
	if elapsed >= dwell {
		return true, 0
	}
	return false, dwell - elapsed
}
