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
)

// State is a key's position in the rotation machine.
type State string

const (
	StateNext    State = "next"
	StateActive  State = "active"
	StatePassive State = "passive"
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
	// PublishedAt drives the promotion and retirement dwell times.
	PublishedAt() time.Time
}

// softwareKey holds private material in process memory. It is the development
// and small-deployment implementation; PKCS#11 and cloud-KMS implementations
// satisfy the same interface without anything above this package changing.
type softwareKey struct {
	kid         string
	alg         Algorithm
	state       State
	signer      crypto.Signer
	publishedAt time.Time
}

func (k *softwareKey) KID() string            { return k.kid }
func (k *softwareKey) Algorithm() Algorithm   { return k.alg }
func (k *softwareKey) State() State           { return k.state }
func (k *softwareKey) Signer() crypto.Signer  { return k.signer }
func (k *softwareKey) PublishedAt() time.Time { return k.publishedAt }

func (k *softwareKey) PublicJWK() jose.JSONWebKey {
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
	return &softwareKey{kid: kid, alg: alg, state: state, signer: signer, publishedAt: publishedAt}, nil
}

// Generate creates fresh private material for alg. New keys always enter the set
// as StateNext -- never as active, because an unpublished key that signs
// immediately is precisely the rotation outage this package exists to prevent.
func Generate(kid string, alg Algorithm) (Key, error) {
	var (
		signer crypto.Signer
		err    error
	)
	switch alg {
	case RS256, PS256:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case ES256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EdDSA:
		_, priv, e := ed25519.GenerateKey(rand.Reader)
		signer, err = priv, e
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", alg, err)
	}
	return &softwareKey{
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
	switch alg {
	case RS256, PS256:
		if _, ok := signer.Public().(*rsa.PublicKey); !ok {
			return fmt.Errorf("algorithm %s requires an RSA key, got %T", alg, signer.Public())
		}
	case ES256:
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm ES256 requires an ECDSA key, got %T", signer.Public())
		}
		if pub.Curve != elliptic.P256() {
			return fmt.Errorf("algorithm ES256 requires curve P-256, got %s", pub.Curve.Params().Name)
		}
	case EdDSA:
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
	keys []Key
	now  func() time.Time
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
	out := make([]Key, len(s.keys))
	copy(out, s.keys)
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
	default:
		return nil, fmt.Errorf("unknown key state %q", state)
	}
	return NewSoftwareKey(k.KID(), k.Algorithm(), state, k.Signer(), k.PublishedAt())
}

// Active returns the key currently signing for alg.
func (s *Set) Active(alg Algorithm) (Key, error) {
	for _, k := range s.keys {
		if k.Algorithm() == alg && k.State() == StateActive {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no active key for algorithm %s", alg)
}

// ByKID finds any published key, whatever its state. Verification must accept
// passive keys -- that is the entire point of the passive state.
func (s *Set) ByKID(kid string) (Key, bool) {
	for _, k := range s.keys {
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
	out := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(s.keys))}
	for _, k := range s.keys {
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
	for _, k := range s.keys {
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
