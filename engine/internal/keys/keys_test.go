package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

func mustGen(t *testing.T, kid string, alg Algorithm) Key {
	t.Helper()
	k, err := Generate(kid, alg)
	if err != nil {
		t.Fatalf("Generate(%s): %v", alg, err)
	}
	return k
}

func withState(t *testing.T, k Key, s State, published time.Time) Key {
	t.Helper()
	out, err := NewSoftwareKey(k.KID(), k.Algorithm(), s, k.Signer(), published)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGenerateAllAlgorithms(t *testing.T) {
	for _, alg := range []Algorithm{RS256, ES256, EdDSA, PS256} {
		k := mustGen(t, "k-"+string(alg), alg)
		if k.Algorithm() != alg {
			t.Errorf("Algorithm() = %s, want %s", k.Algorithm(), alg)
		}
		// A newly generated key must never be able to sign immediately.
		if k.State() != StateNext {
			t.Errorf("%s: new key state = %s, want %s", alg, k.State(), StateNext)
		}
		jwk := k.PublicJWK()
		if jwk.KeyID != k.KID() || jwk.Use != "sig" {
			t.Errorf("%s: bad JWK: kid=%q use=%q", alg, jwk.KeyID, jwk.Use)
		}
		if jwk.IsPublic() != true {
			t.Errorf("%s: PublicJWK leaked private material", alg)
		}
	}
}

func TestGenerateRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := Generate("k", Algorithm("HS256")); err == nil {
		t.Fatal("expected HS256 to be rejected: symmetric algorithms have no place in a JWKS")
	}
}

// Pinning algorithm to key type at construction is the first line of defence
// against the algorithm-confusion CVE class.
func TestKeyTypeMustMatchAlgorithm(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if _, err := NewSoftwareKey("k", ES256, StateActive, rsaKey, time.Now()); err == nil {
		t.Error("ES256 accepted an RSA key")
	}
	if _, err := NewSoftwareKey("k", RS256, StateActive, ecKey, time.Now()); err == nil {
		t.Error("RS256 accepted an ECDSA key")
	}
	if _, err := NewSoftwareKey("k", EdDSA, StateActive, ecKey, time.Now()); err == nil {
		t.Error("EdDSA accepted an ECDSA key")
	}
	// ES256 is P-256 specifically. A P-384 key is still ECDSA and would otherwise
	// slip through a naive type check.
	if _, err := NewSoftwareKey("k", ES256, StateActive, p384, time.Now()); err == nil {
		t.Error("ES256 accepted a P-384 key")
	} else if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("P-384 rejection should name the curve, got: %v", err)
	}
}

func TestSetRejectsTwoActiveKeysForOneAlgorithm(t *testing.T) {
	a := withState(t, mustGen(t, "a", ES256), StateActive, time.Now())
	b := withState(t, mustGen(t, "b", ES256), StateActive, time.Now())
	_, err := NewSet(a, b)
	if err == nil {
		t.Fatal("expected two active ES256 keys to be rejected")
	}
	if !strings.Contains(err.Error(), "two active keys") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// Two active keys for *different* algorithms is the normal steady state:
// ES256 default, RS256 always available as the universal floor.
func TestSetAllowsOneActivePerAlgorithm(t *testing.T) {
	es := withState(t, mustGen(t, "es", ES256), StateActive, time.Now())
	rs := withState(t, mustGen(t, "rs", RS256), StateActive, time.Now())
	s, err := NewSet(es, rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Algorithms()) != 2 {
		t.Errorf("Algorithms() = %v, want both ES256 and RS256", s.Algorithms())
	}
}

func TestSetRejectsDuplicateKID(t *testing.T) {
	a := withState(t, mustGen(t, "same", ES256), StateActive, time.Now())
	b := withState(t, mustGen(t, "same", RS256), StatePassive, time.Now())
	if _, err := NewSet(a, b); err == nil {
		t.Fatal("expected duplicate kid to be rejected")
	}
}

// The JWKS must publish next and passive keys too: `next` so relying parties
// cache it before it signs, `passive` so already-issued tokens still verify.
func TestJWKSPublishesAllThreeStates(t *testing.T) {
	next := withState(t, mustGen(t, "n", ES256), StateNext, time.Now())
	act := withState(t, mustGen(t, "a", ES256), StateActive, time.Now())
	pass := withState(t, mustGen(t, "p", ES256), StatePassive, time.Now())

	s, err := NewSet(next, act, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s.JWKS().Keys); got != 3 {
		t.Fatalf("JWKS has %d keys, want 3 (next, active, passive)", got)
	}
	for _, jwk := range s.JWKS().Keys {
		if !jwk.IsPublic() {
			t.Fatalf("kid %q published private material", jwk.KeyID)
		}
	}
	// Only the active key signs.
	got, err := s.Active(ES256)
	if err != nil {
		t.Fatal(err)
	}
	if got.KID() != "a" {
		t.Errorf("Active() = %q, want %q", got.KID(), "a")
	}
	// But verification must still resolve a passive key by kid.
	if _, ok := s.ByKID("p"); !ok {
		t.Error("passive key not resolvable by kid; tokens signed before rotation would fail")
	}
}

func TestActiveErrorsWhenNoKeyForAlgorithm(t *testing.T) {
	s, err := NewSet(withState(t, mustGen(t, "es", ES256), StateActive, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Active(RS256); err == nil {
		t.Fatal("expected an error for an algorithm with no active key")
	}
}

// Advertising an algorithm the server cannot actually sign with is the classic
// OIDF Config OP failure: metadata claiming something the server does not honour.
func TestAlgorithmsOnlyReportsActive(t *testing.T) {
	s, err := NewSet(
		withState(t, mustGen(t, "a", ES256), StateActive, time.Now()),
		withState(t, mustGen(t, "n", RS256), StateNext, time.Now()),
	)
	if err != nil {
		t.Fatal(err)
	}
	algs := s.Algorithms()
	if len(algs) != 1 || algs[0] != ES256 {
		t.Errorf("Algorithms() = %v; a `next` key must not be advertised as signable", algs)
	}
}

func TestCanPromoteEnforcesPublicationDwell(t *testing.T) {
	fresh := withState(t, mustGen(t, "n", ES256), StateNext, time.Now())
	old := withState(t, mustGen(t, "o", RS256), StateNext,
		time.Now().Add(-MinPublishBeforeActive-time.Minute))

	s, err := NewSet(fresh, old)
	if err != nil {
		t.Fatal(err)
	}

	if ok, wait := s.CanPromote(fresh); ok {
		t.Error("a just-published key was promotable; rotation would break RPs with cached JWKS")
	} else if wait <= 0 {
		t.Error("expected a positive remaining wait")
	}

	if ok, _ := s.CanPromote(old); !ok {
		t.Error("a key published beyond the dwell time should be promotable")
	}

	// An already-active key is not a promotion candidate.
	act := withState(t, mustGen(t, "a", EdDSA), StateActive, time.Now().Add(-48*time.Hour))
	s2, _ := NewSet(act)
	if ok, _ := s2.CanPromote(act); ok {
		t.Error("an active key should not be promotable")
	}
}
