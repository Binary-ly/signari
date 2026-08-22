package httpapi

import (
	"signari.dev/engine/internal/ratelimit"
	"testing"
)

// The JWKS rate limit must never throttle a real estate of relying parties.
//
// # Why this test exists
//
// The first version limited JWKS to 20 requests a second globally. The
// reasoning was sound -- a relying party that refetches whenever it sees an
// unknown `kid` is a free amplifier -- but the lever was wrong. JWKS is fetched
// by EVERY relying party, and they all refetch at once after a key rotation,
// which is precisely the moment throttling must not happen: a relying party
// that cannot fetch the key set cannot verify any token, so a throttle turns
// one rotation into an estate-wide outage.
//
// A benchmark found it. 597 of 640 concurrent requests came back 429. Nothing
// in the test suite noticed, because nothing sent more than one at a time.
//
// The fix was to make the response cheap -- precomputed, cached between
// rotations, ETagged so repeat fetchers get a 304 -- rather than to make the
// traffic small. What remains is an amplification backstop.

// A hundred relying parties refetching after a rotation is an ordinary event,
// not an attack. The burst capacity must absorb it without a single refusal.
func TestTheJWKSLimitAbsorbsAnEstateRefetching(t *testing.T) {
	const (
		// Deliberately conservative figures for "a large but unremarkable
		// deployment". If these ever exceed the bucket, the limit is throttling
		// customers rather than attackers.
		relyingParties  = 500
		instancesEachRP = 4
	)
	burst := float64(relyingParties * instancesEachRP)

	b := ratelimit.New(5000, 10000) // must match the server's configuration

	refused := 0
	for i := 0; i < int(burst); i++ {
		if !b.Allow() {
			refused++
		}
	}
	if refused > 0 {
		t.Fatalf("%d of %.0f simultaneous key-set fetches were refused. Every "+
			"relying party refetches after a key rotation, and one that cannot "+
			"fetch the key set cannot verify any token -- so this throttle turns "+
			"a rotation into an estate-wide outage", refused, burst)
	}
}

// The backstop must still exist. A limit removed entirely is an amplifier.
func TestTheJWKSLimitStillStopsAmplification(t *testing.T) {
	b := ratelimit.New(5000, 10000)
	// Drained until it refuses, rather than by a fixed count: the bucket refills
	// while the loop runs, so "consume exactly capacity" leaves a few tokens and
	// the assertion fails for a reason that has nothing to do with the limit.
	// Found by writing it the fixed-count way first.
	const ceiling = 200_000 // far beyond any real estate; a runaway guard
	refusedAt := -1
	for i := 0; i < ceiling; i++ {
		if !b.Allow() {
			refusedAt = i
			break
		}
	}
	if refusedAt < 0 {
		t.Fatal("the bucket never empties, so there is no amplification backstop " +
			"at all -- the limit has been removed rather than raised")
	}
	// And it must not refuse so early that ordinary traffic hits it. The estate
	// test covers the lower bound; this records that the two are far apart.
	if refusedAt < 10_000 {
		t.Fatalf("the bucket refused after only %d requests", refusedAt)
	}
}
