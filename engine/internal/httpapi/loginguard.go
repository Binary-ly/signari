package httpapi

import (
	"math"
	"sync"
	"time"

	"signari.dev/engine/internal/passwords"
)

// The sign-in guard's rate (E.28), sized from this machine. The guard is the cheap
// in-process bucket in front of the keyed sign-in limits, whose job is to keep a flood
// from becoming a flood of database round trips, and it is meant to be generous enough
// that a real deployment never sees it (docs/high-availability.md). It was a fixed 100 a
// second, and on four cores the engine hashes about 110 sign-ins a second, so a load the
// machine could serve was refused 429 ten times in a hundred; on sixteen it would have
// refused three in four. It is now half again what this machine can hash, measured at
// startup with the cost new hashes are made with, and never less than it was.
// What may hash at once is still the hasher's own bound (passwords.Hasher), so sign-ins
// beyond what the machine can hash wait for a slot rather than run.
const loginGuardFloor = 100

// loginGuardRate is half again slots hashes a perHash each, and at least loginGuardFloor.
func loginGuardRate(slots int, perHash time.Duration) float64 {
	if slots < 1 || perHash <= 0 {
		return loginGuardFloor
	}
	return math.Max(loginGuardFloor, 1.5*float64(slots)/perHash.Seconds())
}

// loginGuard is loginGuardRate for this machine, measured once: three derivations at the
// configured cost, the middle one taken (passwords.Measure).
var loginGuard = sync.OnceValue(func() float64 {
	h := passwords.Shared()
	return loginGuardRate(h.Concurrency(), passwords.Measure(h.Params()))
})
