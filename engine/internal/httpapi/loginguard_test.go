package httpapi

import (
	"math"
	"testing"
	"time"
)

// The sign-in guard is half again what this machine can hash, and never less than the
// 100 a second it was (E.28): fixed at 100, it refused a load four cores could serve, which
// its own comment and docs/high-availability.md say a real deployment never sees.
func TestTheSignInGuardIsSizedFromTheMachine(t *testing.T) {
	for _, c := range []struct {
		slots   int
		perHash time.Duration
		want    float64
	}{
		{8, 30 * time.Millisecond, 400},
		{32, 20 * time.Millisecond, 2400},
		{2, 200 * time.Millisecond, loginGuardFloor},
		{0, 30 * time.Millisecond, loginGuardFloor},
		{8, 0, loginGuardFloor},
	} {
		if got := loginGuardRate(c.slots, c.perHash); math.Abs(got-c.want) > 0.001 {
			t.Errorf("%d slots at %s a hash gave a guard of %.1f a second, want %.1f", c.slots, c.perHash, got, c.want)
		}
	}

	f := newTokenFixture(t)
	if got, want := f.srv.login.Rate(), loginGuard(); got != want || got < loginGuardFloor {
		t.Errorf("the server's sign-in guard refills at %.1f a second; this machine's is %.1f, and the floor %d",
			got, want, loginGuardFloor)
	}
	t.Logf("this machine's sign-in guard: %.0f a second", loginGuard())
}
