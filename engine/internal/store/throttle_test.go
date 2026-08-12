package store

import (
	"testing"
	"time"
)

// The backoff curve. Each property here is a decision that would be a real
// vulnerability inverted.
func TestLoginDelayCurve(t *testing.T) {
	// People mistype passwords. Charging the first few costs real users far more
	// than it costs an attacker, who is not typing.
	for i := 0; i <= FreeAttempts; i++ {
		if d := LoginDelay(i); d != 0 {
			t.Errorf("failure %d cost %v; the first %d must be free", i, d, FreeAttempts)
		}
	}

	// Doubling: guessing becomes infeasible within a handful of attempts.
	if d := LoginDelay(FreeAttempts + 1); d != time.Second {
		t.Errorf("first charged failure = %v, want 1s", d)
	}
	if d := LoginDelay(FreeAttempts + 4); d != 8*time.Second {
		t.Errorf("fourth charged failure = %v, want 8s", d)
	}

	// CAPPED. Uncapped exponential backoff is a permanent lockout with extra
	// steps -- and a permanent lockout is a button an attacker can press on any
	// account they can name.
	for _, n := range []int{20, 50, 1000, 1 << 20} {
		if d := LoginDelay(n); d != MaxLoginDelay {
			t.Errorf("%d failures = %v, want the cap %v", n, d, MaxLoginDelay)
		}
	}

	// Monotonic, with no overflow flipping it negative on the way up.
	prev := time.Duration(0)
	for i := 0; i < 64; i++ {
		d := LoginDelay(i)
		if d < prev {
			t.Fatalf("delay went backwards at %d failures: %v after %v", i, d, prev)
		}
		if d < 0 {
			t.Fatalf("delay overflowed to %v at %d failures", d, i)
		}
		prev = d
	}
}
