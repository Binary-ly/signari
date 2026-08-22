package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestABucketStartsFullAndDrains(t *testing.T) {
	b := New(1, 10)
	for i := 0; i < 10; i++ {
		if !b.Allow() {
			t.Fatalf("refused request %d of the initial burst of 10", i+1)
		}
	}
	if b.Allow() {
		t.Fatal("an eleventh request was allowed from a capacity of 10")
	}
}

// Starting full is deliberate: a server restarting under load should serve the
// burst it was sized for, not throttle everybody while its buckets fill.
func TestARefillRestoresCapacityOverTime(t *testing.T) {
	base := time.Now()
	b := New(10, 10) // ten per second
	b.now = func() time.Time { return base }
	b.last = base

	for i := 0; i < 10; i++ {
		b.Allow()
	}
	if b.Allow() {
		t.Fatal("the bucket did not drain")
	}

	b.now = func() time.Time { return base.Add(500 * time.Millisecond) }
	allowed := 0
	for i := 0; i < 10; i++ {
		if b.Allow() {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("half a second at 10/s allowed %d, want 5", allowed)
	}
}

func TestRefillNeverExceedsCapacity(t *testing.T) {
	base := time.Now()
	b := New(10, 10)
	b.now = func() time.Time { return base }
	b.last = base
	b.Allow()

	// An hour later: the bucket must be full, not overflowing.
	b.now = func() time.Time { return base.Add(time.Hour) }
	allowed := 0
	for i := 0; i < 50; i++ {
		if b.Allow() {
			allowed++
		}
	}
	if allowed != 10 {
		t.Errorf("after an hour idle the bucket allowed %d, want its capacity of 10", allowed)
	}
}

// One key running out must not affect another. This is the whole reason Keyed
// exists rather than a second global bucket.
func TestOneKeyCannotStarveAnother(t *testing.T) {
	k := NewKeyed(1, 5, 64)

	for i := 0; i < 5; i++ {
		if !k.Allow("noisy") {
			t.Fatalf("the noisy key was refused within its own burst at %d", i)
		}
	}
	if k.Allow("noisy") {
		t.Fatal("the noisy key was not throttled")
	}

	for i := 0; i < 5; i++ {
		if !k.Allow("quiet") {
			t.Fatalf("a second key was refused because the first exhausted itself (%d)", i)
		}
	}
}

// The map must not grow without bound.
func TestTheKeyedLimiterIsBounded(t *testing.T) {
	k := NewKeyed(1, 5, 8)
	for i := 0; i < 200; i++ {
		k.Allow(fmt.Sprintf("key-%d", i))
	}
	if n := k.Len(); n > 8 {
		t.Errorf("the limiter holds %d keys, above its bound of 8", n)
	}
}

// Eviction must not hand a throttled key a fresh allowance.
//
// The obvious eviction policies are wrong here. Dropping the OLDEST or a RANDOM
// entry means a caller who has exhausted their bucket can flood the limiter with
// other keys until their own entry is evicted, and a new entry starts full — so
// the limit becomes something they reset rather than something they are subject
// to. Evicting the FULLEST entry drops the one that has consumed least, which is
// both the least informative to keep and the least useful to displace.
func TestEvictionDoesNotResetAThrottledKey(t *testing.T) {
	k := NewKeyed(0, 3, 4) // rate 0: nothing refills, so only eviction could

	// Exhaust the victim.
	for i := 0; i < 3; i++ {
		k.Allow("throttled")
	}
	if k.Allow("throttled") {
		t.Fatal("the key did not exhaust")
	}

	// Now push well past the bound with other keys, each barely used.
	for i := 0; i < 100; i++ {
		k.Allow(fmt.Sprintf("filler-%d", i))
	}

	if k.Allow("throttled") {
		t.Fatal("a throttled key regained its allowance by forcing eviction; the " +
			"limit is something the caller can reset rather than be subject to")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	b := New(1000, 1000)
	k := NewKeyed(1000, 1000, 64)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				b.Allow()
				k.Allow(fmt.Sprintf("k%d", n%8))
			}
		}(i)
	}
	wg.Wait()
}
