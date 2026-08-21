package federation

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The cache exists so a JWKS lookup can sit on the token endpoint. Each test
// below is one of the reasons it could not before.

func keySet(kids ...string) *jose.JSONWebKeySet {
	s := &jose.JSONWebKeySet{}
	for _, k := range kids {
		s.Keys = append(s.Keys, jose.JSONWebKey{KeyID: k})
	}
	return s
}

// counting returns a fetch function and a counter of how often it ran.
func counting(set *jose.JSONWebKeySet, err error) (func(context.Context, *http.Client, string) (*jose.JSONWebKeySet, error), *int64) {
	var n int64
	return func(context.Context, *http.Client, string) (*jose.JSONWebKeySet, error) {
		atomic.AddInt64(&n, 1)
		return set, err
	}, &n
}

func TestASecondLookupDoesNotHitTheNetwork(t *testing.T) {
	fetch, n := counting(keySet("a"), nil)
	c := &JWKSCache{Fetch: fetch}
	for i := 0; i < 5; i++ {
		if _, err := c.Get(context.Background(), nil, "https://p/jwks", "a"); err != nil {
			t.Fatal(err)
		}
	}
	if *n != 1 {
		t.Errorf("fetched %d times, want 1: the cache is not caching", *n)
	}
}

// A burst on a cold cache must produce ONE request, not one per caller. This is
// the stampede that shows up exactly when the deployment is busiest.
func TestConcurrentLookupsCollapseIntoOneFetch(t *testing.T) {
	var n int64
	release := make(chan struct{})
	fetch := func(context.Context, *http.Client, string) (*jose.JSONWebKeySet, error) {
		atomic.AddInt64(&n, 1)
		<-release // hold every caller inside the fetch
		return keySet("a"), nil
	}
	c := &JWKSCache{Fetch: fetch}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Get(context.Background(), nil, "https://p/jwks", "a")
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt64(&n); got != 1 {
		t.Errorf("20 concurrent lookups made %d fetches, want 1", got)
	}
}

// Key rotation. A provider publishes a new kid; a plain TTL cache rejects every
// token signed with it until the entry expires, which is an outage that looks
// like a signature bug.
func TestAnUnknownKidForcesOneRefresh(t *testing.T) {
	var n int64
	fetch := func(context.Context, *http.Client, string) (*jose.JSONWebKeySet, error) {
		i := atomic.AddInt64(&n, 1)
		if i == 1 {
			return keySet("old"), nil
		}
		return keySet("old", "new"), nil // the provider has rotated
	}
	c := &JWKSCache{Fetch: fetch}

	if _, err := c.Get(context.Background(), nil, "https://p/jwks", "old"); err != nil {
		t.Fatal(err)
	}
	set, err := c.Get(context.Background(), nil, "https://p/jwks", "new")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range set.Keys {
		if k.KeyID == "new" {
			found = true
		}
	}
	if !found {
		t.Error("the rotated-in key was never picked up; rotation breaks verification")
	}
	if n != 2 {
		t.Errorf("fetched %d times, want 2 (initial plus one forced refresh)", n)
	}
}

// And the other half of that: invented kids must not become a fetch amplifier.
// Without the rate limit, one attacker turns each request into an outbound
// request to the provider.
func TestRepeatedUnknownKidsDoNotAmplify(t *testing.T) {
	fetch, n := counting(keySet("a"), nil)
	c := &JWKSCache{Fetch: fetch}

	for i := 0; i < 50; i++ {
		_, _ = c.Get(context.Background(), nil, "https://p/jwks",
			fmt.Sprintf("invented-%d", i))
	}
	// One initial fetch, plus at most one forced refresh inside the window.
	if *n > 2 {
		t.Errorf("50 unknown kids caused %d fetches; the refresh rate limit is not holding", *n)
	}
}

// A provider having a bad minute must not invalidate keys we already hold.
func TestAFailedRefreshKeepsTheKeysWeHave(t *testing.T) {
	base := time.Now()
	var fail atomic.Bool
	fetch := func(context.Context, *http.Client, string) (*jose.JSONWebKeySet, error) {
		if fail.Load() {
			return nil, fmt.Errorf("provider is down")
		}
		return keySet("a"), nil
	}
	c := &JWKSCache{now: func() time.Time { return base }, Fetch: fetch}

	if _, err := c.Get(context.Background(), nil, "https://p/jwks", "a"); err != nil {
		t.Fatal(err)
	}
	// Move past the TTL so the next call refetches, and make that fetch fail.
	fail.Store(true)
	c.now = func() time.Time { return base.Add(jwksTTL + time.Second) }

	set, err := c.Get(context.Background(), nil, "https://p/jwks", "a")
	if err != nil {
		t.Fatalf("a failed refresh returned an error instead of the keys we had: %v", err)
	}
	if set == nil || len(set.Keys) != 1 || set.Keys[0].KeyID != "a" {
		t.Error("the previously cached key set was discarded when the provider failed")
	}
}

// A provider that is down must not be retried on every single request.
func TestAFailureIsCachedBriefly(t *testing.T) {
	base := time.Now()
	fetch, n := counting(nil, fmt.Errorf("unreachable"))
	c := &JWKSCache{now: func() time.Time { return base }, Fetch: fetch}

	for i := 0; i < 10; i++ {
		if _, err := c.Get(context.Background(), nil, "https://p/jwks", ""); err == nil {
			t.Fatal("an unreachable provider reported success")
		}
	}
	if *n != 1 {
		t.Errorf("a down provider was fetched %d times, want 1 within the negative TTL", *n)
	}

	// And recovery is quick, not TTL-long.
	c.now = func() time.Time { return base.Add(jwksNegativeTTL + time.Second) }
	if _, err := c.Get(context.Background(), nil, "https://p/jwks", ""); err == nil {
		t.Fatal("expected the retry to run")
	}
	if *n != 2 {
		t.Errorf("after the negative TTL the fetch ran %d times, want 2", *n)
	}
}

// The map is driven by operator-supplied URLs, so it must not grow without bound.
func TestTheCacheIsBounded(t *testing.T) {
	base := time.Now()
	i := 0
	fetch, _ := counting(keySet("a"), nil)
	c := &JWKSCache{now: func() time.Time { return base.Add(time.Duration(i) * time.Second) }, Fetch: fetch}

	for ; i < jwksMaxCachedIssuer+50; i++ {
		_, _ = c.Get(context.Background(), nil, fmt.Sprintf("https://p%d/jwks", i), "a")
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > jwksMaxCachedIssuer {
		t.Errorf("cache holds %d entries, above the %d bound", n, jwksMaxCachedIssuer)
	}
}
