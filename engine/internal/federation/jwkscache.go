package federation

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// A cache in front of every provider JWKS fetch.
//
// # Why this exists
//
// fetchJWKS did an outbound HTTP GET on every call. For interactive sign-in that
// is once per login and nobody notices. It stops being acceptable the moment a
// JWKS lookup sits on the token endpoint, where three separate things go wrong at
// once:
//
//   - **Amplification.** One request here becomes one request to the provider, so
//     anybody who can call the token endpoint can aim our outbound bandwidth at
//     Google. The provider rate-limits us, and then real sign-ins fail.
//   - **Availability.** A provider whose JWKS endpoint is briefly unreachable
//     takes our grant down with it, for tokens whose keys we already knew.
//   - **Latency.** The token endpoint's p50 is well under a millisecond. A
//     network round trip is two orders of magnitude more.
//
// # The rotation problem, and why a plain TTL is not enough
//
// A provider that rotates its signing key publishes a new `kid`. With a plain TTL
// every token signed by the new key fails until the entry expires -- an outage
// that looks like a signature bug and lasts exactly as long as the TTL.
//
// The fix is to refetch when a `kid` is missing. That reintroduces the
// amplification: an attacker sends tokens with invented `kid`s and every one
// forces a fetch. So a forced refresh is itself rate-limited per URL. Unknown
// `kid`s are then bounded by minRefreshInterval no matter how many arrive, and a
// real rotation is picked up within it.
const (
	jwksTTL             = 10 * time.Minute
	jwksNegativeTTL     = 30 * time.Second
	jwksMinRefresh      = 1 * time.Minute
	jwksMaxCachedIssuer = 512
)

type jwksEntry struct {
	set       *jose.JSONWebKeySet
	err       error
	fetchedAt time.Time
	// refreshedAt is when a kid-miss last forced a fetch, which is rate-limited
	// separately from ordinary expiry.
	refreshedAt time.Time
}

// JWKSCache holds provider key sets. The zero value is ready to use.
type JWKSCache struct {
	mu      sync.Mutex
	entries map[string]*jwksEntry
	// inflight collapses concurrent fetches for the same URL into one. Without
	// it, a burst arriving on a cold entry produces one outbound request each --
	// the stampede the cache was added to prevent, at exactly the busiest moment.
	inflight map[string]*sync.WaitGroup
	now      func() time.Time
	// Fetch is how a key set is retrieved. Nil means FetchJWKS.
	//
	// A field rather than a parameter on Get: the fetcher is a property of the
	// cache, and threading it through every call site meant the one caller that
	// mattered -- assertion verification -- had FetchJWKS wired in literally and
	// could not be tested without a network.
	Fetch func(context.Context, *http.Client, string) (*jose.JSONWebKeySet, error)
}

func (c *JWKSCache) fetcher() func(context.Context, *http.Client, string) (*jose.JSONWebKeySet, error) {
	if c.Fetch != nil {
		return c.Fetch
	}
	return FetchJWKS
}

func (c *JWKSCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Get returns the key set for a URL, fetching it when the cached copy is absent
// or stale.
//
// `wantKID` names the key the caller is looking for, or is empty when it does not
// care. A cached set that does not contain it triggers one rate-limited refresh,
// which is what makes key rotation survivable.
func (c *JWKSCache) Get(ctx context.Context, hc *http.Client, url, wantKID string) (*jose.JSONWebKeySet, error) {
	fetch := c.fetcher()

	for {
		c.mu.Lock()
		if c.entries == nil {
			c.entries = map[string]*jwksEntry{}
			c.inflight = map[string]*sync.WaitGroup{}
		}
		now := c.clock()
		e := c.entries[url]

		if e != nil && !c.stale(e, now, wantKID) {
			set, err := e.set, e.err
			c.mu.Unlock()
			return set, err
		}

		// Somebody else is already fetching: wait for them rather than issuing a
		// second identical request.
		if wg := c.inflight[url]; wg != nil {
			c.mu.Unlock()
			wg.Wait()
			continue
		}

		wg := &sync.WaitGroup{}
		wg.Add(1)
		c.inflight[url] = wg
		forced := e != nil
		c.mu.Unlock()

		set, err := fetch(ctx, hc, url)

		c.mu.Lock()
		// A failed refresh must not discard a key set we already have. The old
		// keys are still the provider's keys; serving them beats failing every
		// verification because the provider's web server had a bad minute.
		if err != nil && e != nil && e.set != nil {
			e.fetchedAt = now
			if forced {
				e.refreshedAt = now
			}
			set, err = e.set, nil
		} else {
			ne := &jwksEntry{set: set, err: err, fetchedAt: now}
			if forced {
				ne.refreshedAt = now
			}
			c.evictIfFull()
			c.entries[url] = ne
		}
		delete(c.inflight, url)
		c.mu.Unlock()
		wg.Done()
		return set, err
	}
}

// stale reports whether an entry must be refetched. Caller holds the lock.
func (c *JWKSCache) stale(e *jwksEntry, now time.Time, wantKID string) bool {
	ttl := jwksTTL
	if e.err != nil {
		// A failure is cached briefly so an unreachable provider is not retried
		// on every request, and briefly so recovery is quick.
		ttl = jwksNegativeTTL
	}
	if now.Sub(e.fetchedAt) >= ttl {
		return true
	}
	if wantKID == "" || e.set == nil {
		return false
	}
	for _, k := range e.set.Keys {
		if k.KeyID == wantKID {
			return false
		}
	}
	// The kid is not here. Refresh, but no more often than this.
	return now.Sub(e.refreshedAt) >= jwksMinRefresh
}

// evictIfFull keeps the map bounded. Caller holds the lock.
//
// Unbounded, this map is a memory leak driven by whatever URLs the configuration
// names -- and in a multi-tenant deployment that is operator-supplied input.
func (c *JWKSCache) evictIfFull() {
	if len(c.entries) < jwksMaxCachedIssuer {
		return
	}
	var oldestURL string
	var oldest time.Time
	for u, e := range c.entries {
		if oldestURL == "" || e.fetchedAt.Before(oldest) {
			oldestURL, oldest = u, e.fetchedAt
		}
	}
	delete(c.entries, oldestURL)
}

// FetchJWKS is the uncached fetch, exported so the cache can drive it and tests
// can substitute their own.
func FetchJWKS(ctx context.Context, hc *http.Client, url string) (*jose.JSONWebKeySet, error) {
	if url == "" {
		return nil, fmt.Errorf("no JWKS URL is configured for this provider, so its " +
			"signature cannot be checked")
	}
	if hc == nil {
		// Refused rather than defaulted. http.DefaultClient has NO timeout, so
		// falling back to it turns a missing-configuration bug into a goroutine
		// parked forever on a request path -- and `hc.Do` on a nil client panics,
		// which on the token endpoint is a denial of service.
		return nil, fmt.Errorf("no HTTP client was configured for fetching provider keys")
	}
	return fetchJWKSFrom(ctx, hc, url)
}
