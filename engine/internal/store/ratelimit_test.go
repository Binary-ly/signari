package store

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func rateTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestAllowRateCountsAndRefuses(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	key := fmt.Sprintf("test:%d", time.Now().UnixNano())

	for i := 1; i <= 5; i++ {
		r, err := AllowRate(ctx, pool, key, 5, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Allowed {
			t.Fatalf("request %d of 5 was refused", i)
		}
		if r.Count != i {
			t.Fatalf("count is %d on request %d", r.Count, i)
		}
	}
	r, err := AllowRate(ctx, pool, key, 5, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Fatal("the sixth request against a limit of five was allowed")
	}
	if r.RetryAfter <= 0 || r.RetryAfter > time.Minute {
		t.Fatalf("RetryAfter is %s, which tells the caller nothing useful", r.RetryAfter)
	}
}

// TestAllowRateIsSharedAcrossConnections is the property the whole change
// exists for: two connections are two instances.
func TestAllowRateIsSharedAcrossConnections(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	a, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	key := fmt.Sprintf("test:shared:%d", time.Now().UnixNano())
	allowed := 0
	for i := 0; i < 10; i++ {
		// Alternating pools, as a load balancer alternates instances.
		p := a
		if i%2 == 1 {
			p = b
		}
		r, err := AllowRate(ctx, p, key, 5, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if r.Allowed {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("two instances allowed %d requests against a limit of 5. The "+
			"limit must mean the same thing whatever the deployment scales to.",
			allowed)
	}
}

// TestAllowRateUnderConcurrency is why this is a fixed window and not a token
// bucket: a bucket reads then writes, and concurrent readers lose decrements.
func TestAllowRateUnderConcurrency(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	key := fmt.Sprintf("test:race:%d", time.Now().UnixNano())

	const limit = 20
	const attempts = 100

	var mu sync.Mutex
	allowed := 0
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := AllowRate(ctx, pool, key, limit, time.Minute)
			if err != nil {
				return
			}
			if r.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed != limit {
		t.Fatalf("%d of %d concurrent requests were allowed against a limit of %d. "+
			"A limiter that leaks under concurrency leaks under exactly the load it "+
			"exists for.", allowed, attempts, limit)
	}
}

// TestAllowRateSeparatesKeys: one subject's limit must not spend another's.
func TestAllowRateSeparatesKeys(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()

	for i := 0; i < 5; i++ {
		if _, err := AllowRate(ctx, pool, fmt.Sprintf("test:a:%d", stamp), 5, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	r, err := AllowRate(ctx, pool, fmt.Sprintf("test:b:%d", stamp), 5, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Fatal("exhausting one key refused another; one attacker would rate-limit " +
			"every other user")
	}
}

func TestAllowRateRefusesAnUnconfiguredLimit(t *testing.T) {
	pool := rateTestPool(t)
	if _, err := AllowRate(context.Background(), pool, "test:zero", 0, time.Minute); err == nil {
		t.Fatal("a limit of zero was accepted; it would refuse every request " +
			"or allow every request depending on a comparison nobody checked")
	}
}

// One exhausted address must not refuse a different one.
//
// This is the property the device verification endpoint was missing. It used a
// single process-wide token bucket of 3/s, so anybody sending four requests a
// second held it empty and every legitimate person in every organisation was
// refused while trying to sign in a television -- an unauthenticated denial of
// service that cost the attacker nothing.
//
// RFC 8628 §5.1 asks for the user interaction endpoint to be rate limited
// because an eight-character code is guessable. A limit that punishes everyone
// for one guesser satisfies the letter and inverts the intent.
func TestOneExhaustedKeyDoesNotRefuseAnother(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	attacker := fmt.Sprintf("device:ip:198.51.100.7:%d", stamp)
	victim := fmt.Sprintf("device:ip:203.0.113.9:%d", stamp)

	const limit = 5
	for i := 0; i < limit*3; i++ {
		if _, err := AllowRate(ctx, pool, attacker, limit, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	// The attacker is now well past their budget.
	r, err := AllowRate(ctx, pool, attacker, limit, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Fatal("an address was still allowed after 15 attempts against a limit of 5")
	}

	// Somebody else, unaffected.
	r, err = AllowRate(ctx, pool, victim, limit, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Fatal("a second address was refused because a FIRST address had " +
			"exhausted its budget; the limit is shared, which turns the " +
			"defence into a denial of service")
	}
}
