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

// The purge keeps every row that could still be a live window. It deleted
// whatever started over an hour ago, and a daily SMS ceiling starts at
// midnight UTC, so from 01:00 the janitor reset it every minute.
func TestThePurgeKeepsADailyWindowThatIsStillOpen(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	key := fmt.Sprintf("purge-test:%d", time.Now().UnixNano())
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.rate_limits (bucket_key, window_start, count) VALUES
		    ($1 || ':open', now() - interval '23 hours', 7),
		    ($1 || ':over', now() - interval '25 hours', 7)`, key); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgeRateLimits(ctx, tx); err != nil {
		t.Fatal(err)
	}
	var open, over int
	if err := tx.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE bucket_key = $1 || ':open'),
		count(*) FILTER (WHERE bucket_key = $1 || ':over')
		FROM core.rate_limits WHERE bucket_key LIKE $1 || ':%'`, key).Scan(&open, &over); err != nil {
		t.Fatal(err)
	}
	if open != 1 {
		t.Error("a 24-hour window that started 23 hours ago was purged while still counting")
	}
	if over != 0 {
		t.Error("a window older than the longest one any limit uses was kept")
	}

	// And a limit cannot ask for a window the purge would cut short.
	if _, err := AllowRate(ctx, tx, key, 1, MaxRateWindow+time.Hour); err == nil {
		t.Error("a window longer than the purge keeps was accepted")
	}
}

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

	// The window is the clock's minute, so a run that straddles one counts
	// into two windows, each allowing the limit. What must hold is per window:
	// exactly min(count, limit) allowed in each. The test compared the total
	// with one limit and failed whenever the requests crossed a minute (4.20).
	rows, err := pool.Query(ctx, `SELECT count FROM core.rate_limits WHERE bucket_key = $1`, key)
	if err != nil {
		t.Fatal(err)
	}
	want, windows := 0, 0
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		windows++
		want += min(n, limit)
	}
	rows.Close()
	if windows == 0 || allowed != want {
		t.Fatalf("%d of %d concurrent requests were allowed against a limit of %d over %d "+
			"window(s), which allow %d. A limiter that leaks under concurrency leaks under "+
			"exactly the load it exists for.", allowed, attempts, limit, windows, want)
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
