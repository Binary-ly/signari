package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// statements counts what a combiner sends, and fails it all when told to.
type statements struct {
	q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}
	n    atomic.Int64
	fail atomic.Bool
}

func (s *statements) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	s.n.Add(1)
	if s.fail.Load() {
		return failedRow{}
	}
	return s.q.QueryRow(ctx, sql, args...)
}

type failedRow struct{}

func (failedRow) Scan(...any) error { return errors.New("the database did not answer") }

// awayFromAMinutesEnd waits out the last seconds of a minute, so what follows counts
// into one window.
func awayFromAMinutesEnd(t *testing.T) {
	t.Helper()
	if left := time.Until(time.Now().Truncate(time.Minute).Add(time.Minute)); left < 5*time.Second {
		time.Sleep(left + 100*time.Millisecond)
	}
}

// Requests counted together are answered as they would have been one at a time: each has a
// place of its own in the count, the places are 1 to n with none skipped or shared, the
// first limit of them are allowed, and the table has counted every one. Under load the
// statements are fewer than the requests, which is the point.
func TestTheCombinerAnswersEachRequestAsIfItCameAlone(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	awayFromAMinutesEnd(t)
	key := fmt.Sprintf("test:combined:%d", time.Now().UnixNano())
	const limit, attempts = 50, 200

	rc := NewRateCombiner()
	q := &statements{q: pool}
	var mu sync.Mutex
	var places []int
	allowed := 0
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := rc.Allow(ctx, q, key, limit, time.Minute)
			if err != nil {
				t.Error(err)
				return
			}
			if r.RetryAfter <= 0 || r.RetryAfter > time.Minute {
				t.Errorf("a combined request was told to retry after %s", r.RetryAfter)
			}
			mu.Lock()
			defer mu.Unlock()
			places = append(places, r.Count)
			if r.Allowed {
				allowed++
			}
		}()
	}
	close(start)
	wg.Wait()

	slices.Sort(places)
	for i, p := range places {
		if p != i+1 {
			t.Fatalf("the %d requests were given places %v; each must have its own, 1 to %d",
				attempts, places, attempts)
		}
	}
	if allowed != limit {
		t.Errorf("%d of %d requests were allowed against a limit of %d", allowed, attempts, limit)
	}
	var counted int
	if err := pool.QueryRow(ctx, `SELECT sum(count) FROM core.rate_limits WHERE bucket_key = $1`, key).
		Scan(&counted); err != nil {
		t.Fatal(err)
	}
	if counted != attempts {
		t.Errorf("the table counted %d of %d requests", counted, attempts)
	}
	sent := q.n.Load()
	t.Logf("%d requests arriving together, %d statements", attempts, sent)
	if sent > attempts/2 {
		t.Errorf("%d requests arriving together took %d statements; those waiting on one are "+
			"counted by the next together", attempts, sent)
	}
	rc.mu.Lock()
	held := len(rc.keys)
	rc.mu.Unlock()
	if held != 0 {
		t.Errorf("the combiner still holds %d keys with nothing in flight", held)
	}
}

// The limit is the shared table's, so two instances each combining their own requests
// allow the limit between them, as AllowRate's callers do.
func TestCombinedRequestsShareTheLimitAcrossInstances(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	awayFromAMinutesEnd(t)
	key := fmt.Sprintf("test:combined:shared:%d", time.Now().UnixNano())
	instances := []*RateCombiner{NewRateCombiner(), NewRateCombiner(), nil}
	allowed := 0
	for i := range 12 {
		r, err := instances[i%3].Allow(ctx, pool, key, 5, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if r.Count != i+1 {
			t.Fatalf("request %d was counted as %d", i+1, r.Count)
		}
		if r.Allowed {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("three instances allowed %d requests against a limit of 5", allowed)
	}
}

// A statement that fails refuses everybody it was counting: a group never counted is not
// room, and the combiner is free for the next.
func TestACombinedStatementThatFailsAllowsNobody(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	key := fmt.Sprintf("test:combined:fail:%d", time.Now().UnixNano())
	rc := NewRateCombiner()
	q := &statements{q: pool}
	q.fail.Store(true)
	var wg sync.WaitGroup
	var refused atomic.Int64
	start := make(chan struct{})
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := rc.Allow(ctx, q, key, 1000, time.Minute)
			if err == nil || r.Allowed {
				t.Errorf("a request the database never counted was answered %+v, %v", r, err)
				return
			}
			refused.Add(1)
		}()
	}
	close(start)
	wg.Wait()
	if refused.Load() != 40 {
		t.Fatalf("%d of 40 were refused", refused.Load())
	}
	q.fail.Store(false)
	if r, err := rc.Allow(ctx, q, key, 1000, time.Minute); err != nil || !r.Allowed || r.Count != 1 {
		t.Fatalf("after the database came back the next request was answered %+v, %v", r, err)
	}
}
