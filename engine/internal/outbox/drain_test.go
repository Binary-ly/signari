package outbox

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// Draining the outbox from more than one instance.
//
// The first version did the whole drain inside one transaction: claim FOR
// UPDATE SKIP LOCKED, then every HTTP call with those row locks held and a
// pooled connection checked out. Claiming was correct; holding a database
// connection across up to 250 seconds of network I/O was not.
//
// These tests cover what the rewrite must not break -- exactly-once delivery
// across instances -- and what it was meant to fix.
//
// # They share a table with every other package
//
// `go test ./...` runs packages in PARALLEL, and other packages create real
// logout notices as a side effect of ending sessions. Those rows point at
// endpoints that do not resolve, and with a batch of 25 they crowded this
// test's own notices out of the claim entirely -- which showed up as
// "delivered 0 of 7", passed in isolation, and failed in a full run.
//
// So these tests assert on THEIR OWN receivers rather than on counts drawn
// from a table anybody can write to, and take a batch large enough that
// foreign rows do not push theirs out. A test whose result depends on what
// another package happened to be doing is not measuring this code.

func drainTestPool(t *testing.T) *pgxpool.Pool {
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

func drainWorker(t *testing.T, pool *pgxpool.Pool, batch int) *Worker {
	t.Helper()
	k, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	return &Worker{
		db: pool, keys: set, issuer: "https://id.example.test",
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		batch:  batch,
		client: withNoRedirects(outboundClient(5 * time.Second)),
	}
}

// enqueue puts notices in the outbox pointing at endpoint.
func enqueue(t *testing.T, pool *pgxpool.Pool, endpoint string, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		payload, err := json.Marshal(store.LogoutNotice{
			ClientID:  "rp-" + time.Now().Format("150405.000000000"),
			Endpoint:  endpoint,
			SessionID: "sid-test",
			Reason:    "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO core.outbox (topic, payload) VALUES ('backchannel_logout', $1)`,
			payload); err != nil {
			t.Fatal(err)
		}
	}
}

func clearOutbox(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM core.outbox WHERE topic = 'backchannel_logout'`); err != nil {
		t.Fatal(err)
	}
}

// TestTwoInstancesDeliverEachNoticeOnce is the property that must survive the
// rewrite.
//
// Claiming divides the work between instances. Delivering outside the
// transaction means the row locks are gone while the HTTP call is in flight, so
// something else has to keep the two apart -- pushing next_attempt_at forward
// on claim. Without that, committing in order to deliver hands the same rows
// straight to the other instance.
func TestTwoInstancesDeliverEachNoticeOnce(t *testing.T) {
	pool := drainTestPool(t)
	clearOutbox(t, pool)
	t.Cleanup(func() { clearOutbox(t, pool) })

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const notices = 20
	enqueue(t, pool, srv.URL, notices)

	a := drainWorker(t, pool, 500)
	b := drainWorker(t, pool, 500)

	// Both drain at once, as two instances on the same tick do, and repeatedly,
	// as a ticker does.
	//
	// One pass is not the real shape: a claim can lose a race, a transient error
	// defers a notice, and a parallel package's rows compete for the batch. What
	// must hold is that every notice arrives EXACTLY once across all passes --
	// duplication is the bug, and no number of retries can hide it.
	for round := 0; round < 8; round++ {
		var wg sync.WaitGroup
		for _, w := range []*Worker{a, b} {
			wg.Add(1)
			go func(w *Worker) {
				defer wg.Done()
				if _, err := w.drainOnce(context.Background()); err != nil {
					t.Errorf("drain: %v", err)
				}
			}(w)
		}
		wg.Wait()

		if int(atomic.LoadInt64(&hits)) >= notices {
			break
		}
		// A claim lease hides a lost race for a moment; the product retries on a
		// ticker, so the test does too.
		time.Sleep(200 * time.Millisecond)
	}

	total := int(atomic.LoadInt64(&hits))
	if total != notices {
		t.Fatalf("the receiver was called %d times for %d notices. Two instances "+
			"must divide the work, not duplicate it -- and every notice must "+
			"arrive.", total, notices)
	}
}

// TestClaimHidesRowsFromAnotherInstance covers the half that is easy to omit.
//
// After claim() commits, the locks are released. If next_attempt_at were not
// pushed forward, a second instance would immediately see the same rows as due.
func TestClaimHidesRowsFromAnotherInstance(t *testing.T) {
	pool := drainTestPool(t)
	clearOutbox(t, pool)
	t.Cleanup(func() { clearOutbox(t, pool) })

	enqueue(t, pool, "https://unused.test/logout", 5)

	a := drainWorker(t, pool, 500)
	b := drainWorker(t, pool, 500)

	claimedRows, err := a.claimTopic(context.Background(), "backchannel_logout", 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimedRows) != 5 {
		t.Fatalf("claimed %d of 5", len(claimedRows))
	}

	// The first claim has committed. A second instance must find nothing.
	also, err := b.claimTopic(context.Background(), "backchannel_logout", 500)
	if err != nil {
		t.Fatal(err)
	}
	// Compared by id: a parallel package may legitimately have queued notices
	// of its own between the two claims, and those are not a duplication.
	held := map[int64]bool{}
	for _, p := range claimedRows {
		held[p.id] = true
	}
	for _, p := range also {
		if held[p.id] {
			t.Fatalf("a second instance claimed row %d which the first already "+
				"holds. They would both deliver the same logout notice.", p.id)
		}
	}
}

// TestDeliveryHoldsNoTransaction is the reason for the rewrite.
//
// The receiver blocks until the test says otherwise. While it is blocked, the
// database must be usable: under the old design a pooled connection was checked
// out with row locks held for the whole of that wait.
func TestDeliveryHoldsNoTransaction(t *testing.T) {
	pool := drainTestPool(t)
	clearOutbox(t, pool)
	t.Cleanup(func() { clearOutbox(t, pool) })

	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	enqueue(t, pool, srv.URL, 1)

	w := drainWorker(t, pool, 500)
	done := make(chan struct{})
	go func() {
		_, _ = w.drainOnce(context.Background())
		close(done)
	}()

	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver was never called")
	}

	// The delivery is in flight. The row must be visible and unlocked: an
	// UPDATE on it must not block, which it would if the drain still held a
	// transaction open across the HTTP call.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx,
		`UPDATE core.outbox SET last_error = 'probe'
		 WHERE topic = 'backchannel_logout'`); err != nil {
		t.Fatalf("the outbox row is still locked while an HTTP call is in flight: %v\n"+
			"Delivery must happen with no transaction open, or a slow receiver "+
			"holds a database connection and row locks for the length of its "+
			"timeout.", err)
	}

	release <- struct{}{}
	<-done
}

// TestSlowReceiverDoesNotBlockOthers covers the concurrency the rewrite added.
//
// Serially, one hanging receiver delayed every later notice in the batch behind
// it -- 25 notices at a 10 second timeout is over four minutes during which a
// single slow relying party blocks everybody else's logout.
func TestSlowReceiverDoesNotBlockOthers(t *testing.T) {
	pool := drainTestPool(t)
	clearOutbox(t, pool)
	t.Cleanup(func() { clearOutbox(t, pool) })

	var fast int64
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	quick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&fast, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer quick.Close()

	// One slow receiver first in the queue, then several quick ones.
	enqueue(t, pool, slow.URL, 1)
	enqueue(t, pool, quick.URL, 6)

	w := drainWorker(t, pool, 500)
	start := time.Now()
	n, err := w.drainOnce(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if n < 7 {
		t.Fatalf("delivered %d, expected at least this test's 7", n)
	}
	if got := atomic.LoadInt64(&fast); got != 6 {
		t.Fatalf("the quick receiver was called %d times, want 6", got)
	}
	// Serially this would be at least the slow receiver's 2s plus each quick
	// one; concurrently it is bounded by the slowest.
	if elapsed > 4*time.Second {
		t.Fatalf("the batch took %s. One slow receiver is delaying the others.", elapsed)
	}
}

// TestSSFDrainHoldsNoTransaction is the twin of the logout test above.
//
// The SSF drain kept the bug the logout drain had, for exactly as long as it
// had no test at this level: both had HTTP calls inside the claiming
// transaction, the logout one was fixed, and nothing failed to say the other
// still did.
func TestSSFDrainHoldsNoTransaction(t *testing.T) {
	pool := drainTestPool(t)
	clearSSF(t, pool)
	t.Cleanup(func() { clearSSF(t, pool) })

	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	defer close(release)

	payload, err := json.Marshal(map[string]string{
		"stream_id": "stream-test", "client_id": "rp-ssf",
		"endpoint": srv.URL, "event": "session-revoked",
		"subject": "user-1", "sid": "sid-1", "reason": "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO core.outbox (topic, payload) VALUES ('ssf_event', $1)`, payload); err != nil {
		t.Fatal(err)
	}

	w := drainWorker(t, pool, 500)
	done := make(chan struct{})
	go func() {
		_, _ = w.DrainSSF(context.Background())
		close(done)
	}()

	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver was never called")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx,
		`UPDATE core.outbox SET last_error = 'probe' WHERE topic = 'ssf_event'`); err != nil {
		t.Fatalf("the ssf_event row is still locked while an HTTP call is in "+
			"flight: %v\nSecurity events must not hold a database connection for "+
			"the length of a receiver's timeout any more than logout notices do.", err)
	}

	release <- struct{}{}
	<-done
}

func clearSSF(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM core.outbox WHERE topic = 'ssf_event'`); err != nil {
		t.Fatal(err)
	}
}
