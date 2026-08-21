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
// # They share a table with anything else pointed at the same database
//
// Two ways that bit, both worth recording because both looked like product
// bugs:
//
//	`go test ./...` runs packages in PARALLEL, and other packages create real
//	logout notices as a side effect of ending sessions. With a batch of 25
//	those crowded this test's notices out of the claim -- "delivered 0 of 7",
//	passing alone and failing in a full run.
//
//	A `signari serve` left running against the same database drains the outbox
//	on a ticker and claims these rows first. That produced intermittent
//	"claimed 0 of 5" and "the receiver was never called" which I first blamed
//	on -race scheduling. It was not scheduling; it was a live engine competing
//	for the same table, and ten consecutive race runs pass once it is stopped.
//
// So these tests assert on THEIR OWN receivers rather than on counts drawn
// from a table anybody can write to, take a batch large enough that foreign
// rows do not push theirs out, and retry as the product does. A test whose
// result depends on what else happened to be running is not measuring this
// code -- and a wrong diagnosis of why it failed is worse than the flake.

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
	// Delivery tests necessarily target a listener on loopback, which is exactly
	// what the address check refuses. The opt-out is set here rather than the
	// check being weakened: what these tests exercise is draining, batching and
	// deduplication, and `ssrf_test.go` is where the address policy itself is
	// tested.
	t.Setenv(AllowPrivateDelivery, "1")

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
	// EVERY topic, not just backchannel_logout.
	//
	// This used to scope the delete to one topic, and the tests below call
	// drainOnce -- which drains ALL of them. So a test that measures how long a
	// drain takes was also draining whatever other topics had accumulated, and
	// the outbox is a table this suite's other packages write to and never clean.
	//
	// The test database had 633 undelivered rows by the time this was found,
	// almost all webhook deliveries pointing at httptest ports that stopped
	// existing when those tests ended. TestSlowReceiverDoesNotBlockOthers claims
	// a batch of up to 500 and tries every one of them, so its timing assertion
	// was measuring the accumulated debris of every previous run. It eventually
	// took long enough to blow a 90-second package timeout.
	//
	// A test that asserts on elapsed time must control everything the code under
	// test will touch. Scoping this to one topic looked tidier and quietly made
	// the assertion depend on unrelated history.
	//
	// # And why it is bounded by age rather than deleting everything
	//
	// Deleting the whole table was the first fix, and it broke the janitor
	// package: `go test ./...` runs packages in PARALLEL against one database, so
	// a bare DELETE removed rows another package's test had just written and was
	// about to assert on. The failure read "no back-channel logout notice was
	// queued" and had nothing to do with the janitor.
	//
	// Age separates the two cases exactly. Debris from previous runs is minutes
	// or days old; a row a concurrently-running test just wrote is seconds old.
	// Two minutes is far longer than any test here takes and far shorter than the
	// gap between runs.
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM core.outbox WHERE created_at < now() - interval '2 minutes'`); err != nil {
		t.Fatal(err)
	}
	// The current run's own rows, whatever their age, since a test that measures
	// a drain must start from a known state for its own topic.
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
	// At least this test's five. Another package running in parallel, or a
	// soak left running against the same database, legitimately adds more --
	// and an exact count turns that into "claimed 65 of 5", which reads like a
	// claiming bug and is a shared table.
	if len(claimedRows) < 5 {
		t.Fatalf("claimed %d rows, expected at least this test's 5", len(claimedRows))
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
		defer close(done)
		// Retried, because a claim can lose a race with another drain and the
		// point of this test is the transaction boundary, not the first attempt.
		for round := 0; round < 10; round++ {
			if n, err := w.drainOnce(context.Background()); err != nil || n > 0 {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-arrived:
	case <-time.After(30 * time.Second):
		// A liveness bound, not a latency one.
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

	// The property is CONCURRENCY, and it is asserted structurally rather than
	// as elapsed wall-clock.
	//
	// This test used to assert `elapsed < 4s`. That is a load-sensitive proxy for
	// the thing it cares about: on a busy machine the whole batch legitimately
	// takes longer, and the test fails while the property it names still holds.
	// It did exactly that during a full-suite run alongside a static-analysis
	// pass, reporting 36 seconds — and in isolation, seconds later, 2.1.
	//
	// What "one slow receiver does not block the others" actually means is that a
	// quick delivery COMPLETES WHILE THE SLOW ONE IS STILL IN FLIGHT. That is
	// observable directly, and no amount of machine load changes it: if delivery
	// were serial, every quick receiver would be hit only after the slow one
	// returned, whatever the clock says.
	var fast int64
	var mu sync.Mutex
	var slowDone, lastQuick time.Time

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		mu.Lock()
		slowDone = time.Now()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	quick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		lastQuick = time.Now()
		mu.Unlock()
		atomic.AddInt64(&fast, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer quick.Close()

	// One slow receiver first in the queue, then several quick ones.
	enqueue(t, pool, slow.URL, 1)
	enqueue(t, pool, quick.URL, 6)

	w := drainWorker(t, pool, 500)
	start := time.Now()
	// Drained until this test's own receivers have been hit, as the product
	// drains on a ticker rather than in a single pass.
	var elapsed time.Duration
	for round := 0; round < 10; round++ {
		if _, err := w.drainOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		elapsed = time.Since(start)
		if atomic.LoadInt64(&fast) >= 6 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&fast); got != 6 {
		t.Fatalf("the quick receiver was called %d times, want 6", got)
	}
	// Compare the instants, not the total.
	//
	// Concurrent: every quick delivery lands within milliseconds, and the slow one
	// finishes two seconds later -- so lastQuick is BEFORE slowDone.
	// Serial:     the slow one is first in the queue, so the quick deliveries
	//             cannot start until it returns -- lastQuick is AFTER slowDone.
	//
	// Total elapsed is ~2s either way, which is why the previous assertion
	// (`elapsed < 4s`) passed whether or not the deliveries overlapped. It was
	// measuring the slow receiver's own sleep and calling it concurrency.
	mu.Lock()
	sd, lq := slowDone, lastQuick
	mu.Unlock()
	if sd.IsZero() || lq.IsZero() {
		t.Fatalf("both receivers must have been reached: slowDone=%v lastQuick=%v", sd, lq)
	}
	if lq.After(sd) {
		t.Fatalf("every quick delivery finished only after the slow receiver "+
			"returned (last quick %s after it; batch took %s). That is a serial "+
			"drain: one unreachable relying party delays the logout notices for "+
			"all the others.", lq.Sub(sd).Round(time.Millisecond), elapsed)
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
		defer close(done)
		for round := 0; round < 10; round++ {
			if n, err := w.DrainSSF(context.Background()); err != nil || n > 0 {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-arrived:
	case <-time.After(30 * time.Second):
		// A liveness bound, not a latency one.
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
