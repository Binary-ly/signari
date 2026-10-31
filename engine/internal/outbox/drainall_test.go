package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// privateTopic queues n rows on a topic of the test's own, each saying its number,
// so nothing another package queues can take a place in a batch.
func privateTopic(t *testing.T, pool *pgxpool.Pool, n int) string {
	t.Helper()
	ctx := context.Background()
	topic := "drain-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := pool.Exec(ctx, `INSERT INTO core.outbox (topic, payload)
		SELECT $1, jsonb_build_object('n', g) FROM generate_series(1, $2::int) g`, topic, n); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1`, topic) })
	return topic
}

// A queue longer than a batch used to wait a tick for each batch, which capped a
// mass logout at 12 notices a second however fast the receivers were.
func TestAQueueIsDrainedToItsEndOnOneTick(t *testing.T) {
	pool := drainTestPool(t)
	topic := privateTopic(t, pool, 25)
	var sent atomic.Int32
	w := drainWorker(t, pool, 10)
	w.drainAll(context.Background(), drainer{"a test topic", 10, func(ctx context.Context) (int, error) {
		return w.drainTopic(ctx, drainSpec{topic: topic, batch: 10, backoff: backoffFor,
			deliver: func(context.Context, []byte) error { sent.Add(1); return nil }})
	}})
	if got := sent.Load(); got != 25 {
		t.Errorf("one tick delivered %d of 25", got)
	}
}

// Going on until the queue is empty must not mean going on against a receiver
// that is down: its rows are backing off, and a short batch ends the tick.
func TestADeadReceiverDoesNotSpinTheDrain(t *testing.T) {
	pool := drainTestPool(t)
	topic := privateTopic(t, pool, 25)
	var tried atomic.Int32
	w := drainWorker(t, pool, 10)
	w.drainAll(context.Background(), drainer{"a test topic", 10, func(ctx context.Context) (int, error) {
		return w.drainTopic(ctx, drainSpec{topic: topic, batch: 10, backoff: backoffFor,
			deliver: func(context.Context, []byte) error { tried.Add(1); return errors.New("connection refused") }})
	}})
	if got := tried.Load(); got != 10 {
		t.Errorf("a tick against a dead receiver tried %d, wanting one batch of 10", got)
	}
}

// One receiver timing out in one topic held up every other, since a tick took
// them in turn: a logout could wait on a webhook subscriber nobody was answering.
func TestAHungTopicHoldsUpOnlyItself(t *testing.T) {
	w := &Worker{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	quick := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.runEach(ctx, 5*time.Millisecond, []drainer{
			{"hung", 1, func(ctx context.Context) (int, error) { <-ctx.Done(); return 0, nil }},
			{"quick", 1, func(context.Context) (int, error) {
				select {
				case quick <- struct{}{}:
				default:
				}
				return 0, nil
			}},
		})
	}()
	select {
	case <-quick:
	case <-time.After(10 * time.Second):
		t.Error("a topic waited behind one that had hung")
	}
	cancel()
	<-done
}

type statementCounter struct{ n atomic.Int64 }

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Each way a delivery can go is recorded as it was, and a batch of them takes a
// statement a way rather than a statement a row.
func TestABatchIsRecordedTogetherAndEachRowAsItWent(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	spent := &statementCounter{}
	cfg.ConnConfig.Tracer = spent
	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	topic := privateTopic(t, pool, 40)
	w := drainWorker(t, pool, 40)
	before := spent.n.Load()
	delivered, err := w.drainTopic(ctx, drainSpec{topic: topic, batch: 40, backoff: backoffFor,
		deliver: func(_ context.Context, raw []byte) error {
			var row struct {
				N int `json:"n"`
			}
			if err := json.Unmarshal(raw, &row); err != nil {
				return err
			}
			switch row.N % 4 {
			case 0:
				return nil
			case 1:
				return &heldError{reason: "paused", wait: time.Hour}
			case 2:
				return &droppedError{reason: "gone"}
			}
			return errors.New("refused")
		}})
	if err != nil {
		t.Fatal(err)
	}
	if used := spent.n.Load() - before; delivered != 10 || used > 10 {
		t.Errorf("delivered %d of 10 in %d statements", delivered, used)
	}
	for _, c := range []struct {
		name, where string
		want        int
	}{
		{"delivered", `delivered_at IS NOT NULL AND attempts = 0 AND last_error IS NULL`, 10},
		{"held", `delivered_at IS NULL AND attempts = 0 AND last_error = 'paused' AND next_attempt_at > now() + interval '30 minutes'`, 10},
		{"dropped", `delivered_at IS NOT NULL AND attempts = 0 AND last_error = 'gone'`, 10},
		{"failed", `delivered_at IS NULL AND attempts = 1 AND last_error = 'refused' AND next_attempt_at > now()`, 10},
	} {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM core.outbox WHERE topic = $1 AND `+c.where, topic).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != c.want {
			t.Errorf("%d rows %s, wanting %d", n, c.name, c.want)
		}
	}
}

// queueEvent queues one event delivery to url, for a subscription of its own, and
// parks everybody else's so a drain sees only this.
func queueEvent(t *testing.T, pool *pgxpool.Pool, root *keys.RootKey, url string) {
	t.Helper()
	ctx := context.Background()
	orgID := seedOrg(t, pool)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sub, err := store.CreateSubscription(ctx, tx, root, orgID, "siem", "https://subscriber.example/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "login.failed", OrgID: orgID,
		CorrelationID: "6f1d4a2e-0000-4000-8000-000000000001"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.outbox SET payload = jsonb_set(payload, '{url}', to_jsonb($1::text))
		WHERE topic = 'event' AND delivered_at IS NULL AND payload->>'subscription_id' = $2`, url, sub.ID); err != nil {
		t.Fatal(err)
	}
}

// parkOtherEvents hides every event but those going to url.
func parkOtherEvents(t *testing.T, pool *pgxpool.Pool, url string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `UPDATE core.outbox SET next_attempt_at = now() + interval '1 hour'
		WHERE topic = 'event' AND delivered_at IS NULL AND payload->>'url' <> $1`, url); err != nil {
		t.Fatal(err)
	}
}

// The drain held one transaction across every call in a batch, each up to 15
// seconds. The row a delivery is in flight for is free, and another worker cannot
// have it: the lease is what the locks were doing.
func TestAnEventDeliveryHoldsNoTransactionAndIsNotTakenTwice(t *testing.T) {
	ctx := context.Background()
	pool := drainTestPool(t)
	root := testRoot(t)
	audit.SetPublisher(store.AuditPublisher)
	defer audit.SetPublisher(nil)
	swap(t)

	arrived := make(chan struct{}, 8)
	release := make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		arrived <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	url := srv.URL + "/hook"
	queueEvent(t, pool, root, url)
	parkOtherEvents(t, pool, url)

	first := webhookWorker(t, pool, root)
	done := make(chan error, 1)
	go func() {
		_, err := first.DrainWebhooks(ctx)
		done <- err
	}()
	select {
	case <-arrived:
	case <-time.After(30 * time.Second):
		close(release)
		t.Fatal("the subscriber was never called")
	}

	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var locked int64
	err := pool.QueryRow(probe, `SELECT id FROM core.outbox WHERE topic = 'event' AND payload->>'url' = $1
		FOR UPDATE NOWAIT`, url).Scan(&locked)
	if err != nil {
		t.Errorf("the row is held while a delivery is in flight: %v", err)
	}
	if n, err := webhookWorker(t, pool, root).DrainWebhooks(ctx); err != nil || n != 0 {
		t.Errorf("a second worker drained %d, %v", n, err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("the subscriber was called %d times for one event", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var delivered bool
	if err := pool.QueryRow(ctx, `SELECT delivered_at IS NOT NULL FROM core.outbox WHERE topic = 'event'
		AND payload->>'url' = $1`, url).Scan(&delivered); err != nil || !delivered {
		t.Errorf("after the drain the row reads delivered %v, %v", delivered, err)
	}
}

// One slow subscriber does not make the others wait: each of these answers only
// once all of them have arrived, which they cannot do one at a time.
func TestEventDeliveriesDoNotQueueBehindEachOther(t *testing.T) {
	ctx := context.Background()
	pool := drainTestPool(t)
	root := testRoot(t)
	audit.SetPublisher(store.AuditPublisher)
	defer audit.SetPublisher(nil)
	swap(t)

	const want = 3
	var arrived atomic.Int32
	everyone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if arrived.Add(1) == want {
			close(everyone)
		}
		select {
		case <-everyone:
			w.WriteHeader(http.StatusOK)
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	url := srv.URL + "/hook"
	for range want {
		queueEvent(t, pool, root, url)
	}
	parkOtherEvents(t, pool, url)
	n, err := webhookWorker(t, pool, root).DrainWebhooks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Errorf("delivered %d of %d, so they ran one after another", n, want)
	}
}

// A mass logout, measured rather than asserted, since a rate depends on the
// machine: `MEASURE_OUTBOX=1 go test ./internal/outbox -run MassLogout -v`.
func TestMassLogoutRate(t *testing.T) {
	if os.Getenv("MEASURE_OUTBOX") == "" {
		t.Skip("a measurement; MEASURE_OUTBOX=1 runs it")
	}
	pool := drainTestPool(t)
	clearOutbox(t, pool)
	t.Cleanup(func() { clearOutbox(t, pool) })
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	const notices = 5000
	if _, err := pool.Exec(context.Background(), `INSERT INTO core.outbox (topic, payload)
		SELECT 'backchannel_logout', jsonb_build_object('client_id', 'rp', 'endpoint', $1::text,
		       'sid', 'sid-' || g, 'reason', 'test') FROM generate_series(1, $2::int) g`, srv.URL, notices); err != nil {
		t.Fatal(err)
	}
	w := drainWorker(t, pool, 100)
	started := time.Now()
	w.drainAll(context.Background(), drainer{"logout notices", 100, w.drainOnce})
	took := time.Since(started)
	t.Logf("%d of %d notices in %s: %.0f a second", received.Load(), notices, took.Round(time.Millisecond),
		float64(received.Load())/took.Seconds())
}

func TestTheDrainersCoverEveryTopic(t *testing.T) {
	w := &Worker{batch: 7}
	got := map[string]bool{}
	for _, d := range w.drainers() {
		got[d.what] = true
		if d.drain == nil || d.batch == 0 {
			t.Errorf("%s has no drain or no batch", d.what)
		}
	}
	for _, want := range []string{"logout notices", "security events", "CIBA ping notifications",
		"CIBA token pushes", "events", "account notices"} {
		if !got[want] {
			t.Errorf("nothing drains %s", want)
		}
	}
	if s := fmt.Sprint(len(got)); s != "6" {
		t.Errorf("%s topics; a new one needs a row here", s)
	}
}
