package outbox

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// The whole event path, against a real database and a real HTTP receiver.
//
// The receiver listens on loopback -- the address the delivery client refuses --
// so these tests swap the client. That the DEFAULT still refuses loopback is
// asserted separately by TestTheDefaultClientRefusesLoopback; without it, this
// swap would be a way to quietly disable the SSRF guard.

func webhookWorker(t *testing.T, pool *pgxpool.Pool, root *keys.RootKey) *Worker {
	t.Helper()
	return &Worker{
		db: pool, root: root, issuer: "https://id.example.test",
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func testRoot(t *testing.T) *keys.RootKey {
	t.Helper()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	return root
}

// seedOrg makes an org to hang a subscription off.
func seedOrg(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	var instanceID, orgID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.instances (issuer, display_name) VALUES ($1,'wh')
		RETURNING id::text`,
		"https://wh-"+time.Now().Format("150405.000000000")+".test").Scan(&instanceID); err != nil {
		t.Fatalf("instance: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1,$2,'WH') RETURNING id::text`,
		instanceID, "wh"+itoa64(suffix)).Scan(&orgID); err != nil {
		t.Fatalf("org: %v", err)
	}
	return orgID
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// An audited event must reach a subscriber, signed, with no separate call.
func TestAnAuditedEventIsDeliveredAndVerifies(t *testing.T) {
	ctx := context.Background()
	pool := drainTestPool(t)
	root := testRoot(t)
	orgID := seedOrg(t, pool)

	var got atomic.Int32
	var gotSig, gotBody, gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotSig, gotBody, gotType = r.Header.Get(SignatureHeader), string(body),
			r.Header.Get("Signari-Event-Type")
		got.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// The subscription URL must be https by CHECK constraint, so it is written
	// with the right scheme and the delivery is pointed at the test server by
	// rewriting the row -- the constraint is what is being respected here, not
	// worked around.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sub, err := store.CreateSubscription(ctx, tx, root, orgID, "siem",
		"https://subscriber.example/hook", nil)
	if err != nil {
		t.Fatalf("creating the subscription: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sub.Secret, "whsec_") {
		t.Fatalf("secret = %q, want a whsec_ prefix", sub.Secret)
	}

	// Record an audited event. NOT a separate "publish" call: the fan-out lives
	// inside audit.Write, so a path that records an event cannot forget it.
	audit.SetPublisher(store.AuditPublisher)
	defer audit.SetPublisher(nil)

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "login.failed", OrgID: orgID, CorrelationID: "6f1d4a2e-0000-4000-8000-000000000001",
		Detail: map[string]any{"reason": "bad_password"},
	}); err != nil {
		t.Fatalf("writing the audit event: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Point the queued delivery at the test server -- THIS subscription's only.
	//
	// Scoped, because `go test ./...` runs packages in parallel and other tests
	// leave event rows in the same table. An unscoped update makes this test
	// deliver everybody's leftovers and report the wrong count, which passes
	// alone and fails in a full run. drain_test.go records the same trap.
	if _, err := pool.Exec(ctx,
		`UPDATE core.outbox SET payload = jsonb_set(payload,'{url}',to_jsonb($1::text))
		  WHERE topic = 'event' AND delivered_at IS NULL
		    AND payload->>'subscription_id' = $2`, srv.URL+"/hook", sub.ID); err != nil {
		t.Fatal(err)
	}
	// Park everything else so the drain sees only ours.
	if _, err := pool.Exec(ctx,
		`UPDATE core.outbox SET next_attempt_at = now() + interval '1 hour'
		  WHERE topic = 'event' AND delivered_at IS NULL
		    AND payload->>'subscription_id' <> $1`, sub.ID); err != nil {
		t.Fatal(err)
	}
	swap(t)
	w := webhookWorker(t, pool, root)
	n, err := w.DrainWebhooks(ctx)
	if err != nil {
		t.Fatalf("draining: %v", err)
	}
	if n != 1 || got.Load() != 1 {
		t.Fatalf("delivered %d, receiver saw %d, want 1 and 1", n, got.Load())
	}
	if gotType != "login.failed" {
		t.Fatalf("event type header = %q", gotType)
	}

	// Verify exactly as docs/events.md tells a subscriber to.
	var ts, v1 string
	for _, part := range strings.Split(gotSig, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			v1 = v
		}
	}
	mac := hmac.New(sha256.New, []byte(sub.Secret))
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write([]byte(gotBody))
	if want := hex.EncodeToString(mac.Sum(nil)); v1 != want {
		t.Fatalf("the delivered signature does not verify with the secret we were "+
			"given: got %s want %s", v1, want)
	}

	var env store.EventEnvelope
	if err := json.Unmarshal([]byte(gotBody), &env); err != nil {
		t.Fatalf("the body is not the documented envelope: %v", err)
	}
	if env.Type != "login.failed" || env.OrgID != orgID || env.Version != 1 {
		t.Fatalf("envelope = %+v", env)
	}
	if !strings.HasPrefix(env.ID, "ev_") {
		t.Fatalf("event id = %q, want an ev_ prefix -- a sequential internal id "+
			"would tell every subscriber how busy the whole deployment is", env.ID)
	}

	// The delivery row must say so, or "did they get it" has no answer.
	var delivered bool
	var status int
	if err := pool.QueryRow(ctx, `
		SELECT delivered_at IS NOT NULL, COALESCE(status_code,0)
		  FROM core.event_deliveries WHERE subscription_id = $1::uuid`,
		sub.ID).Scan(&delivered, &status); err != nil {
		t.Fatal(err)
	}
	if !delivered || status != 200 {
		t.Fatalf("delivery row: delivered=%v status=%d", delivered, status)
	}
}

// A subscriber that keeps failing is parked and its subscription switched off,
// with the reason -- not retried forever into a growing table.
func TestARepeatedlyFailingSubscriberIsDisabledWithItsReason(t *testing.T) {
	ctx := context.Background()
	pool := drainTestPool(t)
	root := testRoot(t)
	orgID := seedOrg(t, pool)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// 410 Gone. NOT treated as an unsubscribe: letting a status code turn
		// events off lets anyone who can answer that URL do it.
		w.WriteHeader(410)
	}))
	defer srv.Close()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sub, err := store.CreateSubscription(ctx, tx, root, orgID, "gone",
		"https://subscriber.example/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishEvent(ctx, tx, store.EventEnvelope{
		Version: 1, ID: "ev_test", Type: "login.failed", OrgID: orgID,
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE core.outbox SET payload = jsonb_set(payload,'{url}',to_jsonb($1::text))
		 WHERE topic = 'event' AND delivered_at IS NULL
		   AND payload->>'subscription_id' = $2`, srv.URL+"/hook", sub.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE core.outbox SET next_attempt_at = now() + interval '1 hour'
		  WHERE topic = 'event' AND delivered_at IS NULL
		    AND payload->>'subscription_id' <> $1`, sub.ID); err != nil {
		t.Fatal(err)
	}
	swap(t)
	w := webhookWorker(t, pool, root)

	// Drive it to the limit. Backoff is reset each round so the test does not
	// wait a day for the behaviour it is checking.
	for i := 0; i < MaxWebhookAttempts; i++ {
		if _, err := w.DrainWebhooks(ctx); err != nil {
			t.Fatalf("drain %d: %v", i, err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE core.outbox SET next_attempt_at = now()
			  WHERE topic='event' AND delivered_at IS NULL
			    AND payload->>'subscription_id' = $1
			    AND next_attempt_at < now() + interval '50 years'`, sub.ID); err != nil {
			t.Fatal(err)
		}
	}

	var enabled bool
	var why string
	if err := pool.QueryRow(ctx, `
		SELECT enabled, COALESCE(disabled_reason,'')
		  FROM core.event_subscriptions WHERE id = $1::uuid`, sub.ID).
		Scan(&enabled, &why); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatalf("still enabled after %d failures; events queue forever and the "+
			"table grows until somebody notices for the wrong reason", MaxWebhookAttempts)
	}
	if !strings.Contains(why, "410") {
		t.Fatalf("disabled_reason = %q, want it to name the failure", why)
	}

	// Parked, not deleted: a delivery that was given up on is an operational
	// fact somebody has to be able to see.
	var parked bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.outbox
		  WHERE topic='event' AND delivered_at IS NULL
		    AND next_attempt_at > now() + interval '50 years')`).Scan(&parked); err != nil {
		t.Fatal(err)
	}
	if !parked {
		t.Fatal("the give-up delivery was not parked")
	}
}

// swap points deliveries at a client that will talk to loopback, for the
// duration of one test.
func swap(t *testing.T) {
	t.Helper()
	prev := webhookClient
	webhookClient = func() *http.Client { return &http.Client{Timeout: 5 * time.Second} }
	t.Cleanup(func() { webhookClient = prev })
}
