package outbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/ssf"
)

// ssfStream registers a push stream with the given status for a fresh client,
// and returns the stream's id and the client's. The endpoint on the row is a
// placeholder the schema accepts; delivery goes to the endpoint in the payload.
func ssfStream(t *testing.T, pool *pgxpool.Pool, status string) (streamID, clientID string) {
	t.Helper()
	ctx := context.Background()
	var org string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation to register a stream in: %v", err)
	}
	clientID = fmt.Sprintf("ssfst-%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash)
		VALUES ($1, $2::uuid, 'ssf status', 'confidential', 'x')`, clientID, org); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.ssf_streams (org_id, client_id, delivery_method, endpoint_url, events_requested, status)
		VALUES ($1::uuid, $2, 'push', 'https://rp.test/events', ARRAY[$3], $4) RETURNING id::text`,
		org, clientID, ssf.EventSessionRevoked, status).Scan(&streamID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM core.outbox WHERE topic = 'ssf_event' AND payload->>'stream_id' = $1`, streamID)
		_, _ = pool.Exec(ctx, `DELETE FROM core.clients WHERE client_id = $1`, clientID)
	})
	return streamID, clientID
}

// queueSSF puts one event for a stream in the outbox and returns its row id.
func queueSSF(t *testing.T, pool *pgxpool.Pool, payload map[string]string) int64 {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO core.outbox (topic, payload) VALUES ('ssf_event', $1) RETURNING id`, raw).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// A paused stream delivers its stream-updated notice and holds everything else,
// and a disabled one drops what it held (2.29). The status was read only when an
// event was queued, so one queued a moment before a pause was still sent: "The
// Transmitter MUST NOT transmit events over the stream" (specs/ssf-1_0.txt:2592).
func TestAPausedStreamSendsOnlyItsStatusNotice(t *testing.T) {
	pool := drainTestPool(t)
	ctx := context.Background()

	var mu sync.Mutex
	var received []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parts := strings.Split(string(body), ".")
		if len(parts) == 3 {
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]any
			_ = json.Unmarshal(raw, &claims)
			mu.Lock()
			received = append(received, claims)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	types := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, c := range received {
			for k := range c["events"].(map[string]any) {
				out = append(out, k)
			}
		}
		return out
	}
	row := func(id int64) (delivered bool, attempts int, lastError string, later bool) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT delivered_at IS NOT NULL, attempts, coalesce(last_error, ''),
			next_attempt_at > now() FROM core.outbox WHERE id = $1`, id).Scan(&delivered, &attempts, &lastError, &later); err != nil {
			t.Fatal(err)
		}
		return
	}
	w := drainWorker(t, pool, 500)
	drain := func(until func() bool) {
		t.Helper()
		for round := 0; round < 30 && !until(); round++ {
			if _, err := w.DrainSSF(ctx); err != nil {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	streamID, clientID := ssfStream(t, pool, "paused")
	revoked := queueSSF(t, pool, map[string]string{"stream_id": streamID, "client_id": clientID,
		"endpoint": srv.URL, "event": ssf.EventSessionRevoked, "subject": "user-1", "sid": "sid-1", "reason": "test"})
	queueSSF(t, pool, map[string]string{"stream_id": streamID, "client_id": clientID,
		"endpoint": srv.URL, "event": ssf.StreamUpdated, "status": "paused", "reason": "maintenance"})

	drain(func() bool { d, _, e, _ := row(revoked); return len(types()) > 0 && (d || e != "") })
	if got := types(); len(got) != 1 || got[0] != ssf.StreamUpdated {
		t.Fatalf("a paused stream sent %v, want only its stream-updated notice", got)
	}
	mu.Lock()
	notice := received[0]
	mu.Unlock()
	sub, _ := notice["sub_id"].(map[string]any)
	event, _ := notice["events"].(map[string]any)[ssf.StreamUpdated].(map[string]any)
	if sub["format"] != "opaque" || sub["id"] != streamID || event["status"] != "paused" || event["reason"] != "maintenance" {
		t.Errorf("the notice says sub_id %v and %v; want the stream as an opaque subject, paused, with the reason",
			sub, event)
	}
	if d, attempts, e, later := row(revoked); d || attempts != 0 || !strings.HasPrefix(e, "held") || !later {
		t.Errorf("the paused stream's event: delivered %v, attempts %d, last_error %q, waiting %v; "+
			"want held, uncharged, and waiting", d, attempts, e, later)
	}

	// Disabled: what it held is dropped, never sent.
	if _, err := pool.Exec(ctx, `UPDATE core.ssf_streams SET status = 'disabled' WHERE id = $1::uuid`, streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.outbox SET next_attempt_at = now() WHERE id = $1`, revoked); err != nil {
		t.Fatal(err)
	}
	drain(func() bool { d, _, _, _ := row(revoked); return d })
	if d, _, e, _ := row(revoked); !d || e != "stream disabled" {
		t.Errorf("a disabled stream's held event: closed %v, last_error %q; want closed as disabled", d, e)
	}
	if got := types(); len(got) != 1 {
		t.Errorf("a disabled stream sent %v", got)
	}

	// Enabled: sent.
	if _, err := pool.Exec(ctx, `UPDATE core.ssf_streams SET status = 'enabled' WHERE id = $1::uuid`, streamID); err != nil {
		t.Fatal(err)
	}
	sent := queueSSF(t, pool, map[string]string{"stream_id": streamID, "client_id": clientID,
		"endpoint": srv.URL, "event": ssf.EventSessionRevoked, "subject": "user-1", "sid": "sid-2", "reason": "test"})
	drain(func() bool { d, _, _, _ := row(sent); return d })
	if got := types(); len(got) != 2 || got[1] != ssf.EventSessionRevoked {
		t.Errorf("an enabled stream sent %v, want the revocation after the notice", got)
	}
}
