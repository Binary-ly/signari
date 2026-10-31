package outbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// A push stream's verification goes the way its events go: queued by the store,
// sent by the worker, and at the endpoint on the stream's own row.
func TestAPushStreamsVerificationReachesItsReceiver(t *testing.T) {
	pool := drainTestPool(t)
	ctx := context.Background()

	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parts := strings.Split(string(body), ".")
		if len(parts) == 3 {
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]any
			_ = json.Unmarshal(raw, &claims)
			got <- claims
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	streamID, clientID := ssfStream(t, pool, "enabled")
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.QueueVerification(ctx, tx, clientID, streamID, "the-state"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// The stream's address is https, as the schema demands, and the test server's
	// is not, so the queued copy is pointed at it; delivery reads the copy.
	if _, err := pool.Exec(ctx, `UPDATE core.outbox SET payload = jsonb_set(payload, '{endpoint}', to_jsonb($2::text))
		WHERE topic = 'ssf_event' AND payload->>'stream_id' = $1`, streamID, srv.URL); err != nil {
		t.Fatal(err)
	}

	w := drainWorker(t, pool, 500)
	for round := 0; round < 30; round++ {
		if _, err := w.DrainSSF(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case claims := <-got:
			sub, _ := claims["sub_id"].(map[string]any)
			if sub["format"] != "opaque" || sub["id"] != streamID {
				t.Errorf("sub_id is %v, want the stream as an opaque subject", sub)
			}
			event, ok := claims["events"].(map[string]any)[ssf.Verification].(map[string]any)
			if !ok || event["state"] != "the-state" {
				t.Errorf("events are %v, want a verification carrying the state", claims["events"])
			}
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("nothing reached the receiver")
}
