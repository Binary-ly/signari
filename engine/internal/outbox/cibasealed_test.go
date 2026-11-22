package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// A parked CIBA delivery holds the client's notification token and the
// auth_req_id sealed, and the worker opens them at delivery. Driven from a row
// the store really parked, because the property is the round trip: sealed by
// the request, opened by the worker, and in the clear only on the wire.
func TestASealedPingIsDeliveredWithItsCredentials(t *testing.T) {
	pool := drainTestPool(t)
	ctx := context.Background()
	w, root := pushWorker(t)

	var gotAuth string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	requestID := fmt.Sprintf("00000000-0000-4000-8000-%012d", time.Now().UnixNano()%1e12)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM core.outbox WHERE topic = 'ciba_ping' AND subject_key = $1`, requestID)
	})
	if err := store.QueueCIBAPing(ctx, pool, root, requestID, "c1", srv.URL,
		"notify-token-xyz", "auth-req-xyz"); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT payload FROM core.outbox
		WHERE topic = 'ciba_ping' AND subject_key = $1`, requestID).Scan(&raw); err != nil {
		t.Fatal(err)
	}

	if err := w.deliverCIBAPingRow(ctx, raw); err != nil {
		t.Fatalf("delivering the parked ping: %v", err)
	}
	if gotAuth != "Bearer notify-token-xyz" {
		t.Errorf("Authorization = %q, want the client's notification token", gotAuth)
	}
	if gotBody["auth_req_id"] != "auth-req-xyz" {
		t.Errorf("body = %v, want the auth_req_id the client holds", gotBody)
	}

	// A worker holding another key opens nothing and sends nothing.
	gotAuth = ""
	other, err := keys.NewRootKey("other", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	w.root = other
	if err := w.deliverCIBAPingRow(ctx, raw); err == nil || gotAuth != "" {
		t.Errorf("a worker on another root key delivered (err %v, auth %q)", err, gotAuth)
	}
}

// A row parked by a build before the credentials were sealed carries them in
// the clear, and still delivers: a pending request must not be stranded by an
// upgrade.
func TestAPingParkedBeforeSealingStillDelivers(t *testing.T) {
	w, _ := pushWorker(t)
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	legacy := fmt.Sprintf(`{"endpoint":%q,"token":"old-token","auth_req_id":"old-ar","client_id":"c1"}`, srv.URL)
	if err := w.deliverCIBAPingRow(context.Background(), []byte(legacy)); err != nil {
		t.Fatalf("a pre-sealing row did not deliver: %v", err)
	}
	if gotAuth != "Bearer old-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}

	// And a row with neither is refused, not sent with an empty bearer.
	empty := fmt.Sprintf(`{"endpoint":%q,"client_id":"c1"}`, srv.URL)
	gotAuth = ""
	if err := w.deliverCIBAPingRow(context.Background(), []byte(empty)); err == nil || gotAuth != "" {
		t.Errorf("a row with no credentials was delivered (err %v, auth %q)", err, gotAuth)
	}
}
