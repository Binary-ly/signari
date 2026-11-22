package signari

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A request the Admin API turned away at its arrival limit is sent again, as
// Retry-After asks, the same body each time: the limit answers before it
// authenticates, so nothing was done. An apply of a few dozen objects met it
// and failed on a request the server never read.
func TestARequestTurnedAwayAtTheDoorIsSentAgain(t *testing.T) {
	var waits []time.Duration
	real := retryWait
	retryWait = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	t.Cleanup(func() { retryWait = real })

	var bodies []string
	refuse := 2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b)+" "+r.Header.Get("If-Match"))
		if refuse > 0 {
			refuse--
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		w.Header().Set("ETag", `"8"`)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := &Client{Endpoint: srv.URL, Token: "t"}

	v, err := c.Write(context.Background(), http.MethodPatch, "/admin/groups/g", map[string]string{"a": "b"}, 7)
	if err != nil || v != 8 {
		t.Fatalf("the write answered %d, %v", v, err)
	}
	if len(bodies) != 3 || bodies[0] != bodies[2] || bodies[2] != `{"a":"b"} "7"` {
		t.Errorf("sent %q, want the same body and precondition three times", bodies)
	}
	if len(waits) != 2 || waits[0] != 3*time.Second {
		t.Errorf("waited %v, want the server's 3s twice", waits)
	}

	// It gives up, and says why, rather than waiting for ever.
	refuse = 1000
	waits = nil
	_, err = c.Write(context.Background(), http.MethodPatch, "/admin/groups/g", nil, 0)
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusTooManyRequests || len(waits) != arrivalRetries {
		t.Errorf("after %d waits it answered %v", len(waits), err)
	}
}
