package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"signari.dev/engine/internal/metrics"
)

// Every call says how it ended, and every failure what its mode decided, to
// the observer the metrics install (3.08). A provider failing open is a
// control quietly not applied, and a log line per call was the only sign.
func TestEveryCallTellsTheObserverHowItEnded(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	SetObserver(func(h Hook, outcome string) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, string(h)+":"+outcome)
	})
	t.Cleanup(func() { SetObserver(nil) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(`{"decision": true}`))
		case "/broken":
			w.WriteHeader(http.StatusInternalServerError)
		case "/garbled":
			_, _ = w.Write([]byte(`{not json`))
		case "/slow":
			time.Sleep(300 * time.Millisecond)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	call := func(path string, timeout time.Duration) error {
		p := good()
		p.URL, p.Timeout = srv.URL+path, timeout
		var out map[string]any
		return p.Call(context.Background(), srv.Client(), struct{}{}, &out)
	}
	if err := call("/ok", time.Second); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/broken", "/garbled"} {
		if err := call(path, time.Second); err == nil {
			t.Fatalf("%s answered", path)
		}
	}
	if err := call("/slow", 50*time.Millisecond); err == nil {
		t.Fatal("a provider slower than its timeout answered")
	}
	unreachable := good()
	unreachable.URL = "http://127.0.0.1:1/decide"
	var out map[string]any
	if err := unreachable.Call(context.Background(), http.DefaultClient, struct{}{}, &out); err == nil {
		t.Fatal("a closed port answered")
	}

	open, closed := good(), good()
	open.Mode = FailOpen
	if !open.Decide(errors.New("down")) || closed.Decide(errors.New("down")) || !closed.Decide(nil) {
		t.Fatal("Decide does not apply the modes")
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"authorize:answered", "authorize:bad_status", "authorize:bad_answer",
		"authorize:timeout", "authorize:unreachable", "authorize:failed_open", "authorize:failed_closed"}
	if len(seen) != len(want) {
		t.Fatalf("the observer saw %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("outcome %d: %s, want %s", i, seen[i], want[i])
		}
	}
	// And every one is a value the counter declares, or it is exported as
	// "other" and the outcome is lost.
	for _, s := range seen {
		outcome := strings.SplitN(s, ":", 2)[1]
		if !slices.Contains(metrics.ProviderOutcomes, outcome) {
			t.Errorf("outcome %q is not in metrics.ProviderOutcomes", outcome)
		}
	}
}
