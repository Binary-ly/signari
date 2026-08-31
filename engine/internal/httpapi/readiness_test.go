package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Liveness and readiness answer different questions and must fail differently.
//
// # The outage this shape prevents
//
// If /healthz touched the database, a database blip would fail liveness on every
// replica at once. An orchestrator would restart the whole fleet — replacing a
// degraded service that was going to recover with a cold one that cannot start,
// because the thing it needs in order to come up is the thing that is down. The
// blast radius of a five-minute database hiccup becomes a full outage plus a
// cold start.
//
// So the rule is: liveness says "is this process wedged", readiness says "should
// traffic come here", and only the second one is allowed to depend on anything
// external.

func readinessServer(t *testing.T) *Server {
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
	return &Server{db: pool, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestReadinessReportsReadyWhenTheDatabaseAnswers(t *testing.T) {
	s := readinessServer(t)
	rec := httptest.NewRecorder()
	s.handleReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("gave %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
}

// Once draining, readiness fails while the listener is still up.
//
// This is the half that makes graceful shutdown actually graceful. Without it,
// the socket closes before anything upstream has noticed the node is going away,
// and every request routed here in between is refused — the drain window becomes
// the error window.
func TestADrainingNodeReportsNotReady(t *testing.T) {
	s := readinessServer(t)

	rec := httptest.NewRecorder()
	s.handleReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("not ready before draining even began: %d %s", rec.Code, rec.Body.String())
	}

	s.BeginDraining()

	rec = httptest.NewRecorder()
	s.handleReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a draining node answered %d, want 503. A load balancer would "+
			"keep routing to a process that is about to stop listening.", rec.Code)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "draining" {
		t.Errorf("status = %q, want draining -- the reason matters to whoever "+
			"is reading the probe during a deploy", body.Status)
	}
}

// Liveness must not consult the database, and draining must not affect it.
//
// A draining process is not a wedged process: it is doing exactly what it was
// asked to do. Failing liveness during a drain invites the orchestrator to
// SIGKILL it in the middle of the graceful shutdown that is in progress.
func TestLivenessIgnoresTheDatabaseAndTheDrain(t *testing.T) {
	// No database at all: a Server literal with a nil pool. If /healthz ever
	// grows a database call this test panics rather than quietly passing.
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness gave %d with no database. It must report on the "+
			"process only -- a database-dependent liveness check turns an "+
			"outage into a fleet-wide restart loop.", rec.Code)
	}

	s.BeginDraining()
	rec = httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness gave %d while draining. A draining process is not a "+
			"wedged one, and failing here invites a SIGKILL in the middle of "+
			"the graceful shutdown it is performing.", rec.Code)
	}
}

// Both probes are routed, not merely implemented.
func TestTheProbesAreRouted(t *testing.T) {
	s := readinessServer(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		s.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s is not registered", path)
		}
	}
}
