package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"signari.dev/engine/internal/ratelimit"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
)

// ASVS 5.0.0 V16.5.4, the last-resort error handler.
//
// `recover()` appeared nowhere in this engine. net/http recovers panics itself,
// so nothing crashed -- which is exactly why the gap was invisible: the process
// survived, and the evidence went to stderr in a format this server's log
// processor does not read, with no correlation id on it.

func recoveryServer(t *testing.T, buf *bytes.Buffer, panicWith any) http.Handler {
	t.Helper()
	s := &Server{
		log: slog.New(slog.NewJSONHandler(buf, nil)),
		cfg: oidc.Config{Issuer: "https://recover.test"},
	}
	return s.withCorrelation(s.withRecovery(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { panic(panicWith) })))
}

func TestAPanickingHandlerAnswersAndIsLoggedInThisServersFormat(t *testing.T) {
	var buf bytes.Buffer
	h := recoveryServer(t, &buf, "the database driver exploded: SELECT secret FROM core.clients")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything?state=abc123", nil))

	// The caller gets an answer, not a dropped connection.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: without a last-resort handler the client "+
			"sees a transport error and the investigation starts at the network",
			rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the response is not JSON: %q", rec.Body.String())
	}

	// V16.5.1: a generic message, with "no exposure of sensitive internal system
	// data such as stack traces, queries, secret keys, and tokens". A pgx error
	// carries the SQL it was running, so the panic value must not reach here.
	whole := rec.Body.String()
	for _, leak := range []string{"SELECT", "core.clients", "exploded", "goroutine", ".go:"} {
		if strings.Contains(whole, leak) {
			t.Errorf("the response body leaks %q to the caller: %s", leak, whole)
		}
	}
	// It must still be actionable: the reference is what ties the caller's
	// complaint to the log entry holding the detail.
	if !strings.Contains(body["error_description"], "Reference:") {
		t.Errorf("no reference code in %q; the caller has nothing to quote to "+
			"support, so the log entry below cannot be found from their end",
			body["error_description"])
	}

	// V16.2.4 / V16.2.1: the entry must be in this server's structured format
	// and must carry the correlation id, or it cannot be tied to the request.
	logged := buf.String()
	if logged == "" {
		t.Fatal("the panic was not logged by this server at all")
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(logged, "\n", 2)[0]), &entry); err != nil {
		t.Fatalf("the log entry is not in the configured format: %q", logged)
	}
	if entry["correlation_id"] == nil || entry["correlation_id"] == "" {
		t.Error("the panic entry carries no correlation_id, so it cannot be " +
			"joined to the access log or audit rows for the same request")
	}
	if entry["stack"] == nil {
		t.Error("no stack in the log entry: V16.5.4 exists to avoid losing the " +
			"error details that must go to log files")
	}
	// V16.2.5: the query string can hold `code`, `state` or `login_hint`.
	if s, _ := entry["path"].(string); strings.Contains(s, "state=") {
		t.Errorf("the logged path carries the query string: %q", s)
	}
}

// http.ErrAbortHandler is net/http's signal to abandon a response silently. It
// must pass through, or aborting a streamed response starts logging false
// panics and answering 500 over a body already on the wire.
func TestErrAbortHandlerIsNotTreatedAsAPanic(t *testing.T) {
	var buf bytes.Buffer
	h := recoveryServer(t, &buf, http.ErrAbortHandler)

	defer func() {
		if rec := recover(); rec != http.ErrAbortHandler {
			t.Errorf("ErrAbortHandler was swallowed (got %v); net/http never sees "+
				"its own abort signal and the response is answered instead", rec)
		}
		if strings.Contains(buf.String(), "a handler panicked") {
			t.Error("an intentional abort was logged as a panic")
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

// A handler that panics AFTER committing its status must not have a second
// response appended: the status is already on the wire, and writing again
// produces a body that parses as neither one thing nor the other.
func TestAPanicAfterTheResponseStartedDoesNotAppendASecondBody(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{
		log: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		cfg: oidc.Config{Issuer: "https://recover.test"},
	}
	h := s.withCorrelation(s.withRecovery(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"partial":true`))
			panic("halfway through")
		})))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; it was committed as 200 before the panic and "+
			"cannot be changed afterwards", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "server_error") {
		t.Errorf("a second body was appended to a started response: %q", rec.Body.String())
	}
	_ = buf
}

// The handler being correct and the handler being REACHABLE are different
// claims, and the tests above only establish the first: each builds the
// middleware chain by hand. A recovery handler that is not in Routes() catches
// nothing, and every test above would still pass.
//
// This drives a real route through the real chain. A Server with no database
// panics inside the sign-in page when it loads its branding, which is a genuine
// unhandled panic from a genuine handler rather than one this test injected.
func TestRecoveryIsWiredIntoTheRouter(t *testing.T) {
	s := &Server{
		log:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		login: ratelimit.New(5, 20),
		cfg:   oidc.Config{Issuer: "https://recover.test"},
	}

	rec := httptest.NewRecorder()
	// If recovery is not in the chain this call panics out of ServeHTTP and the
	// test fails as a panic rather than an assertion, which is the correct
	// failure: it is exactly what a client's connection would do.
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 from the last-resort handler", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Reference:") {
		t.Errorf("no reference code in the answer: %q", rec.Body.String())
	}
	// The security headers must survive the panic. They are set before the
	// handler runs, so a 500 built afterwards still carries them -- and an error
	// response is not a good place to start omitting them.
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q on the error response", got)
	}
}
