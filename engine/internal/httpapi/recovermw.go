package httpapi

import (
	"fmt"
	"net/http"
	"runtime/debug"
)

// The last-resort error handler — OWASP ASVS 5.0.0 V16.5.4.
//
//	"Verify that a 'last resort' error handler is defined which will catch all
//	unhandled exceptions. This is both to avoid losing error details that must go
//	to log files and to ensure that an error does not take down the entire
//	application process, leading to a loss of availability."
//
// # What Go already did, and why it was not enough
//
// `recover()` appeared nowhere in this engine, and the reason that was survivable
// is that `net/http` recovers panics itself: `conn.serve` has a deferred recover
// that logs the panic and closes the connection. The process does not die, so the
// availability half of V16.5.4 was already met.
//
// The other half was not, and it fails in the way that costs most:
//
//   - The panic is written by Go's `log` package to stderr, in Go's own format.
//     This server logs through `slog` with a configured handler. So the one event
//     an operator most needs to find is the one entry their log processor cannot
//     parse — V16.2.4, "logs can be read and correlated by the log processor that
//     is in use".
//   - It carries no correlation id, so it cannot be tied to the request that
//     caused it, or to the audit rows and access-log lines for that request —
//     V16.2.1, the "when, where, who, what" that "would allow for a detailed
//     investigation of the timeline".
//   - The client receives a dropped connection rather than a response. There is
//     nothing to quote to support, and a relying party sees a transport error
//     rather than a server error, which sends the investigation to the network.
//
// # What is deliberately not done
//
// The panic value is never sent to the client. V16.5.1 requires "a generic
// message... ensuring no exposure of sensitive internal system data such as stack
// traces, queries, secret keys, and tokens", and a panic message in this codebase
// can contain any of those — a pgx error carries the SQL it was running. The
// client gets the reference code; the log gets the detail. That pairing is the
// whole point of the correlation id.
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := &startedWriter{ResponseWriter: w}

		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// net/http's own signal for "abandon this response silently". It is
			// not an error and must be passed through, or aborting a hijacked or
			// streamed response starts logging false panics.
			if rec == http.ErrAbortHandler {
				panic(rec)
			}

			id := correlationID(r.Context())
			s.log.Error("a handler panicked",
				"err", fmt.Sprint(rec),
				"method", r.Method,
				// The path, NOT the raw URL: a query string here can hold a
				// `code`, a `state` or a `login_hint`, and V16.2.5 governs what
				// may be written even when the writer is an error path.
				"path", r.URL.Path,
				"correlation_id", id,
				"stack", string(debug.Stack()))

			// If the handler already began the response, the status is on the
			// wire and cannot be changed. Writing again would append a JSON body
			// to a half-written one and produce a response that parses as
			// neither. The log entry above is the whole of what can be done.
			if started.wrote {
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error",
				"the request could not be completed. Reference: "+shortCode(id))
		}()

		next.ServeHTTP(started, r)
	})
}

// startedWriter records whether the response has begun.
type startedWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *startedWriter) WriteHeader(code int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *startedWriter) Write(b []byte) (int, error) {
	// An implicit 200 counts as started, which is the case that matters: a
	// handler that panics midway through streaming a body has already committed
	// its status without ever calling WriteHeader.
	w.wrote = true
	return w.ResponseWriter.Write(b)
}
