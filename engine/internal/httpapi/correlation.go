package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/sulimanbenhalim/signari/engine/internal/audit"
)

type correlationKey struct{}

// WithCorrelation assigns every request an id and puts it on the context.
//
// One id ties the log lines, the audit rows and the code shown to the user
// together. The point is the last of those: when someone says "it said
// 7QF-2K9", support can pull the entire decision trace for that request instead
// of asking what time it was and guessing. Nothing in this field does that
// today, and it costs a uuid per request.
func (s *Server) withCorrelation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately NOT taken from an inbound header. A caller-supplied
		// correlation id lets one client forge entries that appear to belong to
		// another's request trace, and there is no upstream here whose id we
		// need to preserve.
		id := newCorrelationID()
		if id == "" {
			// No entropy. Serving a request we cannot trace is worse than
			// failing it loudly on a machine that has bigger problems.
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		ctx := context.WithValue(r.Context(), correlationKey{}, id)

		// Echoed so an operator reading a proxy log or a client's network trace
		// can find the same request. Safe to expose: it identifies a request,
		// not a principal, and it is unguessable.
		w.Header().Set("X-Correlation-Id", id)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// correlationID returns the id for this request, or "" outside a request.
func correlationID(ctx context.Context) string {
	if v, ok := ctx.Value(correlationKey{}).(string); ok {
		return v
	}
	return ""
}

// shortCode renders a correlation id as something a person can read aloud.
//
// Nine characters from an alphabet with no 0/O or 1/I/L, grouped in threes. A
// user reading a uuid over the phone will get it wrong; this is the difference
// between a support call that can look up the request and one that cannot.
//
// It is a display form of the full id, not a replacement: the id is what is
// stored and searched. The short code narrows a search to a handful of rows,
// which is all support needs to start.
func shortCode(id string) string {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	if id == "" {
		return ""
	}
	// Derived from the id so the same request always yields the same code,
	// rather than being independently random and needing its own column.
	out := make([]byte, 0, 11)
	for i, b := range []byte(id) {
		if i >= 9 {
			break
		}
		if i > 0 && i%3 == 0 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(b)%len(alphabet)])
	}
	return string(out)
}

// auditDetached writes an audit event in its own transaction.
//
// For decision points that have no transaction of their own -- a failed login
// writes nothing else, so there is nothing to join. Everywhere a transaction
// DOES exist, audit.Write must join it instead: an audit row that commits
// independently of the decision it describes can outlive a rollback and become
// a record of something that never happened.
//
// A failure here is logged, not returned. The operation these accompany has
// already been refused, so there is no outcome left to fail.
func (s *Server) auditDetached(ctx context.Context, e audit.Event) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.log.Error("auditing", "event", e.Type, "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := audit.Write(ctx, tx, e); err != nil {
		s.log.Error("auditing", "event", e.Type, "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("committing audit", "event", e.Type, "err", err)
	}
}

// newCorrelationID returns a RFC 4122 version 4 uuid.
//
// Written out rather than pulled from a dependency: the column is a uuid, this
// is sixteen random bytes with six bits set, and a module for that is a supply
// chain edge on a security product for no benefit.
func newCorrelationID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
