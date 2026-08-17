package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// Wiring the audit trail to event subscriptions.
//
// Kept in its own file, and installed with audit.SetPublisher at startup, so the
// audit package does not have to import this one -- the tables it writes are
// read from here, and a direct call would be a cycle.

// AuditPublisher is the fan-out audit.Write calls.
//
// Every audited event is publishable. Filtering happens per subscription, not
// here: an operator deciding which events they want is a configuration
// question, and deciding it in code means the answer is whatever somebody
// happened to add to a list.
func AuditPublisher(ctx context.Context, tx pgx.Tx, e audit.Event, detail string) error {
	var d map[string]any
	if detail != "" {
		// Best effort. A detail blob that will not parse is not a reason to drop
		// the event -- the type, subject and time are the parts subscribers
		// mostly act on.
		_ = json.Unmarshal([]byte(detail), &d)
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}

	_, err := PublishEvent(ctx, tx, EventEnvelope{
		Version: 1,
		// The event's OWN id, not the audit row's. A subscriber uses it to be
		// idempotent, and exposing a sequential internal id would tell every
		// subscriber how much activity the whole deployment has.
		ID:            "ev_" + hex.EncodeToString(id),
		Type:          e.Type,
		OccurredAt:    time.Now().UTC().Format(time.RFC3339),
		OrgID:         e.OrgID,
		SubjectID:     e.SubjectID,
		CorrelationID: e.CorrelationID,
		Detail:        d,
	})
	return err
}
