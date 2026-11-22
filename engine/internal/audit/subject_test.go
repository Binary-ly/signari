package audit

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A subject that is a client, not a person, is recorded rather than lost. An
// exchanged or transaction token for a client's own token named the client as
// the subject, the uuid cast failed, and the record was never written.
func TestAClientAsSubjectIsRecordedInTheDetail(t *testing.T) {
	inRollback(t, func(tx pgx.Tx) {
		ctx := context.Background()
		from := tail(t, tx)
		detail := map[string]any{"scope": "api.read"}
		if err := Write(ctx, tx, Event{Type: "oauth.token_exchanged", SubjectID: "billing-service",
			ClientID: "gateway", Detail: detail}); err != nil {
			t.Fatalf("an event whose subject is a client was not written: %v", err)
		}
		if _, ok := detail["subject"]; ok {
			t.Error("the caller's detail map was changed")
		}
		var subject *string
		var kept string
		if err := tx.QueryRow(ctx, `SELECT subject_id::text, detail->>'subject' FROM core.audit_events
			WHERE client_id = 'gateway' AND event_type = 'oauth.token_exchanged'
			ORDER BY occurred_at DESC, id DESC LIMIT 1`).Scan(&subject, &kept); err != nil {
			t.Fatal(err)
		}
		if subject != nil || kept != "billing-service" {
			t.Errorf("stored subject_id %v and detail subject %q, want none and the client", subject, kept)
		}
		if broken, _, err := VerifyFrom(ctx, tx, from); err != nil || broken != 0 {
			t.Errorf("the chain does not verify over it: broken at %d, %v", broken, err)
		}
	})
}
