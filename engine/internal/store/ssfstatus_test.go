package store

import (
	"context"
	"errors"
	"testing"

	"signari.dev/engine/internal/ssf"
)

// A stream's status changes as SSF 1.0 §8.1.2.1 and §8.1.5 require (2.29):
// the receiver is told when the stream leaves or returns to enabled, a paused
// stream holds what it would have sent, and a disabled one holds nothing. No
// command could change the status at all before.
func TestAStreamStatusChangeTellsTheReceiverAndHoldsOrDrops(t *testing.T) {
	for _, method := range []string{"push", "poll"} {
		t.Run(method, func(t *testing.T) {
			ctx := context.Background()
			conn := connect(t)
			orgID, _, clientID, sid := fixture(t, conn)
			tx, err := conn.Begin(ctx)
			must(t, err)
			defer func() { _ = tx.Rollback(ctx) }()

			var endpoint *string
			if method == "push" {
				e := "https://rp.test/events"
				endpoint = &e
			}
			var streamID string
			must(t, tx.QueryRow(ctx, `
				INSERT INTO core.ssf_streams (org_id, client_id, delivery_method, endpoint_url,
				                              events_requested, status)
				VALUES ($1, $2, $3, $4, ARRAY[$5], 'enabled') RETURNING id::text`,
				orgID, clientID, method, endpoint, ssf.EventSessionRevoked).Scan(&streamID))

			// What waits for this stream's receiver, oldest first, as event:status.
			waiting := func() string {
				t.Helper()
				q := `SELECT coalesce(string_agg(
				        CASE WHEN payload->>'event' = $2 THEN 'updated:' || (payload->>'status') ELSE 'revoked' END,
				        ' ' ORDER BY id), '')
				      FROM core.outbox WHERE topic = 'ssf_event' AND delivered_at IS NULL
				       AND payload->>'stream_id' = $1`
				if method == "poll" {
					q = `SELECT coalesce(string_agg(
					       CASE WHEN event_type = $2 THEN 'updated:' || (payload->>'status') ELSE 'revoked' END,
					       ' ' ORDER BY id), '')
					     FROM core.ssf_poll_queue WHERE stream_id = $1::uuid`
				}
				var s string
				must(t, tx.QueryRow(ctx, q, streamID, ssf.StreamUpdated).Scan(&s))
				return s
			}
			set := func(status string) string {
				t.Helper()
				prev, err := SetStreamStatus(ctx, tx, orgID, clientID, status, "maintenance")
				must(t, err)
				return prev
			}

			if prev := set("paused"); prev != "enabled" {
				t.Errorf("pausing reported the stream was %q, want enabled", prev)
			}
			if got := waiting(); got != "updated:paused" {
				t.Fatalf("after pausing, the receiver is owed %q, want the stream-updated notice", got)
			}
			// An event raised while paused is held, not lost.
			_, err = TerminateSessions(ctx, tx, sid, "", ReasonAdminRevoke)
			must(t, err)
			if got := waiting(); got != "updated:paused revoked" {
				t.Fatalf("an event raised while paused left %q, want it held behind the notice", got)
			}
			set("paused")
			set("disabled")
			if got := waiting(); got != "updated:paused" {
				t.Fatalf("after paused to disabled the receiver is owed %q; want nothing new sent "+
					"and the held event discarded", got)
			}
			if prev := set("enabled"); prev != "disabled" {
				t.Errorf("enabling reported the stream was %q, want disabled", prev)
			}
			if got := waiting(); got != "updated:paused updated:enabled" {
				t.Fatalf("after enabling, the receiver is owed %q, want a second notice", got)
			}
			var status string
			must(t, tx.QueryRow(ctx, `SELECT status FROM core.ssf_streams WHERE id = $1::uuid`, streamID).Scan(&status))
			if status != "enabled" {
				t.Errorf("the stream ended %q", status)
			}

			if _, err := SetStreamStatus(ctx, tx, orgID, clientID, "asleep", ""); err == nil {
				t.Error("a status SSF does not define was accepted")
			}
			var otherOrg string
			must(t, tx.QueryRow(ctx, `SELECT id::text FROM core.organizations WHERE id <> $1::uuid LIMIT 1`,
				orgID).Scan(&otherOrg))
			if _, err := SetStreamStatus(ctx, tx, otherOrg, clientID, "paused", ""); !errors.Is(err, ErrStreamUnknown) {
				t.Errorf("another organisation paused this stream: %v", err)
			}
		})
	}
}

// A paused stream's held events are released when it is enabled, not at the
// next hold interval: the worker would otherwise sit on them for up to a minute
// after the receiver was told the stream was back.
func TestEnablingAStreamReleasesWhatItHeld(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, _, clientID, sid := fixture(t, conn)
	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	var streamID string
	must(t, tx.QueryRow(ctx, `
		INSERT INTO core.ssf_streams (org_id, client_id, delivery_method, endpoint_url, events_requested, status)
		VALUES ($1, $2, 'push', 'https://rp.test/events', ARRAY[$3], 'paused') RETURNING id::text`,
		orgID, clientID, ssf.EventSessionRevoked).Scan(&streamID))
	_, err = TerminateSessions(ctx, tx, sid, "", ReasonAdminRevoke)
	must(t, err)
	// As the worker leaves a held row.
	_, err = tx.Exec(ctx, `UPDATE core.outbox SET next_attempt_at = now() + interval '1 hour'
		WHERE payload->>'stream_id' = $1`, streamID)
	must(t, err)

	_, err = SetStreamStatus(ctx, tx, orgID, clientID, "enabled", "")
	must(t, err)
	var later int
	must(t, tx.QueryRow(ctx, `SELECT count(*) FROM core.outbox
		WHERE payload->>'stream_id' = $1 AND next_attempt_at > now()`, streamID).Scan(&later))
	if later != 0 {
		t.Errorf("%d held event(s) still wait after the stream was enabled", later)
	}
}
