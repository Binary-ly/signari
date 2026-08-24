package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// insertPollStream gives a client an enabled poll stream and returns its id.
func insertPollStream(t *testing.T, conn *pgx.Conn, orgID, clientID string, events []string) string {
	t.Helper()
	var id string
	must(t, conn.QueryRow(context.Background(), `
		INSERT INTO core.ssf_streams (org_id, client_id, delivery_method, endpoint_url,
		                              events_requested, status)
		VALUES ($1, $2, 'poll', NULL, $3, 'enabled') RETURNING id::text`,
		orgID, clientID, events).Scan(&id))
	return id
}

// queue plants a SET on a poll stream the way the revoke fan-out does.
func queue(t *testing.T, conn *pgx.Conn, streamID, jti, subject string) {
	t.Helper()
	_, err := conn.Exec(context.Background(), `
		INSERT INTO core.ssf_poll_queue (stream_id, jti, event_type, payload)
		VALUES ($1::uuid, $2, 'session-revoked',
		        jsonb_build_object('subject', $3::text, 'reason', 'admin_revoke'))`,
		streamID, jti, subject)
	must(t, err)
}

func TestPollStreamForClientFindsOnlyAnEnabledPollStream(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, _, clientID, _ := fixture(t, conn)

	// No stream yet.
	if _, ok, err := PollStreamForClient(ctx, conn, clientID); err != nil || ok {
		t.Fatalf("a client with no stream resolved one: ok=%v err=%v", ok, err)
	}

	streamID := insertPollStream(t, conn, orgID, clientID, []string{"session-revoked"})
	got, ok, err := PollStreamForClient(ctx, conn, clientID)
	must(t, err)
	if !ok || got != streamID {
		t.Fatalf("poll stream = %q ok=%v, want %q", got, ok, streamID)
	}

	// A paused stream is "nothing to poll".
	_, err = conn.Exec(ctx, `UPDATE core.ssf_streams SET status='paused' WHERE id=$1::uuid`, streamID)
	must(t, err)
	if _, ok, _ := PollStreamForClient(ctx, conn, clientID); ok {
		t.Error("a paused stream was offered for polling")
	}
}

func TestPollStreamForClientIgnoresPushStreams(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, _, clientID, _ := fixture(t, conn)

	_, err := conn.Exec(ctx, `
		INSERT INTO core.ssf_streams (org_id, client_id, delivery_method, endpoint_url,
		                              events_requested, status)
		VALUES ($1, $2, 'push', 'https://rp.test/events', ARRAY['session-revoked'], 'enabled')`,
		orgID, clientID)
	must(t, err)

	// A push stream must not be pollable: its events go out via the outbox, and
	// answering a poll for it would deliver them twice.
	if _, ok, _ := PollStreamForClient(ctx, conn, clientID); ok {
		t.Error("a push stream was offered for polling")
	}
}

func TestPollFetchReturnsOldestFirstAndReportsMore(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, _, clientID, _ := fixture(t, conn)
	streamID := insertPollStream(t, conn, orgID, clientID, []string{"session-revoked"})

	for _, jti := range []string{"a", "b", "c"} {
		queue(t, conn, streamID, jti, "sub-"+jti)
	}

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	// max=2 of 3 -> two oldest, more=true.
	got, more, err := PollFetch(ctx, tx, streamID, 2)
	must(t, err)
	if !more {
		t.Error("moreAvailable is false with a third event still queued")
	}
	if len(got) != 2 || got[0].JTI != "a" || got[1].JTI != "b" {
		t.Fatalf("fetch order = %v, want [a b] oldest-first", jtis(got))
	}
	if got[0].Subject != "sub-a" || got[0].Reason != "admin_revoke" {
		t.Errorf("payload not decoded: %+v", got[0])
	}

	// Fetch does NOT delete: the same rows are still there.
	all, more, err := PollFetch(ctx, tx, streamID, 10)
	must(t, err)
	if more {
		t.Error("moreAvailable is true when everything fits")
	}
	if len(all) != 3 {
		t.Fatalf("fetch removed rows it should only have read: got %d, want 3", len(all))
	}
}

func TestPollAckDeletesOnlyTheAcknowledgedAndOnlyOnThisStream(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, _, clientA, _ := fixture(t, conn)
	streamA := insertPollStream(t, conn, orgID, clientA, []string{"session-revoked"})

	// A second client + stream to prove ack cannot reach across streams.
	clientB := "client-b-" + itoa(time.Now().UnixNano())
	_, err := conn.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash)
		VALUES ($1, $2, 'B', 'confidential', 'x')`, clientB, orgID)
	must(t, err)
	streamB := insertPollStream(t, conn, orgID, clientB, []string{"session-revoked"})

	queue(t, conn, streamA, "shared-jti", "sub1")
	queue(t, conn, streamA, "keep", "sub2")
	queue(t, conn, streamB, "shared-jti", "sub3") // same jti, different stream

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	n, err := PollAck(ctx, tx, streamA, []string{"shared-jti"})
	must(t, err)
	if n != 1 {
		t.Fatalf("ack deleted %d rows, want exactly 1 (this stream's shared-jti)", n)
	}

	// streamA keeps its other event; streamB keeps its identically-named one.
	aLeft, _, err := PollFetch(ctx, tx, streamA, 10)
	must(t, err)
	if len(aLeft) != 1 || aLeft[0].JTI != "keep" {
		t.Errorf("stream A after ack = %v, want [keep]", jtis(aLeft))
	}
	bLeft, _, err := PollFetch(ctx, tx, streamB, 10)
	must(t, err)
	if len(bLeft) != 1 || bLeft[0].JTI != "shared-jti" {
		t.Errorf("another stream's event was deleted by an ack naming its jti: %v", jtis(bLeft))
	}

	// Acking nothing is a no-op, not an error.
	if n, err := PollAck(ctx, tx, streamA, nil); err != nil || n != 0 {
		t.Errorf("empty ack: n=%d err=%v", n, err)
	}
}

func TestPurgeStalePollEventsDropsOnlyTheOld(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, _, clientID, _ := fixture(t, conn)
	streamID := insertPollStream(t, conn, orgID, clientID, []string{"session-revoked"})

	queue(t, conn, streamID, "fresh", "sub-fresh")
	queue(t, conn, streamID, "stale", "sub-stale")
	_, err := conn.Exec(ctx,
		`UPDATE core.ssf_poll_queue SET queued_at = now() - interval '40 days' WHERE jti='stale'`)
	must(t, err)

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	n, err := PurgeStalePollEvents(ctx, tx, 30*24*time.Hour)
	must(t, err)
	if n != 1 {
		t.Fatalf("purged %d, want 1 (only the 40-day-old event)", n)
	}
	left, _, err := PollFetch(ctx, tx, streamID, 10)
	must(t, err)
	if len(left) != 1 || left[0].JTI != "fresh" {
		t.Errorf("purge kept the wrong rows: %v", jtis(left))
	}
}

// The revoke fan-out queues for a POLL stream (into the poll queue) and NOT into
// the push outbox -- the whole point is that a poll receiver pulls rather than
// being pushed to.
func TestSessionRevokeQueuesForAPollStream(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, userID, clientID, sid := fixture(t, conn)
	streamID := insertPollStream(t, conn, orgID, clientID, []string{
		"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
	})

	tx, err := conn.Begin(ctx)
	must(t, err)
	if _, err := TerminateSessions(ctx, tx, sid, "", ReasonAdminRevoke); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	must(t, tx.Commit(ctx))

	// One queued SET for this poll stream, about this user.
	var n int
	must(t, conn.QueryRow(ctx, `
		SELECT count(*) FROM core.ssf_poll_queue
		WHERE stream_id = $1::uuid
		  AND event_type = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked'
		  AND payload->>'subject' = $2`, streamID, userID).Scan(&n))
	if n != 1 {
		t.Fatalf("poll queue has %d events for the revoked session, want 1", n)
	}

	// And nothing went to the push outbox for it -- a poll stream is not pushed.
	var pushed int
	must(t, conn.QueryRow(ctx, `
		SELECT count(*) FROM core.outbox
		WHERE topic = 'ssf_event' AND payload->>'stream_id' = $1`, streamID).Scan(&pushed))
	if pushed != 0 {
		t.Errorf("a poll stream also queued %d push deliveries; it must pull, not be pushed", pushed)
	}
}

func jtis(evs []QueuedPollEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.JTI
	}
	return out
}
