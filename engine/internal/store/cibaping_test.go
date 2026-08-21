package store

import (
	"context"
	"encoding/json"
	"testing"
)

// The parking mechanism, which is what makes ping delivery possible at all.
//
// A ping notification must carry the `auth_req_id` the client holds, and this
// server stores only its hash. So the payload is built at creation, while the
// value still exists, and parked with `next_attempt_at = 'infinity'` so the drain
// cannot see it. The person's decision releases it.
//
// This test drives that sequence directly, because the property that matters is
// invisible from the outside: a parked row and a row scheduled for delivery look
// identical apart from one timestamp, and getting it wrong sends a notification
// before anybody has approved anything.
func TestACIBAPingIsParkedUntilTheRequestIsDecided(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	const requestID = "11111111-1111-1111-1111-111111111111"

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM core.outbox WHERE subject_key = $1`, requestID)
	})

	if err := QueueCIBAPing(ctx, pool, requestID, "client-1",
		"https://rp.example/ciba", "notification-token-abc", "the-auth-req-id"); err != nil {
		t.Fatalf("parking: %v", err)
	}

	// Parked: not claimable. The drain takes rows with next_attempt_at <= now(),
	// so 'infinity' is what keeps it invisible.
	var due int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM core.outbox
		WHERE subject_key = $1 AND next_attempt_at <= now()`, requestID).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if due != 0 {
		t.Fatalf("a parked ping was already due for delivery; the client would be "+
			"notified before anyone approved anything (due=%d)", due)
	}

	// The payload must carry the auth_req_id, not the row id: the client
	// correlates on the value it was given.
	var raw []byte
	if err := pool.QueryRow(ctx,
		`SELECT payload FROM core.outbox WHERE subject_key = $1`, requestID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var p CIBAPing
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if p.AuthReqID != "the-auth-req-id" {
		t.Errorf("payload auth_req_id = %q, want the value the client holds", p.AuthReqID)
	}
	if p.Token != "notification-token-abc" {
		t.Errorf("payload token = %q; without it the callback cannot be "+
			"authenticated to the client", p.Token)
	}

	// Released by the decision.
	released, err := ReleaseCIBAPing(ctx, pool, requestID)
	if err != nil {
		t.Fatalf("releasing: %v", err)
	}
	if !released {
		t.Fatal("the decision released nothing; the notification stays parked forever")
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM core.outbox
		WHERE subject_key = $1 AND next_attempt_at <= now()`, requestID).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if due != 1 {
		t.Fatalf("after the decision the ping is still not due (due=%d)", due)
	}
}

// A poll client has nothing parked, so releasing must be a no-op rather than an
// error: the approval path calls it for every request without knowing the mode.
func TestReleasingWithNothingParkedIsNotAnError(t *testing.T) {
	pool := rateTestPool(t)
	released, err := ReleaseCIBAPing(context.Background(), pool,
		"22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatalf("releasing a poll request errored: %v", err)
	}
	if released {
		t.Error("something was released for a request that never parked one")
	}
}

// Ping without an endpoint or without a token is refused at the point of
// parking, not discovered at delivery time. The schema forbids the first and
// §7.1 the second; this is the belt to those braces, and it fails loudly because
// the alternative is a notification nobody can authenticate.
func TestParkingRefusesAnIncompletePing(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	if err := QueueCIBAPing(ctx, pool, "33333333-3333-3333-3333-333333333333",
		"client-1", "", "token", "auth-req"); err == nil {
		t.Error("a ping with no notification endpoint was parked")
	}
	if err := QueueCIBAPing(ctx, pool, "33333333-3333-3333-3333-333333333333",
		"client-1", "https://rp.example/ciba", "", "auth-req"); err == nil {
		t.Error("a ping with no notification token was parked; the callback could " +
			"not be authenticated to the client")
	}
}
