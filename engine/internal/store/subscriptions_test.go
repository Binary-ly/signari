package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// Subscriptions name real event types, and can be removed, rotated, enabled and
// tested (2.34). An unknown name was stored and received nothing; the remove
// and rotate docs/events.md described did not exist.
func TestASubscriptionNamesRealEventsAndCanBeManaged(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	// Rolled back: visible to this connection, residue for nobody.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	var orgID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://subscriptions-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'subscriptions-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const url = "https://subscriber.example/hook"

	_, err = CreateSubscription(ctx, tx, root, orgID, "typo", url, []string{"login.failure"})
	if !errors.Is(err, ErrUnknownEventType) || !strings.Contains(err.Error(), `"login.failed"`) {
		t.Errorf("subscribing to login.failure gave %v, want the unknown-type refusal suggesting login.failed", err)
	}
	if _, err := CreateSubscription(ctx, tx, root, orgID, "nonsense", url, []string{"nothing"}); !errors.Is(err, ErrUnknownEventType) {
		t.Errorf("subscribing to an unrelated name gave %v", err)
	}

	sub, err := CreateSubscription(ctx, tx, root, orgID, "siem", url, []string{"login.failed", "impersonation.started"})
	if err != nil {
		t.Fatalf("subscribing to real types: %v", err)
	}
	sealed := func() []byte {
		t.Helper()
		var b []byte
		if err := tx.QueryRow(ctx, `SELECT secret_sealed FROM core.event_subscriptions WHERE id = $1::uuid`,
			sub.ID).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	rotated, err := RotateSubscriptionSecret(ctx, tx, root, orgID, "siem")
	if err != nil || rotated == sub.Secret || !strings.HasPrefix(rotated, "whsec_") {
		t.Fatalf("rotation gave %q, %v", rotated, err)
	}
	if opened, err := root.Open(sealed(), "event-subscription"); err != nil || string(opened) != rotated {
		t.Errorf("after rotation the stored secret opens to %q (%v), want the new one", opened, err)
	}

	if err := DisableSubscription(ctx, tx, sub.ID, "ten failures"); err != nil {
		t.Fatal(err)
	}
	if err := EnableSubscription(ctx, tx, orgID, "siem"); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	var reason *string
	if err := tx.QueryRow(ctx, `SELECT enabled AND disabled_at IS NULL, disabled_reason
		FROM core.event_subscriptions WHERE id = $1::uuid`, sub.ID).Scan(&enabled, &reason); err != nil {
		t.Fatal(err)
	}
	if !enabled || reason != nil {
		t.Errorf("after enable: live %v, reason %v", enabled, reason)
	}

	id, err := SendTestEvent(ctx, tx, orgID, "siem")
	if err != nil {
		t.Fatal(err)
	}
	var queued int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.event_deliveries d
		JOIN core.outbox o ON o.id = d.outbox_id
		WHERE d.subscription_id = $1::uuid AND d.event_type = $2
		  AND o.payload->'envelope'->>'id' = $3`, sub.ID, TestEventType, id).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Errorf("the test delivery queued %d outbox rows, want 1", queued)
	}

	if removed, err := RemoveSubscription(ctx, tx, orgID, "siem"); err != nil || !removed {
		t.Fatalf("remove gave %v, %v", removed, err)
	}
	if removed, _ := RemoveSubscription(ctx, tx, orgID, "siem"); removed {
		t.Error("removing it twice removed something")
	}
	for _, err := range []error{
		EnableSubscription(ctx, tx, orgID, "siem"),
		func() error { _, err := RotateSubscriptionSecret(ctx, tx, root, orgID, "siem"); return err }(),
		func() error { _, err := SendTestEvent(ctx, tx, orgID, "siem"); return err }(),
	} {
		if err == nil {
			t.Error("an action on a removed subscription succeeded")
		}
	}
}
