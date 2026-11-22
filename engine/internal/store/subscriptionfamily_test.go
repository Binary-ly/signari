package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// A family is every event under its name and nothing beside it: "group.*" has to
// reach a subscriber for each group event, and not for "groups" or anything that
// merely begins the same way. A plain name goes on matching exactly.
func TestAFamilySubscriptionReceivesEachOfItsEvents(t *testing.T) {
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
			VALUES ('https://family-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'family-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const url = "https://subscriber.example/hook"

	for _, refused := range []string{"nothing.*", ".*", "*", "keys.*"} {
		if _, err := CreateSubscription(ctx, tx, root, orgID, "bad", url, []string{refused}); !errors.Is(err, ErrUnknownEventType) {
			t.Errorf("subscribing to %q gave %v", refused, err)
		}
	}
	if _, err := CreateSubscription(ctx, tx, root, orgID, "family", url, []string{"admin.*", "login.failed"}); err != nil {
		t.Fatalf("subscribing to a family: %v", err)
	}

	for event, want := range map[string]int{
		"admin.group_created": 1,
		"admin.group_deleted": 1,
		"login.failed":        1,
		"login.succeeded":     0,
		"administrator.other": 0,
	} {
		got, err := PublishEvent(ctx, tx, EventEnvelope{OrgID: orgID, Type: event, ID: event})
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s reached %d subscribers, want %d", event, got, want)
		}
	}
}
