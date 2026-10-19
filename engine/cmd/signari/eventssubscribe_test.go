package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// `events subscribe -events` filters, as docs/events.md has always shown it
// (2.34). -events was the SSF commands' flag and the subscription read
// -event-types, so a subscription made as documented ignored its list and was
// sent every event in the organisation. A name nothing records is refused.
//
// A fresh organisation, removed afterwards, so no other test's events are
// queued to these subscriptions.
func TestEventsSubscribeFiltersByTheDocumentedFlag(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	if os.Getenv("SIGNARI_ROOT_KEY") == "" {
		t.Setenv("SIGNARI_ROOT_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) }) // after the delete below
	var org, instance string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://events-cli-' || gen_random_uuid() || '.test', 'events CLI test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'e' || substr(gen_random_uuid()::text, 1, 8), 'Events' FROM i
		RETURNING id::text, instance_id::text`).Scan(&org, &instance); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = db.Exec(c, `DELETE FROM core.event_subscriptions WHERE org_id = $1::uuid`, org)
		_, _ = db.Exec(c, `DELETE FROM core.organizations WHERE id = $1::uuid`, org)
		_, _ = db.Exec(c, `DELETE FROM core.instances WHERE id = $1::uuid`, instance)
	})
	subscribe := func(name string, flags ...string) error {
		return run(append([]string{"events", "subscribe", "-dsn", dsn, "-org", org, "-name", name,
			"-url", "https://subscriber.example/hook"}, flags...))
	}
	types := func(name string) string {
		t.Helper()
		var got []string
		if err := db.QueryRow(ctx, `SELECT event_types FROM core.event_subscriptions
			WHERE org_id = $1::uuid AND display_name = $2`, org, name).Scan(&got); err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		return fmt.Sprint(got)
	}

	if err := subscribe("documented", "-events", "login.failed,impersonation.started"); err != nil {
		t.Fatal(err)
	}
	if got := types("documented"); got != "[login.failed impersonation.started]" {
		t.Errorf("subscribed with -events as documented, the subscription holds %s; empty means every event", got)
	}
	if err := subscribe("older", "-event-types", "login.failed"); err != nil || types("older") != "[login.failed]" {
		t.Errorf("-event-types stopped working: %v", err)
	}
	if err := subscribe("typo", "-events", "login.failure"); err == nil || !strings.Contains(err.Error(), "login.failed") {
		t.Errorf("subscribing to login.failure gave %v, want a refusal suggesting login.failed", err)
	}
	if err := subscribe("both", "-events", "login.failed", "-event-types", "user.created"); err == nil {
		t.Error("two different lists were accepted")
	}
}
