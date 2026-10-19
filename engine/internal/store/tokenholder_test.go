package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TokenHolderLive is the ADR-007 read for an access token's client and
// subject (2.50). Each row is one way a token outlived its holder before.
func TestATokenIsOnlyAsLiveAsItsClientAndSubject(t *testing.T) {
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
			VALUES ('https://tokenholder-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'tokenholder-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	person := func(status string) string {
		t.Helper()
		var id string
		if err := tx.QueryRow(ctx, `
			INSERT INTO core.users (org_id, user_handle, email, status)
			VALUES ($1::uuid, sha256(convert_to(gen_random_uuid()::text, 'UTF8'))
			                  || sha256(convert_to(gen_random_uuid()::text, 'UTF8')),
			        gen_random_uuid()::text || '@tokenholder.invalid', $2)
			RETURNING id::text`, orgID, status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	client := func(id string, enabled bool) string {
		t.Helper()
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type, enabled)
			VALUES ($1, $2::uuid, 'probe', 'public', $3)`, id, orgID, enabled); err != nil {
			t.Fatal(err)
		}
		return id
	}

	app := client("tokenholder-app", true)
	off := client("tokenholder-off", false)
	active := person("active")
	deactivated := person("deactivated")
	// A client registered under a deactivated person's id: the person decides.
	impostor := client(deactivated, true)
	// A client whose id merely looks like a UUID and names nobody.
	uuidShaped := client("6f1c9a52-0d3b-4c8e-9a71-2b5e8d4f0c13", true)

	for _, c := range []struct {
		name          string
		clientID, sub string
		want          bool
	}{
		{"an enabled client's token for an active person", app, active, true},
		{"a disabled client's token", off, active, false},
		{"a deleted client's token", "tokenholder-gone", active, false},
		{"a deactivated person's token", app, deactivated, false},
		{"a deleted person's token", app, "0b6f0e7e-3c1a-4d55-8f6e-5a2a9c3d7e10", false},
		{"a client's token for itself", app, app, true},
		{"a disabled client's token for itself", off, off, false},
		{"an exchange of a disabled client's own token", app, off, false},
		{"a client named by a deactivated person's id", impostor, impostor, false},
		{"a client whose id looks like a UUID", uuidShaped, uuidShaped, true},
	} {
		got, err := TokenHolderLive(ctx, tx, c.clientID, c.sub)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: live = %v, want %v", c.name, got, c.want)
		}
	}
}
