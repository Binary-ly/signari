package importer

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/passwords"
)

// The regression this file exists for.
//
// The first version stored an imported client secret VERBATIM in
// client_secret_hash. Two things were wrong, and only one was visible: a
// plaintext secret sat in a column named `_hash`, and the Argon2 verifier
// correctly refused it -- so every imported client silently could not
// authenticate. "Verbatim import" meant "verbatim and unusable", and nothing
// failed until an application tried to get a token.
func TestImportedClientSecretIsHashedAndStillVerifies(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "SET ROLE signari_maintenance"); err != nil {
		t.Fatal(err)
	}

	var orgID string
	if err := conn.QueryRow(ctx, `SELECT id::text FROM core.organizations LIMIT 1`).Scan(&orgID); err != nil {
		t.Skip("no organisation seeded")
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // never commits; the database is untouched

	const secret = "the-apps-existing-secret"
	realm := &KeycloakRealm{Realm: "r", Clients: []keycloakClient{{
		ClientID: "imported-secret-test", Secret: secret, Enabled: true,
		StandardFlowEnabled: true, RedirectURIs: []string{"https://app.test/cb"},
	}}}

	h := passwords.NewHasher(passwords.MemoryBudgetMiB)
	if _, err := Import(ctx, tx, orgID, realm, h, false); err != nil {
		t.Fatal(err)
	}

	var stored string
	if err := tx.QueryRow(ctx,
		`SELECT client_secret_hash FROM core.clients WHERE client_id = 'imported-secret-test'`).
		Scan(&stored); err != nil {
		t.Fatal(err)
	}

	// 1. The plaintext must not be in the column.
	if stored == secret || strings.Contains(stored, secret) {
		t.Fatal("the imported secret was stored in plaintext")
	}
	if !strings.HasPrefix(stored, "$argon2id$") {
		t.Fatalf("stored value is not an argon2id hash: %.20q", stored)
	}

	// 2. And the application's EXISTING secret must still authenticate -- which
	//    is the entire point of importing it rather than issuing a new one.
	if _, err := h.Verify(ctx, stored, secret); err != nil {
		t.Fatalf("the application's existing secret no longer works: %v", err)
	}
	if _, err := h.Verify(ctx, stored, secret+"x"); err == nil {
		t.Fatal("a wrong secret verified")
	}
}
