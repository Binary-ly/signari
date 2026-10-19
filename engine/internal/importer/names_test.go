package importer

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/passwords"
)

// A realm export's names reach the account, and a re-run never replaces a
// name the account already holds. The importer read firstName and lastName
// and wrote neither (2.15).
func TestAnImportedPersonKeepsTheirNames(t *testing.T) {
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
	defer func() { _ = tx.Rollback(ctx) }() // never commits

	email := fmt.Sprintf("names-%d@example.test", time.Now().UnixNano())
	h := passwords.NewHasher(passwords.MemoryBudgetMiB)
	realm := &KeycloakRealm{Realm: "r", Users: []keycloakUser{{Username: "ada", Email: email,
		FirstName: "Ada", LastName: "Lovelace", Enabled: true,
		// An importable password, or the importer rightly skips the person.
		Credentials: []keycloakCredential{{Type: "password",
			SecretData:     `{"value":"aGFzaA==","salt":"c2FsdA=="}`,
			CredentialData: `{"algorithm":"pbkdf2-sha256","hashIterations":27500}`}}}}}
	if _, err := Import(ctx, tx, orgID, realm, h, false); err != nil {
		t.Fatal(err)
	}
	read := func() (string, string, string) {
		t.Helper()
		var given, surname, display string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(given_name,''), COALESCE(surname,''), COALESCE(display_name,'')
			FROM core.users WHERE org_id = $1::uuid AND lower(email) = $2`, orgID, email).
			Scan(&given, &surname, &display); err != nil {
			t.Fatal(err)
		}
		return given, surname, display
	}
	if g, s, d := read(); g != "Ada" || s != "Lovelace" || d != "Ada Lovelace" {
		t.Errorf("imported as given %q, surname %q, display %q", g, s, d)
	}

	// The person renames themselves here; a second import must not undo it.
	if _, err := tx.Exec(ctx, `UPDATE core.users SET display_name = 'Countess of Lovelace'
		WHERE org_id = $1::uuid AND lower(email) = $2`, orgID, email); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(ctx, tx, orgID, realm, h, false); err != nil {
		t.Fatal(err)
	}
	if _, _, d := read(); d != "Countess of Lovelace" {
		t.Errorf("a re-run replaced the account's own name with %q", d)
	}
}
