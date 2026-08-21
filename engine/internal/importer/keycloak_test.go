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

// Keycloak calls the client credentials grant "service accounts", and a client
// may have it alongside the browser flow or on its own.
//
// The importer read `serviceAccountsEnabled` off the realm export and dropped
// it, hardcoding every imported client to authorization_code + refresh_token.
// The two halves fail differently and the first is the dangerous one:
//
//   - Both flows: the client is imported, browser logins keep working, and its
//     machine-to-machine calls start failing `unauthorized_client` at cutover.
//     Nothing in the migration report mentions it. It is found by whichever
//     batch job runs next, which may be a month later.
//   - Service accounts only: skipped, and reported as "not using the
//     authorization code flow" — true, and beside the point, because we
//     implement the grant it does use.
//
// This file's neighbour already records the same class of bug from the first
// version of this importer: "verbatim import" that meant "verbatim and
// unusable". Same failure, one column over.
func TestServiceAccountClientsKeepTheirGrant(t *testing.T) {
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
	defer func() { _ = tx.Rollback(ctx) }()

	realm := &KeycloakRealm{Realm: "r", Clients: []keycloakClient{
		{ClientID: "kc-both", Secret: "s1", Enabled: true,
			StandardFlowEnabled: true, ServiceAccountEnabled: true,
			RedirectURIs: []string{"https://app.test/cb"}},
		{ClientID: "kc-machine", Secret: "s2", Enabled: true,
			StandardFlowEnabled: false, ServiceAccountEnabled: true},
		{ClientID: "kc-browser", Secret: "s3", Enabled: true,
			StandardFlowEnabled: true, RedirectURIs: []string{"https://app.test/cb"}},
		// Keycloak does not permit service accounts on a public client, and a
		// public client holds no secret to authenticate this grant with.
		// Importing it would create the unusable shape the skip exists to avoid.
		{ClientID: "kc-public-sa", Enabled: true, PublicClient: true,
			StandardFlowEnabled: true, ServiceAccountEnabled: true,
			RedirectURIs: []string{"https://app.test/cb"}},
		{ClientID: "kc-nothing", Enabled: true},
	}}

	h := passwords.NewHasher(passwords.MemoryBudgetMiB)
	res, err := Import(ctx, tx, orgID, realm, h, false)
	if err != nil {
		t.Fatal(err)
	}

	grantsOf := func(id string) []string {
		t.Helper()
		var g []string
		if err := tx.QueryRow(ctx,
			`SELECT grant_types FROM core.clients WHERE client_id = $1`, id).Scan(&g); err != nil {
			t.Fatalf("%s was not imported: %v", id, err)
		}
		return g
	}
	has := func(g []string, want string) bool {
		for _, v := range g {
			if v == want {
				return true
			}
		}
		return false
	}

	both := grantsOf("kc-both")
	if !has(both, "client_credentials") {
		t.Errorf("kc-both lost client_credentials: %v. Its browser logins work and "+
			"its machine-to-machine calls fail after cutover, with nothing in the "+
			"migration report saying so", both)
	}
	if !has(both, "authorization_code") {
		t.Errorf("kc-both lost authorization_code: %v", both)
	}

	machine := grantsOf("kc-machine")
	if !has(machine, "client_credentials") {
		t.Errorf("kc-machine was imported without the only grant it uses: %v", machine)
	}
	if has(machine, "authorization_code") {
		t.Errorf("kc-machine gained a browser flow it never had: %v", machine)
	}

	browser := grantsOf("kc-browser")
	if has(browser, "client_credentials") {
		t.Errorf("kc-browser gained client_credentials it never had: %v. An import "+
			"that widens a client's grants is a privilege escalation performed by "+
			"the migration tool", browser)
	}

	if pub := grantsOf("kc-public-sa"); has(pub, "client_credentials") {
		t.Errorf("a PUBLIC client was given client_credentials: %v. It holds no "+
			"secret, so the grant cannot authenticate and the client is imported "+
			"in a shape that cannot work", pub)
	}

	var skipped bool
	for _, s := range res.ClientsSkipped {
		if strings.HasPrefix(s, "kc-nothing") {
			skipped = true
		}
	}
	if !skipped {
		t.Errorf("a client using no flow we implement was imported anyway: %v",
			res.ClientsSkipped)
	}
}
