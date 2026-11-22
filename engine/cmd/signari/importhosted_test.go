package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store/storetest"
)

// `import entra` through run(), so the flags reach the importer (6.26): a dry run
// writes nobody, the import then makes the enabled person, keeps their object ID
// as their id and links them to the -via provider by it, and an import with no
// -file says how to get one.
func TestImportEntraThroughTheCommand(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	var org string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://import-hosted-' || gen_random_uuid() || '.test', 'hosted import') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'Hosted' FROM i RETURNING id::text`).
		Scan(&org); err != nil {
		t.Fatal(err)
	}
	storetest.Forget(t, db, org)
	n := time.Now().UnixNano()
	via := fmt.Sprintf("entra-cli-%d", n)
	if _, err := db.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
		VALUES ($1::uuid, $2, 'Entra', 'oidc', 'c')`, org, via); err != nil {
		t.Fatal(err)
	}
	ada, off := uuid.NewString(), uuid.NewString()
	file := filepath.Join(t.TempDir(), "users.csv")
	if err := os.WriteFile(file, []byte("userPrincipalName,displayName,mail,objectId,accountEnabled\n"+
		fmt.Sprintf("ada-%[1]d@contoso.test,Ada,ada-%[1]d@contoso.test,%[2]s,True\n", n, ada)+
		fmt.Sprintf("off-%[1]d@contoso.test,Off,,%[2]s,False\n", n, off)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.users WHERE id IN ($1::uuid, $2::uuid)`, ada, off)
	})
	people := func() (n int) {
		t.Helper()
		if err := db.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE org_id = $1::uuid`, org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	args := []string{"import", "entra", "-dsn", dsn, "-org", org, "-file", file, "-via", via}
	if err := run(append(args, "-dry-run")); err != nil || people() != 0 {
		t.Fatalf("the dry run: %v, and %d people written", err, people())
	}
	if err := run(args); err != nil {
		t.Fatalf("import entra: %v", err)
	}
	var subject string
	if err := db.QueryRow(ctx, `SELECT f.subject FROM core.federated_identities f JOIN core.users u ON u.id = f.user_id
		WHERE u.id = $1::uuid`, ada).Scan(&subject); err != nil || subject != ada || people() != 1 {
		t.Errorf("ada, by her object ID, is linked as %q (%v), and %d people were made", subject, err, people())
	}
	if err := run([]string{"import", "entra", "-dsn", dsn, "-org", org}); err == nil ||
		!strings.Contains(err.Error(), "Download users") {
		t.Errorf("no -file: %v", err)
	}
}
