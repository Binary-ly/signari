package importer

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// importFixture is a transaction rolled back at the end of the test, and an
// organisation of its own made in it.
func importFixture(t *testing.T) (context.Context, pgx.Tx, string) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	n := time.Now().UnixNano()
	var org string
	if err := tx.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name) VALUES ($1, 'probe') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, $2, 'probe' FROM i RETURNING id::text`,
		fmt.Sprintf("https://import-%d.invalid", n), fmt.Sprintf("import-%d", n)).Scan(&org); err != nil {
		t.Fatal(err)
	}
	return ctx, tx, org
}

// An imported hash whose cost is over what sign-in will verify is refused at
// import, by name and with the reason, rather than imported and then refused
// at every attempt. Both importers asked only "is the format known", so a
// phpass hash at 2^21 iterations or a Keycloak credential at two million
// became an account nobody could sign in to.

func TestAnImportedHashCostingMoreThanSignInAllowsIsSkippedWithTheReason(t *testing.T) {
	exp, err := ParseAuthentik(strings.NewReader(`[
	 {"model":"authentik_core.user","pk":1,"fields":{"username":"cheap","email":"cheap@x.test",
	  "password":"$P$Isaltsalt0123456789abcdefghij","is_active":true,"ak_groups":[]}},
	 {"model":"authentik_core.user","pk":2,"fields":{"username":"dear","email":"dear@x.test",
	  "password":"$P$Jsaltsalt0123456789abcdefghij","is_active":true,"ak_groups":[]}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	// Both imports read what the organisation holds, so each runs in a
	// transaction, rolled back.
	actx, atx, aorg := importFixture(t)
	res, err := ImportAuthentik(actx, atx, aorg, exp, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.UsersCreated != 1 {
		t.Errorf("%d users would be created, want only the one at 2^20 iterations", res.UsersCreated)
	}
	if len(res.UsersSkipped) != 1 || !strings.Contains(res.UsersSkipped[0], "dear@x.test") ||
		!strings.Contains(res.UsersSkipped[0], "2^21") {
		t.Errorf("the 2^21 hash was not skipped with its reason: %q", res.UsersSkipped)
	}

	ctx, tx, org := importFixture(t)
	n := time.Now().UnixNano()
	realm, err := Parse(strings.NewReader(fmt.Sprintf(`{"realm":"r","users":[
	 {"username":"dear","email":"dear-%[1]d@x.test","enabled":true,"credentials":[{"type":"password",
	  "secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}",
	  "credentialData":"{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":2000000}"}]},
	 {"username":"cheap","email":"cheap-%[1]d@x.test","enabled":true,"credentials":[{"type":"password",
	  "secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}",
	  "credentialData":"{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":27500}"}]}]}`, n)))
	if err != nil {
		t.Fatal(err)
	}
	kres, err := Import(ctx, tx, org, realm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if kres.UsersCreated != 1 {
		t.Errorf("%d Keycloak users would be created, want only the one at 27500 iterations", kres.UsersCreated)
	}
	if len(kres.UsersSkipped) != 1 || !strings.Contains(kres.UsersSkipped[0], "2000000") {
		t.Errorf("the two-million-iteration credential was not skipped with its reason: %q", kres.UsersSkipped)
	}
}
