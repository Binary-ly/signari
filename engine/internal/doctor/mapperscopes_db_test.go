package doctor

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A claim mapper saved before 2.33 with a typo in required_scope releases
// nothing to anybody. Doctor names it; a standard or declared scope is quiet.
func TestAClaimMapperWaitingForAnUndeclaredScopeIsReported(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("no dsn")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skip(err)
	}
	defer conn.Close(ctx)
	// Rolled back: visible to this connection, residue for nobody.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	var orgID, attrID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://mapperscopes-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'mapperscopes-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.user_attribute_schema (org_id, name, value_type, personal)
		VALUES ($1::uuid, 'department', 'string', false) RETURNING id::text`, orgID).Scan(&attrID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.scopes (org_id, name) VALUES ($1::uuid, 'hr_records')`, orgID); err != nil {
		t.Fatal(err)
	}
	reported := func(scope string) bool {
		t.Helper()
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer sp.Rollback(ctx)
		if _, err := sp.Exec(ctx, `
			INSERT INTO core.claim_mappers (org_id, attribute_id, claim_name, destination, required_scope)
			VALUES ($1::uuid, $2::uuid, 'department', 'userinfo', $3)`, orgID, attrID, scope); err != nil {
			t.Fatal(err)
		}
		r := &Report{}
		if err := checkClaimMapperScopes(ctx, sp, r); err != nil {
			t.Fatal(err)
		}
		return r.Count(Warning) > 0
	}
	for scope, want := range map[string]bool{
		"profle": true, "profile": false, "hr_records": false, "": false,
	} {
		if got := reported(scope); got != want {
			t.Errorf("a mapper waiting for %q: reported = %v, want %v", scope, got, want)
		}
	}
}
