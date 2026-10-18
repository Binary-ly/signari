package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// An organisation that accepts a password alone over LDAP, RADIUS or an outpost
// has an MFA mandate with a side door. Doctor must name it where the door is
// open, and stop once it is shut.
func TestAPasswordOnlySideDoorIsNamed(t *testing.T) {
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

	var orgID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://binds-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name, password_only_binds)
		SELECT id, 'binds-probe', 'probe', 'allow' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatalf("seeding an organisation: %v", err)
	}
	for _, k := range []string{"SIGNARI_LDAP_ADDR", "SIGNARI_LDAP_ORG_ID",
		"SIGNARI_RADIUS_ADDR", "SIGNARI_RADIUS_ORG_ID"} {
		t.Setenv(k, "")
	}

	names := func(want string) bool {
		t.Helper()
		r := &Report{}
		if err := checkPasswordOnlyBinds(ctx, tx, r); err != nil {
			t.Fatal(err)
		}
		for _, f := range r.Findings {
			if f.Area == "password-only binds" && strings.Contains(f.Summary, `"binds-probe"`) &&
				strings.Contains(f.Summary, want) {
				return true
			}
		}
		return false
	}

	// No door, nothing to say: `allow` on an organisation nothing binds to is
	// not a bypass of anything.
	if names("") {
		t.Fatal("an organisation with no LDAP, RADIUS or outpost was reported")
	}

	t.Setenv("SIGNARI_LDAP_ADDR", ":3389")
	t.Setenv("SIGNARI_LDAP_ORG_ID", orgID)
	if !names("the LDAP listener") {
		t.Fatal("the LDAP listener's organisation accepts a password alone and was not named")
	}
	t.Setenv("SIGNARI_LDAP_ADDR", "")

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.outposts (org_id, name, kind, token_hash)
		VALUES ($1::uuid, 'vpn', 'radius', sha256('binds-probe'::bytea))`, orgID); err != nil {
		t.Fatal(err)
	}
	if !names("an LDAP or RADIUS outpost") {
		t.Fatal("an organisation with a RADIUS outpost accepting a password alone was not named")
	}

	if _, err := tx.Exec(ctx,
		`UPDATE core.organizations SET password_only_binds = 'refuse_when_mfa' WHERE id = $1::uuid`,
		orgID); err != nil {
		t.Fatal(err)
	}
	if names("") {
		t.Fatal("still reported after the organisation started refusing password-only binds")
	}
}
