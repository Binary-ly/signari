package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// An approved-model allow-list with no FIDO catalogue refuses every passkey
// registration in its organisation. Doctor must say so, and must stop saying so
// once a catalogue is configured.
func TestAnAllowListWithNoCatalogueIsReported(t *testing.T) {
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

	if _, err := tx.Exec(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://allowlist-probe.invalid', 'probe') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'allowlist-probe', 'probe' FROM i RETURNING id
		)
		INSERT INTO core.webauthn_policy (org_id, attestation_conveyance, allowed_aaguids)
		SELECT id, 'direct', ARRAY['ee882879-721c-4913-9775-3dfcce97072a']::uuid[] FROM o`); err != nil {
		t.Fatalf("seeding an allow-list: %v", err)
	}

	for _, k := range []string{"SIGNARI_FIDO_MDS_PATH", "SIGNARI_FIDO_MDS_URL", "SIGNARI_FIDO_MDS_FETCH"} {
		t.Setenv(k, "")
	}
	r := &Report{}
	if err := checkAuthenticatorAllowList(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	if !reported(r, "approved authenticator models") {
		t.Fatal("an allow-list with no catalogue was not reported; every registration in that " +
			"organisation is refused and the operator would hear it first from users")
	}

	t.Setenv("SIGNARI_FIDO_MDS_FETCH", "1")
	r = &Report{}
	if err := checkAuthenticatorAllowList(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	if reported(r, "approved authenticator models") {
		t.Fatal("the allow-list was still reported with a catalogue configured")
	}
}

func reported(r *Report, area string) bool {
	for _, f := range r.Findings {
		if strings.Contains(f.Area, area) {
			return true
		}
	}
	return false
}
