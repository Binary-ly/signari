package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A provider registered before 2.04 has no signing secret and is called
// unsigned. Doctor says so; one with a secret is quiet.
func TestAnUnsignedProviderIsReported(t *testing.T) {
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
			VALUES ('https://providersecrets-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'providersecrets-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms)
		VALUES ($1::uuid, 'provider-authorize', 'authorize', 'https://pdp.example.test', 'fail_closed', 1000)`,
		orgID); err != nil {
		t.Fatal(err)
	}
	// This organisation's findings only: the check reads the whole deployment,
	// and the shared test database holds other tests' providers.
	reported := func() bool {
		t.Helper()
		r := &Report{}
		if err := checkProviderSecrets(ctx, tx, r); err != nil {
			t.Fatal(err)
		}
		for _, f := range r.Findings {
			if f.Severity == Warning && strings.Contains(f.Summary, "providersecrets-probe") {
				return true
			}
		}
		return false
	}
	if !reported() {
		t.Error("a provider with no signing secret was not reported")
	}
	if _, err := tx.Exec(ctx, `UPDATE core.providers SET token_wrapped = '\x00'::bytea
		WHERE org_id = $1::uuid`, orgID); err != nil {
		t.Fatal(err)
	}
	if reported() {
		t.Error("a provider with a signing secret was reported")
	}
}
