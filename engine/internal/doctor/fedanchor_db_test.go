package doctor

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A stored federation configuration with no authority_hints is a Trust Anchor
// this engine cannot publish (2.37). Doctor says so; with a superior it is quiet.
func TestAStoredTrustAnchorConfigurationIsCritical(t *testing.T) {
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

	var instanceID string
	if err := tx.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://fedanchor-probe.invalid', 'probe') RETURNING id::text`).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	reported := func() bool {
		t.Helper()
		r := &Report{}
		if err := checkFederationAnchor(ctx, tx, r); err != nil {
			t.Fatal(err)
		}
		return r.Count(Critical) > 0
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.federation_config (instance_id, authority_hints)
		VALUES ($1::uuid, '{https://anchor.example}')`, instanceID); err != nil {
		t.Fatal(err)
	}
	if reported() {
		t.Fatal("a configuration naming a superior was reported")
	}
	if _, err := tx.Exec(ctx, `UPDATE core.federation_config SET authority_hints = NULL
		WHERE instance_id = $1::uuid`, instanceID); err != nil {
		t.Fatal(err)
	}
	if !reported() {
		t.Error("a configuration with no authority_hints, a Trust Anchor, was not reported")
	}
}
