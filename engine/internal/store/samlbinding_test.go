package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// An assertion consumer URL is HTTP-POST only (0147). HTTP-Artifact was
// allowed by the schema and implemented nowhere, so a row naming it described
// a delivery that never happens (2.45).
func TestAnACSURLMayNotClaimTheArtifactBinding(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	// Rolled back: visible to this connection, residue for nobody.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	var providerID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://samlbinding-probe.invalid', 'probe') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'samlbinding-probe', 'probe' FROM i RETURNING id
		)
		INSERT INTO core.saml_providers (org_id, entity_id, display_name)
		SELECT id, 'urn:samlbinding-probe', 'probe' FROM o RETURNING id::text`).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.saml_acs_urls (provider_id, url, binding)
		VALUES ($1::uuid, 'https://sp.example.test/acs', 'HTTP-POST')`, providerID); err != nil {
		t.Fatalf("an HTTP-POST consumer URL was refused: %v", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO core.saml_acs_urls (provider_id, url, binding)
		VALUES ($1::uuid, 'https://sp.example.test/artifact', 'HTTP-Artifact')`, providerID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("an HTTP-Artifact consumer URL answered %v, want a check violation", err)
	}
}
