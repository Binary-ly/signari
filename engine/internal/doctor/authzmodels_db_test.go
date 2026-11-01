package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The engine evaluates the compiled copy of a model, so a copy that does not load
// is the organisation's authorization not working. Doctor says whose.
func TestAStoredModelThatDoesNotLoadIsCritical(t *testing.T) {
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
			VALUES ('https://authz-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'authz-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	store := func(compiled string) {
		t.Helper()
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.authorization_models (org_id, source, compiled) VALUES ($1::uuid, '', $2)
			ON CONFLICT (org_id) DO UPDATE SET compiled = EXCLUDED.compiled`, orgID, compiled); err != nil {
			t.Fatal(err)
		}
	}
	probe := func() *Finding {
		t.Helper()
		r := &Report{}
		if err := checkAuthorizationModels(ctx, tx, r); err != nil {
			t.Fatal(err)
		}
		for i, f := range r.Findings {
			if strings.Contains(f.Summary, "authz-probe") {
				return &r.Findings[i]
			}
		}
		return nil
	}

	// Device posture and risk are facts a session carries now (11.07), so a model set
	// when doctor called them critical is an ordinary model.
	store(`{"types":{"doc":{"relations":{"owner":[]},"permissions":{"read":["owner"]},"require":{"read":{"max_risk":30}}}}}`)
	if f := probe(); f != nil {
		t.Fatalf("a model that loads was reported: %s", f.Summary)
	}

	store(`{"types":"not a map of types"}`)
	f := probe()
	if f == nil || !strings.Contains(f.Summary, "does not load") {
		t.Fatalf("a stored model that does not load was not reported: %+v", f)
	}
	if f.Severity != Critical {
		t.Errorf("reported as %s, want critical", f.Severity)
	}
}
