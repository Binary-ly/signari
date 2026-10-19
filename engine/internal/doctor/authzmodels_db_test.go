package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A model stored before `authz set-model` refused device posture and risk is
// still the one evaluated. Doctor names the organisation and the rule, and says
// nothing about a model on facts the decision point has.
func TestAStoredModelOnUnpopulatedFactsIsCritical(t *testing.T) {
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

	store(`{"types":{"doc":{"relations":{"owner":[]},"permissions":{"read":["owner"]},"require":{"read":{"mfa":true}}}}}`)
	if f := probe(); f != nil {
		t.Fatalf("a model on facts the decision point has was reported: %s", f.Summary)
	}

	store(`{"types":{"doc":{"relations":{"owner":[]},"permissions":{"read":["owner"]},"require":{"read":{"max_risk":30}}}}}`)
	f := probe()
	if f == nil || !strings.Contains(f.Summary, "doc.read: max_risk") {
		t.Fatalf("a stored max_risk rule was not reported naming the rule: %+v", f)
	}
	if f.Severity != Critical {
		t.Errorf("reported as %s, want critical", f.Severity)
	}
}
