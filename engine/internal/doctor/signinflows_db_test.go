package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A stored sign-in flow the engine refuses to load leaves its organisation on
// a journey nobody applied. Doctor names the organisation and the reason, and
// says nothing about a flow that loads.
func TestAStoredFlowThatWillNotLoadIsCritical(t *testing.T) {
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
			VALUES ('https://flows-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'flows-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	const loads = `
version: 1
flows:
  - name: plain
    on: authentication
    stages: [password, session]
    tests: [{name: t, given: {}, expect: [password, session]}]
`
	if _, err := tx.Exec(ctx, `INSERT INTO core.sign_in_flows (org_id, document) VALUES ($1::uuid, $2)`,
		orgID, loads); err != nil {
		t.Fatal(err)
	}
	r := &Report{}
	if err := checkSignInFlows(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Summary, "flows-probe") {
			t.Fatalf("a flow that loads was reported: %s", f.Summary)
		}
	}

	// It loads, and it refuses a way in the organisation uses (2.49): only a
	// password is admitted, and a provider is enabled.
	if _, err := tx.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
		VALUES ($1::uuid, 'flows-probe-idp', 'probe', 'oidc', 'x')`, orgID); err != nil {
		t.Fatal(err)
	}
	r = &Report{}
	if err := checkSignInFlows(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	refusesProvider := false
	for _, f := range r.Findings {
		if strings.Contains(f.Summary, "flows-probe") {
			refusesProvider = strings.Contains(f.Summary, "refuses a federated sign-in") && f.Severity == Warning
		}
	}
	if !refusesProvider {
		t.Errorf("a password-only flow in an organisation with an enabled provider was not reported: %v", r.Findings)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.identity_providers WHERE slug = 'flows-probe-idp'`); err != nil {
		t.Fatal(err)
	}

	// device_managed, which no sign-in answers; this used risk_elevated until
	// 4.10 answered it.
	refused := strings.Replace(loads, "[password, session]", "[password, {stage: mfa, when: device_managed}, session]", 1)
	if _, err := tx.Exec(ctx, `UPDATE core.sign_in_flows SET document = $2 WHERE org_id = $1::uuid`,
		orgID, refused); err != nil {
		t.Fatal(err)
	}
	r = &Report{}
	if err := checkSignInFlows(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Summary, "flows-probe") && strings.Contains(f.Summary, "device_managed") {
			if f.Severity != Critical {
				t.Errorf("reported as %s, want critical", f.Severity)
			}
			return
		}
	}
	t.Fatalf("a stored flow the engine refuses was not reported naming its organisation and "+
		"condition: %+v", r.Findings)
}
