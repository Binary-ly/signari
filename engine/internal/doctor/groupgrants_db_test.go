package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A relation granted to a group that does not exist is named, with its
// organisation, until a group of that name exists.
func TestAGrantToNoGroupIsReported(t *testing.T) {
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
			VALUES ('https://grants-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'grants-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
		VALUES ($1::uuid, 'group', 'ghost-finance', 'viewer', 'document', 'payroll')`, orgID); err != nil {
		t.Fatal(err)
	}
	probe := func() *Finding {
		t.Helper()
		r := &Report{}
		if err := checkGrantsToNoGroup(ctx, tx, r); err != nil {
			t.Fatal(err)
		}
		for i, f := range r.Findings {
			if strings.Contains(f.Summary, "grants-probe") {
				return &r.Findings[i]
			}
		}
		return nil
	}
	f := probe()
	if f == nil || f.Severity != Warning || !strings.Contains(f.Summary, "ghost-finance") {
		t.Fatalf("a grant to no group: %+v", f)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'ghost-finance', 'Finance')`, orgID); err != nil {
		t.Fatal(err)
	}
	if f := probe(); f != nil {
		t.Errorf("reported once the group exists: %+v", f)
	}
}
