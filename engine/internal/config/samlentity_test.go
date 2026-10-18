package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A SAML request names only its entity ID, so a second organisation
// registering the same one would make every request to either an even bet.
// `apply` must refuse the second registration by name and keep upserting the
// first organisation's own row.
func TestApplyRefusesAnotherOrganisationsSAMLEntityID(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	entity := fmt.Sprintf("https://sp-%d.example.test", time.Now().UnixNano())
	f := &File{SAMLProviders: []SAMLProvider{{
		EntityID: entity,
		ACSURLs:  []string{"https://sp.example.test/acs"},
	}}}
	apply := func(orgID string) error {
		t.Helper()
		plan, err := BuildPlan(ctx, tx, orgID, f, false)
		if err != nil {
			t.Fatal(err)
		}
		return Apply(ctx, tx, orgID, f, plan)
	}

	if err := apply(org); err != nil {
		t.Fatalf("the first registration was refused: %v", err)
	}

	var other string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'saml-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		FROM core.organizations WHERE id = $1::uuid
		RETURNING id::text`, org).Scan(&other); err != nil {
		t.Fatal(err)
	}

	// A savepoint, because the refusal aborts the transaction and the
	// re-apply below has to run in it.
	if _, err := tx.Exec(ctx, `SAVEPOINT second`); err != nil {
		t.Fatal(err)
	}
	err = apply(other)
	if err == nil {
		t.Fatal("a second organisation registered an entity ID the first already holds")
	}
	if !strings.Contains(err.Error(), "registered by another organisation") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT second`); err != nil {
		t.Fatal(err)
	}

	if err := apply(org); err != nil {
		t.Fatalf("re-applying the first organisation's own registration was refused: %v", err)
	}
}
