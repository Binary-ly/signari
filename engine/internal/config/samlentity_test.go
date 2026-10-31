package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A sign-in started here is declared like the rest of a provider (8.02): off when the
// file says nothing, left alone by a file that stops naming it, and exported so a file
// made from one organisation does the same in another.
func TestASignInStartedHereIsDeclared(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	entity := fmt.Sprintf("https://sp-%d.example.test", time.Now().UnixNano())
	on, relay := true, "/home"
	plain := SAMLProvider{EntityID: entity, ACSURLs: []string{"https://sp.example.test/acs"}}
	opted := plain
	opted.IdPInitiated, opted.DefaultRelayState = &on, &relay
	apply := func(p SAMLProvider) string {
		t.Helper()
		f := &File{SAMLProviders: []SAMLProvider{p}}
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return plan.String()
	}
	held := func() (taken bool, state string) {
		t.Helper()
		if err := tx.QueryRow(ctx, `SELECT idp_initiated, default_relay_state FROM core.saml_providers
			WHERE entity_id = $1`, entity).Scan(&taken, &state); err != nil {
			t.Fatal(err)
		}
		return taken, state
	}

	apply(plain)
	if taken, state := held(); taken || state != "" {
		t.Errorf("a file that says nothing opted it in: %t %q", taken, state)
	}
	if plan := apply(opted); !strings.Contains(plan, "idp_initiated") || !strings.Contains(plan, "default_relay_state") {
		t.Errorf("opting in was planned as\n%s", plan)
	}
	if taken, state := held(); !taken || state != relay {
		t.Errorf("the provider holds %t %q", taken, state)
	}
	if plan := apply(opted); strings.Contains(plan, entity) {
		t.Errorf("applied again it plans\n%s", plan)
	}
	if plan := apply(plain); strings.Contains(plan, "idp_initiated") {
		t.Errorf("a file that stops naming it plans\n%s", plan)
	}
	if taken, _ := held(); !taken {
		t.Error("a file that stopped naming it turned it off")
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range exported.SAMLProviders {
		if p.EntityID == entity {
			found = p.IdPInitiated != nil && *p.IdPInitiated && p.DefaultRelayState != nil && *p.DefaultRelayState == relay
		}
	}
	if !found {
		t.Error("the export left it out")
	}

	long := strings.Repeat("x", 81)
	over := opted
	over.DefaultRelayState = &long
	if err := (&File{Version: 1, SAMLProviders: []SAMLProvider{over}}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "default_relay_state") {
		t.Errorf("a RelayState SAML would not carry answered %v", err)
	}
}

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
