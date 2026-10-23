package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// What a file may not say about scopes, attributes and the sign-up rule
// (6.19), refused before anything is written: by Validate where the file alone
// shows it, by the plan where only the deployment does.
func TestTheNewKindsRefuseWhatTheDeploymentCannotHonour(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for name, raw := range map[string]string{
		"a standard scope declared":  "scopes: [{name: email}]",
		"a scope twice":              "scopes: [{name: hr}, {name: hr}]",
		"an unknown value type":      "attributes: [{name: x, value_type: colour}]",
		"writable and not readable":  "attributes: [{name: x, user_writable: true}]",
		"a relative resource":        "resources: [{resource: /api}]",
		"a resource with a fragment": "resources: [{resource: 'https://api.example.test/#x'}]",
		"sign-up for nobody named":   "signup: {groups: [staff]}",
		"any domain and domains":     "signup: {any_domain: true, domains: [example.test]}",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	n := time.Now().UnixNano()
	plan := func(raw string) error {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			return err
		}
		return Apply(ctx, tx, org, f, p)
	}
	attr := fmt.Sprintf("badge%d", n)
	if err := plan(fmt.Sprintf("attributes: [{name: %s, value_type: number, personal: true}]", attr)); err != nil {
		t.Fatal(err)
	}
	if err := plan(fmt.Sprintf("attributes: [{name: %s, value_type: number}]", attr)); err == nil ||
		!strings.Contains(err.Error(), "sealed") {
		t.Errorf("unsealing a personal attribute answered %v", err)
	}
	// Retyped while nothing is stored, it is; with a value held, it is not.
	if err := plan(fmt.Sprintf("attributes: [{name: %s, value_type: string, personal: true}]", attr)); err != nil {
		t.Errorf("retyping an attribute holding nothing: %v", err)
	}
	var user, attrID string
	if err := tx.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email) VALUES ($1::uuid,
		sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea), $2) RETURNING id::text`,
		org, fmt.Sprintf("held-%d@example.test", n)).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT id::text FROM core.user_attribute_schema WHERE org_id = $1::uuid AND name = $2`,
		org, attr).Scan(&attrID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.user_attributes (user_id, attribute_id, org_id, value_sealed)
		VALUES ($1::uuid, $2::uuid, $3::uuid, '\x00'::bytea)`, user, attrID, org); err != nil {
		t.Fatal(err)
	}
	if err := plan(fmt.Sprintf("attributes: [{name: %s, value_type: number, personal: true}]", attr)); err == nil ||
		!strings.Contains(err.Error(), "retyping") {
		t.Errorf("retyping an attribute holding a value answered %v", err)
	}

	if err := plan(fmt.Sprintf("signup: {domains: [example.test], groups: [never-made-%d]}", n)); err == nil ||
		!strings.Contains(err.Error(), "no group") {
		t.Errorf("sign-up into a group that does not exist answered %v", err)
	}
	// Not when the file makes the group too.
	if err := plan(fmt.Sprintf("groups: [{name: made-%[1]d}]\nsignup: {domains: [example.test], groups: [made-%[1]d]}",
		n)); err != nil {
		t.Errorf("sign-up into a group the same file makes: %v", err)
	}

	// A scope a claim mapper is gated on is not pruned out from under it, while
	// the attribute the mapper releases is kept.
	scope := fmt.Sprintf("gated%d", n)
	if err := plan(fmt.Sprintf("scopes: [{name: %s}]", scope)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.claim_mappers (org_id, attribute_id, claim_name, destination,
		required_scope) VALUES ($1::uuid, $2::uuid, 'badge', 'id_token', $3)`, org, attrID, scope); err != nil {
		t.Fatal(err)
	}
	f, err := Parse([]byte(fmt.Sprintf("version: 1\nattributes: [{name: %s, personal: true}]\n", attr)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlan(ctx, tx, org, f, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, tx, org, f, p); err == nil || !strings.Contains(err.Error(), "claim mapper") {
		t.Errorf("pruning a scope a mapper is gated on answered %v", err)
	}
}
