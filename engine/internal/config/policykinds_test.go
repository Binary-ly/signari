package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A prompt a pruned file leaves out is switched off and kept (6.19): its
// answers are the record of who agreed to what, and deleting the prompt would
// delete them.
func TestAPrunedPromptIsDisabledNotDeleted(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	slug := fmt.Sprintf("terms-%d", time.Now().UnixNano())
	apply := func(raw string, prune bool) *Plan {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlan(ctx, tx, org, f, prune)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	apply(fmt.Sprintf("prompts: [{slug: %s, title: Terms, fields: [{name: ok, type: checkbox, label: I accept, "+
		"required: true}]}]\n", slug), false)
	p := apply("", true)
	if p.Destructive() != nil || !strings.Contains(p.String(), "disabled rather than deleted") {
		t.Errorf("the pruned plan reads:\n%s", p)
	}
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT enabled FROM core.prompts WHERE org_id = $1::uuid AND slug = $2`, org, slug).
		Scan(&enabled); err != nil {
		t.Fatalf("the pruned prompt is gone: %v", err)
	}
	if enabled {
		t.Error("the pruned prompt is still asked")
	}
	// Pruned again, an already disabled prompt plans nothing.
	if p := apply("", true); strings.Contains(p.String(), slug) {
		t.Errorf("a disabled prompt was planned again:\n%s", p)
	}
}

// What a file may not say about mappers and documents, refused by Validate.
func TestMappersAndDocumentsAreCheckedBeforeAnything(t *testing.T) {
	for name, raw := range map[string]string{
		"a mapper for nobody named":   "claim_mappers: [{attribute: a, claim: a, destination: id_token}]",
		"a mapper for both":           "claim_mappers: [{attribute: a, claim: a, destination: id_token, client_id: x, all_clients: true}]",
		"a destination that is none":  "claim_mappers: [{attribute: a, claim: a, destination: logs, all_clients: true}]",
		"the same mapper twice":       "claim_mappers: [{attribute: a, claim: a, destination: id_token, all_clients: true}, {attribute: a, claim: b, destination: id_token, all_clients: true}]",
		"a policy that will not load": "access_policy: \"version: 1\\npolicies: []\\n\"",
		"a flow that will not load":   "sign_in_flow: \"version: 1\\nflows: [{name: x, on: authentication, stages: [session]}]\\n\"",
		"a prompt with no title":      "prompts: [{slug: x}]",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
