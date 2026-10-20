package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A client's acr floor is set by `apply`, left alone when omitted, planned
// when changed, and refused by `plan` outside the ladder (4.02).
func TestApplySetsAClientsMinimumACR(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id := fmt.Sprintf("cfg-acr-%d", time.Now().UnixNano())
	parse := func(lines string) *File {
		t.Helper()
		f, err := Parse([]byte("version: 1\nclients:\n  - client_id: " + id +
			"\n    redirect_uris: [https://app.test/cb]\n" + lines))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	apply := func(f *File) *Plan {
		t.Helper()
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}

	apply(parse("    minimum_acr: \"2\"\n"))
	if got, err := store.ClientSettingsOf(ctx, tx, id); err != nil || got.MinimumACR != "2" {
		t.Fatalf("after apply the floor is %q (%v)", got.MinimumACR, err)
	}
	if plan := apply(parse("")); !plan.Empty() {
		t.Errorf("a file not naming the floor planned %+v", plan.Changes)
	}
	if plan := apply(parse("    minimum_acr: \"1\"\n")); plan.Empty() ||
		!strings.Contains(fmt.Sprint(plan.Changes), "minimum_acr") {
		t.Errorf("a lowered floor planned %+v", plan.Changes)
	}
	if got, _ := store.ClientSettingsOf(ctx, tx, id); got.MinimumACR != "1" {
		t.Errorf("after lowering the floor is %q", got.MinimumACR)
	}

	f, err := Parse([]byte("version: 1\nclients:\n  - client_id: x\n    redirect_uris: [https://app.test/cb]\n" +
		"    minimum_acr: \"3\"\n"))
	if err == nil {
		err = f.Validate()
	}
	if err == nil || !strings.Contains(err.Error(), "acr") {
		t.Errorf("a floor of 3 was not refused before applying: %v", err)
	}
}
