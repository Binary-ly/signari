package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// How a client names people is set by `apply`, its sector taken from the redirect URIs
// the same file gives it, left alone when omitted and planned when changed (9.07).
func TestApplySetsAClientsSubjectType(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id := fmt.Sprintf("cfg-sub-%d", time.Now().UnixNano())
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

	apply(parse("    subject_type: pairwise\n"))
	got, err := store.ClientSettingsOf(ctx, tx, id)
	if err != nil || got.SubjectType != "pairwise" || got.Sector != "app.test" {
		t.Fatalf("after apply: %q in %q (%v)", got.SubjectType, got.Sector, err)
	}
	if plan := apply(parse("")); !plan.Empty() {
		t.Errorf("a file not naming it planned %+v", plan.Changes)
	}
	if plan := apply(parse("    subject_type: pairwise\n    sector: app.test\n")); !plan.Empty() {
		t.Errorf("a file saying what is there planned %+v", plan.Changes)
	}
	if plan := apply(parse("    sector: shared.test\n")); plan.Empty() ||
		!strings.Contains(fmt.Sprint(plan.Changes), "sector") {
		t.Errorf("a new sector planned %+v", plan.Changes)
	}
	if got, _ := store.ClientSettingsOf(ctx, tx, id); got.SubjectType != "pairwise" || got.Sector != "shared.test" {
		t.Errorf("after changing the sector: %q in %q", got.SubjectType, got.Sector)
	}
	if plan := apply(parse("    subject_type: public\n")); plan.Empty() ||
		!strings.Contains(fmt.Sprint(plan.Changes), "subject_type") {
		t.Errorf("going back planned %+v", plan.Changes)
	}
	if got, _ := store.ClientSettingsOf(ctx, tx, id); got.SubjectType != "public" {
		t.Errorf("after going back: %q", got.SubjectType)
	}

	f, err := Parse([]byte("version: 1\nclients:\n  - client_id: x\n    redirect_uris: [https://app.test/cb]\n" +
		"    subject_type: secret\n"))
	if err == nil {
		_, err = BuildPlan(ctx, tx, org, f, false)
	}
	if err == nil || !strings.Contains(err.Error(), "public or pairwise") {
		t.Errorf("a subject type of secret: %v", err)
	}
}
