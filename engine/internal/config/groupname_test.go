package config

import (
	"fmt"
	"testing"
	"time"
)

// A group declared by name alone is created displayed as its name, as
// `signari group create` makes one, and a second plan finds nothing to do.
// Applied, it failed on the column's NOT NULL, so the shortest file the
// format allows could not be applied; and a group the command had made was
// planned as an update on every run, its display name compared with an empty
// one.
func TestAGroupDeclaredByNameAloneIsAppliedAndThenLeftAlone(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	name := fmt.Sprintf("cfg-bare-%d", time.Now().UnixNano())
	f := &File{Groups: []Group{{Name: name}}}
	plan, err := BuildPlan(ctx, tx, org, f, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, tx, org, f, plan); err != nil {
		t.Fatalf("applying a group declared by name alone: %v", err)
	}
	var shown string
	if err := tx.QueryRow(ctx, `SELECT display_name FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		org, name).Scan(&shown); err != nil {
		t.Fatal(err)
	}
	if shown != name {
		t.Errorf("the group is displayed as %q, want its name", shown)
	}
	again, err := BuildPlan(ctx, tx, org, f, false)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Empty() {
		t.Errorf("the applied file plans again:\n%s", again.String())
	}
}
