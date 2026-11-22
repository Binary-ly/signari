package config

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// member_of in a configuration file (11.09).

func edges(t *testing.T, ctx context.Context, tx pgx.Tx, org, prefix string) []string {
	t.Helper()
	rows, err := tx.Query(ctx, `SELECT c.name || '>' || p.name FROM core.group_parents n
		JOIN core.groups c ON c.id = n.group_id JOIN core.groups p ON p.id = n.parent_id
		WHERE n.org_id = $1::uuid AND c.name LIKE $2 || '%' ORDER BY 1`, org, prefix)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func in(names ...string) *[]string { return &names }

// Planned with what each group would be inside, applied, planned again as nothing,
// exported as it is, turned upside down in one apply, and left alone when omitted.
func TestMemberOfIsPlannedAppliedAndExported(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	p := fmt.Sprintf("cfg-nest-%d-", time.Now().UnixNano())
	a, b, c := p+"a", p+"b", p+"c"

	apply := func(f *File) *Plan {
		t.Helper()
		if err := f.Validate(); err != nil {
			t.Fatal(err)
		}
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatalf("applying:\n%s\n%v", plan.String(), err)
		}
		return plan
	}

	plan := apply(&File{Groups: []Group{{Name: a, MemberOf: in(b)}, {Name: b, MemberOf: in(c)}, {Name: c}}})
	for _, ch := range plan.Changes {
		if ch.Kind == "group" && ch.Name == a && !slices.Equal(ch.Inside, []string{b, c}) {
			t.Errorf("the plan says %s will be inside %v, want [%s %s]: the scope check reads this", a, ch.Inside, b, c)
		}
	}
	if got, want := edges(t, ctx, tx, org, p), []string{a + ">" + b, b + ">" + c}; !slices.Equal(got, want) {
		t.Fatalf("nested %v, want %v", got, want)
	}
	again, err := BuildPlan(ctx, tx, org, &File{Groups: []Group{{Name: a, MemberOf: in(b)}, {Name: b, MemberOf: in(c)},
		{Name: c}}}, false)
	if err != nil || !again.Empty() {
		t.Errorf("the applied file plans again: %v\n%s", err, again.String())
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range exported.Groups {
		switch g.Name {
		case a:
			if g.MemberOf == nil || !slices.Equal(*g.MemberOf, []string{b}) {
				t.Errorf("exported %s inside %v, want [%s]", a, g.MemberOf, b)
			}
		case c:
			if g.MemberOf != nil {
				t.Errorf("exported %s, inside nothing, with member_of %v; it should say nothing", c, *g.MemberOf)
			}
		}
	}

	// Upside down, listed so that the first group the apply reaches would be put inside
	// one it is still above: only removing every old nesting first lets this through.
	apply(&File{Groups: []Group{{Name: c, MemberOf: in(b)}, {Name: b, MemberOf: in(a)}, {Name: a, MemberOf: in()}}})
	if got, want := edges(t, ctx, tx, org, p), []string{b + ">" + a, c + ">" + b}; !slices.Equal(got, want) {
		t.Fatalf("turned upside down to %v, want %v", got, want)
	}

	left, err := BuildPlan(ctx, tx, org, &File{Groups: []Group{{Name: a}, {Name: b}, {Name: c}}}, false)
	if err != nil || !left.Empty() {
		t.Errorf("a file saying nothing of member_of plans a change: %v\n%s", err, left.String())
	}
}

// A loop among the file's own nestings is refused with no database; one closed through
// the organisation's is refused when applied; a parent nobody has is refused when planned.
func TestMemberOfThatCannotBeHonouredIsRefused(t *testing.T) {
	_, err := Parse([]byte(`version: 1
groups:
  - {name: a, member_of: [b]}
  - {name: b, member_of: [c]}
  - {name: c, member_of: [a]}
`))
	if err == nil || !strings.Contains(err.Error(), "member_of makes a loop") {
		t.Errorf("a loop in the file: %v, want it refused before anything is applied", err)
	}
	if _, err := Parse([]byte("version: 1\ngroups:\n  - {name: a, member_of: [a]}\n")); err == nil ||
		!strings.Contains(err.Error(), "inside itself") {
		t.Errorf("a group in its own member_of: %v", err)
	}

	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	p := fmt.Sprintf("cfg-loop-%d-", time.Now().UnixNano())
	first := &File{Groups: []Group{{Name: p + "a", MemberOf: in(p + "b")}, {Name: p + "b"}}}
	plan, err := BuildPlan(ctx, tx, org, first, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, tx, org, first, plan); err != nil {
		t.Fatal(err)
	}
	closing := &File{Groups: []Group{{Name: p + "b", MemberOf: in(p + "a")}}}
	if err := closing.Validate(); err != nil {
		t.Fatalf("the file alone has no loop and should validate: %v", err)
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT before_loop"); err != nil {
		t.Fatal(err)
	}
	plan, err = BuildPlan(ctx, tx, org, closing, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, tx, org, closing, plan); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("a file closing a loop through the organisation's nesting: %v, want it refused", err)
	}
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT before_loop"); err != nil {
		t.Fatal(err)
	}

	if _, err := BuildPlan(ctx, tx, org, &File{Groups: []Group{{Name: p + "a", MemberOf: in(p + "nobody")}}}, false); err == nil ||
		!strings.Contains(err.Error(), "does not have") {
		t.Errorf("member_of naming no group: %v, want it refused", err)
	}
}
