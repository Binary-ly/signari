package config

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// What a resource's metadata offers is declared with it (12.15), and a file that does
// not mention it leaves it alone.
func TestAResourcesScopesAreDeclaredAndLeftAloneWhenAbsent(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	resource := fmt.Sprintf("https://api-%d.example.test", time.Now().UnixNano())
	apply := func(r Resource) int {
		t.Helper()
		f := &File{Resources: []Resource{r}}
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		changes := len(plan.Changes)
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return changes
	}
	exported := func() []string {
		t.Helper()
		f, err := Export(ctx, tx, org)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range f.Resources {
			if r.Resource == resource {
				return r.Scopes
			}
		}
		t.Fatalf("%s was not exported", resource)
		return nil
	}

	apply(Resource{Resource: resource, Name: "Bills", Scopes: []string{"read", "write"}})
	if got := exported(); !slices.Equal(got, []string{"read", "write"}) {
		t.Fatalf("exported %v", got)
	}
	if n := apply(Resource{Resource: resource, Name: "Bills", Scopes: []string{"read", "write"}}); n != 0 {
		t.Errorf("a file that matches planned %d changes", n)
	}
	if n := apply(Resource{Resource: resource, Name: "Bills"}); n != 0 {
		t.Errorf("a file saying nothing about scopes planned %d changes", n)
	}
	if got := exported(); !slices.Equal(got, []string{"read", "write"}) {
		t.Errorf("a file saying nothing about scopes left %v", got)
	}
	if n := apply(Resource{Resource: resource, Name: "Bills", Scopes: []string{"read"}}); n != 1 {
		t.Errorf("a change of scopes planned %d changes", n)
	}
	if got := exported(); !slices.Equal(got, []string{"read"}) {
		t.Errorf("the change left %v", got)
	}
}
