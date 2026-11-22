package config

import (
	"bytes"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// Two providers on a hook in a file (10.06). Keyed by the hook alone, the second would have
// been read as the first, an export would have lost one, and a prune would have taken both.
func TestAFileHoldsSeveralProvidersOnAHook(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	apply := func(prune bool, ps ...Provider) *Plan {
		t.Helper()
		f := &File{Providers: ps}
		plan, err := BuildPlanWith(ctx, tx, org, f, prune, Options{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	plain := Provider{Hook: "client_access", URL: "https://plain.example.test/hook", Mode: "fail_open"}
	second := Provider{Hook: "client_access", Name: "fraud", Position: 3, URL: "https://fraud.example.test/hook", Mode: "fail_closed"}

	if plan := apply(false, plain, second); len(plan.Minted) != 2 {
		t.Fatalf("minted %+v, want one for each", plan.Minted)
	}
	held := func() map[string]store.ProviderRow {
		t.Helper()
		rows, err := store.ListProviders(ctx, tx, org)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]store.ProviderRow{}
		for _, r := range rows {
			if r.Hook == "client_access" {
				out[r.Name] = r
			}
		}
		return out
	}
	got := held()
	if len(got) != 2 || got["fraud"].Position != 3 || got["provider-client_access"].Mode != "fail_open" {
		t.Fatalf("held %+v", got)
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	var named, unnamed int
	for _, p := range exported.Providers {
		switch {
		case p.Hook == "client_access" && p.Name == "fraud":
			named++
		case p.Hook == "client_access" && p.Name == "":
			unnamed++
		}
	}
	if named != 1 || unnamed != 1 {
		t.Errorf("exported %d named and %d unnamed", named, unnamed)
	}

	if plan := apply(false, plain, second); len(plan.Changes) != 0 {
		t.Errorf("the same file planned %+v", plan.Changes)
	}
	moved := second
	moved.Position = 1
	if plan := apply(false, plain, moved); len(plan.Changes) != 1 || plan.Changes[0].Name != "client_access/fraud" {
		t.Errorf("moving one planned %+v", plan.Changes)
	}
	if got := held(); got["fraud"].Position != 1 {
		t.Errorf("moving one left %+v", got["fraud"])
	}

	apply(true, plain)
	if got := held(); len(got) != 1 || got["provider-client_access"].URL != plain.URL {
		t.Errorf("pruning the one left out left %+v", got)
	}
}

func TestAFileNamesAProviderOnce(t *testing.T) {
	raw := "version: 1\nproviders:\n" +
		"  - {hook: authorize, name: a, url: 'https://a.example.test/', mode: fail_closed}\n" +
		"  - {hook: authorize, name: a, url: 'https://b.example.test/', mode: fail_closed}\n"
	if _, err := Parse([]byte(raw)); err == nil {
		t.Error("the same provider twice in a file parsed")
	}
	two := "version: 1\nproviders:\n" +
		"  - {hook: authorize, name: a, url: 'https://a.example.test/', mode: fail_closed}\n" +
		"  - {hook: authorize, name: b, url: 'https://b.example.test/', mode: fail_closed}\n"
	if _, err := Parse([]byte(two)); err != nil {
		t.Errorf("two providers on a hook: %v", err)
	}
}
