package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A client's names in other languages in a configuration file (10.12).
func TestLocalizedNamesArePlannedAppliedAndExported(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id := fmt.Sprintf("cfg-names-%d", time.Now().UnixNano())
	client := func(names *map[string]string) *File {
		return &File{Clients: []Client{{ClientID: id, Name: "My Client", RedirectURIs: []string{"https://rp.test/cb"},
			LocalizedNames: names}}}
	}
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

	apply(client(&map[string]string{"ja": "日本語の名前", "de": "Mein Client"}))
	if got, err := store.ClientNames(ctx, tx, id); err != nil || got["ja"] != "日本語の名前" || len(got) != 2 {
		t.Fatalf("applied names %v, %v", got, err)
	}
	if again, err := BuildPlan(ctx, tx, org, client(&map[string]string{"ja": "日本語の名前", "de": "Mein Client"}), false); err != nil ||
		!again.Empty() {
		t.Errorf("the applied file plans again: %v\n%s", err, again.String())
	}
	if left, err := BuildPlan(ctx, tx, org, client(nil), false); err != nil || !left.Empty() {
		t.Errorf("a file saying nothing of localized_names plans a change: %v\n%s", err, left.String())
	}
	changed, err := BuildPlan(ctx, tx, org, client(&map[string]string{"ja": "新しい名前"}), false)
	if err != nil || !strings.Contains(changed.String(), "localized_names") {
		t.Errorf("a changed name is not planned as one: %v\n%s", err, changed.String())
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range exported.Clients {
		if c.ClientID == id && (c.LocalizedNames == nil || (*c.LocalizedNames)["de"] != "Mein Client") {
			t.Errorf("exported without its names: %v", c.LocalizedNames)
		}
	}

	apply(client(&map[string]string{}))
	if got, _ := store.ClientNames(ctx, tx, id); len(got) != 0 {
		t.Errorf("{} left %v", got)
	}

	bad := client(&map[string]string{"not a tag": "x"})
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "localized_names") {
		t.Errorf("a tag that is not one: %v, want it refused before anything is applied", err)
	}
}
