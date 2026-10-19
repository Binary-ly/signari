package config

import (
	"fmt"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A client's sign-out registration is set by `apply`, left alone when the file
// omits it, and cleared by an empty list (2.11).
func TestApplyRegistersSignOut(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id := fmt.Sprintf("cfg-logout-%d", time.Now().UnixNano())
	apply := func(c Client) *Plan {
		t.Helper()
		c.ClientID, c.RedirectURIs = id, []string{"https://app.test/cb"}
		f := &File{Clients: []Client{c}}
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	bye, fc := []string{"https://app.test/bye"}, "https://app.test/fc"
	apply(Client{PostLogoutRedirectURIs: &bye, FrontchannelLogoutURI: &fc})
	if uris, got, _, err := store.ClientLogoutOf(ctx, tx, id); err != nil || len(uris) != 1 || got != fc {
		t.Fatalf("after apply: %q %q %v", uris, got, err)
	}
	if plan := apply(Client{}); !plan.Empty() {
		t.Errorf("a file naming neither planned %+v", plan.Changes)
	}
	if uris, got, _, _ := store.ClientLogoutOf(ctx, tx, id); len(uris) != 1 || got != fc {
		t.Errorf("an omitted registration changed to %q %q", uris, got)
	}
	none := []string{}
	if plan := apply(Client{PostLogoutRedirectURIs: &none}); plan.Empty() {
		t.Error("clearing the list planned nothing")
	}
	if uris, _, _, _ := store.ClientLogoutOf(ctx, tx, id); len(uris) != 0 {
		t.Errorf("an empty list left %q", uris)
	}
}
