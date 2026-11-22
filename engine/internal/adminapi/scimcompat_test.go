package adminapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/store"
)

func TestATargetsCompatibilityIsSetAndRead(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/scim-targets"

	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "typo",
		"base_url": "https://scim.example.test/v2", "token": "t", "compatibility": []string{"no-patches"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a misspelling answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "native", "kind": "entra",
		"credentials":   map[string]any{"tenant_id": "t", "client_id": "c", "client_secret": "s"},
		"compatibility": []string{"no-patch"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a native target answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "quirky",
		"base_url": "https://scim.example.test/v2", "token": "t", "compatibility": []string{"no-patch", "typed-members"}}); rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	read := func() []string {
		t.Helper()
		got, err := store.SCIMTargets(ctx, s.db, org)
		if err != nil || len(got) != 1 {
			t.Fatalf("read %v, %v", got, err)
		}
		return got[0].Compatibility
	}
	if got := read(); len(got) != 2 {
		t.Errorf("held %v", got)
	}
	// A sync is what it is for: the client gets it from the same row.
	loaded, err := store.LoadSCIMTargets(ctx, s.db, s.root, org, "quirky")
	if err != nil || len(loaded) != 1 || len(loaded[0].Compatibility) != 2 {
		t.Errorf("loaded %+v, %v", loaded, err)
	}

	if rec := call(t, s, http.MethodPatch, base+"/quirky", testToken, map[string]any{"compatibility": []string{"no-filter"}}); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got := read(); len(got) != 1 || got[0] != "no-filter" {
		t.Errorf("replaced to %v", got)
	}
	if rec := call(t, s, http.MethodPatch, base+"/quirky", testToken, map[string]any{"compatibility": []string{}}); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got := read(); len(got) != 0 {
		t.Errorf("cleared to %v", got)
	}
	if rec := call(t, s, http.MethodPatch, base+"/quirky", testToken, map[string]any{"compatibility": []string{"nope"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a misspelling answered %d %s", rec.Code, rec.Body.String())
	}
	if list := call(t, s, http.MethodGet, base, testToken, nil); !strings.Contains(list.Body.String(), `"compatibility":[]`) {
		t.Errorf("the list read %s", list.Body.String())
	}
}

func TestANativeTargetCannotBeGivenCompatibility(t *testing.T) {
	err := (&provision.TargetSpec{Slug: "g", Kind: "google", Compatibility: []string{"no-patch"}}).Validate()
	if err == nil || !strings.Contains(err.Error(), "only a SCIM target") {
		t.Errorf("answered %v", err)
	}
}
