package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// An authorization model is stored and a relation granted and revoked
// through the Admin API as `signari authz` does it (6.07): a model whose own
// tests fail never reaches the table, and a grant decides the next question.
func TestAuthorizationIsConfiguredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org
	errorOf := func(method, path string, body any, want int) string {
		t.Helper()
		rec := call(t, s, method, path, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s answered %d, want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}

	wrong := strings.Replace(driftModel, "allow: true", "allow: false", 1)
	if e := errorOf(http.MethodPut, base+"/authorization-model", map[string]string{"source": wrong},
		http.StatusBadRequest); e != "invalid_model" {
		t.Errorf("a model whose test fails answered %q", e)
	}
	if src, _ := store.ModelSource(ctx, s.db, org); src != "" {
		t.Fatal("a refused model was stored")
	}
	if rec := call(t, s, http.MethodPut, base+"/authorization-model", testToken,
		map[string]string{"source": driftModel}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"tests_passed":1`) {
		t.Fatalf("storing the model: %d %s", rec.Code, rec.Body.String())
	}
	if got := call(t, s, http.MethodGet, base+"/authorization-model", testToken, nil); !strings.Contains(got.Body.String(), "an owner may read") {
		t.Errorf("the model reads %s", got.Body.String())
	}

	holds := func() bool {
		m, err := store.LoadModel(ctx, s.db, org)
		if err != nil || m == nil {
			t.Fatalf("loading the model: %v", err)
		}
		relations, _ := m.RelationsFor("document", "read")
		held, err := store.HoldsAny(ctx, s.db, org, "user", "alice", relations, "document", "1", nil)
		if err != nil {
			t.Fatal(err)
		}
		return held != ""
	}
	if e := errorOf(http.MethodPut, base+"/relations", map[string]string{"subject": "alice", "relation": "owner",
		"object": "document:1"}, http.StatusBadRequest); e != "invalid_relation" {
		t.Errorf("a subject without a type answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, base+"/relations", testToken, map[string]string{"subject": "user:alice",
		"relation": "owner", "object": "document:1"}); rec.Code != http.StatusOK || !holds() {
		t.Fatalf("granting answered %d and alice may read: %v", rec.Code, holds())
	}
	revoke := base + "/relations?subject=user:alice&relation=owner&object=document:1"
	if rec := call(t, s, http.MethodDelete, revoke, testToken, nil); rec.Code != http.StatusOK || holds() {
		t.Fatalf("revoking answered %d and alice may still read: %v", rec.Code, holds())
	}
	if e := errorOf(http.MethodDelete, revoke, nil, http.StatusNotFound); e != "relation_not_found" {
		t.Errorf("revoking it again answered %q", e)
	}
}
