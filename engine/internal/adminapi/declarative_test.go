package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/store"
)

// An access policy and a sign-in flow file are put in force through the Admin
// API as the apply commands do (6.07): parsed and their own tests run first,
// so one that will not load never reaches the table the engine reads.
func TestPolicyAndFlowDocumentsAreAppliedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org
	put := func(path, doc string, want int) map[string]any {
		t.Helper()
		rec := call(t, s, http.MethodPut, base+path, testToken, map[string]string{"document": doc})
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("PUT %s answered %d, want %d: %s", path, rec.Code, want, rec.Body.String())
		}
		return out
	}

	if got := call(t, s, http.MethodGet, base+"/access-policy", testToken, nil); !strings.Contains(got.Body.String(),
		`"applied_at":null`) {
		t.Errorf("no policy reads %s", got.Body.String())
	}
	// Its own test disagrees with it: the file says deny by default and the
	// case expects allow.
	broken := "version: 1\ndefault: deny\npolicies: []\ntests:\n  - name: open\n" +
		"    given: {client: anything}\n    expect: allow\n"
	if out := put("/access-policy", broken, http.StatusBadRequest); out["error"] != "invalid_policy" {
		t.Errorf("a policy whose test fails answered %v", out)
	}
	if got, _ := store.AccessPolicyOf(ctx, s.db, org); got.AppliedAt != nil {
		t.Fatal("a refused policy was stored")
	}
	good := "version: 1\ndefault: deny\npolicies: []\ntests:\n  - name: closed\n" +
		"    given: {client: anything}\n    expect: deny\n"
	put("/access-policy", good, http.StatusOK)
	if got, _ := store.AccessPolicyOf(ctx, s.db, org); got.Document != good {
		t.Errorf("the stored policy is %q", got.Document)
	}

	if out := put("/sign-in-flow", "flows: [", http.StatusBadRequest); out["error"] != "invalid_flow" {
		t.Errorf("an unparseable flow answered %v", out)
	}
	if got, _ := store.SignInFlowOf(ctx, s.db, org); got.AppliedAt != nil {
		t.Fatal("a refused flow was stored")
	}
	out := put("/sign-in-flow", string(flow.DefaultDocument()), http.StatusOK)
	if out["summary"] == "" {
		t.Errorf("applying the built-in flows answered %v", out)
	}
	read := call(t, s, http.MethodGet, base+"/sign-in-flow", testToken, nil)
	var view struct {
		Document  string
		AppliedAt *string `json:"applied_at"`
	}
	_ = json.Unmarshal(read.Body.Bytes(), &view)
	if view.Document != string(flow.DefaultDocument()) || view.AppliedAt == nil {
		t.Errorf("the applied flow reads %s", read.Body.String())
	}
}
