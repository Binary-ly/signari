package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/store"
)

// newExplainOrg is an organisation of the test's own with a model.
func newExplainOrg(t *testing.T, s *Server) string {
	t.Helper()
	org := newDriftMigrationOrg(t, s, false)
	m, err := authzen.ParseModel([]byte(umaModel))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveModel(context.Background(), s.db, org, umaModel, m, ""); err != nil {
		t.Fatal(err)
	}
	return org
}

// An explanation says what the relations say and whose grant answered, and an
// action the model does not have is said to be that, not merely a no.
func TestAQuestionIsExplained(t *testing.T) {
	s, _ := newTestServer(t)
	org := newExplainOrg(t, s)
	base := "/admin/organizations/" + org
	if rec := call(t, s, http.MethodPut, base+"/relations", testToken, map[string]string{
		"subject": "user:ada", "relation": "viewer", "object": "document:1"}); rec.Code != http.StatusOK {
		t.Fatalf("granting: %d %s", rec.Code, rec.Body.String())
	}
	explain := func(query string, want int) map[string]any {
		t.Helper()
		rec := call(t, s, http.MethodGet, base+"/authorization/explain?"+query, testToken, nil)
		if rec.Code != want {
			t.Fatalf("%s answered %d: %s", query, rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	got := explain("subject=user:ada&action=read&object=document:1", http.StatusOK)
	if got["allowed"] != true || got["relation"] != "viewer" || got["via"] != "user:ada" || got["defined"] != true {
		t.Errorf("ada's answer is %v", got)
	}
	got = explain("subject=user:bob&action=read&object=document:1", http.StatusOK)
	if got["allowed"] != false || got["relation"] != "" || got["defined"] != true {
		t.Errorf("bob's answer is %v", got)
	}
	got = explain("subject=user:ada&action=shred&object=document:1", http.StatusOK)
	if got["allowed"] != false || got["defined"] != false {
		t.Errorf("an action nobody defined answered %v", got)
	}
	explain("subject=ada&action=read&object=document:1", http.StatusBadRequest)

	bare := newDriftMigrationOrg(t, s, false)
	rec := call(t, s, http.MethodGet, "/admin/organizations/"+bare+
		"/authorization/explain?subject=user:a&action=read&object=document:1", testToken, nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("an organisation with no model answered %d", rec.Code)
	}
}
