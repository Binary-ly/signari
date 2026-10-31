package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// The client PATCH sets how a client names people through the writer `client
// set-subject-type` and `apply` use, and answers what it stored (9.07).
func TestAClientPATCHSetsTheSubjectType(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	id := fmt.Sprintf("sub-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	if rec := call(t, s, http.MethodPost, "/admin/clients", testToken, map[string]any{
		"client_id": id, "org_id": org,
		"redirect_uris": []string{"https://app.example.test/cb", "https://other.example.test/cb"},
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create gave %d %s", rec.Code, rec.Body.String())
	}
	if got, err := store.ClientSettingsOf(context.Background(), s.db, id); err != nil || got.SubjectType != "public" {
		t.Fatalf("a new client's subjects are %q (%v), want public", got.SubjectType, err)
	}

	var out map[string]any
	rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{"subject_type": "pairwise"})
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_setting" {
		t.Errorf("pairwise with two hosts and no sector gave %d %v", rec.Code, out["error"])
	}

	rec = call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken,
		map[string]any{"subject_type": "pairwise", "sector": "example.test"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH gave %d %s", rec.Code, rec.Body.String())
	}
	out = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["subject_type"] != "pairwise" || out["sector"] != "example.test" {
		t.Errorf("the response gave %v in %v", out["subject_type"], out["sector"])
	}
	if got, _ := store.ClientSettingsOf(context.Background(), s.db, id); got.SubjectType != "pairwise" || got.Sector != "example.test" {
		t.Errorf("stored %q in %q", got.SubjectType, got.Sector)
	}

	rec = call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{"sector": "not a host"})
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_setting" {
		t.Errorf("a bad sector gave %d %v", rec.Code, out["error"])
	}
}
