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

// The client PATCH sets the client's acr floor through the writer `client
// set-acr` and `apply` use, and refuses one outside the ladder (4.02).
func TestAClientPATCHSetsTheMinimumACR(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	id := fmt.Sprintf("acr-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	if rec := call(t, s, http.MethodPost, "/admin/clients", testToken, map[string]any{
		"client_id": id, "org_id": org, "redirect_uris": []string{"https://app.example.test/cb"},
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create gave %d %s", rec.Code, rec.Body.String())
	}
	if got, err := store.ClientSettingsOf(context.Background(), s.db, id); err != nil || got.MinimumACR != "1" {
		t.Fatalf("a new client's floor is %q (%v), want 1", got.MinimumACR, err)
	}

	rec := call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{"minimum_acr": "2"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH gave %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["minimum_acr"] != "2" {
		t.Errorf("the response gave minimum_acr %v, want 2", out["minimum_acr"])
	}
	if got, _ := store.ClientSettingsOf(context.Background(), s.db, id); got.MinimumACR != "2" {
		t.Errorf("stored floor %q, want 2", got.MinimumACR)
	}

	// "3" and "4" are rungs since 4.15; "5" is none.
	rec = call(t, s, http.MethodPatch, "/admin/clients/"+id, testToken, map[string]any{"minimum_acr": "5"})
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_setting" {
		t.Errorf("a floor of 5 gave %d %v", rec.Code, out["error"])
	}
}
