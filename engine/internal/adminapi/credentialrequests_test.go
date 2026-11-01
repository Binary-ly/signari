package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A credential held for a decision, through the routes the console will use (12.08).
func TestACredentialRequestIsDecidedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, _, config, userID := newDriftWallet(t, s)
	base := "/admin/organizations/" + org
	path := base + "/credential-configurations/" + config

	define := func(body map[string]any) {
		t.Helper()
		body["vct"], body["always"] = "https://drift.example.test/id", []string{"email"}
		if rec := call(t, s, http.MethodPut, path, testToken, body); rec.Code != http.StatusOK {
			t.Fatalf("defining: %d %s", rec.Code, rec.Body.String())
		}
	}
	deferred := func() bool {
		t.Helper()
		list := call(t, s, http.MethodGet, base+"/credential-configurations", testToken, nil).Body.String()
		return strings.Contains(list, `"deferred":true`)
	}
	define(map[string]any{"deferred": true})
	if !deferred() {
		t.Fatal("deferred was not set")
	}
	// Redefining the claims does not quietly drop it.
	define(map[string]any{})
	if !deferred() {
		t.Error("redefining without saying dropped it")
	}

	request := func(id string) string {
		t.Helper()
		transaction, err := store.NewCredentialRequest(ctx, s.db, org, userID, id, config, []byte(`[]`))
		if err != nil {
			t.Fatal(err)
		}
		return transaction
	}
	request("jti-a")
	var listed struct {
		Requests []struct {
			ID, Email, Configuration string
			UserID                   string `json:"user_id"`
		} `json:"requests"`
	}
	rec := call(t, s, http.MethodGet, base+"/credential-requests", testToken, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Requests) != 1 {
		t.Fatalf("listed %s (%v)", rec.Body.String(), err)
	}
	got := listed.Requests[0]
	if got.UserID != userID || got.Configuration != config || !strings.HasPrefix(got.Email, "holder-") {
		t.Errorf("listed %+v", got)
	}
	decide := base + "/credential-requests/" + got.ID
	if rec := call(t, s, http.MethodPut, decide, testToken, map[string]any{"decision": "perhaps"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a decision of its own answered %d %s", rec.Code, rec.Body.String())
	}
	// Another organisation's request is not this one's to decide.
	other := "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/credential-requests/" + got.ID
	if rec := call(t, s, http.MethodPut, other, testToken, map[string]any{"decision": "approve"}); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPut, decide, testToken, map[string]any{"decision": "approve"}); rec.Code != http.StatusOK {
		t.Fatalf("approving answered %d %s", rec.Code, rec.Body.String())
	}
	// It stands, and it has left the list.
	if rec := call(t, s, http.MethodPut, decide, testToken, map[string]any{"decision": "deny"}); rec.Code != http.StatusNotFound {
		t.Errorf("deciding twice answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodGet, base+"/credential-requests", testToken, nil); strings.Contains(rec.Body.String(), got.ID) {
		t.Errorf("a decided request is still waiting: %s", rec.Body.String())
	}
}
