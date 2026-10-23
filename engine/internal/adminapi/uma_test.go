package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/uma"
)

// umaModel lets a viewer read a document.
const umaModel = `
types:
  document:
    relations:
      viewer: []
    permissions:
      read: [viewer]
tests:
  - name: a viewer may read
    subject: user:x
    action: read
    resource: document:1
    relations: [viewer]
    allow: true
`

// newDriftUMARequest is an organisation of the test's own with that model and
// one request waiting for a decision: somebody asking to read document 42.
func newDriftUMARequest(t *testing.T, s *Server) (orgID, requestID, person string) {
	t.Helper()
	ctx := context.Background()
	orgID = newDriftMigrationOrg(t, s, false)
	m, err := authzen.ParseModel([]byte(umaModel))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveModel(ctx, s.db, orgID, umaModel, m, ""); err != nil {
		t.Fatal(err)
	}
	client, rs := clientIn(t, s, orgID), clientIn(t, s, orgID)
	person = fmt.Sprintf("uma-%d@example.test", time.Now().UnixNano())
	var userID string
	if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256(convert_to($2::text, 'UTF8')) || sha256(convert_to($2::text, 'UTF8')), $2::text)
		RETURNING id::text`, orgID, person).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, userID) })
	p, err := store.SubmitRequest(ctx, s.db, store.PendingRequest{OrgID: orgID, ResourceServer: rs, ClientID: client,
		RequestingParty: userID, Permissions: []uma.Permission{{ResourceType: "document", ResourceID: "42",
			ResourceScopes: []string{"read"}}}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return orgID, p.ID, person
}

// A UMA request waiting for a resource owner is decided through the Admin API
// as `signari uma approve|deny` decides it (6.07): the relations that would
// let it through are listed, one that would not is refused, and approving
// grants the relation in the authorization model.
func TestAUMARequestIsDecidedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	orgID, requestID, person := newDriftUMARequest(t, s)
	base := "/admin/organizations/" + orgID + "/uma"

	if rec := call(t, s, http.MethodPut, base, testToken, map[string]any{"owner_intervention": true,
		"poll_interval_s": 1}); rec.Code != http.StatusBadRequest {
		t.Errorf("a one-second poll interval answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodPut, base, testToken, map[string]any{"owner_intervention": true}); rec.Code != http.StatusOK {
		t.Fatalf("offering intervention: %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := store.LoadUMASettings(ctx, s.db, orgID); !got.OwnerIntervention || got.PollInterval != 30*time.Second {
		t.Errorf("the settings read %+v", got)
	}

	rec := call(t, s, http.MethodGet, base+"/requests", testToken, nil)
	var listed struct {
		Requests []umaRequestView `json:"requests"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	if len(listed.Requests) != 1 || listed.Requests[0].ID != requestID ||
		!slices.Equal(listed.Requests[0].Relations, []string{"viewer"}) {
		t.Fatalf("the waiting requests read %+v", listed.Requests)
	}

	approve := base + "/requests/" + requestID + "/approve"
	rec = call(t, s, http.MethodPost, approve, testToken, map[string]any{"relation": "owner"})
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusBadRequest || out["error"] != "relation_does_not_satisfy" {
		t.Errorf("approving with a relation that lets nothing through answered %d %v", rec.Code, out)
	}
	if p, _ := store.PendingRequestByID(ctx, s.db, requestID); p.State != "pending" {
		t.Errorf("a refused approval left the request %s", p.State)
	}

	if rec := call(t, s, http.MethodPost, approve, testToken, map[string]any{"relation": "viewer"}); rec.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", rec.Code, rec.Body.String())
	}
	// What the policy check asks of the model.
	if held, err := store.HoldsAny(ctx, s.db, orgID, "user", person, []string{"viewer"}, "document", "42", nil); err != nil ||
		held != "viewer" {
		t.Errorf("after approval the person holds %q on document 42 (%v)", held, err)
	}
	if rec := call(t, s, http.MethodPost, base+"/requests/"+requestID+"/deny", testToken, nil); rec.Code != http.StatusConflict {
		t.Errorf("denying a decided request answered %d", rec.Code)
	}

	// Another organisation's token, or its path, finds nothing to decide.
	other := newDriftMigrationOrg(t, s, false)
	if rec := call(t, s, http.MethodPost, "/admin/organizations/"+other+"/uma/requests/"+requestID+"/deny",
		testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("deciding a request under another organisation answered %d", rec.Code)
	}
}
