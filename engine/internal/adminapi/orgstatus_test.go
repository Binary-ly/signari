package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Suspension is set by a deployment-wide token alone, refuses the suspended
// organisation's own tokens with the reason, and is read back (6.09).
func TestOnlyADeploymentWideTokenSuspendsAndTheTenantsOwnStopWorking(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `UPDATE core.organizations SET status = 'active' WHERE id = $1::uuid`, org)
	})
	own := mintToken(t, s, "orgstatus-own-"+org[:8], org, []string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)

	if rec := call(t, s, http.MethodPatch, "/admin/organizations/"+org, own,
		map[string]string{"status": "suspended"}); rec.Code != http.StatusForbidden {
		t.Fatalf("the organisation's own token set its status: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPatch, "/admin/organizations/"+org, testToken,
		map[string]string{"status": "paused"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a status that does not exist answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodPatch, "/admin/organizations/"+org, testToken,
		map[string]string{"status": "suspended"}); rec.Code != http.StatusOK {
		t.Fatalf("suspending: %d %s", rec.Code, rec.Body.String())
	}

	rec := call(t, s, http.MethodGet, "/admin/organizations/"+org, own, nil)
	var refused map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &refused)
	if rec.Code != http.StatusForbidden || refused["error"] != "organisation_suspended" {
		t.Errorf("the suspended organisation's own token: %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, s, http.MethodGet, "/admin/organizations/"+org, testToken, nil)
	var got organization
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusOK || got.Status != "suspended" || rec.Header().Get("ETag") == "" {
		t.Errorf("reading it back: %d %+v", rec.Code, got)
	}
	var recorded int
	_ = s.db.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
		WHERE org_id = $1::uuid AND event_type = 'admin.organization_suspended'`, org).Scan(&recorded)
	if recorded != 1 {
		t.Errorf("%d suspension records", recorded)
	}

	if rec := call(t, s, http.MethodPatch, "/admin/organizations/"+org, testToken,
		map[string]string{"status": "active"}); rec.Code != http.StatusOK {
		t.Fatalf("reactivating: %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, s, http.MethodGet, "/admin/organizations", own, nil)
	var listed struct {
		Organizations []organization `json:"organizations"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	if rec.Code != http.StatusOK || len(listed.Organizations) != 1 || listed.Organizations[0].ID != org ||
		listed.Organizations[0].Status != "active" {
		t.Errorf("reactivated, its own token lists %d %s", rec.Code, rec.Body.String())
	}
}
