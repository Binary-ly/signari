package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A configuration file is planned and applied through the Admin API as
// `signari plan` and `signari apply` take it (6.07): the plan writes nothing
// and names the version it read, an apply over a deployment that moved since
// is refused, a file already in force moves nothing, and every change needs
// the scope its own route would.
func TestAConfigurationFileIsPlannedAndAppliedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + org + "/config"
	clientID := fmt.Sprintf("cfg-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, clientID)
	})
	file := "version: 1\ngroups:\n  - name: platform\n    display_name: Platform\nclients:\n" +
		"  - client_id: " + clientID + "\n    name: Dashboard\n    redirect_uris: [\"https://app.example.test/cb\"]\n"
	send := func(token, ifMatch string, body map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := adminReq(t, http.MethodPost, path, string(b), ifMatch)
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, r)
		return rec
	}
	count := func(query string, arg any) int {
		var n int
		if err := s.db.QueryRow(ctx, query, arg).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	groups := func() int {
		return count(`SELECT count(*) FROM core.groups WHERE org_id = $1::uuid AND name = 'platform'`, org)
	}

	rec := send(testToken, "", map[string]any{"document": file, "dry_run": true})
	var plan struct {
		Changes       []struct{ Action, Kind, Name string }
		Create        int
		ConfigVersion int64 `json:"config_version"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &plan)
	if rec.Code != http.StatusOK || plan.Create != 2 || plan.ConfigVersion == 0 ||
		rec.Header().Get("ETag") != fmt.Sprintf(`"%d"`, plan.ConfigVersion) {
		t.Fatalf("planning: %d %s", rec.Code, rec.Body.String())
	}
	if groups() != 0 {
		t.Fatal("a dry run created the group")
	}

	// Somebody else writes after the plan was read: the reviewed plan is no
	// longer what would be applied.
	if _, err := s.db.Exec(ctx, `UPDATE core.config_version SET version = version + 1 WHERE id = true`); err != nil {
		t.Fatal(err)
	}
	if rec := send(testToken, fmt.Sprintf(`"%d"`, plan.ConfigVersion), map[string]any{"document": file}); rec.Code != http.StatusPreconditionFailed || groups() != 0 {
		t.Fatalf("an apply over a moved deployment answered %d and wrote %d groups", rec.Code, groups())
	}

	// A token that may change the organisation and not its applications.
	orgOnly, _, err := NewToken(ctx, s.db, "cfg-org-only-"+clientID, org, []string{ScopeOrganizationsWrite,
		ScopeGroupsWrite}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(orgOnly))
	})
	if rec := send(orgOnly, "", map[string]any{"document": file}); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), ScopeClientsWrite) || groups() != 0 {
		t.Fatalf("a token without clients:write answered %d %s and wrote %d groups", rec.Code, rec.Body.String(), groups())
	}

	if rec := send(testToken, "", map[string]any{"document": file}); rec.Code != http.StatusOK {
		t.Fatalf("applying: %d %s", rec.Code, rec.Body.String())
	}
	if groups() != 1 || count(`SELECT count(*) FROM core.client_redirect_uris WHERE client_id = $1`, clientID) != 1 {
		t.Fatal("the apply did not create the group and the client with its redirect URI")
	}

	// Again: the deployment matches, so nothing is written, recorded or
	// moved. The version is global and other packages' tests move it, so a
	// no-op must answer the version read just before it on at least one of
	// eight tries; one that bumps never does (the 4.19 pattern).
	unmoved := false
	for i := 0; i < 8 && !unmoved; i++ {
		before := currentVersion(t, s)
		rec = send(testToken, "", map[string]any{"document": file})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"changes":[]`) {
			t.Fatalf("applying it again answered %d %s", rec.Code, rec.Body.String())
		}
		unmoved = rec.Header().Get("ETag") == fmt.Sprintf(`"%d"`, before)
	}
	if !unmoved {
		t.Error("applying a file already in force moved the configuration version every time")
	}
	if n := count(`SELECT count(*) FROM core.audit_events WHERE event_type = 'admin.config_applied'
		AND org_id = $1::uuid`, org); n != 1 {
		t.Errorf("a file already in force left %d apply records, want the first one only", n)
	}

	// The application administrators sign in through is privileged.
	if _, err := s.db.Exec(ctx, `UPDATE core.clients SET admin_api = true WHERE client_id = $1`, clientID); err != nil {
		t.Fatal(err)
	}
	unprivileged, _, err := NewToken(ctx, s.db, "cfg-unprivileged-"+clientID, org, []string{ScopeOrganizationsWrite,
		ScopeClientsWrite, ScopeGroupsWrite}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(unprivileged))
	})
	moved := strings.Replace(file, "https://app.example.test/cb", "https://elsewhere.example.test/cb", 1)
	if rec := send(unprivileged, "", map[string]any{"document": moved}); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), ScopePrivilegedUsersWrite) {
		t.Fatalf("moving the Admin API client's redirect without privileged-users:write answered %d %s",
			rec.Code, rec.Body.String())
	}
	if count(`SELECT count(*) FROM core.client_redirect_uris WHERE client_id = $1 AND redirect_uri LIKE '%elsewhere%'`,
		clientID) != 0 {
		t.Fatal("the refused apply moved the redirect")
	}

	if rec := send(testToken, "", map[string]any{"document": "version: 1\norg: 00000000-0000-4000-8000-000000000000\n"}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "org_mismatch") {
		t.Errorf("a file for another organisation answered %d %s", rec.Code, rec.Body.String())
	}

	// Pruned, what the file does not declare goes.
	if _, err := s.db.Exec(ctx, `UPDATE core.clients SET admin_api = false WHERE client_id = $1`, clientID); err != nil {
		t.Fatal(err)
	}
	if rec := send(testToken, "", map[string]any{"document": "version: 1\nclients:\n  - client_id: " + clientID +
		"\n    name: Dashboard\n    redirect_uris: [\"https://app.example.test/cb\"]\n", "prune": true}); rec.Code != http.StatusOK {
		t.Fatalf("pruning: %d %s", rec.Code, rec.Body.String())
	}
	if groups() != 0 {
		t.Error("a pruned apply kept the group the file no longer declares")
	}
}

// A file the deployment cannot honour, which only the plan can see, is the
// caller's mistake: 400 config_refused with the reason, planned or applied
// (6.19), not a server error.
func TestAConfigurationThePlanRefusesIsTheCallersMistake(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	file := "version: 1\nsignup: {domains: [example.test], groups: [never-made]}\n"
	for _, dry := range []bool{true, false} {
		rec := call(t, s, http.MethodPost, "/admin/organizations/"+org+"/config", testToken,
			map[string]any{"document": file, "dry_run": dry})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "config_refused") ||
			!strings.Contains(rec.Body.String(), "never-made") {
			t.Errorf("dry_run %v answered %d %s", dry, rec.Code, rec.Body.String())
		}
	}
}
