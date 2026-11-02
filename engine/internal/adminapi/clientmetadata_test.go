package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// Whose URLs to fetch, through the API as `signari client-metadata` manages it, and only
// for a caller who speaks for the whole deployment.
func TestClientMetadataRulesAreKeptThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	id := newDriftInstance(t, s)
	org := newDriftOrgIn(t, s, id)
	elsewhere := newDriftMigrationOrg(t, s, false)
	path := "/admin/instances/" + id + "/client-metadata-rules"
	prefix := "https://mcp.example.test/"

	put := func(body map[string]any) int {
		t.Helper()
		return call(t, s, http.MethodPut, path, testToken, body).Code
	}
	for name, body := range map[string]map[string]any{
		"no organisation":  {"url_prefix": prefix},
		"no trailing path": {"url_prefix": "https://mcp.example.test", "org_id": org},
		"http":             {"url_prefix": "http://mcp.example.test/", "org_id": org},
		"no host":          {"url_prefix": "https://", "org_id": org},
		"a query":          {"url_prefix": "https://mcp.example.test/?a=/", "org_id": org},
		"a scope of two":   {"url_prefix": prefix, "org_id": org, "scopes": []string{"two words"}},
		"another instance": {"url_prefix": prefix, "org_id": elsewhere},
	} {
		if code := put(body); code != http.StatusBadRequest {
			t.Errorf("%s answered %d", name, code)
		}
	}
	if code := put(map[string]any{"url_prefix": prefix, "org_id": "00000000-0000-4000-8000-000000000000"}); code == http.StatusOK {
		t.Error("a rule named an organisation that does not exist")
	}
	if code := put(map[string]any{"url_prefix": prefix, "org_id": org, "scopes": []string{"openid"}}); code != http.StatusOK {
		t.Fatalf("the rule answered %d", code)
	}
	rec := call(t, s, http.MethodGet, path, testToken, nil)
	var list struct {
		Rules []clientMetadataRuleView `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Rules) != 1 ||
		list.Rules[0].URLPrefix != prefix || list.Rules[0].OrgID != org {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	client := fmt.Sprintf("%sclient-%d.json", prefix, time.Now().UnixNano())
	if _, err := s.db.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_metadata_prefix)
		VALUES ($1, $2::uuid, 'From a document', 'public', $3)`, client, org, prefix); err != nil {
		t.Fatal(err)
	}
	tenant := mintToken(t, s, fmt.Sprintf("rules-tenant-%s", org), org, []string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	if rec := call(t, s, http.MethodGet, path, tenant, nil); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token read the list: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodPut, path, tenant, map[string]any{"url_prefix": prefix, "org_id": org}); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token wrote a rule: %d", rec.Code)
	}
	remove := path + "?url_prefix=" + url.QueryEscape(prefix)
	if rec := call(t, s, http.MethodDelete, remove, tenant, nil); rec.Code != http.StatusForbidden {
		t.Errorf("an organisation's token removed a rule: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a removal naming nothing answered %d", rec.Code)
	}
	rec = call(t, s, http.MethodDelete, remove, testToken, nil)
	var gone struct {
		Clients int `json:"clients_removed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &gone); err != nil || rec.Code != http.StatusOK || gone.Clients != 1 {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, http.MethodDelete, remove, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("removing it twice answered %d", rec.Code)
	}
}
