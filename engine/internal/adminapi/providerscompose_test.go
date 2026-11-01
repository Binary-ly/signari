package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Several providers on one hook through the API (10.06): each by name, and a change that
// could mean either is sent back rather than guessed at.
func TestSeveralProvidersOnAHookAreToldApartByName(t *testing.T) {
	s, _ := newTestServer(t)
	base := "/admin/organizations/" + newDriftMigrationOrg(t, s, false) + "/providers"
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
	put := func(hook, name string, position int) *responseOf {
		t.Helper()
		rec := call(t, s, http.MethodPut, base+"/"+hook, testToken, map[string]any{"name": name, "position": position,
			"url": "https://" + name + ".example.test/hook", "mode": "fail_closed"})
		return &responseOf{code: rec.Code, body: rec.Body.String()}
	}
	if got := put("token_issue", "fraud", 2); got.code != http.StatusOK {
		t.Fatalf("the first answered %d %s", got.code, got.body)
	}
	if got := put("token_issue", "compliance", 1); got.code != http.StatusOK || !strings.Contains(got.body, `"secret":"`) {
		t.Fatalf("the second answered %d %s", got.code, got.body)
	}
	if got := put("token_issue", "two words", 3); got.code != http.StatusBadRequest {
		t.Errorf("a name of two words answered %d %s", got.code, got.body)
	}

	listed := call(t, s, http.MethodGet, base, testToken, nil).Body.String()
	if strings.Index(listed, `"name":"compliance"`) > strings.Index(listed, `"name":"fraud"`) || !strings.Contains(listed, `"position":2`) {
		t.Errorf("the list does not read in the order they are asked: %s", listed)
	}

	if e := errorOf(http.MethodPost, base+"/token_issue/rotate-secret", nil, http.StatusConflict); e != "name_required" {
		t.Errorf("rotating with no name answered %q", e)
	}
	if e := errorOf(http.MethodDelete, base+"/token_issue", nil, http.StatusConflict); e != "name_required" {
		t.Errorf("removing with no name answered %q", e)
	}
	if e := errorOf(http.MethodPut, base+"/token_issue/claims?name=fraud", map[string]any{"claims": []string{"risk"}}, http.StatusOK); e != "" {
		t.Errorf("claims by name answered %q", e)
	}
	if e := errorOf(http.MethodPut, base+"/token_issue/claims?name=compliance", map[string]any{"claims": []string{"risk"}},
		http.StatusConflict); e != "claim_taken" {
		t.Errorf("a claim with a source answered %q", e)
	}
	if rec := call(t, s, http.MethodPost, base+"/token_issue/rotate-secret?name=fraud", testToken, nil); rec.Code != http.StatusOK {
		t.Errorf("rotating by name answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodDelete, base+"/token_issue?name=fraud", testToken, nil); rec.Code != http.StatusOK {
		t.Errorf("removing by name answered %d %s", rec.Code, rec.Body.String())
	}
	if listed := call(t, s, http.MethodGet, base, testToken, nil).Body.String(); strings.Contains(listed, `"name":"fraud"`) ||
		!strings.Contains(listed, `"name":"compliance"`) {
		t.Errorf("removing one left %s", listed)
	}
	if rec := call(t, s, http.MethodDelete, base+"/token_issue", testToken, nil); rec.Code != http.StatusOK {
		t.Errorf("removing the only one, unnamed, answered %d %s", rec.Code, rec.Body.String())
	}

	if got := put("flow_condition", "one", 0); got.code != http.StatusOK {
		t.Fatalf("a flow_condition provider answered %d %s", got.code, got.body)
	}
	if e := errorOf(http.MethodPut, base+"/flow_condition", map[string]any{"name": "two",
		"url": "https://two.example.test/hook", "mode": "fail_closed"}, http.StatusConflict); e != "provider_taken" {
		t.Errorf("a second on a hook with one answer answered %q", e)
	}
}

type responseOf struct {
	code int
	body string
}
