package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The resource servers an organisation's tokens may be audienced to (1.87),
// through the routes the console and Terraform use: a malformed resource is
// refused, a registered one is listed, and removal is real.
func TestResourceServersAreRegisteredListedAndRemoved(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/resource-servers"
	do := func(method, path, body string) (int, string) {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, path, body, ""))
		return rec.Code, rec.Body.String()
	}

	for _, bad := range []string{`{"resource":"api.example.test"}`, `{"resource":"https://api.example.test#x"}`,
		`{"resource":"urn:example:api"}`} {
		if code, body := do(http.MethodPut, base, bad); code != http.StatusBadRequest {
			t.Errorf("PUT %s answered %d %s, want 400 invalid_resource", bad, code, body)
		}
	}
	if code, body := do(http.MethodPut, base, `{"resource":"https://api.example.test","name":"Billing"}`); code != http.StatusOK {
		t.Fatalf("PUT a resource answered %d %s", code, body)
	}
	code, body := do(http.MethodGet, base, "")
	var listed []struct{ Resource, Name string }
	if err := json.Unmarshal([]byte(body), &listed); err != nil || code != http.StatusOK {
		t.Fatalf("GET answered %d %s", code, body)
	}
	if len(listed) != 1 || listed[0].Resource != "https://api.example.test" || listed[0].Name != "Billing" {
		t.Errorf("listed %+v, want the one registered", listed)
	}
	if code, body := do(http.MethodDelete, base+"?resource=https://api.example.test", ""); code != http.StatusOK {
		t.Errorf("DELETE answered %d %s", code, body)
	}
	if code, _ := do(http.MethodDelete, base+"?resource=https://api.example.test", ""); code != http.StatusNotFound {
		t.Errorf("a second DELETE answered %d, want 404", code)
	}
	if code, _ := do(http.MethodDelete, base, ""); code != http.StatusBadRequest {
		t.Errorf("a DELETE naming no resource answered %d, want 400", code)
	}
}
