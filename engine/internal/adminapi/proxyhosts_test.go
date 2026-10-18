package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Protected hosts through the admin API: register, list, disable, remove, each
// bumping the configuration version and leaving an audit record.
func TestProtectedHostsCanBeManagedThroughTheAdminAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	host := fmt.Sprintf("Grafana-%d.Example.com", time.Now().UnixNano())
	stored := "grafana-" + host[len("Grafana-"):len(host)-len(".Example.com")] + ".example.com"
	base := "/admin/organizations/" + org + "/proxy-hosts"

	do := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, path, body, ""))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	audited := func(event string) int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(context.Background(), `
			SELECT count(*) FROM core.audit_events
			 WHERE event_type = $1 AND detail->>'host' = $2`, event, stored).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	before := currentVersion(t, s)
	if code, body := do(http.MethodPut, base, fmt.Sprintf(`{"host":%q}`, host)); code != http.StatusOK || body["host"] != stored {
		t.Fatalf("registering a host answered %d %v, want 200 with the host lower-cased", code, body)
	}
	if currentVersion(t, s) <= before {
		t.Error("registering a host did not bump the configuration version")
	}
	if audited("admin.proxy_host_set") != 1 {
		t.Error("registering a host left no audit record")
	}

	code, body := do(http.MethodGet, base, "")
	listed := false
	if hosts, ok := body["proxy_hosts"].([]any); ok {
		for _, h := range hosts {
			if m, _ := h.(map[string]any); m["host"] == stored && m["enabled"] == true {
				listed = true
			}
		}
	}
	if code != http.StatusOK || !listed {
		t.Fatalf("the registered host is not listed as enabled: %d %v", code, body)
	}

	if code, _ := do(http.MethodPut, base, fmt.Sprintf(`{"host":%q,"enabled":false}`, stored)); code != http.StatusOK {
		t.Fatalf("disabling answered %d", code)
	}
	var enabled bool
	if err := s.db.QueryRow(context.Background(),
		`SELECT enabled FROM core.proxy_hosts WHERE org_id = $1::uuid AND host = $2`, org, stored).
		Scan(&enabled); err != nil || enabled {
		t.Fatalf("the host is still enabled (%v, %v)", enabled, err)
	}

	if code, _ := do(http.MethodPut, base, `{"host":"https://x.example.com/path"}`); code != http.StatusBadRequest {
		t.Errorf("a URL instead of a host answered %d, want 400", code)
	}

	if code, _ := do(http.MethodDelete, base+"/"+stored, ""); code != http.StatusOK {
		t.Fatalf("removing answered %d", code)
	}
	if code, _ := do(http.MethodDelete, base+"/"+stored, ""); code != http.StatusNotFound {
		t.Errorf("removing it twice answered %d, want 404", code)
	}
	if audited("admin.proxy_host_removed") != 1 {
		t.Error("removing a host left no audit record")
	}
}
