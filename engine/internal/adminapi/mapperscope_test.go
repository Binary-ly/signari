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

// A claim mapper waits for a scope a grant can carry (2.33). A typo in
// required_scope made a mapper that released nothing, to anybody, while the
// configuration looked right; and deleting a declared scope under a mapper did
// the same from the other side.
func TestAClaimMapperNeedsAScopeAGrantCanCarry(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	orgID := orgWithDriftAttribute(t, s)
	clientID := newPreconditionClient(t, s)
	scope := fmt.Sprintf("hr_records_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.claim_mappers WHERE org_id = $1::uuid AND client_id = $2`, orgID, clientID)
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.scopes WHERE org_id = $1::uuid AND name = $2`, orgID, scope)
	})

	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, path, body, ""))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	mapper := func(claim, requiredScope string) (int, map[string]any) {
		return call(http.MethodPost, "/admin/organizations/"+orgID+"/claim-mappers",
			fmt.Sprintf(`{"attribute":%q,"claim_name":%q,"destination":"userinfo",`+
				`"client_id":%q,"required_scope":%q}`,
				driftAttributeName, claim, clientID, requiredScope))
	}
	mappers := func() int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.claim_mappers
			WHERE org_id = $1::uuid AND client_id = $2`, orgID, clientID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if code, body := mapper("department", "profle"); code != http.StatusBadRequest || body["error"] != "unknown_scope" {
		t.Errorf("a mapper waiting for the typo \"profle\" gave %d %v, want 400 unknown_scope", code, body)
	}
	if mappers() != 0 {
		t.Fatal("the refused mapper was stored anyway")
	}
	if code, body := mapper("department", scope); code != http.StatusBadRequest {
		t.Errorf("a mapper waiting for an undeclared scope gave %d %v, want 400", code, body)
	}

	if code, body := mapper("department", "profile"); code != http.StatusOK {
		t.Fatalf("a mapper waiting for the standard profile scope gave %d %v", code, body)
	}
	if code, body := call(http.MethodPut, "/admin/organizations/"+orgID+"/scopes",
		fmt.Sprintf(`{"name":%q}`, scope)); code != http.StatusOK {
		t.Fatalf("declaring the scope: %d %v", code, body)
	}
	code, body := mapper("employee_record", scope)
	if code != http.StatusOK {
		t.Fatalf("a mapper waiting for a declared scope gave %d %v", code, body)
	}
	mapperID, _ := body["id"].(string)

	code, body = call(http.MethodDelete, "/admin/organizations/"+orgID+"/scopes/"+scope, "")
	if code != http.StatusConflict || body["error"] != "scope_in_use" || body["claim_mappers"] != float64(1) {
		t.Errorf("deleting a scope a mapper waits for gave %d %v, want 409 scope_in_use naming 1 mapper",
			code, body)
	}
	if code, body := call(http.MethodDelete,
		"/admin/organizations/"+orgID+"/claim-mappers/"+mapperID, ""); code != http.StatusOK {
		t.Fatalf("deleting the mapper: %d %v", code, body)
	}
	if code, body := call(http.MethodDelete,
		"/admin/organizations/"+orgID+"/scopes/"+scope, ""); code != http.StatusOK {
		t.Errorf("deleting the scope once nothing waits for it gave %d %v", code, body)
	}
}
