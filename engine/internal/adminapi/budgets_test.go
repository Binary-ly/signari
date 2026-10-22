package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// An organisation's budget is set by a deployment-wide caller and read back as
// in force (6.10).
func TestAnOrganisationsBudgetIsSetByTheDeployment(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + org + "/budgets"
	read := func() budgetsView {
		t.Helper()
		rec := call(t, s, http.MethodGet, path, testToken, nil)
		var v budgetsView
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		if rec.Code != http.StatusOK {
			t.Fatalf("reading the budgets: %d %s", rec.Code, rec.Body.String())
		}
		return v
	}
	if v := read(); v.TokensPerMinute != store.DefaultTokenBudget || !v.TokensDefault || !v.SignInsDefault {
		t.Errorf("a new organisation's budgets: %+v", v)
	}

	tenant := mintToken(t, s, fmt.Sprintf("budget-tenant-%d", time.Now().UnixNano()), org,
		[]string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	if rec := call(t, s, http.MethodPut, path, tenant, map[string]any{"tokens_per_minute": 1000000}); rec.Code != http.StatusForbidden {
		t.Errorf("the tenant's own token set its budget: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodGet, path, tenant, nil); rec.Code != http.StatusOK {
		t.Errorf("the tenant's own token could not read its budget: %d", rec.Code)
	}
	for _, bad := range []map[string]any{{"tokens_per_minute": 0}, {"sign_ins_per_minute": 1000001}} {
		if rec := call(t, s, http.MethodPut, path, testToken, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%v answered %d", bad, rec.Code)
		}
	}

	if rec := call(t, s, http.MethodPut, path, testToken,
		map[string]any{"tokens_per_minute": 40, "sign_ins_per_minute": 7}); rec.Code != http.StatusOK {
		t.Fatalf("setting the budgets: %d %s", rec.Code, rec.Body.String())
	}
	if v := read(); v.TokensPerMinute != 40 || v.SignInsPerMinute != 7 || v.TokensDefault || v.SignInsDefault {
		t.Errorf("after setting: %+v", v)
	}
	if rec := call(t, s, http.MethodPut, path, testToken, map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("restoring the defaults: %d", rec.Code)
	}
	if v := read(); !v.TokensDefault || v.SignInsPerMinute != store.DefaultSignInBudget {
		t.Errorf("after restoring the defaults: %+v", v)
	}
}
