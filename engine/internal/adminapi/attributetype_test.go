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

// What the API says when a value does not fit its attribute's type, and when a
// type is changed under stored values (2.32): 400 and 409, naming the attribute
// and never the value.
func TestTheAPIRefusesAValueThatDoesNotFitItsType(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	orgID := anyOrgID(t, s)
	userID := newDriftUser(t, s)
	name := fmt.Sprintf("on_call_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.user_attribute_schema WHERE org_id = $1::uuid AND name = $2`, orgID, name)
	})

	call := func(method, path, body string) (int, map[string]string) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, method, path, body, ""))
		var out map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	declare := func(kind string) (int, map[string]string) {
		return call(http.MethodPut, "/admin/organizations/"+orgID+"/attributes",
			fmt.Sprintf(`{"name":%q,"value_type":%q,"personal":false}`, name, kind))
	}
	set := func(value string) (int, map[string]string) {
		return call(http.MethodPut, "/admin/users/"+userID+"/attributes",
			fmt.Sprintf(`{"attributes":{%q:%q}}`, name, value))
	}

	if code, body := declare("boolean"); code != http.StatusOK {
		t.Fatalf("declaring: %d %v", code, body)
	}
	code, body := set("yes")
	if code != http.StatusBadRequest || body["error"] != "invalid_attribute_value" {
		t.Errorf("a boolean set to \"yes\" gave %d %v, want 400 invalid_attribute_value", code, body)
	}
	if !strings.Contains(body["detail"], name) || strings.Contains(body["detail"], "yes") {
		t.Errorf("the refusal should name the attribute and not the value: %q", body["detail"])
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.user_attributes WHERE user_id = $1::uuid`,
		userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("the refused value was stored anyway (%d rows)", n)
	}

	if code, body := set("true"); code != http.StatusOK {
		t.Fatalf("a boolean set to \"true\" gave %d %v", code, body)
	}
	if code, body := declare("string"); code != http.StatusConflict || body["error"] != "attribute_type_in_use" {
		t.Errorf("retyping an attribute that holds a value gave %d %v, want 409 attribute_type_in_use",
			code, body)
	}
}
