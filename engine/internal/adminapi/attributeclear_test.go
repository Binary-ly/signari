package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A person's attribute value is cleared through the Admin API (6.07), which
// before could set one and never take one away; a required attribute is
// replaced rather than cleared, as the person's own profile refuses.
func TestAnAttributeValueIsClearedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	if _, err := s.db.Exec(ctx, `INSERT INTO core.user_attribute_schema (org_id, name, required)
		VALUES ($1::uuid, 'department', false), ($1::uuid, 'employee_id', true)`, org); err != nil {
		t.Fatal(err)
	}
	var userID string
	if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea), $2)
		RETURNING id::text`, org, "leaver-"+org[:8]+"@example.test").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	// Before the organisation's cleanup, which a person in it would refuse.
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, userID) })
	attrs := "/admin/users/" + userID + "/attributes"
	if rec := call(t, s, http.MethodPut, attrs, testToken, map[string]any{"attributes": map[string]string{
		"department": "Finance", "employee_id": "E-1"}}); rec.Code != http.StatusOK {
		t.Fatalf("setting the values: %d %s", rec.Code, rec.Body.String())
	}
	answer := func(name string, want int) string {
		t.Helper()
		rec := call(t, s, http.MethodDelete, attrs+"/"+name, testToken, nil)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("clearing %s answered %d, want %d: %s", name, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}
	answer("department", http.StatusOK)
	got := call(t, s, http.MethodGet, attrs, testToken, nil).Body.String()
	if strings.Contains(got, "Finance") || !strings.Contains(got, "E-1") {
		t.Errorf("after clearing the department the values read %s", got)
	}
	if e := answer("department", http.StatusNotFound); e != "attribute_not_set" {
		t.Errorf("clearing it again answered %q", e)
	}
	if e := answer("undeclared", http.StatusNotFound); e != "unknown_attribute" {
		t.Errorf("an undeclared attribute answered %q", e)
	}
	if e := answer("employee_id", http.StatusConflict); e != "attribute_required" {
		t.Errorf("a required attribute answered %q", e)
	}
	if got := call(t, s, http.MethodGet, attrs, testToken, nil).Body.String(); !strings.Contains(got, "E-1") {
		t.Errorf("the refused clear took the required value: %s", got)
	}
}
