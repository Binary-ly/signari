package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ASVS 5.0.0 V8.2.3 (specs/asvs-5.0.0.txt:2923-2925): field-level access
// restricted to consumers with explicit permissions to specific fields. A token
// narrowed to named user attributes reads, sets and clears only those, releases
// only those to applications, and is refused what reaches every attribute at
// once. Until migration 0295, users:read read every value a person held,
// personal ones unsealed.

// attributeOrg is an organisation declaring a non-personal and a personal
// attribute, and a person holding both.
func attributeOrg(t *testing.T, s *Server) (org, userID string) {
	t.Helper()
	ctx := context.Background()
	org = newDriftMigrationOrg(t, s, false)
	if _, err := s.db.Exec(ctx, `INSERT INTO core.user_attribute_schema (org_id, name, personal)
		VALUES ($1::uuid, 'department', false), ($1::uuid, 'national_id', true)`, org); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256(gen_random_uuid()::text::bytea) || sha256(gen_random_uuid()::text::bytea), $2)
		RETURNING id::text`, org, "narrow-"+org[:8]+"@example.test").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, userID) })
	if rec := call(t, s, http.MethodPut, "/admin/users/"+userID+"/attributes", testToken, map[string]any{
		"attributes": map[string]string{"department": "Finance", "national_id": "NI-777"}}); rec.Code != http.StatusOK {
		t.Fatalf("setting the values: %d %s", rec.Code, rec.Body.String())
	}
	return org, userID
}

func attributeToken(t *testing.T, s *Server, org string, scopes, attributes []string) string {
	t.Helper()
	secret, id, err := NewNarrowedToken(context.Background(), s.db, "narrowed-"+strings.Join(attributes, "-"), org,
		scopes, nil, nil, nil, attributes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE id::text = $1`, id)
	})
	return secret
}

func TestATokenNarrowedToAttributesReachesOnlyThose(t *testing.T) {
	s, _ := newTestServer(t)
	org, userID := attributeOrg(t, s)
	attrs := "/admin/users/" + userID + "/attributes"
	tok := attributeToken(t, s, org, []string{ScopeUsersWrite, ScopeSubjectsExport}, []string{"department"})

	got := call(t, s, http.MethodGet, attrs, tok, nil)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Finance") ||
		strings.Contains(got.Body.String(), "NI-777") || strings.Contains(got.Body.String(), "national_id") {
		t.Fatalf("a token narrowed to department read %d %s", got.Code, got.Body.String())
	}
	if all := call(t, s, http.MethodGet, attrs, testToken, nil).Body.String(); !strings.Contains(all, "NI-777") {
		t.Fatalf("an unnarrowed token no longer reads every value: %s", all)
	}

	refused := func(method, path string, body any, what string) {
		t.Helper()
		rec := call(t, s, method, path, tok, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		// outside_token_objects: until November 2026 such a refusal said
		// "outside this token's organisation", of the token's own organisation.
		if rec.Code != http.StatusForbidden || out["error"] != "outside_token_objects" {
			t.Errorf("%s answered %d, want 403 outside_token_objects: %s", what, rec.Code, rec.Body.String())
		}
	}
	refused(http.MethodPut, attrs, map[string]any{"attributes": map[string]string{"national_id": "NI-000"}},
		"setting an attribute outside the token")
	refused(http.MethodPut, attrs, map[string]any{"attributes": map[string]string{
		"department": "Sales", "national_id": "NI-000"}}, "setting one inside and one outside")
	refused(http.MethodDelete, attrs+"/national_id", nil, "clearing an attribute outside the token")
	refused(http.MethodGet, "/admin/subjects/"+userID+"/export", nil, "exporting the whole person")
	if all := call(t, s, http.MethodGet, attrs, testToken, nil).Body.String(); !strings.Contains(all, "NI-777") ||
		!strings.Contains(all, "Finance") {
		t.Fatalf("a refused request changed the values: %s", all)
	}

	if rec := call(t, s, http.MethodPut, attrs, tok, map[string]any{"attributes": map[string]string{
		"department": "Sales"}}); rec.Code != http.StatusOK {
		t.Fatalf("setting its own attribute: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodDelete, attrs+"/department", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("clearing its own attribute: %d %s", rec.Code, rec.Body.String())
	}
}

// What reaches an attribute another way: a claim mapper releases it to an
// application, a configuration file or a role reaches every one.
func TestATokenNarrowedToAttributesCannotReachTheRestAnotherWay(t *testing.T) {
	s, _ := newTestServer(t)
	org, _ := attributeOrg(t, s)
	tok := attributeToken(t, s, org, []string{ScopeOrganizationsWrite, ScopeUsersWrite}, []string{"department"})
	base := "/admin/organizations/" + org

	mapper := func(attribute string) int {
		t.Helper()
		return call(t, s, http.MethodPost, base+"/claim-mappers", tok, map[string]any{"attribute": attribute,
			"claim_name": "x_" + attribute, "destination": "id_token", "all_clients": true}).Code
	}
	if code := mapper("national_id"); code != http.StatusForbidden {
		t.Errorf("a mapper releasing an attribute outside the token answered %d, want 403", code)
	}
	if code := mapper("department"); code != http.StatusCreated && code != http.StatusOK {
		t.Errorf("a mapper releasing its own attribute answered %d", code)
	}
	var mapperID string
	if err := s.db.QueryRow(context.Background(), `INSERT INTO core.claim_mappers
		(org_id, attribute_id, claim_name, destination)
		SELECT org_id, id, 'nid', 'userinfo' FROM core.user_attribute_schema
		 WHERE org_id = $1::uuid AND name = 'national_id' RETURNING id::text`, org).Scan(&mapperID); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodDelete, base+"/claim-mappers/"+mapperID, tok, nil); rec.Code != http.StatusForbidden {
		t.Errorf("deleting another attribute's mapper answered %d, want 403", rec.Code)
	}

	if rec := call(t, s, http.MethodPost, base+"/config", tok, map[string]any{"document": "version: 1\n"}); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "outside_token_objects") {
		t.Errorf("a configuration file answered %d %s, want 403 outside_token_objects", rec.Code, rec.Body.String())
	}
	var person string
	if err := s.db.QueryRow(context.Background(), `SELECT id::text FROM core.users WHERE org_id = $1::uuid LIMIT 1`,
		org).Scan(&person); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, http.MethodPost, base+"/role-bindings", tok, map[string]any{"role": "user-manager",
		"user_id": person}); rec.Code != http.StatusForbidden {
		t.Errorf("granting a role that reaches every attribute answered %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// A narrowed token mints only tokens narrowed within it, and rotating one keeps
// its narrowing.
func TestANarrowedTokenMintsAndRotatesNarrowed(t *testing.T) {
	s, _ := newTestServer(t)
	org, _ := attributeOrg(t, s)
	tok := attributeToken(t, s, org, []string{ScopeTokensWrite, ScopeUsersRead}, []string{"department"})

	mint := func(attributes []string) (int, string) {
		t.Helper()
		body := map[string]any{"name": "child", "scopes": []string{ScopeUsersRead}, "org_id": org}
		if attributes != nil {
			body["attribute_names"] = attributes
		}
		rec := call(t, s, http.MethodPost, "/admin/tokens", tok, body)
		var out struct{ ID string }
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.ID != "" {
			t.Cleanup(func() {
				_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE id::text = $1`, out.ID)
			})
		}
		return rec.Code, out.ID
	}
	if code, _ := mint(nil); code != http.StatusForbidden {
		t.Errorf("an unnarrowed child answered %d, want 403", code)
	}
	if code, _ := mint([]string{"national_id"}); code != http.StatusForbidden {
		t.Errorf("a child narrowed to another attribute answered %d, want 403", code)
	}
	code, child := mint([]string{"department"})
	if code != http.StatusCreated {
		t.Fatalf("a child narrowed within it answered %d", code)
	}
	typo := call(t, s, http.MethodPost, "/admin/tokens", testToken, map[string]any{"name": "typo",
		"scopes": []string{ScopeUsersRead}, "org_id": org, "attribute_names": []string{"departmnet"}})
	if typo.Code != http.StatusBadRequest {
		t.Errorf("a misspelt attribute answered %d, want 400: %s", typo.Code, typo.Body.String())
	}

	rec := call(t, s, http.MethodPost, "/admin/tokens/"+child+"/rotate", testToken, map[string]any{})
	var rotated struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &rotated)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("rotating: %d %s", rec.Code, rec.Body.String())
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE id::text = $1`, rotated.ID)
	})
	var names []string
	if err := s.db.QueryRow(context.Background(), `SELECT attribute_names FROM core.admin_tokens WHERE id::text = $1`,
		rotated.ID).Scan(&names); err != nil || len(names) != 1 || names[0] != "department" {
		t.Errorf("the rotated token is narrowed to %v (%v), want [department]", names, err)
	}
}
