package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// Administrative roles (6.01).

// The roles the API grants, the ones the store writes and the ones the schema
// accepts are one set: a role one side knows and another does not is
// grantable by nobody or means nothing.
func TestEveryRoleIsKnownToTheSchemaAndTheStore(t *testing.T) {
	s, _ := newTestServer(t)
	var def string
	if err := s.db.QueryRow(context.Background(), `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conname = 'admin_role_bindings_role_check'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	var inSchema []string
	for _, part := range strings.Split(def, "'") {
		if _, ok := Roles[part]; ok || (len(part) > 2 && !strings.ContainsAny(part, " ():,[]")) {
			inSchema = append(inSchema, part)
		}
	}
	got := append([]string(nil), store.AdminRoles...)
	sort.Strings(got)
	sort.Strings(inSchema)
	if !slices.Equal(roleNames(), got) || !slices.Equal(got, inSchema) {
		t.Errorf("adminapi.Roles %v, store.AdminRoles %v, the schema %v", roleNames(), got, inSchema)
	}
	for role, scopes := range Roles {
		for _, sc := range scopes {
			if !slices.Contains(KnownScopes, sc) {
				t.Errorf("%s grants %q, which no token could be given", role, sc)
			}
		}
	}
}

func TestARolePrincipalIsTheUnionOfItsBindingsNarrowedPerScope(t *testing.T) {
	const g1, g2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	bind := func(role, group string) store.RoleBinding { return store.RoleBinding{Role: role, GroupID: group} }

	owner := rolePrincipal("owner", "org", []store.RoleBinding{bind("org-owner", "")}, nil)
	for _, sc := range []string{ScopeUsersWrite, ScopePrivilegedUsersWrite, ScopeAuditRead, ScopeTokensWrite} {
		if !owner.Can(sc) {
			t.Errorf("an owner cannot %s", sc)
		}
	}
	if owner.Can(ScopeAll) || owner.UserGroups != nil || owner.OrgID != "org" {
		t.Errorf("an owner is %+v", owner)
	}

	delegated := rolePrincipal("d", "org", []store.RoleBinding{bind("user-manager", g1), bind("user-manager", g2)}, nil)
	if !delegated.Can(ScopeUsersWrite) || delegated.Can(ScopeClientsRead) || delegated.Can(ScopePrivilegedUsersWrite) {
		t.Errorf("a delegated user manager holds %v", delegated.Scopes)
	}
	for _, sc := range []string{ScopeUsersWrite, ScopeUsersRead} {
		if g := delegated.UserGroups[sc]; len(g) != 2 {
			t.Errorf("%s is narrowed to %v, want both groups: a narrowing that skipped the read "+
				"it implies would let a delegated manager read every person", sc, g)
		}
	}

	// An auditor reads everyone, so only the write stays narrowed.
	both := rolePrincipal("b", "org", []store.RoleBinding{bind("user-manager", g1), bind("auditor", "")}, nil)
	if both.UserGroups[ScopeUsersRead] != nil || len(both.UserGroups[ScopeUsersWrite]) != 1 {
		t.Errorf("delegated manager and auditor narrowed as %v", both.UserGroups)
	}
	// And an undelegated binding of the same role lifts the narrowing.
	wide := rolePrincipal("w", "org", []store.RoleBinding{bind("user-manager", g1), bind("user-manager", "")}, nil)
	if wide.UserGroups != nil {
		t.Errorf("an organisation-wide user manager is narrowed: %v", wide.UserGroups)
	}
	if none := rolePrincipal("n", "org", nil, nil); len(none.Scopes) != 0 {
		t.Errorf("no bindings held %v", none.Scopes)
	}
}

func TestOnlyACallerHoldingAllOfARoleMayGrantIt(t *testing.T) {
	const g = "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		why  string
		p    *Principal
		role string
		ok   bool
	}{
		{"an owner, any role", &Principal{Scopes: Roles["org-owner"]}, "auditor", true},
		{"the scopes missing", &Principal{Scopes: []string{ScopeOrganizationsWrite}}, "user-manager", false},
		{"narrowed to a group", &Principal{Scopes: []string{ScopeUsersWrite, ScopeOrganizationsWrite},
			UserGroups: map[string][]string{ScopeUsersWrite: {g}}}, "user-manager", false},
		{"narrowed to some clients", &Principal{Scopes: []string{ScopeClientsWrite, ScopeConfigRead},
			ClientIDs: []string{"one"}}, "app-manager", false},
		{"narrowed to some groups", &Principal{Scopes: Roles["auditor"], GroupIDs: []string{g}}, "auditor", false},
		{"the break-glass token", &Principal{Scopes: []string{ScopeAll}}, "org-owner", true},
	}
	for _, c := range cases {
		if err := grantable(c.p, c.role); (err == nil) != c.ok {
			t.Errorf("%s granting %s: %v", c.why, c.role, err)
		}
	}
}

// Granted, listed, refused what it must be, and taken away, through the API.
func TestARoleBindingIsGrantedListedAndRevoked(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	other := newDriftMigrationOrg(t, s, false)
	person := newDriftUser(t, s)
	group := newDriftGroup(t, s)
	base := "/admin/organizations/" + org + "/role-bindings"

	grant := func(token string, body map[string]any) (int, map[string]any) {
		t.Helper()
		rec := call(t, s, http.MethodPost, base, token, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := grant(testToken, map[string]any{"role": "user-manager", "user_id": person, "group_id": group})
	if code != http.StatusCreated {
		t.Fatalf("granting a delegated user manager: %d %v", code, out)
	}
	id, _ := out["id"].(string)

	rec := call(t, s, http.MethodGet, base, testToken, nil)
	var listed struct {
		RoleBindings []roleBindingView `json:"role_bindings"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	found := false
	for _, b := range listed.RoleBindings {
		found = found || (b.ID == id && b.UserID == person && b.GroupID == group && b.Role == "user-manager")
	}
	if rec.Code != http.StatusOK || !found {
		t.Errorf("the binding is not listed: %d %s", rec.Code, rec.Body.String())
	}

	narrow := mintToken(t, s, fmt.Sprintf("roles-narrow-%d", time.Now().UnixNano()), org,
		[]string{ScopeOrganizationsWrite, ScopeConfigRead}, nil)
	for _, c := range []struct {
		why   string
		token string
		body  map[string]any
		code  int
		error string
	}{
		{"again", testToken, map[string]any{"role": "user-manager", "user_id": person, "group_id": group},
			http.StatusConflict, "already_exists"},
		{"a person of another organisation", testToken,
			map[string]any{"role": "auditor", "user_id": newDriftUserIn(t, s, other)}, http.StatusNotFound, "not_found"},
		{"a person who does not exist", testToken,
			map[string]any{"role": "auditor", "user_id": "33333333-3333-3333-3333-333333333333"}, http.StatusNotFound, "not_found"},
		{"a group on an auditor", testToken, map[string]any{"role": "auditor", "user_id": person, "group_id": group},
			http.StatusBadRequest, "invalid_request"},
		{"no holder", testToken, map[string]any{"role": "auditor"}, http.StatusBadRequest, "invalid_request"},
		{"an unknown role", testToken, map[string]any{"role": "superuser", "user_id": person},
			http.StatusBadRequest, "unknown_role"},
		{"by a token without the role's scopes", narrow, map[string]any{"role": "user-manager", "user_id": person},
			http.StatusForbidden, "wider_than_caller"},
	} {
		if code, out := grant(c.token, c.body); code != c.code || out["error"] != c.error {
			t.Errorf("granting %s answered %d %v, want %d %s", c.why, code, out, c.code, c.error)
		}
	}

	// Taking it away is held to the same rule, then done.
	if rec := call(t, s, http.MethodDelete, base+"/"+id, narrow, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a token without the role's scopes revoked it: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodDelete, base+"/"+id, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoking: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodDelete, base+"/"+id, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoking it twice answered %d", rec.Code)
	}
	if bs, err := store.RoleBindingsFor(context.Background(), s.db, person, ""); err != nil || len(bs) != 0 {
		t.Errorf("after revocation the person holds %v (%v)", bs, err)
	}
}

// A person who holds a role is written on only with privileged-users:write:
// otherwise a user manager could reset an owner's password and be the owner.
func TestARoleHolderIsAPrivilegedTarget(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	owner := newDriftUser(t, s)
	manager := mintToken(t, s, fmt.Sprintf("roles-manager-%d", time.Now().UnixNano()), org,
		[]string{ScopeUsersWrite}, nil)

	patch := func() int {
		t.Helper()
		return call(t, s, http.MethodPatch, "/admin/users/"+owner, manager, map[string]any{"display_name": "x"}).Code
	}
	if code := patch(); code != http.StatusOK {
		t.Fatalf("before any role, users:write was refused the person: %d", code)
	}
	id, err := store.GrantRole(context.Background(), s.db, store.RoleBinding{OrgID: org, UserID: owner, Role: "org-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if code := patch(); code != http.StatusForbidden {
		t.Errorf("users:write wrote on an owner: %d", code)
	}
	if _, err := store.RevokeRole(context.Background(), s.db, org, id); err != nil {
		t.Fatal(err)
	}
	if code := patch(); code != http.StatusOK {
		t.Errorf("after the role was taken away the person is still protected: %d", code)
	}
}

// newDriftUserIn is newDriftUser in a named organisation.
func newDriftUserIn(t *testing.T, s *Server, org string) string {
	t.Helper()
	var id string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256($2::bytea) || sha256($3::bytea), $4)
		RETURNING id::text`, org, fmt.Sprint(time.Now().UnixNano()), fmt.Sprint(time.Now().UnixNano()+1),
		fmt.Sprintf("drift-in-%d@example.test", time.Now().UnixNano())).Scan(&id); err != nil {
		t.Fatalf("creating the fixture user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, id)
	})
	return id
}
