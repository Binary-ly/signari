package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// Groups inside groups through the Admin API (11.09).

func nestingPath(parent, child string) string {
	return "/admin/groups/" + parent + "/member-groups/" + child
}

func groupNameOf(t *testing.T, s *Server, id string) string {
	t.Helper()
	var name string
	if err := s.db.QueryRow(context.Background(), `SELECT name FROM core.groups WHERE id = $1::uuid`, id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

func joinGroup(t *testing.T, s *Server, groupID, userID string) {
	t.Helper()
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT $1::uuid, id, org_id FROM core.users WHERE id = $2::uuid`, groupID, userID); err != nil {
		t.Fatal(err)
	}
}

func errorOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	e, _ := body["error"].(string)
	return e
}

// Put in, read back from both ends, felt by a member, refused as a loop, and taken out.
func TestAGroupIsPutInsideAnotherAndTakenOut(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	parent, child := newDriftGroup(t, s), newDriftGroup(t, s)
	userID := newDriftUser(t, s)
	joinGroup(t, s, child, userID)
	tok := mintToken(t, s, "groups", "", []string{ScopeGroupsRead, ScopeGroupsWrite}, nil)

	rec := call(t, s, http.MethodPut, nestingPath(parent, child), tok, nil)
	var put struct {
		Changed bool `json:"changed"`
		Member  bool `json:"member"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &put); rec.Code != http.StatusOK || err != nil || !put.Changed || !put.Member {
		t.Fatalf("nesting: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("a nesting answered no ETag, so the next conditional write has nothing to send")
	}
	if rec := call(t, s, http.MethodPut, nestingPath(parent, child), tok, nil); rec.Code != http.StatusOK ||
		json.Unmarshal(rec.Body.Bytes(), &put) != nil || put.Changed {
		t.Errorf("nesting again: %d %s, want 200 and changed false", rec.Code, rec.Body.String())
	}

	var g groupSummary
	rec = call(t, s, http.MethodGet, "/admin/groups/"+child, tok, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil || !slices.Equal(g.MemberOf, []string{parent}) {
		t.Errorf("the group's member_of: %d %s, want [%s]", rec.Code, rec.Body.String(), parent)
	}
	var list struct {
		MemberGroups []memberGroupView `json:"member_groups"`
	}
	rec = call(t, s, http.MethodGet, "/admin/groups/"+parent+"/member-groups", tok, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.MemberGroups) != 1 ||
		list.MemberGroups[0].ID != child {
		t.Errorf("the groups inside it: %d %s, want the one put there", rec.Code, rec.Body.String())
	}
	held, err := store.AllGroupsForUser(ctx, s.db, userID)
	if err != nil || !slices.Contains(held, groupNameOf(t, s, parent)) {
		t.Errorf("a member of the group put inside is in %v, %v; want the group above too", held, err)
	}

	if rec := call(t, s, http.MethodPut, nestingPath(child, parent), tok, nil); rec.Code != http.StatusConflict ||
		errorOf(t, rec) != "nesting_loop" {
		t.Errorf("the group above put inside the one below: %d %s, want 409 nesting_loop", rec.Code, rec.Body.String())
	}

	rec = call(t, s, http.MethodDelete, nestingPath(parent, child), tok, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &put); rec.Code != http.StatusOK || err != nil || !put.Changed || put.Member {
		t.Fatalf("taking it out: %d %s", rec.Code, rec.Body.String())
	}
	held, err = store.AllGroupsForUser(ctx, s.db, userID)
	if err != nil || slices.Contains(held, groupNameOf(t, s, parent)) {
		t.Errorf("still in %v once the group was taken out, %v", held, err)
	}

	var audited int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.audit_events
		WHERE event_type IN ('admin.group_nested', 'admin.group_unnested') AND detail->>'group_id' = $1
		  AND detail->>'member_group_id' = $2`, parent, child).Scan(&audited); err != nil || audited < 3 {
		t.Errorf("%d nesting records, %v; want one for each write", audited, err)
	}
}

// Two organisations' groups cannot be nested in each other.
func TestGroupsOfTwoOrganisationsCannotBeNested(t *testing.T) {
	s, _ := newTestServer(t)
	ours := newDriftGroup(t, s)
	org := newDriftOrgIn(t, s, newDriftInstance(t, s))
	var theirs string
	if err := s.db.QueryRow(context.Background(), `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'elsewhere', 'Elsewhere') RETURNING id::text`, org).Scan(&theirs); err != nil {
		t.Fatal(err)
	}
	tok := mintToken(t, s, "groups", "", []string{ScopeGroupsWrite}, nil)
	for _, path := range []string{nestingPath(ours, theirs), nestingPath(theirs, ours)} {
		if rec := call(t, s, http.MethodPut, path, tok, nil); rec.Code != http.StatusBadRequest ||
			errorOf(t, rec) != "cross_organisation_membership" {
			t.Errorf("%s: %d %s, want 400 cross_organisation_membership", path, rec.Code, rec.Body.String())
		}
	}
}

// A token narrowed to named groups, and a role delegated over some, are refused: a
// nesting reaches people neither names, and widens every delegate's reach above it.
func TestNestingIsRefusedToANarrowedCaller(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	parent, child := newDriftGroup(t, s), newDriftGroup(t, s)

	secret, _, err := NewToken(ctx, s.db, "narrowed nesting", anyOrgID(t, s), []string{ScopeGroupsWrite}, nil,
		nil, []string{parent, child})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(ctx, `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(secret))
	})
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if rec := call(t, s, method, nestingPath(parent, child), secret, nil); rec.Code != http.StatusForbidden ||
			errorOf(t, rec) != "outside_token_objects" {
			t.Errorf("%s by a token narrowed to both groups: %d %s, want 403 outside_token_objects",
				method, rec.Code, rec.Body.String())
		}
	}

	delegate := &Principal{OrgID: anyOrgID(t, s), Scopes: []string{ScopeGroupsWrite, ScopeUsersWrite},
		UserGroups: map[string][]string{ScopeUsersWrite: {parent}}}
	r := httptest.NewRequest(http.MethodPut, nestingPath(parent, child), nil).WithContext(withPrincipal(ctx, delegate))
	r.SetPathValue("groupID", parent)
	r.SetPathValue("memberGroupID", child)
	rec := httptest.NewRecorder()
	s.addMemberGroup(rec, r)
	if rec.Code != http.StatusForbidden || errorOf(t, rec) != "outside_token_objects" {
		t.Errorf("a role delegated over a group: %d %s, want 403 outside_token_objects", rec.Code, rec.Body.String())
	}

	var nested bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.group_parents
		WHERE group_id = $1::uuid AND parent_id = $2::uuid)`, child, parent).Scan(&nested); err != nil || nested {
		t.Errorf("a refused nesting was made: %v, %v", nested, err)
	}
}

// A configuration file that puts a group inside one that may impersonate, directly or
// through a group the same file makes, needs privileged-users:write, as the route does:
// planned as the group it is before the apply, it would pass as an ordinary group.
func TestAConfigFileCannotNestIntoImpersonationWithoutTheScope(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	if _, err := s.db.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
		VALUES ($1::uuid, 'support-admins', 'Support admins', true)`, org); err != nil {
		t.Fatal(err)
	}
	lesser, _, err := NewToken(ctx, s.db, "cfg-nesting-lesser", org, []string{ScopeOrganizationsWrite, ScopeGroupsWrite},
		nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(lesser))
	})
	send := func(document string) *httptest.ResponseRecorder {
		t.Helper()
		b, err := json.Marshal(map[string]any{"document": document})
		if err != nil {
			t.Fatal(err)
		}
		r := adminReq(t, http.MethodPost, "/admin/organizations/"+org+"/config", string(b), "")
		r.Header.Set("Authorization", "Bearer "+lesser)
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, r)
		return rec
	}
	for _, c := range []struct{ name, document string }{
		{"directly", "version: 1\ngroups:\n  - {name: helpers-a, member_of: [support-admins]}\n"},
		{"through a group the file makes", "version: 1\ngroups:\n  - {name: helpers-b, member_of: [tier-two]}\n" +
			"  - {name: tier-two, member_of: [support-admins]}\n"},
	} {
		rec := send(c.document)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), ScopePrivilegedUsersWrite) {
			t.Errorf("%s: %d %s, want 403 naming %s", c.name, rec.Code, rec.Body.String(), ScopePrivilegedUsersWrite)
		}
	}
	var made int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.groups WHERE org_id = $1::uuid
		AND name IN ('helpers-a', 'helpers-b', 'tier-two')`, org).Scan(&made); err != nil || made != 0 {
		t.Errorf("a refused apply made %d groups, %v", made, err)
	}
	if rec := send("version: 1\ngroups:\n  - {name: helpers, member_of: [tier-two]}\n  - {name: tier-two}\n"); rec.Code != http.StatusOK {
		t.Errorf("nesting ordinary groups by file: %d %s", rec.Code, rec.Body.String())
	}
}

// A group inside one that may impersonate is as privileged as that one, on both routes
// that give it members: putting a group in it, and putting a person in it. The second is
// the one that was open: groups:write added somebody to the group below and they could
// impersonate.
func TestAGroupInsideOneThatMayImpersonateIsPrivileged(t *testing.T) {
	s, _ := newTestServer(t)
	flagged, below, other := newFlaggedGroup(t, s), newDriftGroup(t, s), newDriftGroup(t, s)
	userID := newDriftUser(t, s)
	lesser := mintToken(t, s, "groups only", "", []string{ScopeGroupsWrite}, nil)
	greater := mintToken(t, s, "groups and privileged", "", []string{ScopeGroupsWrite, ScopePrivilegedUsersWrite}, nil)

	if rec := call(t, s, http.MethodPut, nestingPath(flagged, below), lesser, nil); !refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
		t.Fatalf("groups:write putting a group inside one that may impersonate: %d %s, want 403 privileged_target",
			rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPut, nestingPath(flagged, below), greater, nil); rec.Code != http.StatusOK {
		t.Fatalf("the privileged scope could not nest: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPut, "/admin/groups/"+below+"/members/"+userID, lesser, nil); !refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
		t.Fatalf("groups:write adding a person to a group inside one that may impersonate: %d %s, want 403 "+
			"privileged_target", rec.Code, rec.Body.String())
	}
	if isMember(t, s, below, userID) {
		t.Fatal("the refused request still added the member")
	}
	if rec := call(t, s, http.MethodPut, nestingPath(below, other), lesser, nil); !refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
		t.Fatalf("groups:write putting a group inside the group below one that may impersonate: %d %s, want 403",
			rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodPut, "/admin/groups/"+other+"/members/"+userID, lesser, nil); rec.Code != http.StatusOK {
		t.Fatalf("an ordinary group is still groups:write's: %d %s", rec.Code, rec.Body.String())
	}
}
