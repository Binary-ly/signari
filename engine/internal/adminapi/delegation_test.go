package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A token narrowed to named groups may invite only into them, so it lists and
// revokes only invitations into them (0.26): it listed every invitation.
func TestATokenNarrowedToGroupsSeesOnlyTheirInvitations(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)
	group := newDriftGroup(t, s)
	var name string
	if err := s.db.QueryRow(ctx, `SELECT name FROM core.groups WHERE id = $1::uuid`, group).Scan(&name); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	tokName := fmt.Sprintf("narrow-invites-%d", time.Now().UnixNano())
	narrow, _, err := NewToken(ctx, s.db, tokName, org, []string{ScopeUsersWrite}, &expires, nil, []string{group})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(ctx, `DELETE FROM core.admin_tokens WHERE name = $1`, tokName) })

	rec := call(t, s, http.MethodPost, "/admin/invitations", narrow, map[string]any{"org_id": org, "groups": []string{name}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("inviting into its group: %d %s", rec.Code, rec.Body.String())
	}
	var ours struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ours)
	t.Cleanup(func() { _, _ = s.db.Exec(ctx, `DELETE FROM core.invitations WHERE id = $1::uuid`, ours.ID) })
	outside := newDriftInvitation(t, s)

	rec = call(t, s, http.MethodGet, "/admin/invitations?limit=200&org_id="+org, narrow, nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), outside) {
		t.Errorf("the list showed an invitation into no group of the token's: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodDelete, "/admin/invitations/"+outside, narrow, nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoking an invitation into no group of the token's answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodDelete, "/admin/invitations/"+ours.ID, narrow, nil); rec.Code != http.StatusNoContent {
		t.Errorf("revoking its own invitation answered %d %s", rec.Code, rec.Body.String())
	}
}

// A user manager delegated over a group reaches its members and nobody else
// (6.01), on every route that acts on a person.
//
// Derived from the router: every operation under users:read or users:write is
// called as such a delegate with the route lists' own fixtures, whose people
// are outside the group. A route naming its person in the path is held to it
// by auth; each other one is listed below with how it applies the reach, and
// a route in neither fails.
func TestEveryRouteOnAPersonIsHeldToADelegatedReach(t *testing.T) {
	a := newAdminTokens(t)
	s := a.s
	ctx := context.Background()
	s.Routes()

	group := newDriftGroup(t, s)
	member := newDriftUser(t, s)
	if _, err := s.db.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, group, member, a.org); err != nil {
		t.Fatal(err)
	}
	delegate := newDriftUser(t, s)
	a.grant(t, store.RoleBinding{UserID: delegate, Role: "user-manager", GroupID: group})
	tok := a.sign(t, a.claims(delegate, a.session(t, delegate, "pwd", "otp")))
	as := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := adminReq(t, method, path, body, "")
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, r)
		return rec
	}
	members := func(ids []string) bool {
		t.Helper()
		for _, id := range ids {
			var in bool
			if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.group_members
				WHERE group_id = $1::uuid AND user_id::text = $2)`, group, id).Scan(&in); err != nil || !in {
				return false
			}
		}
		return true
	}

	// The member is reached, so a refusal below is the reach and not the token.
	if rec := as(http.MethodGet, "/admin/users/"+member, ""); rec.Code != http.StatusOK {
		t.Fatalf("the delegate reading a member of its group: %d %s", rec.Code, rec.Body.String())
	}
	if rec := as(http.MethodPatch, "/admin/users/"+member, `{"display_name":"reached"}`); rec.Code != http.StatusOK {
		t.Fatalf("the delegate changing a member of its group: %d %s", rec.Code, rec.Body.String())
	}
	var groupName string
	if err := s.db.QueryRow(ctx, `SELECT name FROM core.groups WHERE id = $1::uuid`, group).Scan(&groupName); err != nil {
		t.Fatal(err)
	}
	if rec := as(http.MethodPost, "/admin/invitations",
		`{"org_id":"`+a.org+`","groups":["`+groupName+`"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("the delegate inviting into its group: %d %s", rec.Code, rec.Body.String())
	}
	outside := newDriftInvitation(t, s)

	refused := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusForbidden || out["error"] != "outside_token_organisation" {
			t.Errorf("answered %d %s, want 403 outside_token_organisation", rec.Code, rec.Body.String())
		}
	}
	// Each route that finds its person otherwise than by path, and what a
	// delegate must see from it.
	inHandler := map[string]func(t *testing.T, rec *httptest.ResponseRecorder){
		"POST /admin/users": refused,
		"GET /admin/users": func(t *testing.T, rec *httptest.ResponseRecorder) {
			var out struct {
				Users []userSummary `json:"users"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			var ids []string
			for _, u := range out.Users {
				ids = append(ids, u.ID)
			}
			if rec.Code != http.StatusOK || len(ids) == 0 || !members(ids) {
				t.Errorf("listed %d %v; want the group's members only", rec.Code, ids)
			}
		},
		"GET /admin/invitations": func(t *testing.T, rec *httptest.ResponseRecorder) {
			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), outside) {
				t.Errorf("listed %d with an invitation into no group of the delegate's: %s", rec.Code, rec.Body.String())
			}
		},
		// The fixture invites into no group.
		"POST /admin/invitations": refused,
		// Answered as an invitation that does not exist.
		"DELETE /admin/invitations/{invitationID}": func(t *testing.T, rec *httptest.ResponseRecorder) {
			if rec.Code != http.StatusNotFound {
				t.Errorf("revoked an invitation into no group of the delegate's: %d %s", rec.Code, rec.Body.String())
			}
		},
		"DELETE /admin/sessions/{sid}": refused,
	}

	fixtures := map[string]func(t *testing.T) (string, string, string){}
	for _, rt := range allReadRoutes() {
		fixtures[rt.name] = func(t *testing.T) (string, string, string) { return http.MethodGet, rt.path(t, s), "" }
	}
	for _, rt := range allMutatingRoutes() {
		fixtures[rt.name] = func(t *testing.T) (string, string, string) {
			p := rt.path(t, s)
			return rt.method, p, rt.body(t, s, p)
		}
	}
	checked := 0
	for _, op := range s.ops {
		if op.scope != ScopeUsersRead && op.scope != ScopeUsersWrite {
			continue
		}
		name := strings.ToUpper(op.method) + " " + op.path
		byPath := strings.Contains(op.path, "{userID}") || strings.Contains(op.path, "{subjectID}")
		expect, declared := inHandler[name]
		if !byPath && !declared {
			t.Errorf("%s acts on people, names none in its path, and is not in inHandler: say how it "+
				"applies a delegated role's reach (requireReach, reachFilter) and add it", name)
			continue
		}
		fixture, ok := fixtures[name]
		if !ok {
			t.Errorf("%s has no fixture in allReadRoutes or allMutatingRoutes", name)
			continue
		}
		checked++
		t.Run(name, func(t *testing.T) {
			method, path, body := fixture(t)
			rec := as(method, path, body)
			if byPath {
				refused(t, rec)
				return
			}
			expect(t, rec)
		})
	}
	if checked < 20 || !slices.Contains(store.AdminRoles, store.DelegatedRole) {
		t.Fatalf("only %d routes on people were checked; the derivation has gone blind", checked)
	}
}
