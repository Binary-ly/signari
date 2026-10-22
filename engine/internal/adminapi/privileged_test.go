package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// The lesser credential must not reach the greater (privileged.go).

// newFlaggedGroup is a group whose members may impersonate.
func newFlaggedGroup(t *testing.T, s *Server) string {
	t.Helper()
	id := newDriftGroup(t, s)
	if _, err := s.db.Exec(context.Background(),
		`UPDATE core.groups SET may_impersonate = true WHERE id = $1::uuid`, id); err != nil {
		t.Fatalf("flagging the fixture group: %v", err)
	}
	return id
}

// newPrivilegedUser is a user who may impersonate.
func newPrivilegedUser(t *testing.T, s *Server) string {
	t.Helper()
	userID := newDriftUserWithTOTP(t, s)
	groupID := newFlaggedGroup(t, s)
	if _, err := s.db.Exec(context.Background(), `
		INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT $1::uuid, id, org_id FROM core.users WHERE id = $2::uuid`, groupID, userID); err != nil {
		t.Fatalf("joining the flagged group: %v", err)
	}
	return userID
}

// every scope a database token can hold except the one under test.
func allButPrivileged() []string {
	var out []string
	for _, sc := range KnownScopes {
		if sc != ScopePrivilegedUsersWrite {
			out = append(out, sc)
		}
	}
	return out
}

func refusedAsPrivileged(t *testing.T, code int, body string) bool {
	t.Helper()
	var got map[string]string
	_ = json.Unmarshal([]byte(body), &got)
	return code == http.StatusForbidden && got["error"] == "privileged_target"
}

func isMember(t *testing.T, s *Server, groupID, userID string) bool {
	t.Helper()
	var member bool
	if err := s.db.QueryRow(context.Background(), `
		SELECT EXISTS (SELECT 1 FROM core.group_members
		                WHERE group_id = $1::uuid AND user_id = $2::uuid)`,
		groupID, userID).Scan(&member); err != nil {
		t.Fatal(err)
	}
	return member
}

// 1.18: groups:write could grant impersonation by putting its own operator in
// a group that carries it.
func TestAGroupsWriteTokenCannotJoinAGroupThatMayImpersonate(t *testing.T) {
	s, _ := newTestServer(t)
	groupID := newFlaggedGroup(t, s)
	userID := newDriftUser(t, s)
	path := "/admin/groups/" + groupID + "/members/" + userID

	lesser := mintToken(t, s, "groups only", "", []string{ScopeGroupsWrite}, nil)
	rec := call(t, s, http.MethodPut, path, lesser, nil)
	if !refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
		t.Fatalf("groups:write joining a group that may impersonate gave %d %s, want 403 privileged_target",
			rec.Code, rec.Body.String())
	}
	if isMember(t, s, groupID, userID) {
		t.Fatal("the refused request still added the member")
	}

	// The refusal is on the trail, against the group.
	var refusals int
	if err := s.db.QueryRow(context.Background(), `
		SELECT count(*) FROM core.audit_events
		 WHERE event_type = 'admin.privileged_refused' AND detail->>'id' = $1`,
		groupID).Scan(&refusals); err != nil {
		t.Fatal(err)
	}
	if refusals == 0 {
		t.Error("the refusal was not audited")
	}

	// An ordinary group is still groups:write's to manage.
	plain := newDriftGroup(t, s)
	if rec := call(t, s, http.MethodPut, "/admin/groups/"+plain+"/members/"+userID, lesser, nil); rec.Code != http.StatusOK {
		t.Fatalf("groups:write joining an ordinary group gave %d %s", rec.Code, rec.Body.String())
	}

	greater := mintToken(t, s, "groups and privileged", "",
		[]string{ScopeGroupsWrite, ScopePrivilegedUsersWrite}, nil)
	if rec := call(t, s, http.MethodPut, path, greater, nil); rec.Code != http.StatusOK {
		t.Fatalf("the privileged scope could not add the member: %d %s", rec.Code, rec.Body.String())
	}
	if !isMember(t, s, groupID, userID) {
		t.Fatal("the permitted request did not add the member")
	}
}

// respell writes a uuid as PostgreSQL also accepts it: a hyphen after every
// four digits, or braced.
func respell(id string, braced bool) string {
	hex := strings.ReplaceAll(id, "-", "")
	if braced {
		return "{" + hex + "}"
	}
	var b strings.Builder
	for i := 0; i < len(hex); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(hex[i : i+4])
	}
	return b.String()
}

// A respelled id never reaches a handler. The guard once used a Go parser
// stricter than PostgreSQL's, so a respelled id was "nobody" to the guard and
// the real administrator to the write; ids are now refused unless canonical,
// and the guard parses with PostgreSQL besides (store tests).
func TestARespelledIDIsTheSameTargetToTheGuard(t *testing.T) {
	s, _ := newTestServer(t)
	groupID := newFlaggedGroup(t, s)
	userID := newDriftUser(t, s)
	admin := newPrivilegedUser(t, s)
	groupsOnly := mintToken(t, s, "groups only", "", []string{ScopeGroupsWrite}, nil)
	usersOnly := mintToken(t, s, "users only", "", []string{ScopeUsersWrite}, nil)

	for _, braced := range []bool{false, true} {
		path := "/admin/groups/" + url.PathEscape(respell(groupID, braced)) + "/members/" + userID
		rec := call(t, s, http.MethodPut, path, groupsOnly, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "canonical") {
			t.Errorf("groups:write on a flagged group spelled %q: %d %s",
				respell(groupID, braced), rec.Code, rec.Body.String())
		}
		rec = call(t, s, http.MethodPatch, "/admin/users/"+url.PathEscape(respell(admin, braced)),
			usersOnly, map[string]any{"display_name": "taken"})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "canonical") {
			t.Errorf("users:write on an administrator spelled %q: %d %s",
				respell(admin, braced), rec.Code, rec.Body.String())
		}
	}
	if isMember(t, s, groupID, userID) {
		t.Fatal("a respelled id put somebody in a group that may impersonate")
	}
}

// 1.19: users:write could take over or remove a user who may impersonate.
func TestAUsersWriteTokenCannotTakeOverAPrivilegedUser(t *testing.T) {
	s, _ := newTestServer(t)
	admin := newPrivilegedUser(t, s)
	lesser := mintToken(t, s, "users only", "", []string{ScopeUsersWrite}, nil)

	for _, c := range []struct{ method, path string }{
		{http.MethodPatch, "/admin/users/" + admin},
		{http.MethodDelete, "/admin/users/" + admin + "/factors/totp"},
		{http.MethodDelete, "/admin/users/" + admin},
	} {
		var body any
		if c.method == http.MethodPatch {
			body = map[string]any{"email": "taken-over@example.test"}
		}
		rec := call(t, s, c.method, c.path, lesser, body)
		if !refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
			t.Errorf("%s %s with users:write gave %d %s, want 403 privileged_target",
				c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	var email string
	var totp int
	if err := s.db.QueryRow(context.Background(), `
		SELECT email, (SELECT count(*) FROM core.totp_credentials WHERE user_id = u.id)
		  FROM core.users u WHERE id = $1::uuid`, admin).Scan(&email, &totp); err != nil {
		t.Fatalf("the administrator is gone: %v", err)
	}
	if email == "taken-over@example.test" || totp == 0 {
		t.Fatalf("a refused request still changed the account (email %q, totp %d)", email, totp)
	}

	// Signing them out only withdraws access, and stays with users:write so an
	// incident responder can do it with the token they have.
	if rec := call(t, s, http.MethodDelete, "/admin/users/"+admin+"/sessions", lesser, nil); refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
		t.Errorf("ending a privileged user's sessions was refused: %s", rec.Body.String())
	}

	// An ordinary user is still users:write's to manage.
	plain := newDriftUser(t, s)
	if rec := call(t, s, http.MethodPatch, "/admin/users/"+plain, lesser,
		map[string]any{"active": false}); rec.Code != http.StatusOK {
		t.Fatalf("users:write on an ordinary user gave %d %s", rec.Code, rec.Body.String())
	}

	// A token scoped to another organisation learns nothing: it gets the
	// handler's cross-organisation answer, not a refusal that says the id
	// belongs to an administrator somewhere.
	var otherOrg string
	if err := s.db.QueryRow(context.Background(), `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'priv-' || substr(gen_random_uuid()::text, 1, 8), 'other'
		  FROM core.organizations ORDER BY created_at LIMIT 1
		RETURNING id::text`).Scan(&otherOrg); err != nil {
		t.Fatalf("creating a second organisation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, otherOrg)
	})
	other := mintToken(t, s, "elsewhere", otherOrg, []string{ScopeUsersWrite}, nil)
	if rec := call(t, s, http.MethodPatch, "/admin/users/"+admin, other,
		map[string]any{"active": false}); refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
		t.Errorf("a token for another organisation was told the user is privileged: %s", rec.Body.String())
	}
}

// Every write on a user or a group is registered through `privileged`, and
// each one refuses a privileged target. Derived from the router, so a route
// added next month with plain `route` fails here rather than reopening 1.18 or
// 1.19 for whatever it changes.
func TestEveryWriteOnAUserOrGroupGuardsPrivilegedTargets(t *testing.T) {
	s, _ := newTestServer(t)
	s.Routes()

	// Writes on a user or group that need not be guarded, each with the reason.
	exempt := map[string]string{
		"delete /admin/users/{userID}/sessions":            "ending sessions only withdraws access",
		"delete /admin/users/{userID}/consents/{clientID}": "withdrawing a consent only withdraws an application's access",
	}

	lesser := mintToken(t, s, "all but privileged", "", allButPrivileged(), nil)
	greater := mintToken(t, s, "all", "", KnownScopes, nil)
	checked := 0
	for _, op := range s.ops {
		key := op.method + " " + op.path
		onGroup := strings.Contains(op.path, "{groupID}")
		onUser := strings.Contains(op.path, "{userID}") || strings.Contains(op.path, "{subjectID}")
		// A client designated for the Admin API (6.01): where administrators
		// sign in, so its redirect URIs and secret are an owner's role.
		onClient := strings.Contains(op.path, "{clientID}") && !onUser && !onGroup
		if op.method == "get" || (!onGroup && !onUser && !onClient) {
			continue
		}
		if _, ok := exempt[key]; ok {
			if op.privileged {
				t.Errorf("%s is guarded and also listed as exempt", key)
			}
			continue
		}
		if !op.privileged {
			t.Errorf("%s writes on a user or group and is registered with route, not privileged: "+
				"a token without %s could use it on someone who may impersonate", key, ScopePrivilegedUsersWrite)
			continue
		}
		checked++
		t.Run(key, func(t *testing.T) {
			// Fresh targets each time: the permitted call below may delete them.
			// A membership route names a user too; an ordinary one, so the
			// refusal has to come from the group.
			path := op.path
			switch {
			case onClient:
				client := newPreconditionClient(t, s)
				if _, err := s.db.Exec(context.Background(),
					`UPDATE core.clients SET admin_api = true WHERE client_id = $1`, client); err != nil {
					t.Fatal(err)
				}
				path = strings.ReplaceAll(path, "{clientID}", client)
			case onGroup:
				path = strings.ReplaceAll(path, "{groupID}", newFlaggedGroup(t, s))
				path = strings.ReplaceAll(path, "{userID}", newDriftUser(t, s))
			default:
				admin := newPrivilegedUser(t, s)
				path = strings.ReplaceAll(path, "{userID}", admin)
				path = strings.ReplaceAll(path, "{subjectID}", admin)
			}
			path = strings.ReplaceAll(path, "{kind}", "totp")
			path = strings.ReplaceAll(path, "{factorID}", uuid.NewString())
			method := strings.ToUpper(op.method)

			rec := call(t, s, method, path, lesser, map[string]any{})
			if !refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
				t.Fatalf("without %s: %d %s, want 403 privileged_target",
					ScopePrivilegedUsersWrite, rec.Code, rec.Body.String())
			}
			rec = call(t, s, method, path, greater, map[string]any{})
			if refusedAsPrivileged(t, rec.Code, rec.Body.String()) {
				t.Fatalf("refused even with %s: %s", ScopePrivilegedUsersWrite, rec.Body.String())
			}
		})
	}
	if checked == 0 {
		t.Fatal("no guarded route was found, so this test checked nothing")
	}
	if !slices.Contains(KnownScopes, ScopePrivilegedUsersWrite) {
		t.Fatal("the scope cannot be granted to a database token")
	}
}
