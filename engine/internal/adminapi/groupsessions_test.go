package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Groups and sessions: what the endpoints actually do, as opposed to whether
// they are wired up (which the route-walking tests cover).

func groupMemberCount(t *testing.T, s *Server, groupID string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(context.Background(),
		`SELECT count(*) FROM core.group_members WHERE group_id = $1::uuid`, groupID).Scan(&n); err != nil {
		t.Fatalf("counting members: %v", err)
	}
	return n
}

func liveSessionCount(t *testing.T, s *Server, userID string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(context.Background(),
		`SELECT count(*) FROM core.sessions
		  WHERE user_id = $1::uuid AND revoked_at IS NULL`, userID).Scan(&n); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	return n
}

// may_impersonate must not be settable through this API.
//
// The escalation it prevents: `core.groups.may_impersonate` lets members act as
// other users. If a groups:write token could set it, that token could grant
// itself impersonation by flagging a group its own operator belongs to -- getting
// the greater privilege from the lesser credential. It stays a CLI operation,
// where the person is on the host.
func TestMayImpersonateCannotBeSetThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	orgID := anyOrgID(t, s)
	name := fmt.Sprintf("esc-%d", time.Now().UnixNano())

	create := httptest.NewRecorder()
	s.Routes().ServeHTTP(create, adminReq(t, http.MethodPost, "/admin/groups",
		fmt.Sprintf(`{"org_id":%q,"name":%q,"may_impersonate":true}`, orgID, name), ""))
	if create.Code != http.StatusCreated {
		t.Fatalf("create gave %d: %s", create.Code, create.Body.String())
	}
	var body struct {
		ID string `json:"id"`
	}
	decodeBody(t, create, &body)
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.groups WHERE id = $1::uuid`, body.ID)
	})

	var may bool
	if err := s.db.QueryRow(context.Background(),
		`SELECT may_impersonate FROM core.groups WHERE id = $1::uuid`, body.ID).Scan(&may); err != nil {
		t.Fatal(err)
	}
	if may {
		t.Fatal("may_impersonate was set from the request body. A groups:write token " +
			"can now grant impersonation, which is the greater privilege obtained " +
			"from the lesser credential")
	}

	// And a PATCH carrying it must not turn it on either.
	patch := httptest.NewRecorder()
	s.Routes().ServeHTTP(patch, adminReq(t, http.MethodPatch, "/admin/groups/"+body.ID,
		`{"display_name":"x","may_impersonate":true}`, ""))
	if patch.Code != http.StatusOK {
		t.Fatalf("patch gave %d: %s", patch.Code, patch.Body.String())
	}
	if err := s.db.QueryRow(context.Background(),
		`SELECT may_impersonate FROM core.groups WHERE id = $1::uuid`, body.ID).Scan(&may); err != nil {
		t.Fatal(err)
	}
	if may {
		t.Error("may_impersonate was set by a PATCH")
	}
}

// Membership changes actually take effect, in both directions.
func TestGroupMembershipAddsAndRemoves(t *testing.T) {
	s, _ := newTestServer(t)
	groupID := newDriftGroup(t, s)
	userID := newDriftUser(t, s)

	add := httptest.NewRecorder()
	s.Routes().ServeHTTP(add, adminReq(t, http.MethodPut,
		"/admin/groups/"+groupID+"/members/"+userID, "", ""))
	if add.Code != http.StatusOK {
		t.Fatalf("add gave %d: %s", add.Code, add.Body.String())
	}
	if n := groupMemberCount(t, s, groupID); n != 1 {
		t.Fatalf("after adding, the group has %d members, want 1", n)
	}

	remove := httptest.NewRecorder()
	s.Routes().ServeHTTP(remove, adminReq(t, http.MethodDelete,
		"/admin/groups/"+groupID+"/members/"+userID, "", ""))
	if remove.Code != http.StatusOK {
		t.Fatalf("remove gave %d: %s", remove.Code, remove.Body.String())
	}
	if n := groupMemberCount(t, s, groupID); n != 0 {
		t.Errorf("after removing, the group has %d members, want 0", n)
	}
}

// A user cannot be added to a group in a different organisation.
//
// A group decides application access, so a cross-organisation membership is a
// tenancy breach that looks exactly like an ordinary administrative action.
func TestAUserCannotJoinAnotherOrganisationsGroup(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()

	var otherOrg string
	if err := s.db.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, $1, 'other' FROM core.organizations ORDER BY created_at LIMIT 1
		RETURNING id::text`, fmt.Sprintf("xorg-%d", time.Now().UnixNano())).Scan(&otherOrg); err != nil {
		t.Fatalf("creating a second organisation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, otherOrg)
	})

	var otherUser string
	if err := s.db.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, sha256($2::bytea) || sha256($3::bytea), $4)
		RETURNING id::text`,
		otherOrg, fmt.Sprint(time.Now().UnixNano()), fmt.Sprint(time.Now().UnixNano()+1),
		fmt.Sprintf("xorg-%d@example.test", time.Now().UnixNano())).Scan(&otherUser); err != nil {
		t.Fatalf("creating the other organisation's user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, otherUser)
	})

	groupID := newDriftGroup(t, s) // in the FIRST organisation

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPut,
		"/admin/groups/"+groupID+"/members/"+otherUser, "", ""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("adding a user from another organisation gave %d, want 400: %s",
			rec.Code, rec.Body.String())
	}
	if n := groupMemberCount(t, s, groupID); n != 0 {
		t.Errorf("the cross-organisation membership was written anyway (%d members)", n)
	}
}

// Deleting a group removes its memberships with it.
//
// Leaving orphaned rows in group_members would be a dangling grant: the group is
// gone from every listing while the membership rows remain, and a later group
// reusing the identifier would inherit them.
func TestDeletingAGroupRemovesItsMemberships(t *testing.T) {
	s, _ := newTestServer(t)
	groupID := newDriftGroup(t, s)
	userID := newDriftUser(t, s)

	add := httptest.NewRecorder()
	s.Routes().ServeHTTP(add, adminReq(t, http.MethodPut,
		"/admin/groups/"+groupID+"/members/"+userID, "", ""))
	if add.Code != http.StatusOK {
		t.Fatalf("add gave %d", add.Code)
	}

	del := httptest.NewRecorder()
	s.Routes().ServeHTTP(del, adminReq(t, http.MethodDelete, "/admin/groups/"+groupID, "", ""))
	if del.Code != http.StatusOK {
		t.Fatalf("delete gave %d: %s", del.Code, del.Body.String())
	}
	if n := groupMemberCount(t, s, groupID); n != 0 {
		t.Errorf("%d membership rows survived the group's deletion", n)
	}
	var exists int
	if err := s.db.QueryRow(context.Background(),
		`SELECT count(*) FROM core.groups WHERE id = $1::uuid`, groupID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != 0 {
		t.Error("the group row survived a delete; ADR-005 refuses soft deletes")
	}
}

// Revoking a user's sessions ends them AND tells the relying parties.
//
// The property that matters is the SECOND half. Setting `revoked_at` with an
// UPDATE would end the session here and leave the person signed in to every
// application they had reached, with this server reporting success. Termination
// goes through the one path that snapshots the relying parties and queues a
// back-channel logout for each.
func TestRevokingSessionsEndsThemAndQueuesLogoutNotices(t *testing.T) {
	s, _ := newTestServer(t)
	userID := newDriftUser(t, s)
	sid := newDriftSession(t, s, userID)

	// A client with a back-channel logout URI, joined to the session, so there is
	// a notice to queue. Without this the test would pass against a raw UPDATE.
	clientID := newPreconditionClient(t, s)
	ctx := context.Background()
	if _, err := s.db.Exec(ctx,
		`UPDATE core.clients SET backchannel_logout_uri = $2 WHERE client_id = $1`,
		clientID, "https://app.example.test/backchannel"); err != nil {
		t.Fatalf("giving the client a logout uri: %v", err)
	}
	if _, err := s.db.Exec(ctx,
		`INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`, sid, clientID); err != nil {
		t.Fatalf("joining the session to the client: %v", err)
	}

	if liveSessionCount(t, s, userID) != 1 {
		t.Fatal("the fixture session is not live, so this proves nothing")
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete,
		"/admin/users/"+userID+"/sessions", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke gave %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		SessionsEnded int `json:"sessions_ended"`
		NoticesQueued int `json:"notices_queued"`
	}
	decodeBody(t, rec, &body)

	if body.SessionsEnded != 1 {
		t.Errorf("sessions_ended = %d, want 1", body.SessionsEnded)
	}
	if n := liveSessionCount(t, s, userID); n != 0 {
		t.Errorf("%d sessions are still live after revocation", n)
	}
	if body.NoticesQueued < 1 {
		t.Error("no back-channel logout notice was queued, so the relying party will " +
			"never learn the session ended and the person stays signed in there")
	}
}

// Revoking ONE session leaves the user's other sessions alone.
func TestRevokingOneSessionLeavesTheOthers(t *testing.T) {
	s, _ := newTestServer(t)
	userID := newDriftUser(t, s)
	first := newDriftSession(t, s, userID)
	_ = newDriftSession(t, s, userID)

	if n := liveSessionCount(t, s, userID); n != 2 {
		t.Fatalf("expected 2 live sessions, got %d", n)
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete, "/admin/sessions/"+first, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke gave %d: %s", rec.Code, rec.Body.String())
	}
	if n := liveSessionCount(t, s, userID); n != 1 {
		t.Errorf("%d sessions live after revoking one of two, want 1", n)
	}
}

// The session listing must not return the address hash.
//
// `ip_hash` is a hash rather than an address by deliberate choice; an admin API
// that returned it would undo that decision from the other side.
func TestASessionListingDoesNotReturnTheAddressHash(t *testing.T) {
	s, _ := newTestServer(t)
	userID := newDriftUser(t, s)
	newDriftSession(t, s, userID)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet,
		"/admin/users/"+userID+"/sessions", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("listing gave %d: %s", rec.Code, rec.Body.String())
	}
	for _, forbidden := range []string{"ip_hash", "ip_address", "remote_addr"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("the session listing returned %q", forbidden)
		}
	}
}
