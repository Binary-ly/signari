package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Deleting a user must tell every application they were signed in to.
//
// # The failure this exists to catch
//
// Forty foreign keys point at core.users and every one of them is ON DELETE
// CASCADE or SET NULL. So `DELETE FROM core.users` works, empties
// core.sessions, returns no error, and is wrong.
//
// A session row disappearing from this database is not a logout. The relying
// parties hold sessions of their own and learn nothing unless this server sends
// each a back-channel logout notice. Cascading the rows away destroys the list
// of who to notify BEFORE anybody is notified -- so the person stays signed in
// everywhere that matters, under an account that no longer exists, until each
// application's own session expires on its own schedule. The admin API reports
// 200 the whole time.
//
// This is the same defect the direct-UPDATE version of session revocation had,
// and it is worth restating that a reviewer cannot see it in the handler: the
// handler looks complete, the schema looks complete, and the two are separately
// correct. Only running it shows the notice was never raised.
func TestDeletingAUserQueuesBackChannelLogoutNotices(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)
	sid := newDriftSession(t, s, userID)

	// A client with a back-channel logout URI, joined to the session. Without
	// this there is no notice to queue and the test would pass against a plain
	// cascade -- which is precisely how this class of bug survives a test suite.
	clientID := newPreconditionClient(t, s)
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
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete, "/admin/users/"+userID, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete gave %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		SessionsEnded int `json:"sessions_ended"`
		NoticesQueued int `json:"notices_queued"`
		ConfigVersion int `json:"config_version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.SessionsEnded != 1 {
		t.Errorf("sessions_ended = %d, want 1", body.SessionsEnded)
	}
	if body.NoticesQueued != 1 {
		t.Fatalf("notices_queued = %d, want 1. The user is gone and the "+
			"application they were signed in to was never told, so they remain "+
			"signed in there under an account that no longer exists.",
			body.NoticesQueued)
	}
	if body.ConfigVersion == 0 {
		t.Error("no config_version in the response; the mutation did not bump it")
	}

	// The row is really gone. ADR-005: deletion is deletion, and deactivation is
	// a different operation with a different verb.
	var n int
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM core.users WHERE id = $1::uuid`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("the user row survives the delete (%d rows)", n)
	}
}

// The trail describing a person outlives their account.
//
// core.audit_events carries subject_id with NO foreign key to core.users,
// deliberately. That is what makes real deletion possible at all: if the trail
// cascaded, deleting an account would erase the record of what was done with it,
// and the only way to keep the record would be a soft delete -- the thing
// ADR-005 refuses.
func TestDeletingAUserKeepsTheAuditTrail(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete, "/admin/users/"+userID, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete gave %d: %s", rec.Code, rec.Body.String())
	}

	var n int
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM core.audit_events
		 WHERE subject_id = $1::uuid AND event_type = 'admin.user_deleted'`,
		userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("found %d admin.user_deleted events for the deleted user, want "+
			"1. Either the event was never written, or it cascaded away with "+
			"the account -- and the second would mean deletion erases its own "+
			"record.", n)
	}
}

// A second delete is a 404, not a 500 or a cheerful 200.
//
// The full lifecycle matters here because the handler reads the row before it
// deletes it: a caller retrying after a timeout must be told the account is
// already gone rather than receiving a success that implies it deleted
// something.
func TestDeletingAUserTwiceIsNotFound(t *testing.T) {
	s, _ := newTestServer(t)
	userID := newDriftUser(t, s)

	for i, want := range []int{http.StatusOK, http.StatusNotFound} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete, "/admin/users/"+userID, "", ""))
		if rec.Code != want {
			t.Fatalf("delete %d gave %d, want %d: %s", i+1, rec.Code, want, rec.Body.String())
		}
	}
}
