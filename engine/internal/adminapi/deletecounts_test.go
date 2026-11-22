package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A delete reports what it revoked, in its response and in its audit record.
//
// Both used to count core.access_tokens, a table nothing ever wrote, so every
// user and client delete said `tokens_revoked: 0` -- including the ones that
// ended a dozen live refresh tokens. A count that is always zero reads as
// "nothing was outstanding", which is the reassuring answer and the wrong one.
//
// Five families, so each half of the definition is pinned: two that could
// still be redeemed (one held by a session, which ending the session revokes
// before the cascade, and one held by none), and three that were already over
// -- revoked, expired, and spent with no successor.
func TestDeletingAUserCountsTheRefreshFamiliesItEnds(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)
	sid := newDriftSession(t, s, userID)
	clientID := newPreconditionClient(t, s)

	newFamily(t, s, clientID, userID, sid, "live")
	newFamily(t, s, clientID, userID, "", "live")
	newFamily(t, s, clientID, userID, "", "revoked")
	newFamily(t, s, clientID, userID, "", "expired")
	newFamily(t, s, clientID, userID, "", "consumed")

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete, "/admin/users/"+userID, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete gave %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Families *int `json:"refresh_families_revoked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Families == nil || *body.Families != 2 {
		t.Errorf("the response said refresh_families_revoked = %v, want 2 "+
			"(the session's family and the sessionless one): %s",
			deref(body.Families), rec.Body.String())
	}

	var audited int
	if err := s.db.QueryRow(ctx, `
		SELECT (detail->>'refresh_families_revoked')::int FROM core.audit_events
		WHERE event_type = 'admin.user_deleted' AND subject_id = $1::uuid`,
		userID).Scan(&audited); err != nil {
		t.Fatalf("reading the audit record: %v", err)
	}
	if audited != 2 {
		t.Errorf("the audit record says %d families were revoked, want 2", audited)
	}
}

// The same for a client: its families end with it, whoever they belonged to.
func TestDeletingAClientCountsTheRefreshFamiliesItEnds(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)
	sid := newDriftSession(t, s, userID)
	clientID := newPreconditionClient(t, s)

	newFamily(t, s, clientID, userID, sid, "live")
	newFamily(t, s, clientID, userID, "", "live")
	newFamily(t, s, clientID, userID, "", "revoked")
	// Another client's family, held by the same person, is not this delete's.
	other := newPreconditionClient(t, s)
	newFamily(t, s, other, userID, "", "live")

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete, "/admin/clients/"+clientID, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete gave %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Families *int `json:"refresh_families_revoked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Families == nil || *body.Families != 2 {
		t.Errorf("the response said refresh_families_revoked = %v, want 2: %s",
			deref(body.Families), rec.Body.String())
	}

	var audited int
	if err := s.db.QueryRow(ctx, `
		SELECT (detail->>'refresh_families_revoked')::int FROM core.audit_events
		WHERE event_type = 'admin.client_deleted' AND client_id = $1`,
		clientID).Scan(&audited); err != nil {
		t.Fatalf("reading the audit record: %v", err)
	}
	if audited != 2 {
		t.Errorf("the audit record says %d families were revoked, want 2", audited)
	}
}

// newFamily gives a person a refresh token family under a client, with one
// token in the named state. The rows go with the user or the client.
func newFamily(t *testing.T, s *Server, clientID, userID, sid, state string) {
	t.Helper()
	ctx := context.Background()
	var familyID string
	if err := s.db.QueryRow(ctx, `
		INSERT INTO core.refresh_token_families (org_id, client_id, user_id, sid, revoked_at)
		SELECT u.org_id, $1, u.id, NULLIF($3, ''),
		       CASE WHEN $4 = 'revoked' THEN now() END
		FROM core.users u WHERE u.id = $2::uuid
		RETURNING id::text`, clientID, userID, sid, state).Scan(&familyID); err != nil {
		t.Fatalf("creating a %s family: %v", state, err)
	}
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.refresh_tokens (token_hash, family_id, scopes, expires_at, consumed_at)
		VALUES (sha256(convert_to($1::text || clock_timestamp()::text, 'UTF8')), $1::uuid,
		        ARRAY['openid'],
		        CASE WHEN $2 = 'expired' THEN now() - interval '1 minute'
		             ELSE now() + interval '1 hour' END,
		        CASE WHEN $2 = 'consumed' THEN now() END)`,
		familyID, state); err != nil {
		t.Fatalf("creating the %s family's token: %v", state, err)
	}
}

func deref(n *int) any {
	if n == nil {
		return "absent"
	}
	return *n
}
