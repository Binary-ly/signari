package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A token narrowed to named objects may act on those and no others.
//
// Least privilege was available at two granularities before this — tenant and
// capability — and not at the one integrations actually need. A CI job that
// deploys one application needed a credential able to disable the payroll
// system.

func TestARestrictedTokenReachesOnlyItsOwnClient(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	mine := newPreconditionClient(t, s)
	theirs := newPreconditionClient(t, s)

	scoped := &Principal{
		OrgID:     anyOrgID(t, s),
		Scopes:    []string{ScopeClientsWrite},
		ClientIDs: []string{mine},
	}

	for _, c := range []struct {
		clientID string
		want     int
	}{
		{mine, http.StatusOK},
		{theirs, http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodGet, "/admin/clients/"+c.clientID, nil).
			WithContext(withPrincipal(ctx, scoped))
		r.SetPathValue("clientID", c.clientID)

		rec := httptest.NewRecorder()
		s.getClient(rec, r)
		if rec.Code != c.want {
			t.Errorf("client %q gave %d, want %d: %s",
				c.clientID, rec.Code, c.want, rec.Body.String())
		}
	}
}

// nil means unrestricted, which is what every token issued before this carries.
func TestATokenWithNoRestrictionReachesEveryClient(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	clientID := newPreconditionClient(t, s)

	unrestricted := &Principal{OrgID: anyOrgID(t, s), Scopes: []string{ScopeClientsWrite}}
	r := httptest.NewRequest(http.MethodGet, "/admin/clients/"+clientID, nil).
		WithContext(withPrincipal(ctx, unrestricted))
	r.SetPathValue("clientID", clientID)

	rec := httptest.NewRecorder()
	s.getClient(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("an unrestricted token was refused: %d %s. Every token issued "+
			"before this feature existed carries nil and must be unchanged.",
			rec.Code, rec.Body.String())
	}
}

// An EMPTY list means nothing, not everything.
//
// The direction that matters. A `'{}'` reading as unrestricted is how a
// narrowing feature becomes a widening one: somebody clears the list intending
// to revoke access and grants all of it instead.
func TestAnEmptyRestrictionReachesNothing(t *testing.T) {
	p := &Principal{ClientIDs: []string{}, GroupIDs: []string{}}

	if err := p.MayActOnClient("anything"); err == nil {
		t.Error("an empty client list permitted a client. Empty must mean none, " +
			"or clearing a list to revoke access grants all of it instead.")
	}
	if err := p.MayActOnGroup("anything"); err == nil {
		t.Error("an empty group list permitted a group")
	}

	// And nil, the other value, means the opposite.
	unrestricted := &Principal{}
	if err := unrestricted.MayActOnClient("anything"); err != nil {
		t.Errorf("a nil client list refused a client: %v", err)
	}
}

// The restriction is case-insensitive on client ids, matching MayActOn.
func TestClientRestrictionMatchesCaseInsensitively(t *testing.T) {
	p := &Principal{ClientIDs: []string{"Wiki-App"}}
	if err := p.MayActOnClient("wiki-app"); err != nil {
		t.Errorf("case difference refused a listed client: %v", err)
	}
}

// A restricted token cannot add members to a group it does not hold.
func TestARestrictedTokenCannotEditAnotherGroupsMembership(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	theirs := newDriftGroup(t, s)

	scoped := &Principal{
		OrgID:    anyOrgID(t, s),
		Scopes:   []string{ScopeGroupsWrite},
		GroupIDs: []string{"00000000-0000-4000-8000-000000000001"},
	}
	r := httptest.NewRequest(http.MethodPut,
		"/admin/groups/"+theirs+"/members/some-user", nil).
		WithContext(withPrincipal(ctx, scoped))
	r.SetPathValue("groupID", theirs)
	r.SetPathValue("userID", "00000000-0000-4000-8000-000000000002")

	rec := httptest.NewRecorder()
	s.addGroupMember(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("gave %d, want 403: %s. Adding somebody to a group grants them "+
			"whatever that group reaches.", rec.Code, rec.Body.String())
	}
}
