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

// The restriction matches client ids exactly, because they are case-sensitive
// keys: `app` and `APP` are two clients. This test once asserted the opposite,
// and a token for one could read and disable the other.
func TestClientRestrictionMatchesExactly(t *testing.T) {
	p := &Principal{ClientIDs: []string{"Wiki-App"}}
	if err := p.MayActOnClient("Wiki-App"); err != nil {
		t.Errorf("the listed client was refused: %v", err)
	}
	if err := p.MayActOnClient("wiki-app"); err == nil {
		t.Error("a token for Wiki-App may act on the different client wiki-app")
	}
	// Group ids are uuids, compared canonically.
	g := &Principal{GroupIDs: []string{"2194F4E3-4348-4A96-B104-AE5C7E19DA7D"}}
	if err := g.MayActOnGroup("2194f4e3-4348-4a96-b104-ae5c7e19da7d"); err != nil {
		t.Errorf("a group id in upper case refused its own group: %v", err)
	}
}

// End to end: a token restricted to one client cannot read, disable or list
// the client whose id differs only in case.
func TestARestrictedTokenCannotReachAClientThatDiffersOnlyInCase(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := anyOrgID(t, s)
	suffix := fmt.Sprint(time.Now().UnixNano())
	lower, upper := "case-app-"+suffix, "CASE-APP-"+suffix
	for _, id := range []string{lower, upper} {
		if _, err := s.db.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash)
			VALUES ($1, $2::uuid, $1, 'confidential', 'x')`, id, org); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = ANY($1)`,
			[]string{lower, upper})
	})
	secret, _, err := NewToken(ctx, s.db, "case test "+suffix, org, []string{ScopeClientsWrite}, nil,
		[]string{lower}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(secret))
	})

	if rec := call(t, s, http.MethodGet, "/admin/clients/"+upper, secret, nil); rec.Code == http.StatusOK {
		t.Errorf("a token for %s read %s: %d", lower, upper, rec.Code)
	}
	if rec := call(t, s, http.MethodPatch, "/admin/clients/"+upper, secret,
		map[string]any{"enabled": false}); rec.Code == http.StatusOK {
		t.Errorf("a token for %s disabled %s: %d", lower, upper, rec.Code)
	}
	var enabled bool
	if err := s.db.QueryRow(ctx, `SELECT enabled FROM core.clients WHERE client_id = $1`, upper).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("%s is no longer enabled (%v, %v)", upper, enabled, err)
	}
	rec := call(t, s, http.MethodGet, "/admin/clients?org_id="+org, secret, nil)
	if strings.Contains(rec.Body.String(), upper) || !strings.Contains(rec.Body.String(), lower) {
		t.Errorf("the restricted list did not show exactly %s: %s", lower, rec.Body.String())
	}
	if rec := call(t, s, http.MethodGet, "/admin/clients/"+lower, secret, nil); rec.Code != http.StatusOK {
		t.Errorf("the token could not read its own client: %d", rec.Code)
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
