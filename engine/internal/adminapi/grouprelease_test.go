package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"signari.dev/engine/internal/store"
)

// Which groups an application is told of is decided through the Admin API as
// `signari group release` decides it (6.07), and is what the groups claim then
// carries: nothing before, the named group after, nothing again once stopped.
func TestAGroupReleaseDecidesWhatTheGroupsClaimCarries(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	client := newPreconditionClient(t, s)
	groupID := newDriftGroup(t, s)
	person := newDriftUser(t, s)
	var group string
	if err := s.db.QueryRow(ctx, `SELECT name FROM core.groups WHERE id = $1::uuid`, groupID).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT id, $2::uuid, org_id FROM core.groups WHERE id = $1::uuid`, groupID, person); err != nil {
		t.Fatal(err)
	}
	path := "/admin/clients/" + client + "/group-release"
	claim := func() []string {
		t.Helper()
		got, err := store.GroupsForUser(ctx, s.db, person, client)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	read := func() groupReleaseView {
		t.Helper()
		rec := call(t, s, http.MethodGet, path, testToken, nil)
		var v groupReleaseView
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("reading the release: %d %s", rec.Code, rec.Body.String())
		}
		return v
	}

	if v := read(); v.Released || len(claim()) != 0 {
		t.Fatalf("a new application is told of %v (%+v)", claim(), v)
	}
	var out map[string]any
	rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"only_groups": []string{group, "no-such-group"}})
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusBadRequest || out["error"] != "unknown_group" {
		t.Errorf("a release naming a group nobody has answered %d %v", rec.Code, out)
	}
	if read().Released {
		t.Error("a refused release was recorded")
	}

	if rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"only_groups": []string{group}}); rec.Code != http.StatusOK {
		t.Fatalf("releasing the group: %d %s", rec.Code, rec.Body.String())
	}
	if v := read(); !v.Released || !slices.Equal(v.OnlyGroups, []string{group}) {
		t.Errorf("after releasing the group the read was %+v", v)
	}
	if got := claim(); !slices.Equal(got, []string{group}) {
		t.Errorf("after releasing the group the claim carries %v", got)
	}

	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("stopping the release: %d %s", rec.Code, rec.Body.String())
	}
	if v := read(); v.Released || len(claim()) != 0 {
		t.Errorf("after stopping, the application is told of %v (%+v)", claim(), v)
	}
	if rec := call(t, s, http.MethodDelete, path, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("stopping a release that was stopped answered %d", rec.Code)
	}

	// A token narrowed to another group releases neither this one nor every
	// group, and is told of this one as of a group nobody has.
	other := newDriftGroup(t, s)
	narrowed, _, err := NewToken(ctx, s.db, "release-narrowed-"+other, anyOrgID(t, s),
		[]string{ScopeClientsWrite, ScopeClientsRead}, nil, nil, []string{other})
	if err != nil {
		t.Fatal(err)
	}
	rec = call(t, s, http.MethodPut, path, narrowed, map[string]any{"only_groups": []string{group}})
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusBadRequest || out["error"] != "unknown_group" {
		t.Errorf("a token narrowed to another group releasing this one answered %d %v", rec.Code, out)
	}
	rec = call(t, s, http.MethodPut, path, narrowed, map[string]any{"only_groups": []string{}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("a narrowed token releasing every group answered %d", rec.Code)
	}
	if read().Released {
		t.Error("a narrowed token's refused release was recorded")
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE client_id = $1
		AND event_type IN ('admin.group_release_set', 'admin.group_release_removed')`, client).Scan(&n); err != nil || n != 2 {
		t.Errorf("the release and its end were recorded %d times (%v), want 2", n, err)
	}
}
