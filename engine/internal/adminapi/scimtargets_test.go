package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"signari.dev/engine/internal/provision"
)

// fakeTarget is the smallest SCIM server a sync and a group's provisioning
// need: users created, groups created, read, patched and deleted.
type fakeTarget struct {
	*httptest.Server
	mu      sync.Mutex
	users   map[string]bool
	groups  map[string]map[string]bool
	next    int
	deleted []string
}

func newFakeTarget(t *testing.T) *fakeTarget {
	t.Helper()
	f := &fakeTarget{users: map[string]bool{}, groups: map[string]map[string]bool{}}
	answer := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /Users", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.next++
		id := fmt.Sprintf("u-%d", f.next)
		f.users[id] = true
		answer(w, http.StatusCreated, map[string]any{"id": id})
	})
	mux.HandleFunc("PATCH /Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		answer(w, http.StatusOK, map[string]any{"id": r.PathValue("id")})
	})
	mux.HandleFunc("POST /Groups", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.next++
		id := fmt.Sprintf("g-%d", f.next)
		f.groups[id] = map[string]bool{}
		answer(w, http.StatusCreated, map[string]any{"id": id})
	})
	mux.HandleFunc("GET /Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		members, ok := f.groups[r.PathValue("id")]
		if !ok {
			answer(w, http.StatusNotFound, map[string]any{"detail": "no such group"})
			return
		}
		list := []map[string]string{}
		for m := range members {
			list = append(list, map[string]string{"value": m})
		}
		answer(w, http.StatusOK, map[string]any{"id": r.PathValue("id"), "members": list})
	})
	mux.HandleFunc("PATCH /Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var p struct {
			Operations []struct {
				Op    string `json:"op"`
				Value []struct {
					Value string `json:"value"`
				} `json:"value"`
			} `json:"Operations"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		for _, op := range p.Operations {
			for _, v := range op.Value {
				if strings.EqualFold(op.Op, "add") {
					f.groups[r.PathValue("id")][v.Value] = true
				}
			}
		}
		answer(w, http.StatusOK, nil)
	})
	mux.HandleFunc("DELETE /Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.groups, r.PathValue("id"))
		f.deleted = append(f.deleted, r.PathValue("id"))
		answer(w, http.StatusNoContent, nil)
	})
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

// A provisioning target is registered, scoped, synced, given a group and
// rid of it through the Admin API as `signari scim` does it (6.07): the token
// sealed and never read back, a preview that sends nothing, and the accounts
// and memberships an applied sync makes really made at the target.
func TestAProvisioningTargetIsRunThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, fake := newDriftSCIMTarget(t, s, false)
	base := "/admin/organizations/" + org + "/scim-targets"
	errorOf := func(method, path string, body any, want int) string {
		t.Helper()
		rec := call(t, s, method, path, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d, want %d: %s", method, path, body, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}

	// Registration's refusals, and the token never read back.
	for _, bad := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"slug": "x", "base_url": "http://scim.example.test/v2", "token": "t"}, "invalid_target"},
		{map[string]any{"slug": "x", "base_url": "https://scim.example.test/v2"}, "invalid_target"},
		{map[string]any{"slug": "x", "kind": "google", "credentials": map[string]any{}}, "invalid_target"},
		{map[string]any{"slug": "x", "base_url": "https://10.0.0.9/v2", "token": "t"}, "invalid_url"},
	} {
		if e := errorOf(http.MethodPost, base, bad.body, http.StatusBadRequest); e != bad.want {
			t.Errorf("%v answered %q, want %q", bad.body, e, bad.want)
		}
	}
	const secret = "a-token-slack-issued"
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"slug": "slack",
		"base_url": "https://scim.example.test/v2", "token": secret}); rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(http.MethodPost, base, map[string]any{"slug": "slack", "base_url": "https://scim.example.test/v2",
		"token": secret}, http.StatusConflict); e != "already_exists" {
		t.Errorf("a second target of the slug answered %q", e)
	}
	list := call(t, s, http.MethodGet, base, testToken, nil)
	if strings.Contains(list.Body.String(), secret) || !strings.Contains(list.Body.String(), `"slug":"slack"`) {
		t.Errorf("the targets read %s", list.Body.String())
	}

	// A person in the group, so a sync has an account to make and a member
	// to add.
	var userID string
	if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, username, email, status, user_handle)
		VALUES ($1::uuid, 'ada', 'ada@example.test', 'active', decode(md5(random()::text) || md5(random()::text) ||
		        md5(random()::text) || md5(random()::text), 'hex'))
		RETURNING id::text`, org).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT id, $2::uuid, org_id FROM core.groups WHERE org_id = $1::uuid AND name = 'drift-group'`,
		org, userID); err != nil {
		t.Fatal(err)
	}
	group := base + "/drift/groups/drift-group"
	if rec := call(t, s, http.MethodPut, group, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("provisioning the group: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(http.MethodPut, group, nil, http.StatusConflict); e != "already_provisioned" {
		t.Errorf("provisioning it again answered %q", e)
	}

	sync := base + "/drift/sync"
	rec := call(t, s, http.MethodPost, sync, testToken, map[string]any{"apply": false})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"created":1`) || len(fake.users) != 0 {
		t.Fatalf("previewing: %d %s, %d accounts made", rec.Code, rec.Body.String(), len(fake.users))
	}
	rec = call(t, s, http.MethodPost, sync, testToken, map[string]any{"apply": true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"created":1`) || len(fake.users) != 1 {
		t.Fatalf("applying: %d %s, %d accounts made", rec.Code, rec.Body.String(), len(fake.users))
	}
	var remote string
	if err := s.db.QueryRow(ctx, `SELECT remote_id FROM core.scim_links WHERE user_id = $1::uuid`, userID).Scan(&remote); err != nil {
		t.Fatalf("the account made was not linked: %v", err)
	}
	// Members reconcile on the pass after the account exists.
	if rec := call(t, s, http.MethodPost, sync, testToken, map[string]any{"apply": true}); rec.Code != http.StatusOK {
		t.Fatalf("the second pass: %d %s", rec.Code, rec.Body.String())
	}
	member := false
	for _, members := range fake.groups {
		member = member || members[remote]
	}
	if !member {
		t.Errorf("the group at the target has members %v, want %s", fake.groups, remote)
	}

	if rec := call(t, s, http.MethodDelete, group, testToken, nil); rec.Code != http.StatusOK || len(fake.deleted) != 1 {
		t.Fatalf("deprovisioning: %d %s, deleted %v", rec.Code, rec.Body.String(), fake.deleted)
	}
	if e := errorOf(http.MethodDelete, group, nil, http.StatusNotFound); e != "group_not_provisioned" {
		t.Errorf("deprovisioning it again answered %q", e)
	}

	// Scoped to a group that does not exist, then disabled.
	if e := errorOf(http.MethodPatch, base+"/drift", map[string]any{"scope_group": "nobody"}, http.StatusNotFound); e != "group_not_found" {
		t.Errorf("an unknown scope group answered %q", e)
	}
	if rec := call(t, s, http.MethodPatch, base+"/drift", testToken, map[string]any{"enabled": false,
		"scope_group": "drift-group"}); rec.Code != http.StatusOK {
		t.Fatalf("disabling and scoping: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(http.MethodPost, sync, map[string]any{"apply": true}, http.StatusConflict); e != "target_unavailable" {
		t.Errorf("syncing a disabled target answered %q", e)
	}
	if e := errorOf(http.MethodPost, base+"/elsewhere/sync", map[string]any{"apply": true}, http.StatusNotFound); e != "target_not_found" {
		t.Errorf("syncing an unknown target answered %q", e)
	}
}

// A target in dry-run mode records without sending, so a group cannot be
// made there: refused, rather than reported made.
func TestAGroupIsNotProvisionedToADryRunTarget(t *testing.T) {
	s, _ := newTestServer(t)
	org, fake := newDriftSCIMTarget(t, s, true)
	rec := call(t, s, http.MethodPut, "/admin/organizations/"+org+"/scim-targets/drift/groups/drift-group", testToken, nil)
	if rec.Code != http.StatusConflict || len(fake.groups) != 0 {
		t.Errorf("a dry-run target answered %d %s and holds %d groups", rec.Code, rec.Body.String(), len(fake.groups))
	}
}

// newDriftSCIMTarget is an organisation of the test's own with a SCIM
// target pointed at a fake it serves, which the server calls through its
// client, and a group named drift-group.
func newDriftSCIMTarget(t *testing.T, s *Server, dryRun bool) (org string, fake *fakeTarget) {
	t.Helper()
	ctx := context.Background()
	org = newDriftMigrationOrg(t, s, false)
	fake = newFakeTarget(t)
	s.targetClient = func() (*http.Client, error) { return fake.Client(), nil }
	if err := provision.AddTarget(ctx, s.db, s.root, org, provision.TargetSpec{Slug: "drift", BaseURL: fake.URL,
		Token: "a-token-the-target-issued", DryRun: dryRun}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'drift-group', 'Drift group')`, org); err != nil {
		t.Fatal(err)
	}
	return org, fake
}
