package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"signari.dev/engine/internal/provision"
)

// fakeGraph is Microsoft Graph and its token endpoint, reached through rewritten
// requests, since the real hosts are written into the client.
type fakeGraph struct {
	*httptest.Server
	mu      sync.Mutex
	users   map[string]bool
	groups  map[string]map[string]bool
	created map[string]any
	next    int
}

type toFake struct{ to *url.URL }

func (r toFake) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host, out.Host = r.to.Scheme, r.to.Host, r.to.Host
	return http.DefaultTransport.RoundTrip(out)
}

func newFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()
	f := &fakeGraph{users: map[string]bool{}, groups: map[string]map[string]bool{}}
	answer := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant/oauth2/v2.0/token", func(w http.ResponseWriter, _ *http.Request) {
		answer(w, http.StatusOK, map[string]any{"access_token": "graph-token", "expires_in": 3600})
	})
	mux.HandleFunc("POST /v1.0/users", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.next++
		id := fmt.Sprintf("user-%d", f.next)
		f.users[id] = true
		answer(w, http.StatusCreated, map[string]string{"id": id})
	})
	mux.HandleFunc("POST /v1.0/groups", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if err := json.NewDecoder(r.Body).Decode(&f.created); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.next++
		id := fmt.Sprintf("group-%d", f.next)
		f.groups[id] = map[string]bool{}
		answer(w, http.StatusCreated, map[string]string{"id": id})
	})
	mux.HandleFunc("GET /v1.0/groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		value := []map[string]string{}
		for id := range f.groups[r.PathValue("id")] {
			value = append(value, map[string]string{"id": id})
		}
		answer(w, http.StatusOK, map[string]any{"value": value})
	})
	mux.HandleFunc("POST /v1.0/groups/{id}/members/$ref", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		ref := body["@odata.id"]
		const prefix = "https://graph.microsoft.com/v1.0/directoryObjects/"
		if !strings.HasPrefix(ref, prefix) {
			http.Error(w, "a reference is a directoryObjects URL, not "+ref, http.StatusBadRequest)
			return
		}
		f.groups[r.PathValue("id")][strings.TrimPrefix(ref, prefix)] = true
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /v1.0/groups/{id}/members/{member}/$ref", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.groups[r.PathValue("id")], r.PathValue("member"))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /v1.0/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.groups, r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// A group is made in a tenant, filled, followed and removed through the API, as a
// SCIM target's is. The fake refuses what Graph refuses, and it is a fake: nothing
// here has met a real tenant.
func TestAGroupIsProvisionedToEntraAndFollowed(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	graph := newFakeGraph(t)
	to, _ := url.Parse(graph.URL)
	s.targetClient = func() (*http.Client, error) { return &http.Client{Transport: toFake{to}}, nil }
	if err := provision.AddTarget(ctx, s.db, s.root, org, provision.TargetSpec{Kind: "entra", Slug: "tenant",
		Domain:      "corp.example",
		Credentials: []byte(`{"tenant_id":"tenant","client_id":"c","client_secret":"s"}`)}); err != nil {
		t.Fatal(err)
	}
	var group, ada string
	if err := s.db.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, 'platform-team', 'Platform team') RETURNING id::text`, org).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, username, email)
		VALUES ($1::uuid, sha256(convert_to($1::text, 'UTF8')), 'ada', 'ada@corp.example') RETURNING id::text`, org).Scan(&ada); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, ada) })
	if _, err := s.db.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, group, ada, org); err != nil {
		t.Fatal(err)
	}
	base := "/admin/organizations/" + org + "/scim-targets/tenant"
	sync := func() string {
		t.Helper()
		rec := call(t, s, http.MethodPost, base+"/sync", testToken, map[string]any{"apply": true})
		if rec.Code != http.StatusOK {
			t.Fatalf("syncing: %d %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	rec := call(t, s, http.MethodPut, base+"/groups/platform-team", testToken, nil)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("provisioning the group: %d %s", rec.Code, rec.Body.String())
	}
	if len(graph.groups) != 1 {
		t.Fatalf("the tenant holds %v", graph.groups)
	}
	if graph.created["mailEnabled"] != false || graph.created["securityEnabled"] != true ||
		graph.created["mailNickname"] != "platform-team" || graph.created["displayName"] != "Platform team" {
		t.Errorf("the group sent reads %v", graph.created)
	}
	var remote string
	for id := range graph.groups {
		remote = id
	}

	sync() // Creates the account, then fills the group.
	if len(graph.groups[remote]) != 1 {
		t.Fatalf("the group holds %v", graph.groups[remote])
	}

	if _, err := s.db.Exec(ctx, `DELETE FROM core.group_members WHERE group_id = $1::uuid`, group); err != nil {
		t.Fatal(err)
	}
	sync()
	if len(graph.groups[remote]) != 0 {
		t.Errorf("somebody who left the group here is still there: %v", graph.groups[remote])
	}

	if rec := call(t, s, http.MethodDelete, base+"/groups/platform-team", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("removing the group: %d %s", rec.Code, rec.Body.String())
	}
	if len(graph.groups) != 0 {
		t.Errorf("the tenant still holds %v", graph.groups)
	}
}
