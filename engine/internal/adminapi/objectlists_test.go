package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A token narrowed to named objects once listed every object of that kind in
// its organisation and could create new ones nobody had narrowed it to.

// narrowedToken mints a real token restricted to the given clients or groups.
func narrowedToken(t *testing.T, s *Server, orgID string, scopes, clientIDs, groupIDs []string) string {
	t.Helper()
	secret, _, err := NewToken(context.Background(), s.db, "narrowed", orgID, scopes, nil, clientIDs, groupIDs)
	if err != nil {
		t.Fatalf("minting a narrowed token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(secret))
	})
	return secret
}

// listed pages through a list endpoint and returns every value of key.
func listed(t *testing.T, s *Server, path, token, field, key string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	cursor := ""
	for range 1000 {
		rec := call(t, s, http.MethodGet, path+"?limit=200&cursor="+cursor, token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s gave %d %s", path, rec.Code, rec.Body.String())
		}
		var page map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		var items []map[string]any
		_ = json.Unmarshal(page[field], &items)
		for _, it := range items {
			if v, ok := it[key].(string); ok {
				out[v] = true
			}
		}
		var next string
		_ = json.Unmarshal(page["next_cursor"], &next)
		if next == "" {
			return out
		}
		cursor = next
	}
	t.Fatal("paging never ended")
	return nil
}

func TestANarrowedTokenListsOnlyItsOwnClients(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	mine, theirs := newPreconditionClient(t, s), newPreconditionClient(t, s)

	narrowed := narrowedToken(t, s, org, []string{ScopeClientsRead}, []string{mine}, nil)
	got := listed(t, s, "/admin/clients", narrowed, "clients", "client_id")
	if !got[mine] || got[theirs] || len(got) != 1 {
		t.Fatalf("a token narrowed to %s listed %v", mine, got)
	}

	whole := narrowedToken(t, s, org, []string{ScopeClientsRead}, nil, nil)
	if got := listed(t, s, "/admin/clients", whole, "clients", "client_id"); !got[mine] || !got[theirs] {
		t.Fatal("an unrestricted token no longer lists every client in its organisation")
	}
}

func TestANarrowedTokenListsOnlyItsOwnGroups(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	mine, theirs := newDriftGroup(t, s), newDriftGroup(t, s)

	narrowed := narrowedToken(t, s, org, []string{ScopeGroupsRead}, nil, []string{mine})
	got := listed(t, s, "/admin/groups", narrowed, "groups", "id")
	if !got[mine] || got[theirs] || len(got) != 1 {
		t.Fatalf("a token narrowed to %s listed %v", mine, got)
	}
}

// An empty allow-list lists nothing. pgx must send it as '{}' rather than
// NULL, or the filter reads it as "every object".
func TestAnEmptyAllowListListsNothing(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	newPreconditionClient(t, s)

	p := &Principal{OrgID: org, Scopes: []string{ScopeClientsRead}, ClientIDs: []string{}}
	r := httptest.NewRequest(http.MethodGet, "/admin/clients", nil).
		WithContext(withPrincipal(context.Background(), p))
	rec := httptest.NewRecorder()
	s.listClients(rec, r)
	var page struct {
		Clients []clientSummary `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(page.Clients) != 0 {
		t.Fatalf("an empty allow-list listed %d clients", len(page.Clients))
	}
}

func TestANarrowedTokenCannotCreateWhatItIsNarrowedOn(t *testing.T) {
	s, _ := newTestServer(t)
	org := anyOrgID(t, s)
	mine := newPreconditionClient(t, s)
	group := newDriftGroup(t, s)

	clientsOnly := narrowedToken(t, s, org,
		[]string{ScopeClientsWrite, ScopeGroupsWrite}, []string{mine}, nil)
	rec := call(t, s, http.MethodPost, "/admin/clients", clientsOnly, map[string]any{
		"client_id": "narrowed-new", "org_id": org, "display_name": "x",
		"redirect_uris": []string{"https://app.example.test/cb"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a token narrowed to one client created another: %d %s", rec.Code, rec.Body.String())
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = 'narrowed-new'`)
	})

	// Narrowed on clients, not on groups: it may still create a group.
	rec = call(t, s, http.MethodPost, "/admin/groups", clientsOnly, map[string]any{
		"org_id": org, "name": "narrowed-new-group",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("a token narrowed only on clients could not create a group: %d %s", rec.Code, rec.Body.String())
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.groups WHERE org_id = $1::uuid AND name = 'narrowed-new-group'`, org)
	})

	groupsOnly := narrowedToken(t, s, org, []string{ScopeGroupsWrite}, nil, []string{group})
	rec = call(t, s, http.MethodPost, "/admin/groups", groupsOnly, map[string]any{
		"org_id": org, "name": "narrowed-other-group",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a token narrowed to one group created another: %d %s", rec.Code, rec.Body.String())
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.groups WHERE org_id = $1::uuid AND name = 'narrowed-other-group'`, org)
	})
}
