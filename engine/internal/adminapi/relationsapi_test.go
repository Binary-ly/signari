package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// An application keeps its own relations with a token that can do that and nothing else
// (11.01). It grants, and the next decision comes out the other way; it reads them back
// page by page while it goes on writing; and the token that does this reaches no other
// setting of the organisation, where organizations:write was the only way in.
func TestAnApplicationKeepsItsOwnRelations(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org
	if rec := call(t, s, http.MethodPut, base+"/authorization-model", testToken,
		map[string]string{"source": driftModel}); rec.Code != http.StatusOK {
		t.Fatalf("storing the model: %d %s", rec.Code, rec.Body)
	}

	n := time.Now().UnixNano()
	writer := mintToken(t, s, fmt.Sprintf("pep-%d", n), org, []string{ScopeRelationsWrite}, nil)
	reader := mintToken(t, s, fmt.Sprintf("reader-%d", n), org, []string{ScopeRelationsRead}, nil)
	operator := mintToken(t, s, fmt.Sprintf("op-%d", n), org, []string{ScopeOrganizationsWrite}, nil)

	grant := func(token, subject, object string) *httptest.ResponseRecorder {
		t.Helper()
		return call(t, s, http.MethodPut, base+"/relations", token,
			map[string]string{"subject": subject, "relation": "owner", "object": object})
	}
	explain := func() bool {
		t.Helper()
		rec := call(t, s, http.MethodGet, base+"/authorization/explain?subject=user:pep-person&action=read&object=document:1",
			testToken, nil)
		var out struct {
			Allowed bool `json:"allowed"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("explain: %d %s", rec.Code, rec.Body)
		}
		return out.Allowed
	}
	if explain() {
		t.Fatal("allowed before anything was granted")
	}
	if rec := grant(writer, "user:pep-person", "document:1"); rec.Code != http.StatusOK {
		t.Fatalf("a relations:write token granting: %d %s", rec.Code, rec.Body)
	}
	if !explain() {
		t.Error("the grant did not turn the decision")
	}

	// That token reaches relations and stops there.
	for _, c := range []struct{ method, path string }{
		{http.MethodPut, base + "/authorization-model"},
		{http.MethodGet, base + "/authorization-model"},
		{http.MethodPost, base + "/outposts"},
		{http.MethodPut, base + "/scopes"},
		{http.MethodPost, "/admin/users"},
	} {
		if rec := call(t, s, c.method, c.path, writer, json.RawMessage(`{}`)); rec.Code != http.StatusForbidden {
			t.Errorf("relations:write at %s %s: %d, want 403", c.method, c.path, rec.Code)
		}
	}
	if rec := grant(reader, "user:someone", "document:1"); rec.Code != http.StatusForbidden {
		t.Errorf("relations:read granting: %d, want 403", rec.Code)
	}
	if rec := call(t, s, http.MethodGet, base+"/relations", writer, nil); rec.Code != http.StatusOK {
		t.Errorf("relations:write reading: %d", rec.Code)
	}
	// Nobody who could do this before has lost it.
	if rec := grant(operator, "user:op-person", "document:2"); rec.Code != http.StatusOK {
		t.Errorf("organizations:write granting: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, http.MethodGet, base+"/relations", operator, nil); rec.Code != http.StatusOK {
		t.Errorf("organizations:write reading: %d", rec.Code)
	}
	if rec := call(t, s, http.MethodDelete, base+"/relations?"+url.Values{"subject": {"user:op-person"},
		"relation": {"owner"}, "object": {"document:2"}}.Encode(), writer, nil); rec.Code != http.StatusOK {
		t.Errorf("relations:write revoking: %d %s", rec.Code, rec.Body)
	}

	// Two more, and one that has lapsed, which is not a live relation.
	for i := 3; i <= 5; i++ {
		if rec := grant(writer, fmt.Sprintf("user:p%d", i), fmt.Sprintf("document:%d", i)); rec.Code != http.StatusOK {
			t.Fatal(rec.Body)
		}
	}
	if _, err := s.db.Exec(ctx, `UPDATE core.relations SET expires_at = now() - interval '1 minute'
		WHERE org_id = $1::uuid AND object_id = '5'`, org); err != nil {
		t.Fatal(err)
	}
	type page struct {
		Relations []struct {
			Subject string `json:"subject"`
			Object  string `json:"object"`
		} `json:"relations"`
		Next string `json:"next_cursor"`
	}
	read := func(query string) page {
		t.Helper()
		rec := call(t, s, http.MethodGet, base+"/relations?"+query, reader, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("?%s gave %d %s", query, rec.Code, rec.Body)
		}
		var p page
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	first := read("limit=2")
	if len(first.Relations) != 2 || first.Next == "" || first.Relations[0].Object != "document:1" {
		t.Fatalf("the first page: %+v", first)
	}
	// Written while the reader is between pages: it comes after, and nothing shifts.
	if rec := grant(writer, "user:p6", "document:6"); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	second := read("limit=2&cursor=" + first.Next)
	if len(second.Relations) != 2 || second.Relations[0].Object != "document:4" ||
		second.Relations[1].Object != "document:6" || second.Next != "" {
		t.Errorf("the second page: %+v; want the last two with nothing after them", second)
	}
	// A page that ends exactly at the end does not promise another, and one short of it does.
	if exact := read("limit=4"); exact.Next != "" || len(exact.Relations) != 4 {
		t.Errorf("a page holding everything: %+v", exact)
	}
	if short := read("limit=3"); short.Next == "" || len(short.Relations) != 3 {
		t.Errorf("a page one short: %+v", short)
	}

	if got := read("subject=user:p4"); len(got.Relations) != 1 || got.Relations[0].Object != "document:4" {
		t.Errorf("by subject: %+v", got)
	}
	if got := read("object=document:3"); len(got.Relations) != 1 || got.Relations[0].Subject != "user:p3" {
		t.Errorf("by object: %+v", got)
	}
	if got := read("relation=viewer"); len(got.Relations) != 0 {
		t.Errorf("by a relation nobody holds: %+v", got)
	}
	for _, bad := range []string{"subject=nocolon", "object=nocolon", "cursor=x", "cursor=-1"} {
		if rec := call(t, s, http.MethodGet, base+"/relations?"+bad, reader, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("?%s gave %d, want 400", bad, rec.Code)
		}
	}

	// Another organisation's token sees none of it.
	other := newDriftMigrationOrg(t, s, false)
	stranger := mintToken(t, s, fmt.Sprintf("stranger-%d", n), other, []string{ScopeRelationsWrite}, nil)
	if rec := call(t, s, http.MethodGet, base+"/relations", stranger, nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation's token reading: %d", rec.Code)
	}
	if rows, _, err := store.PageRelations(ctx, s.db, other, store.RelationFilter{}, 0, 10); err != nil || len(rows) != 0 {
		t.Errorf("another organisation's page: %v, %v", rows, err)
	}
}

// organizations:write satisfies relations:read through relations:write, and the chain runs
// one way: nothing reads its way up to a write.
func TestAScopeIsFollowedToWhatSatisfiesIt(t *testing.T) {
	for _, c := range []struct {
		holds string
		asked string
		want  bool
	}{
		{ScopeOrganizationsWrite, ScopeRelationsRead, true},
		{ScopeOrganizationsWrite, ScopeRelationsWrite, true},
		{ScopeRelationsWrite, ScopeRelationsRead, true},
		{ScopeRelationsRead, ScopeRelationsWrite, false},
		{ScopeRelationsWrite, ScopeOrganizationsWrite, false},
		{ScopeRelationsRead, ScopeOrganizationsWrite, false},
		{ScopeUsersWrite, ScopeUsersRead, true},
		{ScopeUsersRead, ScopeUsersWrite, false},
		{ScopeAll, ScopeRelationsWrite, true},
	} {
		p := Principal{Scopes: []string{c.holds}}
		if got := p.Can(c.asked); got != c.want {
			t.Errorf("%s asked for %s: %v", c.holds, c.asked, got)
		}
	}
}
