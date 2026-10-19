package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Each source reports a person's groups when asked to (2.02), by a value
// nobody upstream can mint for an existing mapping: the group's object id in
// Entra, its address in Google, its DN in LDAP. None of them fetched a group
// before, so group reconciliation was built and fed by nothing.

func TestEntraReportsEveryGroupAPersonIsInWhenAsked(t *testing.T) {
	var groupCalls atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "graph-token"})
		case strings.HasSuffix(r.URL.Path, "/transitiveMemberOf/microsoft.graph.group"):
			groupCalls.Add(1)
			switch {
			case strings.Contains(r.URL.Path, "/users/u1/") && r.URL.Query().Get("$skiptoken") == "":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"value":           []map[string]any{{"id": "g-engineering"}},
					"@odata.nextLink": srv.URL + r.URL.Path + "?$skiptoken=2",
				})
			case strings.Contains(r.URL.Path, "/users/u1/"):
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "g-everyone"}}})
			case strings.Contains(r.URL.Path, "/users/u3/"):
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "denied"}})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
			}
		case r.URL.Path == "/v1.0/users":
			users := []map[string]any{graphUser("u1", "a@example.test", "", true), graphUser("u2", "b@example.test", "", true)}
			if r.URL.Query().Get("$filter") == "denied" {
				users = append(users, graphUser("u3", "c@example.test", "", true))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": users})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	src := entraSource(srv)
	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if groupCalls.Load() != 0 || got[0].Groups != nil {
		t.Errorf("without Groups the source asked %d time(s) and reported %v", groupCalls.Load(), got[0].Groups)
	}
	src.Groups = true
	got, err = src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got[0].Groups, []string{"g-engineering", "g-everyone"}) || len(got[1].Groups) != 0 || got[1].Groups == nil {
		t.Errorf("groups reported: %v and %v; want both pages for u1 and an empty list for u2", got[0].Groups, got[1].Groups)
	}
	src.Filter = "denied"
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "GroupMember.Read.All") {
		t.Errorf("a refused group read gave %v; want an error naming the permission, never a short list", err)
	}
}

func TestGoogleReportsEveryGroupAPersonIsInWhenAsked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-token", "expires_in": 3600})
		case r.URL.Path == "/admin/directory/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{
				{"id": "1", "primaryEmail": "a@example.test"}, {"id": "2", "primaryEmail": "b@example.test"},
			}})
		case r.URL.Path == "/admin/directory/v1/groups":
			if r.URL.Query().Get("userKey") == "1" && r.URL.Query().Get("pageToken") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"groups": []map[string]any{{"email": "eng@example.test"}}, "nextPageToken": "p2"})
				return
			}
			if r.URL.Query().Get("userKey") == "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{"groups": []map[string]any{{"email": "all@example.test"}}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	src := testSource(t, srv)
	src.Groups = true
	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got[0].Groups, []string{"eng@example.test", "all@example.test"}) || len(got[1].Groups) != 0 {
		t.Errorf("groups reported: %v and %v", got[0].Groups, got[1].Groups)
	}
}

// nestedLDAP answers the user search with users, and an in-chain search for a
// group with the people AD says are in it at any depth.
type nestedLDAP struct {
	fakeLDAP
	members map[string][]*ldap.Entry
	filters []string
}

func (f *nestedLDAP) SearchWithPaging(req *ldap.SearchRequest, pageSize uint32) (*ldap.SearchResult, error) {
	f.filters = append(f.filters, req.Filter)
	for group, entries := range f.members {
		if strings.Contains(req.Filter, "1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(group)) {
			return &ldap.SearchResult{Entries: entries}, nil
		}
	}
	return f.fakeLDAP.SearchWithPaging(req, pageSize)
}

// An Active Directory person in a group nested inside a mapped one is in the
// mapped one. memberOf lists only direct groups, so they read as outside it.
func TestActiveDirectoryResolvesNestedMembershipOfAMappedGroup(t *testing.T) {
	guid := func(b byte) string { return string([]byte{b, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) }
	user := func(name string, b byte, memberOf ...string) *ldap.Entry {
		return entry("cn="+name+",dc=example,dc=test", map[string][]string{
			"sAMAccountName": {name}, "mail": {name + "@example.test"}, "displayName": {name},
			"objectGUID": {guid(b)}, "userAccountControl": {"512"}, "memberOf": memberOf,
		})
	}
	const eng = "CN=Engineering,OU=Groups,DC=example,DC=test"
	const devs = "CN=Developers,OU=Groups,DC=example,DC=test"
	f := &nestedLDAP{
		fakeLDAP: fakeLDAP{entries: []*ldap.Entry{user("ada", 1, eng), user("bob", 2, devs), user("cy", 3)}},
		members: map[string][]*ldap.Entry{eng: {
			entry("cn=ada,dc=example,dc=test", map[string][]string{"objectGUID": {guid(1)}}),
			entry("cn=bob,dc=example,dc=test", map[string][]string{"objectGUID": {guid(2)}}),
		}},
	}
	src := sourceWith(&f.fakeLDAP, FlavourAD)
	src.Dial = func(context.Context, string) (ldapConn, error) { return f, nil }
	src.GroupAttribute = "memberOf"
	src.NestedGroups = []string{eng}

	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string][]string{}
	for _, u := range got {
		byName[strings.TrimSuffix(u.Email, "@example.test")] = u.Groups
	}
	if !slices.Equal(byName["ada"], []string{eng}) {
		t.Errorf("ada, directly in Engineering, has %v; want it once", byName["ada"])
	}
	if !slices.Contains(byName["bob"], eng) || !slices.Contains(byName["bob"], devs) {
		t.Errorf("bob, in Developers inside Engineering, has %v; want both", byName["bob"])
	}
	if len(byName["cy"]) != 0 {
		t.Errorf("cy, in nothing, has %v", byName["cy"])
	}
	if last := f.filters[len(f.filters)-1]; !strings.Contains(last, "(objectCategory=person)") {
		t.Errorf("the in-chain search %q is not limited to people", last)
	}
}
