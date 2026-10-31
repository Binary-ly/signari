package provision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/scim"
)

func TestAGroupsNameBecomesOneAnAddressTakes(t *testing.T) {
	for in, want := range map[string]string{"Platform Team": "platform-team", "eng": "eng", "a.b_c-d": "a.b_c-d",
		" spaced ": "spaced", "فريق": "", strings.Repeat("x", 80): strings.Repeat("x", 64)} {
		if got := groupNickname(in); got != want {
			t.Errorf("%q became %q, want %q", in, got, want)
		}
	}
}

// Every kind of target holds groups, so the check that only SCIM did cannot come back
// as a kind that compiles and fails at the first group.
func TestEveryKindOfTargetHoldsGroups(t *testing.T) {
	var _ GroupProvisioner = SCIM{}
	var _ GroupProvisioner = (*Entra)(nil)
	var _ GroupProvisioner = (*Google)(nil)
}

// A token that asked for groups on every call would stop a target's user sync the day
// it started, on a deployment whose delegation grants only users.
func TestOnlyAGroupCallAsksForGroups(t *testing.T) {
	g := &Google{Domain: "x.test", token: "users-only"}
	if g.scope != "" {
		t.Fatalf("a target asks for %q", g.scope)
	}
	c := g.forGroups()
	if !strings.Contains(c.scope, directory.ScopeGroupWrite) || !strings.Contains(c.scope, directory.ScopeDirectoryWrite) {
		t.Errorf("a group call asks for %q", c.scope)
	}
	if c.token != "" {
		t.Error("a group call would present a token that cannot touch groups")
	}
	raw := []byte(`{"tenant_id":"t","client_id":"c","client_secret":"s"}`)
	if _, err := groupsAt(scim.Target{Kind: "entra", Credentials: raw}, nil); err != nil {
		t.Error(err)
	}
}

// fakeGoogleGroups is a group with two pages of members, one account that has gone.
func fakeGoogleGroups(t *testing.T) (*Google, *[]string) {
	t.Helper()
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		answer := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/groups/g1/members"):
			if r.URL.Query().Get("pageToken") == "" {
				answer(map[string]any{"members": []map[string]string{{"id": "1"}}, "nextPageToken": "next"})
				return
			}
			answer(map[string]any{"members": []map[string]string{{"id": "2"}}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/users/gone"):
			http.Error(w, "{}", http.StatusNotFound)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/users/"):
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			answer(map[string]string{"id": id, "primaryEmail": "user" + id + "@x.test"})
		default:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			line := r.Method + " " + r.URL.Path
			for _, k := range []string{"email", "name"} {
				if v, ok := body[k].(string); ok {
					line += " " + k + "=" + v
				}
			}
			sent = append(sent, line)
			answer(map[string]string{"id": "created"})
		}
	}))
	t.Cleanup(srv.Close)
	return &Google{BaseURL: srv.URL, Domain: "x.test", token: "t", expires: farFuture(), HTTP: srv.Client()}, &sent
}

// The shape is what a real API refuses, and members are named by address.
func TestGoogleGroupsAreDrivenByAddress(t *testing.T) {
	g, sent := fakeGoogleGroups(t)
	ctx := context.Background()
	id, err := g.CreateGroup(ctx, Group{Name: "Platform Team", DisplayName: "Platform", ExternalID: "ours"})
	if err != nil || id != "created" {
		t.Fatalf("%q %v", id, err)
	}
	members, err := g.GroupMembers(ctx, "g1")
	if err != nil || len(members) != 2 {
		t.Fatalf("read %v, %v: a second page unread is a member added twice", members, err)
	}
	if err := g.AddGroupMembers(ctx, "g1", []string{"3"}); err != nil {
		t.Fatal(err)
	}
	if err := g.RemoveGroupMembers(ctx, "g1", []string{"4", "gone"}); err != nil {
		t.Fatalf("an account already gone stopped the removal: %v", err)
	}
	if err := g.DeleteGroup(ctx, "g1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /admin/directory/v1/groups email=platform-team@x.test name=Platform",
		"POST /admin/directory/v1/groups/g1/members email=user3@x.test",
		"DELETE /admin/directory/v1/groups/g1/members/user4@x.test",
		"DELETE /admin/directory/v1/groups/g1",
	}
	if !slices.Equal(*sent, want) {
		t.Errorf("sent\n  %s\nwant\n  %s", strings.Join(*sent, "\n  "), strings.Join(want, "\n  "))
	}
}

// A member on a page unread reads as somebody to add, and Graph refuses a reference
// that already exists, so one long group stops the whole sync. A next link to another
// host is refused, for the same reason a short list is.
func TestEntraMembersAreReadToTheLastPage(t *testing.T) {
	var srv *httptest.Server
	foreign := false
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "" {
			next := srv.URL + "/groups/g/members?page=2"
			if foreign {
				next = "https://elsewhere.test/groups/g/members?page=2"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{{"id": "1"}}, "@odata.nextLink": next})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{{"id": "2"}}})
	}))
	defer srv.Close()
	e := &Entra{BaseURL: srv.URL, token: "t", expires: farFuture(), HTTP: srv.Client()}
	members, err := e.GroupMembers(context.Background(), "g")
	if err != nil || !slices.Equal(members, []string{"1", "2"}) {
		t.Fatalf("read %v, %v", members, err)
	}
	foreign = true
	if members, err := e.GroupMembers(context.Background(), "g"); err == nil {
		t.Errorf("a page that could not be read answered %v", members)
	}
}

func TestAGroupWithNoUsableNameIsRefusedHere(t *testing.T) {
	ctx := context.Background()
	if _, err := (&Google{Domain: "x.test"}).CreateGroup(ctx, Group{Name: "فريق"}); err == nil {
		t.Error("Google: a name nothing of which an address may hold was sent")
	}
	if _, err := (&Entra{}).CreateGroup(ctx, Group{Name: "فريق"}); err == nil {
		t.Error("Entra: a name nothing of which a nickname may hold was sent")
	}
}
