package scim

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Provisioning groups to a target.
//
// A group at a target is an access control list. The two properties below are
// what stop a scheduled sync from quietly removing somebody's access.

type captured struct {
	method string
	path   string
	body   string
}

func captureTarget(t *testing.T, reply string) (*Client, *[]captured) {
	t.Helper()
	var seen []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, captured{r.Method, r.URL.Path, string(b)})
		w.Header().Set("Content-Type", "application/scim+json")
		if reply == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return NewClient(Target{BaseURL: srv.URL, Token: "t"}, srv.Client()), &seen
}

// Membership changes are PATCHed, never PUT.
//
// A PUT replaces the whole resource, so pushing our membership list erases
// anything the target holds that we did not send — accounts a local
// administrator added by hand, service accounts, everything. That is a way to
// remove somebody's access at 3am for a reason nobody can reconstruct.
func TestMembershipChangesArePatchedNotReplaced(t *testing.T) {
	c, seen := captureTarget(t, "")

	if err := c.AddMembers(context.Background(), "g1", []string{"u1", "u2"}); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 {
		t.Fatalf("made %d requests, want 1", len(*seen))
	}
	got := (*seen)[0]
	if got.method != http.MethodPatch {
		t.Errorf("method = %s, want PATCH. A PUT replaces the group and erases "+
			"members this deployment does not know about.", got.method)
	}
	if got.path != "/Groups/g1" {
		t.Errorf("path = %s", got.path)
	}
	if !strings.Contains(got.body, `"op":"add"`) {
		t.Errorf("body does not add members: %s", got.body)
	}
}

// A removal names the member, rather than replacing the attribute.
//
// `path: "members"` with no filter is read as "replace the whole attribute" by
// several implementations — so a list that was short because a query failed
// would empty the group.
func TestARemovalNamesTheMemberRatherThanReplacingTheAttribute(t *testing.T) {
	c, seen := captureTarget(t, "")

	if err := c.RemoveMembers(context.Background(), "g1", []string{"u1"}); err != nil {
		t.Fatal(err)
	}
	body := (*seen)[0].body

	// Asserted on the DECODED path, not the raw body. The filter's quotes are
	// escaped in JSON, so a substring match against the wire bytes compares the
	// encoding rather than the value -- which is what the first version of this
	// test did, and it failed on a request that was exactly right.
	var parsed struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"Operations"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Operations) != 1 {
		t.Fatalf("got %d operations, want 1", len(parsed.Operations))
	}
	op := parsed.Operations[0]

	if op.Path != `members[value eq "u1"]` {
		t.Fatalf("path = %q; the removal must name the member by filter. An "+
			"unfiltered members path is read as replace-the-attribute by several "+
			"targets, which empties the group.", op.Path)
	}
	if op.Value != nil {
		t.Errorf("the remove operation carries a value: %v", op.Value)
	}
}

// A member id is data, and a filter is a query language.
//
// An unescaped quote in an id changes which members the filter matches, so a
// removal aimed at one account could remove several or none. The id arrives
// from a target this deployment does not control.
func TestAMemberIDIsEscapedIntoTheFilter(t *testing.T) {
	c, seen := captureTarget(t, "")

	hostile := `u1" or value pr or value eq "`
	if err := c.RemoveMembers(context.Background(), "g1", []string{hostile}); err != nil {
		t.Fatal(err)
	}
	body := (*seen)[0].body

	if strings.Contains(body, `value pr`) && !strings.Contains(body, `\"`) {
		t.Fatalf("a crafted member id reached the filter unescaped: %s\n"+
			"It could then match members the removal was never aimed at.", body)
	}
	if !strings.Contains(body, `\"`) {
		t.Errorf("the quote in the id was not escaped: %s", body)
	}
}

// A group created without an id cannot be reconciled, so it is a failure.
func TestAGroupCreatedWithoutAnIDIsAFailure(t *testing.T) {
	c, _ := captureTarget(t, `{"displayName":"Engineers"}`)

	_, err := c.CreateGroup(context.Background(), Group{DisplayName: "Engineers"})
	if err == nil {
		t.Fatal("a group with no returned id was accepted. Every later " +
			"reconciliation would create a duplicate, because nothing could find " +
			"the one already there.")
	}
}

// A dry-run target sends nothing.
func TestADryRunTargetMakesNoGroupRequests(t *testing.T) {
	var seen []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, captured{r.Method, r.URL.Path, ""})
	}))
	defer srv.Close()

	c := NewClient(Target{BaseURL: srv.URL, Token: "t", DryRun: true}, srv.Client())
	ctx := context.Background()

	if _, err := c.CreateGroup(ctx, Group{DisplayName: "Engineers"}); err != nil {
		t.Fatal(err)
	}
	must := []error{
		c.AddMembers(ctx, "g1", []string{"u1"}),
		c.RemoveMembers(ctx, "g1", []string{"u1"}),
		c.DeleteGroup(ctx, "g1"),
	}
	for _, err := range must {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 0 {
		t.Fatalf("a dry run made %d requests: %+v", len(seen), seen)
	}
}
