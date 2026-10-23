package signariadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// A generated method sends what its operation says -- the method, the path
// with its parameters escaped, the body, the precondition -- and answers the
// decoded body and the version from the ETag.
func TestAMethodSendsItsOperation(t *testing.T) {
	var method, path, ifMatch string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, ifMatch = r.Method, r.URL.EscapedPath(), r.Header.Get("If-Match")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("ETag", `"42"`)
		fmt.Fprint(w, `{"id":"u/1","config_version":42}`)
	}))
	t.Cleanup(srv.Close)
	c := &Client{Endpoint: srv.URL, Token: "t"}
	out, v, err := c.PatchUsersUserID(context.Background(), "u/1",
		PatchUsersUserIDRequest{DisplayName: Ptr("Ada"), Active: Ptr(false)}, IfMatch(41))
	if err != nil || v != 42 || out.ID != "u/1" {
		t.Fatalf("answered %+v %d %v", out, v, err)
	}
	if method != http.MethodPatch || path != "/admin/users/u%2F1" || ifMatch != `"41"` {
		t.Errorf("sent %s %s If-Match %s", method, path, ifMatch)
	}
	if len(body) != 2 || body["display_name"] != "Ada" || body["active"] != false {
		t.Errorf("sent the body %v, want the two fields set and nothing else", body)
	}
}

// A refused precondition is an error that says so, with both versions.
func TestARefusedPreconditionIsAConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		fmt.Fprint(w, `{"error":"precondition_failed","expected_version":3,"current_version":5}`)
	}))
	t.Cleanup(srv.Close)
	_, _, err := (&Client{Endpoint: srv.URL}).DeleteGroupsGroupID(context.Background(), "g", IfMatch(3))
	var e *Error
	if !IsConflict(err) || !errors.As(err, &e) || e.ExpectedVersion != 3 || e.CurrentVersion != 5 {
		t.Errorf("answered %v", err)
	}
}

// The client against a REAL Admin API (6.18):
//
//	SIGNARI_E2E_ENDPOINT=http://127.0.0.1:18081 SIGNARI_E2E_TOKEN=sgnadm_... \
//	SIGNARI_E2E_ORG_ID=<uuid> go test ./...
//
// A group made, read with its version, renamed on that version, refused on a
// version the deployment has moved past, and deleted. Skipped when unset.
func TestE2EAGroupThroughTheGeneratedClient(t *testing.T) {
	endpoint, token, org := os.Getenv("SIGNARI_E2E_ENDPOINT"), os.Getenv("SIGNARI_E2E_TOKEN"),
		os.Getenv("SIGNARI_E2E_ORG_ID")
	if endpoint == "" || token == "" || org == "" {
		t.Skip("SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN and SIGNARI_E2E_ORG_ID not set")
	}
	ctx := context.Background()
	c := &Client{Endpoint: endpoint, Token: token}
	name := fmt.Sprintf("sdk-go-%d", time.Now().UnixNano())
	made, _, err := c.PostGroups(ctx, PostGroupsRequest{OrgID: Ptr(org), Name: Ptr(name)})
	if err != nil {
		t.Fatalf("making the group: %v", err)
	}
	t.Cleanup(func() { _, _, _ = c.DeleteGroupsGroupID(context.Background(), made.ID) })
	g, read, err := c.GetGroupsGroupID(ctx, made.ID)
	if err != nil || g.Name != name || read == 0 {
		t.Fatalf("reading it: %+v at %d (%v)", g, read, err)
	}
	if _, _, err := c.PatchGroupsGroupID(ctx, made.ID, PatchGroupsGroupIDRequest{DisplayName: Ptr("Renamed")},
		IfMatch(read)); err != nil {
		t.Fatalf("renaming it on the version read: %v", err)
	}
	if _, _, err := c.PatchGroupsGroupID(ctx, made.ID, PatchGroupsGroupIDRequest{DisplayName: Ptr("Stale")},
		IfMatch(read)); !IsConflict(err) {
		t.Errorf("a write on a version the deployment moved past answered %v, want a conflict", err)
	}
	if g, _, _ := c.GetGroupsGroupID(ctx, made.ID); g == nil || g.DisplayName != "Renamed" {
		t.Errorf("the group is %+v", g)
	}
	if _, _, err := c.DeleteGroupsGroupID(ctx, made.ID); err != nil {
		t.Fatalf("deleting it: %v", err)
	}
	if _, _, err := c.GetGroupsGroupID(ctx, made.ID); !IsNotFound(err) {
		t.Errorf("after the delete it reads %v", err)
	}
}
