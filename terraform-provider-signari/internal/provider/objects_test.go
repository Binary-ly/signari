package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// A user's update sends what changed and nothing else. The address sent back
// as it was cleared its verified mark on an engine before 0.46, and a PATCH of
// the whole person would have done that at every apply.
func TestAUserUpdateSendsOnlyWhatChanged(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			raw, _ := io.ReadAll(r.Body)
			var b map[string]any
			_ = json.Unmarshal(raw, &b)
			mu.Lock()
			bodies = append(bodies, b)
			mu.Unlock()
		}
		w.Header().Set("ETag", `"5"`)
		fmt.Fprint(w, `{"id":"u1","org_id":"o","email":"ada@x.test","username":"ada","status":"active",
			"display_name":"Ada","given_name":"","surname":"","locale":"","email_verified":true}`)
	}))
	t.Cleanup(srv.Close)
	h := newHarness[userModel](t, &userResource{}, &providerData{client: &signari.Client{Endpoint: srv.URL,
		Token: "t"}, conditional: true})
	was := userModel{ID: types.StringValue("u1"), OrgID: types.StringValue("o"), Email: types.StringValue("ada@x.test"),
		Username: types.StringValue("ada"), DisplayName: types.StringValue("Ada"), GivenName: types.StringValue(""),
		Surname: types.StringValue(""), Locale: types.StringValue(""), Active: types.BoolValue(true),
		Password: types.StringNull(), Status: types.StringValue("active"), EmailVerified: types.BoolValue(true),
		ConfigVersion: types.Int64Value(4)}
	want := was
	want.DisplayName = types.StringValue("Ada Lovelace")
	if _, d := h.update(h.state(was), want); d.HasError() {
		t.Fatal(d)
	}
	if len(bodies) != 1 || len(bodies[0]) != 1 || bodies[0]["display_name"] != "Ada Lovelace" {
		t.Fatalf("the update sent %v, want the display name alone", bodies)
	}

	// Nothing changed sends nothing.
	bodies = nil
	if _, d := h.update(h.state(was), was); d.HasError() {
		t.Fatal(d)
	}
	if len(bodies) != 0 {
		t.Errorf("an update changing nothing sent %v", bodies)
	}
}

// An organisation is never deleted by Terraform: the destroy refuses, naming
// the command that does it, and sends nothing.
func TestAnOrganisationDestroyRefusesAndSendsNothing(t *testing.T) {
	sent := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	h := newHarness[organizationModel](t, &organizationResource{}, &providerData{client: &signari.Client{
		Endpoint: srv.URL, Token: "t"}, conditional: true})
	d := h.destroy(h.state(organizationModel{ID: types.StringValue("o1"), Slug: types.StringValue("acme"),
		DisplayName: types.StringValue("Acme"), InstanceID: types.StringValue("i"),
		Status: types.StringValue("active"), ConfigVersion: types.Int64Value(3)}))
	if !d.HasError() || !strings.Contains(fmt.Sprint(d), "signari instance org-delete -org o1") || sent != 0 {
		t.Errorf("the destroy answered %v after %d request(s)", d, sent)
	}
}

// A membership is imported as <group_id>/<user_id>, and anything else is
// refused rather than half-read.
func TestAMembershipImportsByGroupAndUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"9"`)
		if strings.HasSuffix(r.URL.Path, "/members") {
			fmt.Fprint(w, `{"members":[{"id":"u2"}],"next_cursor":""}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	h := newHarness[groupMemberModel](t, &groupMemberResource{}, &providerData{client: &signari.Client{
		Endpoint: srv.URL, Token: "t"}, conditional: true})
	st, d := h.imported("g1/u2")
	if d.HasError() {
		t.Fatal(d)
	}
	if m := h.model(st); m.GroupID.ValueString() != "g1" || m.UserID.ValueString() != "u2" ||
		m.ConfigVersion.ValueInt64() != 9 {
		t.Errorf("imported %+v", m)
	}
	if _, d := h.imported("g1"); !d.HasError() {
		t.Error("an import id with no user was taken")
	}
}
