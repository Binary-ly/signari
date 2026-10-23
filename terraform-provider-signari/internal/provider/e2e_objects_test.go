package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// The resources beyond the client against a REAL Admin API (6.17), in the
// calls Terraform makes: each one created, refreshed, changed in place,
// imported and destroyed, with the server read after each step; two of them
// changed in one apply, which once always failed (0.45); and a change made by
// somebody else between the plan and the apply refused, not overwritten.
//
//	SIGNARI_E2E_ENDPOINT=http://127.0.0.1:18081 SIGNARI_E2E_TOKEN=sgnadm_... \
//	SIGNARI_E2E_ORG_ID=<uuid> go test -p 1 -run E2E ./internal/...
//
// SIGNARI_E2E_ORG_CREATE=1 also provisions an organisation, which nothing
// here can delete; give it a throwaway database. Skipped when unset.
func TestE2EEveryObjectLivesThroughAnApply(t *testing.T) {
	endpoint, token, org := os.Getenv("SIGNARI_E2E_ENDPOINT"), os.Getenv("SIGNARI_E2E_TOKEN"),
		os.Getenv("SIGNARI_E2E_ORG_ID")
	if endpoint == "" || token == "" || org == "" {
		t.Skip("SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN and SIGNARI_E2E_ORG_ID not set")
	}
	ctx := context.Background()
	api := &signari.Client{Endpoint: endpoint, Token: token}
	// Each apply is a provider process of its own, with its own write chain.
	apply := func() *providerData { return &providerData{client: api, conditional: true} }
	n := time.Now().UnixNano()
	must := func(step string, d diag.Diagnostics) {
		t.Helper()
		if d.HasError() {
			t.Fatalf("%s: %v", step, d)
		}
	}

	// --- a group -----------------------------------------------------------
	groups := newHarness[groupModel](t, &groupResource{}, apply())
	gplan := groupModel{ID: types.StringUnknown(), OrgID: types.StringValue(org),
		Name: types.StringValue(fmt.Sprintf("tf-e2e-%d", n)), DisplayName: types.StringValue("Terraform e2e"),
		Description: types.StringValue("made by the provider's test"), MayImpersonate: types.BoolUnknown(),
		ConfigVersion: types.Int64Unknown()}
	gst, d := groups.create(gplan)
	must("creating the group", d)
	gid := groups.model(gst).ID.ValueString()
	t.Cleanup(func() { _, _ = api.Write(context.Background(), http.MethodDelete, groupPath(gid), nil, 0) })
	var g signari.Group
	if _, err := api.Get(ctx, groupPath(gid), &g); err != nil || g.DisplayName != "Terraform e2e" ||
		g.Description != "made by the provider's test" {
		t.Fatalf("the server holds %+v (%v)", g, err)
	}

	// --- a user ------------------------------------------------------------
	users := newHarness[userModel](t, &userResource{}, apply())
	uplan := userModel{ID: types.StringUnknown(), OrgID: types.StringValue(org),
		Email: types.StringValue(fmt.Sprintf("tf-e2e-%d@example.test", n)), Username: types.StringValue(""),
		DisplayName: types.StringValue("Ada E2E"), GivenName: types.StringValue("Ada"),
		Surname: types.StringValue("E2E"), Locale: types.StringValue("en"), Active: types.BoolValue(true),
		Password: types.StringValue(fmt.Sprintf("tf-e2e-Passw0rd-%d", n)), Status: types.StringUnknown(),
		EmailVerified: types.BoolUnknown(), ConfigVersion: types.Int64Unknown()}
	ust, d := users.create(uplan)
	must("creating the user", d)
	uid := users.model(ust).ID.ValueString()
	t.Cleanup(func() { _, _ = api.Write(context.Background(), http.MethodDelete, userPath(uid), nil, 0) })
	var u signari.User
	if _, err := api.Get(ctx, userPath(uid), &u); err != nil || u.DisplayName != "Ada E2E" || u.GivenName != "Ada" ||
		u.Locale != "en" || u.Status != "active" {
		t.Fatalf("the server holds %+v (%v)", u, err)
	}

	// --- a membership ------------------------------------------------------
	members := newHarness[groupMemberModel](t, &groupMemberResource{}, apply())
	mst, d := members.create(groupMemberModel{ID: types.StringUnknown(), GroupID: types.StringValue(gid),
		UserID: types.StringValue(uid), ConfigVersion: types.Int64Unknown()})
	must("adding the member", d)
	if in, _, err := api.IsMember(ctx, gid, uid); err != nil || !in {
		t.Fatalf("after the create the person is a member: %v (%v)", in, err)
	}
	// Taken out outside Terraform: the refresh drops it, so the plan adds it back.
	if _, err := api.Write(ctx, http.MethodDelete, memberPath(gid, uid), nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, still, d := members.read(mst); d.HasError() || still {
		t.Errorf("a membership removed outside Terraform stayed in state (%v)", d)
	}
	mst, d = members.create(members.model(mst))
	must("adding the member back", d)

	// --- two changes in one apply (0.45) -----------------------------------
	// Both refreshed at the same version, as a plan reads them.
	one := apply()
	groups, users = newHarness[groupModel](t, &groupResource{}, one), newHarness[userModel](t, &userResource{}, one)
	gst, _, d = groups.read(gst)
	must("refreshing the group", d)
	ust, _, d = users.read(ust)
	must("refreshing the user", d)
	gwant := groups.model(gst)
	gwant.DisplayName = types.StringValue("Terraform e2e, renamed")
	uwant := users.model(ust)
	uwant.Password = uplan.Password
	uwant.Surname = types.StringValue("Lovelace")
	gst, d = groups.update(gst, gwant)
	must("the apply's first change, the group", d)
	ust, d = users.update(ust, uwant)
	must("the apply's second change, the user, which 0.45 refused", d)
	if _, err := api.Get(ctx, groupPath(gid), &g); err != nil || g.DisplayName != "Terraform e2e, renamed" {
		t.Errorf("the group is %+v (%v)", g, err)
	}
	if _, err := api.Get(ctx, userPath(uid), &u); err != nil || u.Surname != "Lovelace" {
		t.Errorf("the user is %+v (%v)", u, err)
	}

	// --- somebody else's change between the plan and the apply -------------
	later := apply()
	groups = newHarness[groupModel](t, &groupResource{}, later)
	gst, _, d = groups.read(gst)
	must("refreshing the group", d)
	if _, err := api.Write(ctx, http.MethodPatch, userPath(uid), map[string]string{"given_name": "Augusta"}, 0); err != nil {
		t.Fatal(err)
	}
	gwant = groups.model(gst)
	gwant.Description = types.StringValue("this must not land")
	if _, d := groups.update(gst, gwant); !d.HasError() || !strings.Contains(fmt.Sprint(d), "changed since") {
		t.Errorf("a change made after the plan was overwritten: %v", d)
	}
	if _, err := api.Get(ctx, groupPath(gid), &g); err != nil || g.Description == "this must not land" {
		t.Errorf("the refused write landed: %+v (%v)", g, err)
	}

	// --- import, and the user deactivated in place -------------------------
	fresh := apply()
	groups, users = newHarness[groupModel](t, &groupResource{}, fresh), newHarness[userModel](t, &userResource{}, fresh)
	if st, d := groups.imported(gid); d.HasError() || groups.model(st).Name.ValueString() != gplan.Name.ValueString() {
		t.Errorf("importing the group: %v %+v", d, groups.model(st))
	}
	ist, d := users.imported(uid)
	must("importing the user", d)
	off := users.model(ist)
	off.Active = types.BoolValue(false)
	if _, d := users.update(ist, off); d.HasError() {
		t.Fatalf("deactivating: %v", d)
	}
	if _, err := api.Get(ctx, userPath(uid), &u); err != nil || u.Status != "deactivated" {
		t.Errorf("after deactivating the user is %q (%v)", u.Status, err)
	}

	// --- destroyed ---------------------------------------------------------
	gone := apply()
	members, groups = newHarness[groupMemberModel](t, &groupMemberResource{}, gone), newHarness[groupModel](t, &groupResource{}, gone)
	users = newHarness[userModel](t, &userResource{}, gone)
	mst, _, _ = members.read(mst)
	gst, _, _ = groups.read(gst)
	ust, _, _ = users.read(ust)
	must("destroying the membership", members.destroy(mst))
	must("destroying the group", groups.destroy(gst))
	must("destroying the user", users.destroy(ust))
	if _, err := api.Get(ctx, groupPath(gid), &g); !errors.Is(err, signari.ErrNotFound) {
		t.Errorf("after destroy the group reads back (%v)", err)
	}
	if _, err := api.Get(ctx, userPath(uid), &u); !errors.Is(err, signari.ErrNotFound) {
		t.Errorf("after destroy the user reads back (%v)", err)
	}

	// --- an organisation, on a throwaway database --------------------------
	if os.Getenv("SIGNARI_E2E_ORG_CREATE") != "1" {
		return
	}
	orgs := newHarness[organizationModel](t, &organizationResource{}, apply())
	ost, d := orgs.create(organizationModel{ID: types.StringUnknown(), Slug: types.StringValue(fmt.Sprintf("tf-%d", n)),
		DisplayName: types.StringValue("Terraform e2e"), InstanceID: types.StringUnknown(),
		Status: types.StringValue("suspended"), ConfigVersion: types.Int64Unknown()})
	must("creating a suspended organisation", d)
	var o signari.Organization
	oid := orgs.model(ost).ID.ValueString()
	if _, err := api.Get(ctx, organizationPath(oid), &o); err != nil || o.Status != "suspended" {
		t.Fatalf("the organisation is %+v (%v)", o, err)
	}
	active := orgs.model(ost)
	active.Status = types.StringValue("active")
	ost, d = orgs.update(ost, active)
	must("reactivating it", d)
	if _, err := api.Get(ctx, organizationPath(oid), &o); err != nil || o.Status != "active" {
		t.Errorf("after reactivating it is %+v (%v)", o, err)
	}
	if d := orgs.destroy(ost); !d.HasError() {
		t.Error("an organisation destroy did not refuse")
	}
	if _, err := api.Get(ctx, organizationPath(oid), &o); err != nil {
		t.Errorf("the refused destroy removed it (%v)", err)
	}
}
