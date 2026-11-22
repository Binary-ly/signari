package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// An application's group release, a scope and a protected host against a
// REAL Admin API (6.17): each made, changed in place, imported and destroyed,
// and the server read after each step. Needs SIGNARI_E2E_CLIENT_ID, a client
// of SIGNARI_E2E_ORG_ID's, as internal/signari's tests do.
func TestE2EReleasesScopesAndHostsLiveThroughAnApply(t *testing.T) {
	endpoint, token, org, client := os.Getenv("SIGNARI_E2E_ENDPOINT"), os.Getenv("SIGNARI_E2E_TOKEN"),
		os.Getenv("SIGNARI_E2E_ORG_ID"), os.Getenv("SIGNARI_E2E_CLIENT_ID")
	if endpoint == "" || token == "" || org == "" || client == "" {
		t.Skip("SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN, SIGNARI_E2E_ORG_ID and SIGNARI_E2E_CLIENT_ID not set")
	}
	ctx := context.Background()
	api := &signari.Client{Endpoint: endpoint, Token: token}
	apply := func() *providerData { return &providerData{client: api, conditional: true} }
	n := time.Now().UnixNano()
	must := func(step string, d diag.Diagnostics) {
		t.Helper()
		if d.HasError() {
			t.Fatalf("%s: %v", step, d)
		}
	}

	// --- the release -------------------------------------------------------
	group := fmt.Sprintf("tf-rel-%d", n)
	gid, _, err := api.Create(ctx, "/admin/groups", map[string]string{"org_id": org, "name": group}, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = api.Write(context.Background(), http.MethodDelete, groupPath(gid), nil, 0) })
	releases := newHarness[groupReleaseModel](t, &groupReleaseResource{}, apply())
	only, _ := types.SetValueFrom(ctx, types.StringType, []string{group})
	rst, d := releases.create(groupReleaseModel{ID: types.StringUnknown(), ClientID: types.StringValue(client),
		OnlyGroups: only, ConfigVersion: types.Int64Unknown()})
	must("releasing the group", d)
	var rel struct {
		Released   bool     `json:"released"`
		OnlyGroups []string `json:"only_groups"`
	}
	if _, err := api.Get(ctx, releasePath(client), &rel); err != nil || !rel.Released || fmt.Sprint(rel.OnlyGroups) != "["+group+"]" {
		t.Fatalf("the server holds %+v (%v)", rel, err)
	}
	all := releases.model(rst)
	all.OnlyGroups = types.SetNull(types.StringType)
	rst, d = releases.update(rst, all)
	must("releasing every group", d)
	if _, err := api.Get(ctx, releasePath(client), &rel); err != nil || !rel.Released || len(rel.OnlyGroups) != 0 {
		t.Errorf("after releasing every group the server holds %+v (%v)", rel, err)
	}
	if st, d := releases.imported(client); d.HasError() || releases.model(st).ClientID.ValueString() != client {
		t.Errorf("importing the release: %v", d)
	}
	must("withdrawing the release", releases.destroy(rst))
	if _, err := api.Get(ctx, releasePath(client), &rel); err != nil || rel.Released {
		t.Errorf("after the destroy the application is still told of groups: %+v (%v)", rel, err)
	}

	// --- a scope -----------------------------------------------------------
	scopes := newHarness[scopeModel](t, &scopeResource{}, apply())
	name := fmt.Sprintf("tf:read-%d", n)
	sst, d := scopes.create(scopeModel{ID: types.StringUnknown(), OrgID: types.StringValue(org),
		Name: types.StringValue(name), DisplayName: types.StringValue("Read things"),
		Description: types.StringValue("made by the provider's test"), Advertise: types.BoolValue(false),
		ConfigVersion: types.Int64Unknown()})
	must("declaring the scope", d)
	held := func() (bool, string, bool) {
		raw := map[string]json.RawMessage{}
		if _, err := api.Get(ctx, scopesPath(org), &raw); err != nil {
			t.Fatal(err)
		}
		var list []struct {
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
			Advertise   bool   `json:"advertise"`
		}
		_ = json.Unmarshal(raw["scopes"], &list)
		for _, s := range list {
			if s.Name == name {
				return true, s.DisplayName, s.Advertise
			}
		}
		return false, "", false
	}
	if ok, display, adv := held(); !ok || display != "Read things" || adv {
		t.Fatalf("the server holds the scope %v %q advertised %v", ok, display, adv)
	}
	shown := scopes.model(sst)
	shown.Advertise, shown.DisplayName = types.BoolValue(true), types.StringValue("Read every thing")
	sst, d = scopes.update(sst, shown)
	must("advertising the scope", d)
	if ok, display, adv := held(); !ok || display != "Read every thing" || !adv {
		t.Errorf("after the update the scope is %v %q advertised %v", ok, display, adv)
	}
	if st, d := scopes.imported(org + "/" + name); d.HasError() || !scopes.model(st).Advertise.ValueBool() {
		t.Errorf("importing the scope: %v", d)
	}
	must("removing the scope", scopes.destroy(sst))
	if ok, _, _ := held(); ok {
		t.Error("after the destroy the scope is still declared")
	}

	// --- a protected host --------------------------------------------------
	hosts := newHarness[proxyHostModel](t, &proxyHostResource{}, apply())
	host := fmt.Sprintf("app-%d.example.test", n)
	hst, d := hosts.create(proxyHostModel{ID: types.StringUnknown(), OrgID: types.StringValue(org),
		Host: types.StringValue(host), Enabled: types.BoolValue(true), ConfigVersion: types.Int64Unknown()})
	must("protecting the host", d)
	protected := func() (bool, bool) {
		var page struct {
			Hosts []struct {
				Host    string `json:"host"`
				Enabled bool   `json:"enabled"`
			} `json:"proxy_hosts"`
		}
		if _, err := api.Get(ctx, hostsPath(org), &page); err != nil {
			t.Fatal(err)
		}
		for _, h := range page.Hosts {
			if h.Host == host {
				return true, h.Enabled
			}
		}
		return false, false
	}
	if ok, on := protected(); !ok || !on {
		t.Fatalf("the server holds the host %v, enabled %v", ok, on)
	}
	off := hosts.model(hst)
	off.Enabled = types.BoolValue(false)
	hst, d = hosts.update(hst, off)
	must("disabling the host", d)
	if ok, on := protected(); !ok || on {
		t.Errorf("after disabling, the host is %v, enabled %v", ok, on)
	}
	if st, d := hosts.imported(org + "/" + host); d.HasError() || hosts.model(st).Enabled.ValueBool() {
		t.Errorf("importing the host: %v", d)
	}
	must("removing the host", hosts.destroy(hst))
	if ok, _ := protected(); ok {
		t.Error("after the destroy the host is still protected")
	}
}
