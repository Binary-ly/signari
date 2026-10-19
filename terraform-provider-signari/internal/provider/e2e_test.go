package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// The resource's lifecycle against a REAL Admin API, in the calls Terraform
// makes (2.17):
//
//	SIGNARI_E2E_ENDPOINT=http://127.0.0.1:18081 SIGNARI_E2E_TOKEN=sgnadm_... \
//	SIGNARI_E2E_ORG_ID=<uuid> go test -run E2E ./internal/provider/
//
// A change of redirect URIs replaces the client, so it is a Delete and then a
// Create, and afterwards the server must hold the new URIs and a refresh must
// find nothing to change. Before, it was an Update that sent `enabled` alone:
// state took the new URIs, the next plan was empty, and the server kept the old.
// Skipped when unset.
func TestE2EARedirectURIChangeReachesTheServer(t *testing.T) {
	endpoint, token, org := os.Getenv("SIGNARI_E2E_ENDPOINT"), os.Getenv("SIGNARI_E2E_TOKEN"),
		os.Getenv("SIGNARI_E2E_ORG_ID")
	if endpoint == "" || token == "" || org == "" {
		t.Skip("SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN and SIGNARI_E2E_ORG_ID not set")
	}
	ctx := context.Background()
	api := &signari.Client{Endpoint: endpoint, Token: token}
	r, _ := clientSchema(t)
	r.data = &providerData{client: api, conditional: true}
	sch := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, sch)

	id := fmt.Sprintf("tf-e2e-%d", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = api.DeleteClient(context.Background(), id, 0) })
	want := func(uri string, enabled bool) clientModel {
		uris, _ := types.SetValueFrom(ctx, types.StringType, []string{uri})
		return clientModel{
			ClientID: types.StringValue(id), OrgID: types.StringValue(org),
			DisplayName: types.StringValue("Terraform e2e"), Public: types.BoolValue(false),
			RedirectURIs: uris, Enabled: types.BoolValue(enabled),
			ClientSecret: types.StringUnknown(), ConfigVersion: types.Int64Unknown(),
		}
	}
	asPlan := func(m clientModel) tfsdk.Plan {
		p := tfsdk.Plan{Schema: sch.Schema}
		if d := p.Set(ctx, m); d.HasError() {
			t.Fatal(d)
		}
		return p
	}
	create := func(m clientModel) tfsdk.State {
		resp := &resource.CreateResponse{State: tfsdk.State{Schema: sch.Schema}}
		r.Create(ctx, resource.CreateRequest{Plan: asPlan(m)}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("create: %v", resp.Diagnostics)
		}
		return resp.State
	}
	refresh := func(st tfsdk.State) clientModel {
		resp := &resource.ReadResponse{State: st}
		r.Read(ctx, resource.ReadRequest{State: st}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("read: %v", resp.Diagnostics)
		}
		var m clientModel
		resp.State.Get(ctx, &m)
		return m
	}
	server := func() *signari.ClientState {
		got, _, err := api.GetClient(ctx, id)
		if err != nil {
			t.Fatalf("GET %s: %v", id, err)
		}
		return got
	}
	same := func(label string, got, w clientModel) {
		if !got.RedirectURIs.Equal(w.RedirectURIs) || !got.DisplayName.Equal(w.DisplayName) ||
			!got.Enabled.Equal(w.Enabled) || !got.Public.Equal(w.Public) || !got.OrgID.Equal(w.OrgID) {
			t.Errorf("%s: a refresh found %v %v enabled=%v public=%v, the config says %v %v enabled=%v public=%v",
				label, got.DisplayName, got.RedirectURIs, got.Enabled, got.Public,
				w.DisplayName, w.RedirectURIs, w.Enabled, w.Public)
		}
	}

	first := create(want("https://a.example/cb", true))
	same("after create", refresh(first), want("https://a.example/cb", true))

	// The replacement Terraform plans for a changed redirect URI.
	del := &resource.DeleteResponse{State: first}
	r.Delete(ctx, resource.DeleteRequest{State: first}, del)
	if del.Diagnostics.HasError() {
		t.Fatalf("delete: %v", del.Diagnostics)
	}
	second := create(want("https://b.example/cb", true))
	if got := server(); got.RedirectURIs == nil || fmt.Sprint(*got.RedirectURIs) != "[https://b.example/cb]" {
		t.Fatalf("after the replacement the server holds %v, want the new URI", got.RedirectURIs)
	}
	same("after the replacement", refresh(second), want("https://b.example/cb", true))

	// The one in-place change.
	up := &resource.UpdateResponse{State: second}
	r.Update(ctx, resource.UpdateRequest{Plan: asPlan(want("https://b.example/cb", false)), State: second}, up)
	if up.Diagnostics.HasError() {
		t.Fatalf("update: %v", up.Diagnostics)
	}
	if server().Enabled {
		t.Error("an update to enabled = false left the client enabled on the server")
	}
	same("after the update", refresh(up.State), want("https://b.example/cb", false))

	gone := &resource.DeleteResponse{State: up.State}
	r.Delete(ctx, resource.DeleteRequest{State: up.State}, gone)
	if gone.Diagnostics.HasError() {
		t.Fatalf("destroy: %v", gone.Diagnostics)
	}
	if _, _, err := api.GetClient(ctx, id); !errors.Is(err, signari.ErrNotFound) {
		t.Errorf("after destroy the client still reads back (%v)", err)
	}
}
