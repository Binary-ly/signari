package provider

import (
	"context"
	"encoding/json"
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

// An organisation's configuration file through Terraform against a REAL
// Admin API (6.17): the plan lists the engine's own plan; the apply makes it
// so; a refresh finds a change made outside Terraform as drift and the next
// plan puts it back; a deployment that moved after the plan is refused, not
// overwritten; and a destroy leaves what the file declared in place.
func TestE2EAConfigurationFileIsPlannedAppliedAndKeptInPlace(t *testing.T) {
	endpoint, token, org := os.Getenv("SIGNARI_E2E_ENDPOINT"), os.Getenv("SIGNARI_E2E_TOKEN"),
		os.Getenv("SIGNARI_E2E_ORG_ID")
	if endpoint == "" || token == "" || org == "" {
		t.Skip("SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN and SIGNARI_E2E_ORG_ID not set")
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
	group, attr := fmt.Sprintf("tf-cfg-%d", n), fmt.Sprintf("tf_cfg_%d", n)
	doc := func(display string) string {
		return fmt.Sprintf("version: 1\ngroups:\n  - name: %s\n    display_name: %s\nattributes:\n  - name: %s\n"+
			"    value_type: string\n", group, display, attr)
	}
	config := func(document string) configurationModel {
		return configurationModel{ID: types.StringUnknown(), OrgID: types.StringValue(org),
			Document: types.StringValue(document), Prune: types.BoolValue(false),
			Changes: types.ListUnknown(types.StringType), Drift: types.ListUnknown(types.StringType),
			Minted: types.MapUnknown(types.StringType), PlannedAt: types.Int64Unknown(),
			ConfigVersion: types.Int64Unknown()}
	}
	groupHeld := func() (string, bool) {
		var found string
		ok := false
		_, err := api.List(ctx, "/admin/groups", "groups", func(raw json.RawMessage) error {
			var g signari.Group
			if json.Unmarshal(raw, &g) == nil && g.Name == group && g.OrgID == org {
				found, ok = g.DisplayName, true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return found, ok
	}

	// Planned, then applied.
	h := newHarness[configurationModel](t, &configurationResource{}, apply())
	p, d := h.planned(h.null(), config(doc("Configured")))
	must("planning", d)
	var planned configurationModel
	p.Get(ctx, &planned)
	var lines []string
	planned.Changes.ElementsAs(ctx, &lines, false)
	if !strings.Contains(strings.Join(lines, "\n"), "create group "+group) {
		t.Fatalf("the plan does not list the group: %v", lines)
	}
	st, d := h.createFrom(p)
	must("applying", d)
	if display, ok := groupHeld(); !ok || display != "Configured" {
		t.Fatalf("after the apply the group is %q, held %v", display, ok)
	}
	t.Cleanup(func() {
		_, _ = api.Do(context.Background(), http.MethodPost, configPath(org), map[string]any{
			"document": "version: 1\n", "prune": false, "dry_run": true}, 0)
	})

	// A change outside Terraform is drift, and the plan after it puts it back.
	var g signari.Group
	gid := ""
	_, _ = api.List(ctx, "/admin/groups", "groups", func(raw json.RawMessage) error {
		if json.Unmarshal(raw, &g) == nil && g.Name == group {
			gid = g.ID
		}
		return nil
	})
	t.Cleanup(func() { _, _ = api.Write(context.Background(), http.MethodDelete, groupPath(gid), nil, 0) })
	if _, err := api.Write(ctx, http.MethodPatch, groupPath(gid), map[string]string{"display_name": "Drifted"}, 0); err != nil {
		t.Fatal(err)
	}
	h = newHarness[configurationModel](t, &configurationResource{}, apply())
	st, _, d = h.read(st)
	must("refreshing", d)
	var drift []string
	h.model(st).Drift.ElementsAs(ctx, &drift, false)
	if len(drift) == 0 {
		t.Fatal("a group renamed outside Terraform was not drift")
	}
	again := h.model(st)
	p, d = h.planned(st, configurationModel{ID: again.ID, OrgID: again.OrgID, Document: again.Document,
		Prune: again.Prune, Changes: types.ListUnknown(types.StringType), Drift: types.ListUnknown(types.StringType),
		Minted: types.MapUnknown(types.StringType), PlannedAt: types.Int64Unknown(), ConfigVersion: types.Int64Unknown()})
	must("planning over the drift", d)
	st, d = h.updateFrom(st, p)
	must("putting it back", d)
	if display, _ := groupHeld(); display != "Configured" {
		t.Errorf("the apply over the drift left the group %q", display)
	}

	// A deployment that moved after the plan is refused.
	h = newHarness[configurationModel](t, &configurationResource{}, apply())
	next := h.model(st)
	p, d = h.planned(st, configurationModel{ID: next.ID, OrgID: next.OrgID, Document: types.StringValue(doc("Reviewed")),
		Prune: next.Prune, Changes: types.ListUnknown(types.StringType), Drift: types.ListUnknown(types.StringType),
		Minted: types.MapUnknown(types.StringType), PlannedAt: types.Int64Unknown(), ConfigVersion: types.Int64Unknown()})
	must("planning a rename", d)
	if _, err := api.Write(ctx, http.MethodPatch, groupPath(gid), map[string]string{"description": "moved"}, 0); err != nil {
		t.Fatal(err)
	}
	if _, d := h.updateFrom(st, p); !d.HasError() || !strings.Contains(fmt.Sprint(d), "changed since") {
		t.Errorf("an apply over a deployment that moved after the plan was not refused: %v", d)
	}
	if display, _ := groupHeld(); display == "Reviewed" {
		t.Error("the refused apply landed")
	}

	// Imported, then destroyed: what it declared stays.
	if st2, d := h.imported(org); d.HasError() || h.model(st2).OrgID.ValueString() != org {
		t.Errorf("importing: %v", d)
	}
	d = h.destroy(st)
	if d.HasError() || d.WarningsCount() != 1 {
		t.Errorf("the destroy answered %v", d)
	}
	if _, ok := groupHeld(); !ok {
		t.Error("destroying the configuration deleted what it declared")
	}
}
