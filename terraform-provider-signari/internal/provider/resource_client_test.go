package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// The wiring between the resource and the client.
//
// internal/signari proves the client sends a precondition when told to. This
// proves the resource TELLS it to -- by taking the version out of Terraform
// state and handing it over. That join is where the feature would die silently:
// every client test would still pass while `Update` quietly sent zero, and the
// only symptom would be a lost update in production months later.

// clientSchema builds the real resource schema, so these tests bind against what
// Terraform actually sees rather than a hand-written copy that could drift.
func clientSchema(t *testing.T) (*clientResource, tftypes.Type) {
	t.Helper()
	r := &clientResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema: %v", resp.Diagnostics)
	}
	return r, resp.Schema.Type().TerraformType(context.Background())
}

// clientState renders one resource's values into a tfsdk state/plan.
func clientState(t *testing.T, r *clientResource, ty tftypes.Type,
	enabled bool, configVersion int64) tfsdk.State {
	t.Helper()

	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	raw := tftypes.NewValue(ty, map[string]tftypes.Value{
		"client_id":      tftypes.NewValue(tftypes.String, "app"),
		"org_id":         tftypes.NewValue(tftypes.String, "org-1"),
		"display_name":   tftypes.NewValue(tftypes.String, "An app"),
		"public":         tftypes.NewValue(tftypes.Bool, false),
		"redirect_uris":  oneRedirectURI(),
		"enabled":        tftypes.NewValue(tftypes.Bool, enabled),
		"client_secret":  tftypes.NewValue(tftypes.String, "s3cret"),
		"config_version": tftypes.NewValue(tftypes.Number, configVersion),
	})
	return tfsdk.State{Schema: resp.Schema, Raw: raw}
}

// oneRedirectURI is the fixture's redirect_uris.
func oneRedirectURI() tftypes.Value {
	return tftypes.NewValue(tftypes.Set{ElementType: tftypes.String},
		[]tftypes.Value{tftypes.NewValue(tftypes.String, "https://app.example/cb")})
}

// recordingServer captures the If-Match of the last write. A read is not a
// write, and every write is now followed by one, so reads are not recorded.
func recordingServer(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			seen = r.Header.Get("If-Match")
		}
		w.Header().Set("ETag", `"99"`)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func newResource(t *testing.T, endpoint string, conditional bool) *clientResource {
	t.Helper()
	r, _ := clientSchema(t)
	r.data = &providerData{
		client:      &signari.Client{Endpoint: endpoint, Token: "t"},
		conditional: conditional,
	}
	return r
}

// Update takes the version out of STATE, not out of the plan.
//
// State holds what the last read observed; the plan holds what is wanted. Using
// the plan's value would be self-fulfilling -- it is computed, so it would carry
// whatever was already in state or be unknown, and either way the precondition
// would stop meaning "nothing changed since I looked".
func TestUpdateSendsThePreconditionFromState(t *testing.T) {
	srv, seen := recordingServer(t, http.StatusOK, `{"client_id":"app","config_version":99}`)
	r := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)

	// The plan carries a DIFFERENT version from state, so a resource that read the
	// wrong one fails here rather than passing by coincidence.
	resp := &resource.UpdateResponse{State: clientState(t, r, ty, true, 0)}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan:  tfsdk.Plan(clientState(t, r, ty, false, 7)),
		State: clientState(t, r, ty, true, 42),
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("update: %v", resp.Diagnostics)
	}
	if *seen == `"7"` {
		t.Fatal("If-Match came from the PLAN. The plan's config_version is computed " +
			"and does not describe what was observed, so the precondition would no " +
			"longer mean \"nothing changed since I read\"")
	}
	if *seen != `"42"` {
		t.Fatalf("If-Match = %q, want %q. The resource is not passing the observed "+
			"version to the client, so every apply is a last-write-wins overwrite", *seen, `"42"`)
	}
}

// Turning conditional_writes off really does turn it off.
//
// The escape hatch has to work, because it is the only thing an operator can
// reach for against a server that does not honour the header.
func TestConditionalWritesOffSendsNoPrecondition(t *testing.T) {
	srv, seen := recordingServer(t, http.StatusOK, `{"client_id":"app","config_version":99}`)
	r := newResource(t, srv.URL, false)
	_, ty := clientSchema(t)

	resp := &resource.UpdateResponse{State: clientState(t, r, ty, true, 0)}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan:  tfsdk.Plan(clientState(t, r, ty, false, 42)),
		State: clientState(t, r, ty, true, 42),
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("update: %v", resp.Diagnostics)
	}
	if *seen != "" {
		t.Errorf("If-Match = %q with conditional_writes off, want none", *seen)
	}
}

// A 412 surfaces as a Terraform ERROR with a remedy, not a silent success and
// not an opaque status code.
//
// An operator reading `terraform apply` output has to learn two things: nothing
// was written, and re-planning is the fix.
func TestAConflictBecomesAnActionableDiagnostic(t *testing.T) {
	srv, _ := recordingServer(t, http.StatusPreconditionFailed,
		`{"error":"precondition_failed","expected_version":42,"current_version":47}`)
	r := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)

	resp := &resource.UpdateResponse{State: clientState(t, r, ty, true, 42)}
	r.Update(context.Background(), resource.UpdateRequest{
		Plan:  tfsdk.Plan(clientState(t, r, ty, false, 42)),
		State: clientState(t, r, ty, true, 42),
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("a 412 produced no error, so Terraform would report the apply as " +
			"successful while nothing was written")
	}
	errs := resp.Diagnostics.Errors()

	// The SUMMARY is checked separately from the detail, and deliberately.
	//
	// Falling through to the generic "updating the client" branch also raises an
	// error carrying the same text, so a test that concatenated the two could not
	// tell the difference -- and a conflict would be reported to an operator as an
	// ordinary update failure. The summary is the line shown against the resource
	// in apply output, so it is the line that has to name the cause.
	var summaries string
	for _, d := range errs {
		summaries += d.Summary() + " "
	}
	if !strings.Contains(summaries, "changed") {
		t.Errorf("the diagnostic summary does not say the configuration changed, so "+
			"a concurrent write reads as a generic failure: %q", summaries)
	}

	var detail string
	for _, d := range errs {
		detail += d.Detail() + " "
	}
	for _, want := range []string{"42", "47", "plan"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the diagnostic is missing %q, which an operator needs to act: %s",
				want, detail)
		}
	}
}

// Destroy deletes (2.17). It disabled the client and warned, from before the
// Admin API had a delete, so the row stayed and a replacement could not create
// its successor under the same client id.
func TestDeleteDeletesTheClient(t *testing.T) {
	var method, path, ifMatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, ifMatch = r.Method, r.URL.Path, r.Header.Get("If-Match")
		w.Header().Set("ETag", `"99"`)
		fmt.Fprint(w, `{"client_id":"app","refresh_families_revoked":0}`)
	}))
	t.Cleanup(srv.Close)
	r := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)

	resp := &resource.DeleteResponse{State: clientState(t, r, ty, true, 42)}
	r.Delete(context.Background(), resource.DeleteRequest{
		State: clientState(t, r, ty, true, 42),
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("delete: %v", resp.Diagnostics)
	}
	if method != http.MethodDelete || path != "/admin/clients/app" {
		t.Errorf("destroy sent %s %s, want DELETE /admin/clients/app", method, path)
	}
	if ifMatch != `"42"` {
		t.Errorf("destroy sent If-Match %q, want %q: a destroy races exactly as an "+
			"update does", ifMatch, `"42"`)
	}
	if n := len(resp.Diagnostics.Warnings()); n != 0 {
		t.Errorf("a destroy that deleted the client warned %d time(s)", n)
	}
}

// Update carries `enabled`, the name and the redirect URIs (6.03), so every
// other attribute an operator can set must replace the client (2.17). Changing
// the redirect URIs was once an in-place
// update that sent `enabled` alone and wrote the new URIs into state: the
// apply reported success and the server kept the old ones. Derived from the
// schema, so an attribute added later fails here until it is either sent by
// Update or marked to replace.
func TestEveryAttributeUpdateCannotSendRequiresReplacement(t *testing.T) {
	ctx := context.Background()
	r := &clientResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, resp)

	inPlace := map[string]bool{"enabled": true, "display_name": true, "redirect_uris": true}
	replaces := func(descs []string) bool {
		for _, d := range descs {
			if strings.Contains(d, "destroy and recreate") {
				return true
			}
		}
		return false
	}
	for name, attr := range resp.Schema.Attributes {
		if inPlace[name] || !(attr.IsRequired() || attr.IsOptional()) {
			continue
		}
		var descs []string
		switch a := attr.(type) {
		case schema.StringAttribute:
			for _, m := range a.PlanModifiers {
				descs = append(descs, m.Description(ctx))
			}
		case schema.BoolAttribute:
			for _, m := range a.PlanModifiers {
				descs = append(descs, m.Description(ctx))
			}
		case schema.SetAttribute:
			for _, m := range a.PlanModifiers {
				descs = append(descs, m.Description(ctx))
			}
		default:
			t.Errorf("%s is a %T, which this test does not read; teach it", name, attr)
			continue
		}
		if !replaces(descs) {
			t.Errorf("%s can be changed in config, is not sent by Update, and does not "+
				"replace the client: an apply would report it changed and send nothing", name)
		}
	}

	// And Update sends exactly what inPlace says it does.
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPatch {
			_ = json.NewDecoder(req.Body).Decode(&sent)
		}
		w.Header().Set("ETag", `"99"`)
		fmt.Fprint(w, `{"client_id":"app","enabled":false}`)
	}))
	t.Cleanup(srv.Close)
	res := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)
	up := &resource.UpdateResponse{State: clientState(t, res, ty, true, 0)}
	res.Update(ctx, resource.UpdateRequest{
		Plan:  tfsdk.Plan(clientState(t, res, ty, false, 42)),
		State: clientState(t, res, ty, true, 42),
	}, up)
	if up.Diagnostics.HasError() {
		t.Fatalf("update: %v", up.Diagnostics)
	}
	for k := range sent {
		if !inPlace[k] {
			t.Errorf("Update sends %q, which inPlace does not list", k)
		}
	}
	for k := range inPlace {
		if _, ok := sent[k]; !ok {
			t.Errorf("inPlace lists %q, which Update does not send", k)
		}
	}
}

// Every write is read back, so state holds what the server holds (2.17). The
// server creates a client enabled whatever the request says, and names it
// after its id when no name is given; state used to record the plan instead.
func TestCreateRecordsWhatTheServerHolds(t *testing.T) {
	var calls []string
	enabled := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls = append(calls, req.Method)
		w.Header().Set("ETag", `"7"`)
		switch req.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"client_id":"app","client_secret":"shown-once","config_version":7}`)
		case http.MethodPatch:
			if got := req.Header.Get("If-Match"); got != `"7"` {
				t.Errorf("the disable after create sent If-Match %q, want the create's version", got)
			}
			enabled = false
			fmt.Fprint(w, `{"client_id":"app","enabled":false}`)
		default:
			fmt.Fprintf(w, `{"client_id":"app","org_id":"org-1","display_name":"app","client_type":"confidential",`+
				`"enabled":%v,"redirect_uris":["https://app.example/cb"]}`, enabled)
		}
	}))
	t.Cleanup(srv.Close)
	r := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)

	plan := clientState(t, r, ty, false, 0)
	plan.Raw = tftypes.NewValue(ty, map[string]tftypes.Value{
		"client_id":      tftypes.NewValue(tftypes.String, "app"),
		"org_id":         tftypes.NewValue(tftypes.String, "org-1"),
		"display_name":   tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"public":         tftypes.NewValue(tftypes.Bool, false),
		"redirect_uris":  oneRedirectURI(),
		"enabled":        tftypes.NewValue(tftypes.Bool, false),
		"client_secret":  tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"config_version": tftypes.NewValue(tftypes.Number, tftypes.UnknownValue),
	})
	resp := &resource.CreateResponse{State: clientState(t, r, ty, true, 0)}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("create: %v", resp.Diagnostics)
	}
	if fmt.Sprint(calls) != "[POST PATCH GET]" {
		t.Errorf("create made %v, want the create, the disable and a read back", calls)
	}
	var got clientModel
	resp.State.Get(context.Background(), &got)
	if got.Enabled.ValueBool() || got.DisplayName.ValueString() != "app" || got.ClientSecret.ValueString() != "shown-once" {
		t.Errorf("state after create: enabled %v, display_name %q, secret %q",
			got.Enabled, got.DisplayName, got.ClientSecret)
	}
}

// A read records the redirect URIs and whether the client is public, and keeps
// the state's URIs when the server does not report them, since an absent list
// is not an empty one (2.17).
func TestReadRecordsTheRedirectURIsWhenTheServerReportsThem(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{`{"client_id":"app","org_id":"org-1","client_type":"public","enabled":true,` +
			`"redirect_uris":["https://other.example/cb"]}`, "[https://other.example/cb]"},
		{`{"client_id":"app","org_id":"org-1","client_type":"public","enabled":true}`, "[https://app.example/cb]"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("ETag", `"77"`)
			fmt.Fprint(w, tc.body)
		}))
		r := newResource(t, srv.URL, true)
		_, ty := clientSchema(t)
		resp := &resource.ReadResponse{State: clientState(t, r, ty, true, 1)}
		r.Read(context.Background(), resource.ReadRequest{State: clientState(t, r, ty, true, 1)}, resp)
		srv.Close()
		if resp.Diagnostics.HasError() {
			t.Fatalf("read: %v", resp.Diagnostics)
		}
		var got clientModel
		resp.State.Get(context.Background(), &got)
		uris := setToStrings(context.Background(), got.RedirectURIs, &resp.Diagnostics)
		if fmt.Sprint(uris) != tc.want || !got.Public.ValueBool() {
			t.Errorf("from %s: state has redirect_uris %v, public %v; want %s and public",
				tc.body, uris, got.Public, tc.want)
		}
	}
}

// A destroy that would clobber a concurrent change is refused too.
func TestAConflictOnDestroyIsRefused(t *testing.T) {
	srv, _ := recordingServer(t, http.StatusPreconditionFailed,
		`{"error":"precondition_failed","expected_version":42,"current_version":47}`)
	r := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)

	resp := &resource.DeleteResponse{State: clientState(t, r, ty, true, 42)}
	r.Delete(context.Background(), resource.DeleteRequest{
		State: clientState(t, r, ty, true, 42),
	}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("a destroy proceeded through a precondition failure")
	}
	// As on the update path, the generic branch also raises an error carrying the
	// same text, so only the summary distinguishes "somebody else changed this"
	// from "the delete failed".
	var summaries string
	for _, d := range resp.Diagnostics.Errors() {
		summaries += d.Summary() + " "
	}
	if !strings.Contains(summaries, "changed") {
		t.Errorf("a destroy refused by a precondition is reported as a generic "+
			"failure: %q", summaries)
	}
	if len(resp.Diagnostics.Warnings()) != 0 {
		t.Error("a refused destroy still claimed the client had been disabled")
	}
}

// Read records the version the server reported, because that is what the next
// write is conditional on. A read that dropped it would leave state at zero and
// silently downgrade the following apply to unconditional.
func TestReadRecordsTheObservedVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"77"`)
		fmt.Fprint(w, `{"client_id":"app","org_id":"org-1","display_name":"An app","enabled":true}`)
	}))
	defer srv.Close()

	r := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)

	resp := &resource.ReadResponse{State: clientState(t, r, ty, true, 1)}
	r.Read(context.Background(), resource.ReadRequest{
		State: clientState(t, r, ty, true, 1),
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("read: %v", resp.Diagnostics)
	}
	var got clientModel
	resp.State.Get(context.Background(), &got)
	if got.ConfigVersion.ValueInt64() != 77 {
		t.Fatalf("state records config_version %d, want 77 from the ETag",
			got.ConfigVersion.ValueInt64())
	}
}

// A client removed outside Terraform drops out of state, so the next plan offers
// to recreate it instead of failing forever.
func TestAVanishedClientIsRemovedFromState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"client_not_found"}`)
	}))
	defer srv.Close()

	r := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)

	resp := &resource.ReadResponse{State: clientState(t, r, ty, true, 1)}
	r.Read(context.Background(), resource.ReadRequest{
		State: clientState(t, r, ty, true, 1),
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("a 404 became an error instead of a removal: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("the resource stayed in state after the server reported it gone")
	}
}
