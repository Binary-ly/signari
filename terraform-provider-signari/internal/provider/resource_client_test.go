package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
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
		"redirect_uris":  tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, nil),
		"enabled":        tftypes.NewValue(tftypes.Bool, enabled),
		"client_secret":  tftypes.NewValue(tftypes.String, "s3cret"),
		"config_version": tftypes.NewValue(tftypes.Number, configVersion),
	})
	return tfsdk.State{Schema: resp.Schema, Raw: raw}
}

// recordingServer captures the If-Match of the last write.
func recordingServer(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("If-Match")
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

// Delete disables, and says so.
//
// The Admin API has no client delete. Removing the resource from state while the
// client kept working would be the worst outcome: Terraform reports it destroyed
// and every application using it carries on signing people in.
func TestDeleteDisablesAndWarnsThatTheRecordRemains(t *testing.T) {
	srv, seen := recordingServer(t, http.StatusOK, `{"client_id":"app","config_version":99}`)
	r := newResource(t, srv.URL, true)
	_, ty := clientSchema(t)

	resp := &resource.DeleteResponse{State: clientState(t, r, ty, true, 42)}
	r.Delete(context.Background(), resource.DeleteRequest{
		State: clientState(t, r, ty, true, 42),
	}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("delete: %v", resp.Diagnostics)
	}
	if *seen != `"42"` {
		t.Errorf("destroy sent If-Match %q, want %q: a destroy races exactly as an "+
			"update does", *seen, `"42"`)
	}
	if len(resp.Diagnostics.Warnings()) == 0 {
		t.Fatal("destroy gave no warning that the client was only disabled")
	}
	w := resp.Diagnostics.Warnings()[0].Detail()
	if !strings.Contains(w, "disabled") {
		t.Errorf("the warning does not say the client was disabled rather than "+
			"deleted: %s", w)
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
	// from "the disable call failed".
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
