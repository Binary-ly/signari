package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// harness drives one resource through the calls Terraform makes, with its
// model M as the plan and the state.
type harness[M any] struct {
	t   *testing.T
	ctx context.Context
	r   resource.Resource
	sch resource.SchemaResponse
}

func newHarness[M any](t *testing.T, r resource.Resource, data *providerData) *harness[M] {
	t.Helper()
	h := &harness[M]{t: t, ctx: context.Background(), r: r}
	r.Schema(h.ctx, resource.SchemaRequest{}, &h.sch)
	if h.sch.Diagnostics.HasError() {
		t.Fatalf("schema: %v", h.sch.Diagnostics)
	}
	cr := &resource.ConfigureResponse{}
	r.(resource.ResourceWithConfigure).Configure(h.ctx, resource.ConfigureRequest{ProviderData: data}, cr)
	return h
}

func (h *harness[M]) plan(m M) tfsdk.Plan {
	h.t.Helper()
	p := tfsdk.Plan{Schema: h.sch.Schema}
	if d := p.Set(h.ctx, m); d.HasError() {
		h.t.Fatal(d)
	}
	return p
}

func (h *harness[M]) state(m M) tfsdk.State {
	h.t.Helper()
	s := tfsdk.State{Schema: h.sch.Schema}
	if d := s.Set(h.ctx, m); d.HasError() {
		h.t.Fatal(d)
	}
	return s
}

func (h *harness[M]) model(s tfsdk.State) M {
	h.t.Helper()
	var m M
	if d := s.Get(h.ctx, &m); d.HasError() {
		h.t.Fatal(d)
	}
	return m
}

func (h *harness[M]) create(m M) (tfsdk.State, diag.Diagnostics) {
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: h.sch.Schema}}
	h.r.Create(h.ctx, resource.CreateRequest{Plan: h.plan(m)}, resp)
	return resp.State, resp.Diagnostics
}

// read refreshes, answering false when the object was removed from state.
func (h *harness[M]) read(s tfsdk.State) (tfsdk.State, bool, diag.Diagnostics) {
	resp := &resource.ReadResponse{State: s}
	h.r.Read(h.ctx, resource.ReadRequest{State: s}, resp)
	return resp.State, !resp.State.Raw.IsNull(), resp.Diagnostics
}

func (h *harness[M]) update(s tfsdk.State, m M) (tfsdk.State, diag.Diagnostics) {
	resp := &resource.UpdateResponse{State: s}
	h.r.Update(h.ctx, resource.UpdateRequest{Plan: h.plan(m), State: s}, resp)
	return resp.State, resp.Diagnostics
}

func (h *harness[M]) destroy(s tfsdk.State) diag.Diagnostics {
	resp := &resource.DeleteResponse{State: s}
	h.r.Delete(h.ctx, resource.DeleteRequest{State: s}, resp)
	return resp.Diagnostics
}

// null is the state of an object that does not exist yet.
func (h *harness[M]) null() tfsdk.State {
	return tfsdk.State{Schema: h.sch.Schema, Raw: tftypes.NewValue(h.sch.Schema.Type().TerraformType(h.ctx), nil)}
}

// planned is `terraform plan`: the configuration m over the prior state,
// through the resource's ModifyPlan when it has one.
func (h *harness[M]) planned(prior tfsdk.State, m M) (tfsdk.Plan, diag.Diagnostics) {
	p := h.plan(m)
	mp, ok := h.r.(resource.ResourceWithModifyPlan)
	if !ok {
		return p, nil
	}
	resp := &resource.ModifyPlanResponse{Plan: p}
	mp.ModifyPlan(h.ctx, resource.ModifyPlanRequest{Plan: p, State: prior,
		Config: tfsdk.Config{Schema: h.sch.Schema, Raw: p.Raw}}, resp)
	return resp.Plan, resp.Diagnostics
}

// createFrom and updateFrom apply a plan made by planned.
func (h *harness[M]) createFrom(p tfsdk.Plan) (tfsdk.State, diag.Diagnostics) {
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: h.sch.Schema}}
	h.r.Create(h.ctx, resource.CreateRequest{Plan: p}, resp)
	return resp.State, resp.Diagnostics
}

func (h *harness[M]) updateFrom(s tfsdk.State, p tfsdk.Plan) (tfsdk.State, diag.Diagnostics) {
	resp := &resource.UpdateResponse{State: s}
	h.r.Update(h.ctx, resource.UpdateRequest{Plan: p, State: s}, resp)
	return resp.State, resp.Diagnostics
}

// imported is `terraform import`: the id into an empty state, then a refresh.
func (h *harness[M]) imported(id string) (tfsdk.State, diag.Diagnostics) {
	// A null object of the schema's type, as Terraform starts an import.
	empty := tfsdk.State{Schema: h.sch.Schema,
		Raw: tftypes.NewValue(h.sch.Schema.Type().TerraformType(h.ctx), nil)}
	resp := &resource.ImportStateResponse{State: empty}
	h.r.(resource.ResourceWithImportState).ImportState(h.ctx, resource.ImportStateRequest{ID: id}, resp)
	if resp.Diagnostics.HasError() {
		return resp.State, resp.Diagnostics
	}
	st, _, d := h.read(resp.State)
	return st, d
}
