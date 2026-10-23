package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// signari_organization_configuration applies an organisation's configuration
// file through the Admin API (POST /admin/organizations/{id}/config), the
// writer `signari plan` and `apply` use (6.17). It declares everything the
// file format does -- attributes, claim mappers, identity providers, SAML
// providers, the access policy, the sign-in flow and the rest, each checked by
// its own writer's rules -- without a resource of its own for each.
//
// The plan shows the engine's own plan: `changes` is the dry run of the
// planned document, so `terraform plan` lists what will be created, updated
// and deleted. A refresh runs the dry run of the document in state: anything
// the deployment moved away from it is `drift`, and drift plans an apply that
// puts it back. Secrets the apply minted are in `minted`, once, as the server
// shows them once.
//
// Destroying the resource forgets the document and deletes nothing it
// declared, and says so: a destroy that pruned the organisation empty would be
// the most destructive thing a provider could do by accident.

func NewConfigurationResource() resource.Resource { return &configurationResource{} }

type configurationResource struct{ data *providerData }

type configurationModel struct {
	ID            types.String `tfsdk:"id"`
	OrgID         types.String `tfsdk:"org_id"`
	Document      types.String `tfsdk:"document"`
	Prune         types.Bool   `tfsdk:"prune"`
	Changes       types.List   `tfsdk:"changes"`
	Drift         types.List   `tfsdk:"drift"`
	Minted        types.Map    `tfsdk:"minted"`
	PlannedAt     types.Int64  `tfsdk:"planned_at"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (r *configurationResource) Metadata(_ context.Context, req resource.MetadataRequest,
	resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_organization_configuration"
}

func (r *configurationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An organisation's configuration file, applied as `signari apply` applies it. " +
			"Imported by the organisation id, with the document then set in the configuration.",
		Attributes: map[string]schema.Attribute{
			"id":     idAttribute("configuration, the organisation id,"),
			"org_id": replacing("The organisation."),
			"document": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The file, YAML, as `signari plan` reads it (see config-as-code.md). One " +
					"naming a secret by reference is refused: the server cannot read the operator's environment.",
			},
			"prune": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				MarkdownDescription: "Delete what the file does not declare, as `apply -prune` does.",
			},
			"changes": schema.ListAttribute{
				Computed: true, ElementType: types.StringType,
				MarkdownDescription: "What the last plan or apply changed: the engine's own plan, one line each.",
			},
			"drift": schema.ListAttribute{
				Computed: true, ElementType: types.StringType,
				MarkdownDescription: "What the deployment holds differently from the document, at the last " +
					"refresh. Not empty plans an apply that puts it back.",
			},
			"minted": schema.MapAttribute{
				Computed: true, Sensitive: true, ElementType: types.StringType,
				MarkdownDescription: "Secrets and tokens the last apply minted, by `<kind>/<name>`: shown by the " +
					"server once and kept here, so give each to what it names.",
				PlanModifiers: []planmodifier.Map{mapplanmodifier.UseStateForUnknown()},
			},
			"planned_at": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "The configuration version the plan's dry run was computed at. The apply is " +
					"sent it as `If-Match`, so a deployment that moved after `terraform plan` is refused, not " +
					"overwritten with a plan nobody read.",
			},
			"config_version": versionAttribute(),
		},
	}
}

func (r *configurationResource) Configure(_ context.Context, req resource.ConfigureRequest,
	resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func configPath(org string) string { return organizationPath(org) + "/config" }

// configAnswer is what the route answers, planned or applied.
type configAnswer struct {
	Changes []struct {
		Action      string `json:"action"`
		Kind        string `json:"kind"`
		Name        string `json:"name"`
		Detail      string `json:"detail"`
		Destructive bool   `json:"destructive"`
	} `json:"changes"`
	ConfigVersion int64 `json:"config_version"`
	Minted        []struct {
		Kind   string `json:"kind"`
		Name   string `json:"name"`
		Secret string `json:"secret"`
	} `json:"minted"`
}

func (a configAnswer) lines() []string {
	out := []string{}
	for _, c := range a.Changes {
		line := c.Action + " " + c.Kind + " " + c.Name
		if c.Detail != "" {
			line += ": " + c.Detail
		}
		if c.Destructive {
			line += " (destructive)"
		}
		out = append(out, line)
	}
	return out
}

// send posts the document, a dry run or an apply; an apply goes through the
// write chain, conditional on the version the resource was read at.
func (r *configurationResource) send(ctx context.Context, org, document string, prune, dryRun bool,
	read int64) (configAnswer, error) {
	var answer configAnswer
	body := map[string]any{"document": document, "prune": prune, "dry_run": dryRun}
	call := func(ifMatch int64) (int64, error) {
		res, err := r.data.client.Do(ctx, http.MethodPost, configPath(org), body, ifMatch)
		if err != nil {
			return 0, err
		}
		if err := json.Unmarshal(res.Body, &answer); err != nil {
			return 0, fmt.Errorf("decoding the plan: %w", err)
		}
		return pick(res.Version, answer.ConfigVersion), nil
	}
	if dryRun {
		_, err := call(0)
		return answer, err
	}
	err := r.data.write(read, call)
	return answer, err
}

func stringList(ctx context.Context, s []string, diags *diag.Diagnostics) types.List {
	l, d := types.ListValueFrom(ctx, types.StringType, s)
	diags.Append(d...)
	return l
}

// ModifyPlan puts the engine's plan of the planned document in `changes`, and
// plans an apply over drift found at the last refresh.
func (r *configurationResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.data == nil {
		return // destroy, or not yet configured
	}
	var plan configurationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || plan.Document.IsUnknown() || plan.OrgID.IsUnknown() {
		return
	}
	answer, err := r.send(ctx, plan.OrgID.ValueString(), plan.Document.ValueString(), plan.Prune.ValueBool(), true, 0)
	if err != nil {
		resp.Diagnostics.AddError("planning the configuration", err.Error())
		return
	}
	lines := answer.lines()
	switch {
	case len(lines) > 0:
		// An apply will run, conditional on the version this dry run saw;
		// what it reads back and mints is known after.
		plan.Changes = stringList(ctx, lines, &resp.Diagnostics)
		plan.PlannedAt = types.Int64Value(answer.ConfigVersion)
		plan.Drift = types.ListUnknown(types.StringType)
		plan.Minted = types.MapUnknown(types.StringType)
		plan.ConfigVersion = types.Int64Unknown()
	case !req.State.Raw.IsNull():
		// Nothing to do: everything computed stays as it is, or every plan
		// would differ from the last apply's lines.
		var state configurationModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		plan.Changes, plan.Drift, plan.Minted = state.Changes, state.Drift, state.Minted
		plan.PlannedAt, plan.ConfigVersion = state.PlannedAt, state.ConfigVersion
	default:
		plan.Changes = stringList(ctx, lines, &resp.Diagnostics)
		plan.PlannedAt = types.Int64Value(answer.ConfigVersion)
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

// apply applies the document, keeping the secrets earlier applies minted
// beside this one's.
func (r *configurationResource) apply(ctx context.Context, m *configurationModel, before types.Map,
	diags *diag.Diagnostics) {
	answer, err := r.send(ctx, m.OrgID.ValueString(), m.Document.ValueString(), m.Prune.ValueBool(), false,
		m.PlannedAt.ValueInt64())
	if err != nil {
		failed(diags, "applying the configuration", err)
		return
	}
	minted := map[string]string{}
	if !before.IsNull() && !before.IsUnknown() {
		diags.Append(before.ElementsAs(ctx, &minted, false)...)
	}
	for _, s := range answer.Minted {
		minted[s.Kind+"/"+s.Name] = s.Secret
	}
	mv, d := types.MapValueFrom(ctx, types.StringType, minted)
	diags.Append(d...)
	m.Minted = mv
	m.ID = types.StringValue(m.OrgID.ValueString())
	if m.Changes.IsUnknown() || m.Changes.IsNull() {
		m.Changes = stringList(ctx, answer.lines(), diags)
	}
	if m.PlannedAt.IsUnknown() || m.PlannedAt.IsNull() {
		m.PlannedAt = types.Int64Value(0)
	}
	r.refresh(ctx, m, diags)
}

// refresh records what the deployment holds differently from the document.
func (r *configurationResource) refresh(ctx context.Context, m *configurationModel, diags *diag.Diagnostics) {
	answer, err := r.send(ctx, m.OrgID.ValueString(), m.Document.ValueString(), m.Prune.ValueBool(), true, 0)
	if err != nil {
		diags.AddError("reading the configuration", err.Error())
		return
	}
	m.Drift = stringList(ctx, answer.lines(), diags)
	m.ConfigVersion = types.Int64Value(answer.ConfigVersion)
}

func (r *configurationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan configurationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, types.MapNull(types.StringType), &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *configurationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state configurationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.Document.IsNull() || state.Document.ValueString() == "" {
		// Imported: nothing to compare until the configuration sets it.
		state.Drift = stringList(ctx, nil, &resp.Diagnostics)
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
		return
	}
	r.refresh(ctx, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *configurationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state configurationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, state.Minted, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *configurationResource) Delete(_ context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state configurationModel
	resp.Diagnostics.Append(req.State.Get(context.Background(), &state)...)
	resp.Diagnostics.AddWarning("the configuration's objects were left in place",
		"Destroying signari_organization_configuration forgets the document and deletes nothing it declared. "+
			"To remove what it declared, apply a smaller document with prune = true first.")
}

func (r *configurationResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("org_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("document"), "")...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("prune"), false)...)
}
