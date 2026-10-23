package provider

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// signari_group manages a group. Its name is what policies, releases and
// directory maps name, so it replaces the group when changed; the display
// name and description change in place. `may_impersonate` is reported and set
// only on the command line, where the person running it is on the host.

func NewGroupResource() resource.Resource { return &groupResource{} }

type groupResource struct{ data *providerData }

type groupModel struct {
	ID             types.String `tfsdk:"id"`
	OrgID          types.String `tfsdk:"org_id"`
	Name           types.String `tfsdk:"name"`
	DisplayName    types.String `tfsdk:"display_name"`
	Description    types.String `tfsdk:"description"`
	MayImpersonate types.Bool   `tfsdk:"may_impersonate"`
	ConfigVersion  types.Int64  `tfsdk:"config_version"`
}

func (r *groupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *groupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A group: who is in it is what policies, application releases and directory " +
			"maps decide on.",
		Attributes: map[string]schema.Attribute{
			"id":     idAttribute("group"),
			"org_id": replacing("The organisation the group belongs to."),
			"name": replacing("The name policies and releases refer to: letters, digits, dots, hyphens " +
				"and underscores, at most 64."),
			"display_name": schema.StringAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "The name people see. Omitted, the server uses the name. Changed in place.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"description": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString(""),
				MarkdownDescription: "Changed in place.",
			},
			"may_impersonate": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether members may act as other people. Reported, and set only with " +
					"`signari group impersonation`, so that a token cannot grant itself the power.",
			},
			"config_version": versionAttribute(),
		},
	}
}

func (r *groupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func groupPath(id string) string { return "/admin/groups/" + url.PathEscape(id) }

// readGroup copies the server's group into m, answering false when it is gone.
func (r *groupResource) readGroup(ctx context.Context, m *groupModel, diags *diag.Diagnostics) bool {
	var g signari.Group
	version, err := r.data.client.Get(ctx, groupPath(m.ID.ValueString()), &g)
	if errors.Is(err, signari.ErrNotFound) {
		return false
	}
	if err != nil {
		diags.AddError("reading the group", err.Error())
		return true
	}
	m.OrgID, m.Name = types.StringValue(g.OrgID), types.StringValue(g.Name)
	m.DisplayName, m.Description = types.StringValue(g.DisplayName), types.StringValue(g.Description)
	m.MayImpersonate = types.BoolValue(g.MayImpersonate)
	m.ConfigVersion = types.Int64Value(version)
	return true
}

func (r *groupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]string{"org_id": plan.OrgID.ValueString(), "name": plan.Name.ValueString(),
		"description": plan.Description.ValueString()}
	if !plan.DisplayName.IsUnknown() && !plan.DisplayName.IsNull() {
		body["display_name"] = plan.DisplayName.ValueString()
	}
	id, _, err := r.data.create(ctx, "/admin/groups", body)
	if err != nil {
		failed(&resp.Diagnostics, "creating the group", err)
		return
	}
	plan.ID = types.StringValue(id)
	r.readGroup(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readGroup(ctx, &state, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *groupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.data.change(ctx, http.MethodPatch, groupPath(state.ID.ValueString()), map[string]string{
		"display_name": plan.DisplayName.ValueString(), "description": plan.Description.ValueString(),
	}, state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "updating the group", err)
		return
	}
	plan.ID = state.ID
	r.readGroup(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Its memberships go with it, in the same transaction.
	if err := r.data.remove(ctx, groupPath(state.ID.ValueString()), state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "deleting the group", err)
	}
}

func (r *groupResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
