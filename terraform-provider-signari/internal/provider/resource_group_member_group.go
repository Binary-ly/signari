package provider

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// signari_group_member_group puts one group inside another, so everybody in it is in
// that one and every group above it, as signari_group_member puts a person in one.
// Read from the groups inside the group, which the API lists whole. A loop is refused
// by the engine; the token must be organisation-wide, and putting a group inside one
// that may impersonate needs privileged-users:write, as in the API.

func NewGroupMemberGroupResource() resource.Resource { return &groupMemberGroupResource{} }

type groupMemberGroupResource struct{ data *providerData }

type groupMemberGroupModel struct {
	ID            types.String `tfsdk:"id"`
	GroupID       types.String `tfsdk:"group_id"`
	MemberGroupID types.String `tfsdk:"member_group_id"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (r *groupMemberGroupResource) Metadata(_ context.Context, req resource.MetadataRequest,
	resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_member_group"
}

func (r *groupMemberGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "One group inside another: everybody in `member_group_id` is in `group_id` and " +
			"every group above it. Imported as `<group_id>/<member_group_id>`.",
		Attributes: map[string]schema.Attribute{
			"id":              idAttribute("nesting, `<group_id>/<member_group_id>`, which"),
			"group_id":        replacing("The group that gains the members."),
			"member_group_id": replacing("The group put inside it, of the same organisation."),
			"config_version":  versionAttribute(),
		},
	}
}

func (r *groupMemberGroupResource) Configure(_ context.Context, req resource.ConfigureRequest,
	resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func memberGroupPath(group, member string) string {
	return "/admin/groups/" + url.PathEscape(group) + "/member-groups/" + url.PathEscape(member)
}

func (r *groupMemberGroupResource) Create(ctx context.Context, req resource.CreateRequest,
	resp *resource.CreateResponse) {
	var plan groupMemberGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	group, member := plan.GroupID.ValueString(), plan.MemberGroupID.ValueString()
	version, err := r.data.change(ctx, http.MethodPut, memberGroupPath(group, member), nil, 0)
	if err != nil {
		failed(&resp.Diagnostics, "putting the group inside the other", err)
		return
	}
	plan.ID = types.StringValue(group + "/" + member)
	plan.ConfigVersion = types.Int64Value(version)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupMemberGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupMemberGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nested, version, err := r.data.client.IsNested(ctx, state.GroupID.ValueString(), state.MemberGroupID.ValueString())
	if errors.Is(err, signari.ErrNotFound) || (err == nil && !nested) {
		// The group is gone, or the other was taken out of it.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("reading the nesting", err.Error())
		return
	}
	state.ID = types.StringValue(state.GroupID.ValueString() + "/" + state.MemberGroupID.ValueString())
	state.ConfigVersion = types.Int64Value(version)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update has nothing to change: both attributes replace the nesting.
func (r *groupMemberGroupResource) Update(ctx context.Context, req resource.UpdateRequest,
	resp *resource.UpdateResponse) {
	var plan groupMemberGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupMemberGroupResource) Delete(ctx context.Context, req resource.DeleteRequest,
	resp *resource.DeleteResponse) {
	var state groupMemberGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.remove(ctx, memberGroupPath(state.GroupID.ValueString(), state.MemberGroupID.ValueString()),
		state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "taking the group out of the other", err)
	}
}

func (r *groupMemberGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	group, member, ok := strings.Cut(req.ID, "/")
	if !ok || group == "" || member == "" {
		resp.Diagnostics.AddError("not a nesting", "import one as <group_id>/<member_group_id>")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group_id"), group)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("member_group_id"), member)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
