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

// signari_group_member puts one person in one group. A membership has no read
// of its own; the group's members are paged to find it. Joining a group that
// may impersonate needs a token holding privileged-users:write, as in the API.

func NewGroupMemberResource() resource.Resource { return &groupMemberResource{} }

type groupMemberResource struct{ data *providerData }

type groupMemberModel struct {
	ID            types.String `tfsdk:"id"`
	GroupID       types.String `tfsdk:"group_id"`
	UserID        types.String `tfsdk:"user_id"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (r *groupMemberResource) Metadata(_ context.Context, req resource.MetadataRequest,
	resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_member"
}

func (r *groupMemberResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "One person's membership of one group. Imported as `<group_id>/<user_id>`.",
		Attributes: map[string]schema.Attribute{
			"id":             idAttribute("membership, `<group_id>/<user_id>`, which"),
			"group_id":       replacing("The group."),
			"user_id":        replacing("The person, of the group's organisation."),
			"config_version": versionAttribute(),
		},
	}
}

func (r *groupMemberResource) Configure(_ context.Context, req resource.ConfigureRequest,
	resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func memberPath(group, user string) string {
	return "/admin/groups/" + url.PathEscape(group) + "/members/" + url.PathEscape(user)
}

func (r *groupMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	group, user := plan.GroupID.ValueString(), plan.UserID.ValueString()
	version, err := r.data.change(ctx, http.MethodPut, memberPath(group, user), nil, 0)
	if err != nil {
		failed(&resp.Diagnostics, "adding the member", err)
		return
	}
	plan.ID = types.StringValue(group + "/" + user)
	plan.ConfigVersion = types.Int64Value(version)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	member, version, err := r.data.client.IsMember(ctx, state.GroupID.ValueString(), state.UserID.ValueString())
	if errors.Is(err, signari.ErrNotFound) || (err == nil && !member) {
		// The group is gone, or they were taken out of it.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("reading the membership", err.Error())
		return
	}
	state.ID = types.StringValue(state.GroupID.ValueString() + "/" + state.UserID.ValueString())
	state.ConfigVersion = types.Int64Value(version)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update has nothing to change: both attributes replace the membership.
func (r *groupMemberResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan groupMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.remove(ctx, memberPath(state.GroupID.ValueString(), state.UserID.ValueString()),
		state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "removing the member", err)
	}
}

func (r *groupMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	group, user, ok := strings.Cut(req.ID, "/")
	if !ok || group == "" || user == "" {
		resp.Diagnostics.AddError("not a membership", "import one as <group_id>/<user_id>")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group_id"), group)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("user_id"), user)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
