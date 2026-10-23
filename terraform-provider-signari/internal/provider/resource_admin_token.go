package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// signari_admin_token mints an Admin API token for another automation, no
// wider than the token the provider holds, as the API refuses any wider.
// Nothing about a token changes in place, so every attribute replaces it;
// the secret is in state from the apply that minted it, once, since the
// server keeps only a hash. Destroying it revokes it.

func NewAdminTokenResource() resource.Resource { return &adminTokenResource{} }

type adminTokenResource struct{ data *providerData }

type adminTokenModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	Scopes     types.Set    `tfsdk:"scopes"`
	OrgID      types.String `tfsdk:"org_id"`
	ClientIDs  types.Set    `tfsdk:"client_ids"`
	GroupIDs   types.Set    `tfsdk:"group_ids"`
	ExpiresInS types.Int64  `tfsdk:"expires_in_s"`
	Secret     types.String `tfsdk:"secret"`
	ExpiresAt  types.String `tfsdk:"expires_at"`
}

func (r *adminTokenResource) Metadata(_ context.Context, req resource.MetadataRequest,
	resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_admin_token"
}

func replacingSet(description string, required bool) schema.SetAttribute {
	return schema.SetAttribute{Required: required, Optional: !required, ElementType: types.StringType,
		MarkdownDescription: description + " Changing it replaces the token.",
		PlanModifiers:       []planmodifier.Set{setplanmodifier.RequiresReplace()}}
}

func (r *adminTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An Admin API token for another automation. Destroying it revokes it.",
		Attributes: map[string]schema.Attribute{
			"id":     idAttribute("token"),
			"name":   replacing("What it is for."),
			"scopes": replacingSet("What it may do, no more than the provider's own token.", true),
			"org_id": schema.StringAttribute{Optional: true,
				MarkdownDescription: "The organisation it is limited to; left out, none. Changing it replaces the token.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"client_ids": replacingSet("The applications it is limited to; left out, every one.", false),
			"group_ids":  replacingSet("The groups it is limited to; left out, every one.", false),
			"expires_in_s": schema.Int64Attribute{Optional: true,
				MarkdownDescription: "Seconds it lasts; left out, ninety days, and 0 for never. Changing it " +
					"replaces the token.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}},
			"secret": schema.StringAttribute{Computed: true, Sensitive: true,
				MarkdownDescription: "The token, from the apply that minted it; empty once imported.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"expires_at": schema.StringAttribute{Computed: true, MarkdownDescription: "When it expires.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		},
	}
}

func (r *adminTokenResource) Configure(_ context.Context, req resource.ConfigureRequest,
	resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func (r *adminTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan adminTokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]any{"name": plan.Name.ValueString(),
		"scopes":     setToStrings(ctx, plan.Scopes, &resp.Diagnostics),
		"client_ids": setToStrings(ctx, plan.ClientIDs, &resp.Diagnostics),
		"group_ids":  setToStrings(ctx, plan.GroupIDs, &resp.Diagnostics),
		"org_id":     plan.OrgID.ValueString()}
	if !plan.ExpiresInS.IsNull() {
		body["expires_in_s"] = plan.ExpiresInS.ValueInt64()
	}
	var minted struct {
		ID        string `json:"id"`
		Secret    string `json:"secret"`
		ExpiresAt string `json:"expires_at"`
	}
	err := r.data.write(0, func(ifMatch int64) (int64, error) {
		res, err := r.data.client.Do(ctx, "POST", "/admin/tokens", body, ifMatch)
		if err != nil {
			return 0, err
		}
		decodeInto(res.Body, &minted)
		return res.Version, nil
	})
	if err != nil {
		failed(&resp.Diagnostics, "minting the token", err)
		return
	}
	plan.ID, plan.Secret = types.StringValue(minted.ID), types.StringValue(minted.Secret)
	plan.ExpiresAt = types.StringValue(minted.ExpiresAt)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// tokenView is a token as the list reports it.
type tokenView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	OrgID     *string  `json:"org_id"`
	Scopes    []string `json:"scopes"`
	ClientIDs []string `json:"client_ids"`
	GroupIDs  []string `json:"group_ids"`
	ExpiresAt *string  `json:"expires_at"`
	RevokedAt *string  `json:"revoked_at"`
}

// held finds the token in the list, nil once it is revoked or gone.
func (r *adminTokenResource) held(ctx context.Context, id string) (*tokenView, error) {
	var found *tokenView
	_, err := r.data.client.List(ctx, "/admin/tokens", "tokens", func(raw json.RawMessage) error {
		var t tokenView
		if json.Unmarshal(raw, &t) == nil && t.ID == id && t.RevokedAt == nil {
			found = &t
		}
		return nil
	})
	return found, err
}

// setOf is a list as a set attribute, null when empty, as the configuration
// leaves an unlimited token's lists out.
func setOf(ctx context.Context, s []string) types.Set {
	if len(s) == 0 {
		return types.SetNull(types.StringType)
	}
	v, _ := types.SetValueFrom(ctx, types.StringType, s)
	return v
}

func (r *adminTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state adminTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.held(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("reading the token", err.Error())
		return
	}
	if t == nil {
		// Revoked outside Terraform, so the next plan mints another.
		resp.State.RemoveResource(ctx)
		return
	}
	state.Name, state.Scopes = types.StringValue(t.Name), setOf(ctx, t.Scopes)
	state.ClientIDs, state.GroupIDs = setOf(ctx, t.ClientIDs), setOf(ctx, t.GroupIDs)
	if t.OrgID != nil && *t.OrgID != "" {
		state.OrgID = types.StringValue(*t.OrgID)
	} else {
		state.OrgID = types.StringNull()
	}
	if t.ExpiresAt != nil && (state.ExpiresAt.IsNull() || state.ExpiresAt.ValueString() == "") {
		state.ExpiresAt = types.StringValue(*t.ExpiresAt)
	}
	if state.Secret.IsNull() {
		state.Secret = types.StringValue("")
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update has nothing to change: every attribute replaces the token.
func (r *adminTokenResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan adminTokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *adminTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state adminTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.remove(ctx, "/admin/tokens/"+url.PathEscape(state.ID.ValueString()), 0); err != nil &&
		!errors.Is(err, signari.ErrNotFound) {
		failed(&resp.Diagnostics, "revoking the token", err)
	}
}

func (r *adminTokenResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
