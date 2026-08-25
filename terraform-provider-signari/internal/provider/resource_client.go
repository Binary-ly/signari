package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// signari_client manages an OAuth client.
//
// # The config_version attribute, and why it is in state
//
// Every read records the configuration version the resource was observed at, and
// every update sends it back as `If-Match`. That is what makes an apply refuse
// rather than clobber when something changed after the plan was produced.
//
// It is marked computed and NOT tracked for drift: it moves whenever ANY
// configuration in the deployment changes, so treating a change in it as a
// change to this resource would produce a permanent diff on every plan. It is
// state that exists to be sent back, not a property of the client.

func NewClientResource() resource.Resource { return &clientResource{} }

type clientResource struct{ data *providerData }

type clientModel struct {
	ClientID     types.String `tfsdk:"client_id"`
	OrgID        types.String `tfsdk:"org_id"`
	DisplayName  types.String `tfsdk:"display_name"`
	Public       types.Bool   `tfsdk:"public"`
	RedirectURIs types.List   `tfsdk:"redirect_uris"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	// ClientSecret is returned once, at creation, and never again.
	ClientSecret types.String `tfsdk:"client_secret"`
	// ConfigVersion is the precondition for the next write.
	ConfigVersion types.Int64 `tfsdk:"config_version"`
}

func (r *clientResource) Metadata(_ context.Context, req resource.MetadataRequest,
	resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_client"
}

func (r *clientResource) Schema(_ context.Context, _ resource.SchemaRequest,
	resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An OAuth 2.0 / OIDC client.",
		Attributes: map[string]schema.Attribute{
			"client_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The client identifier. Changing it replaces the client.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"org_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Organisation UUID the client belongs to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"display_name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Human-readable name.",
			},
			"public": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "A public client has no secret. Changing this " +
					"replaces the client, because a public client cannot grow a secret.",
				Default: booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					boolRequiresReplace(),
				},
			},
			"redirect_uris": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Registered redirect URIs.",
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether the client may be used. Disabling is the emergency lever.",
			},
			"client_secret": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				MarkdownDescription: "Shown once, at creation. Empty for a public client, " +
					"and empty on any later read because the server stores only a hash.",
			},
			"config_version": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "The deployment's configuration version when this " +
					"resource was last read. Sent as `If-Match` on the next update so a " +
					"concurrent change is refused rather than overwritten.",
			},
		},
	}
}

func (r *clientResource) Configure(_ context.Context, req resource.ConfigureRequest,
	resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError("unexpected provider data",
			fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.data = data
}

func (r *clientResource) Create(ctx context.Context, req resource.CreateRequest,
	resp *resource.CreateResponse) {

	var plan clientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in := signari.ClientResource{
		ClientID:     plan.ClientID.ValueString(),
		OrgID:        plan.OrgID.ValueString(),
		DisplayName:  plan.DisplayName.ValueString(),
		Public:       plan.Public.ValueBool(),
		RedirectURIs: listToStrings(ctx, plan.RedirectURIs, &resp.Diagnostics),
		Enabled:      plan.Enabled.ValueBool(),
	}
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.data.client.CreateClient(ctx, in)
	if err != nil {
		resp.Diagnostics.AddError("creating the client", err.Error())
		return
	}

	// The secret is returned exactly once. Anything that loses it here loses it
	// permanently, because the server keeps only a hash.
	var created struct {
		ClientSecret  string `json:"client_secret"`
		ConfigVersion int64  `json:"config_version"`
	}
	decodeInto(res.Body, &created)

	plan.ClientSecret = types.StringValue(created.ClientSecret)
	plan.ConfigVersion = types.Int64Value(pick(res.Version, created.ConfigVersion))
	if plan.DisplayName.IsUnknown() {
		plan.DisplayName = types.StringValue(in.DisplayName)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *clientResource) Read(ctx context.Context, req resource.ReadRequest,
	resp *resource.ReadResponse) {

	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	got, version, err := r.data.client.GetClient(ctx, state.ClientID.ValueString())
	if errors.Is(err, signari.ErrNotFound) {
		// Removed outside Terraform. Dropping it from state is what lets the next
		// plan offer to recreate it, rather than failing forever.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("reading the client", err.Error())
		return
	}

	state.DisplayName = types.StringValue(got.DisplayName)
	state.Enabled = types.BoolValue(got.Enabled)
	state.OrgID = types.StringValue(got.OrgID)
	// The version observed by THIS read is what the next write is conditional on.
	state.ConfigVersion = types.Int64Value(version)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *clientResource) Update(ctx context.Context, req resource.UpdateRequest,
	resp *resource.UpdateResponse) {

	var plan, state clientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The precondition, taken from the version the last READ observed. This is
	// the line that makes a concurrent change a failure rather than a silent
	// overwrite.
	ifMatch := int64(0)
	if r.data.conditional {
		ifMatch = state.ConfigVersion.ValueInt64()
	}

	res, err := r.data.client.SetClientEnabled(ctx,
		plan.ClientID.ValueString(), plan.Enabled.ValueBool(), ifMatch)

	var conflict *signari.ErrConflict
	if errors.As(err, &conflict) {
		// Reported as its own diagnostic, with the remedy, because "412" on its
		// own sends somebody reading HTTP specifications instead of re-planning.
		resp.Diagnostics.AddError("the configuration changed since this plan was made",
			conflict.Error())
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("updating the client", err.Error())
		return
	}

	plan.ClientSecret = state.ClientSecret
	plan.ConfigVersion = types.Int64Value(res.Version)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *clientResource) Delete(ctx context.Context, req resource.DeleteRequest,
	resp *resource.DeleteResponse) {

	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The Admin API has no client delete today, so the honest destroy is to
	// DISABLE the client -- which is the operation that actually stops it being
	// used -- and say plainly that the row remains.
	//
	// Silently removing it from state while it kept working would be the worst of
	// the options: Terraform would report the client destroyed while every
	// application using it carried on signing people in.
	ifMatch := int64(0)
	if r.data.conditional {
		ifMatch = state.ConfigVersion.ValueInt64()
	}
	_, err := r.data.client.SetClientEnabled(ctx, state.ClientID.ValueString(), false, ifMatch)

	var conflict *signari.ErrConflict
	if errors.As(err, &conflict) {
		resp.Diagnostics.AddError("the configuration changed since this plan was made",
			conflict.Error())
		return
	}
	if err != nil && !errors.Is(err, signari.ErrNotFound) {
		resp.Diagnostics.AddError("disabling the client", err.Error())
		return
	}
	resp.Diagnostics.AddWarning("the client was disabled, not deleted",
		fmt.Sprintf("Signari's Admin API has no client-delete operation, so %q has "+
			"been disabled and can no longer be used. Its record remains, which is "+
			"what keeps its audit history intact. Remove it with the CLI if you need "+
			"the row gone.", state.ClientID.ValueString()))
}

func (r *clientResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("client_id"), req, resp)
}
