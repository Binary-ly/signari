package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
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
//
// # What an apply can change in place
//
// Only `enabled`. The Admin API cannot yet rename a client or change its
// redirect URIs, so a change to either replaces the client, and the plan says
// so. It used to be an in-place update that sent `enabled` alone and recorded
// the new values in state: the apply reported success, a fresh plan was empty,
// and the server still held the old URIs. Every write is read back, so state
// holds what the server holds rather than what was asked for.

func NewClientResource() resource.Resource { return &clientResource{} }

type clientResource struct{ data *providerData }

type clientModel struct {
	ClientID     types.String `tfsdk:"client_id"`
	OrgID        types.String `tfsdk:"org_id"`
	DisplayName  types.String `tfsdk:"display_name"`
	Public       types.Bool   `tfsdk:"public"`
	RedirectURIs types.Set    `tfsdk:"redirect_uris"`
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
				Optional: true,
				Computed: true,
				MarkdownDescription: "Human-readable name; omitted, the server uses the client " +
					"id. Changed in place.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
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
			// A set, because the server holds one: a reordered list is the same
			// registration, and must not read as a change.
			"redirect_uris": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Registered redirect URIs, at least one. Changed in place.",
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
		RedirectURIs: setToStrings(ctx, plan.RedirectURIs, &resp.Diagnostics),
		Enabled:      plan.Enabled.ValueBool(),
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// The secret is returned exactly once. Anything that loses it here loses it
	// permanently, because the server keeps only a hash.
	var created struct {
		ClientSecret  string `json:"client_secret"`
		ConfigVersion int64  `json:"config_version"`
	}
	var version int64
	err := r.data.write(0, func(int64) (int64, error) {
		res, err := r.data.client.CreateClient(ctx, in)
		if err != nil {
			return 0, err
		}
		decodeInto(res.Body, &created)
		version = pick(res.Version, created.ConfigVersion)
		return version, nil
	})
	if err != nil {
		resp.Diagnostics.AddError("creating the client", err.Error())
		return
	}
	plan.ClientSecret = types.StringValue(created.ClientSecret)

	// A client is created enabled; the create request has no say in it. So
	// `enabled = false` is a second write, conditional on the version the
	// create produced, and without it the client would be live while state
	// said it was not.
	if !plan.Enabled.ValueBool() {
		if err := r.data.write(version, func(ifMatch int64) (int64, error) {
			res, err := r.data.client.SetClientEnabled(ctx, in.ClientID, false, ifMatch)
			if err != nil {
				return 0, err
			}
			return res.Version, nil
		}); err != nil {
			// The client exists, so it is recorded as it is, which taints it,
			// rather than lost from state with its secret.
			resp.Diagnostics.AddError("disabling the new client", err.Error())
		}
	}
	r.readBack(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// readBack replaces m's server-held fields with what the server reports, so
// state records what was applied rather than what was asked for. A write the
// server did not take then shows up as a difference, at the apply that made
// it, instead of as an empty plan over a server that disagrees.
func (r *clientResource) readBack(ctx context.Context, m *clientModel, diags *diag.Diagnostics) {
	got, version, err := r.data.client.GetClient(ctx, m.ClientID.ValueString())
	if err != nil {
		diags.AddError("reading the client back", err.Error())
		return
	}
	applyServerState(ctx, m, got, version, diags)
}

// applyServerState copies a server read into the model.
func applyServerState(ctx context.Context, m *clientModel, got *signari.ClientState, version int64,
	diags *diag.Diagnostics) {
	m.DisplayName = types.StringValue(got.DisplayName)
	m.Enabled = types.BoolValue(got.Enabled)
	m.OrgID = types.StringValue(got.OrgID)
	m.Public = types.BoolValue(got.ClientType == "public")
	// Left as it was when the server does not report them: an absent list is
	// not an empty one, and reading it as empty would plan to replace every
	// client against an engine that predates the field.
	if got.RedirectURIs != nil {
		uris, d := types.SetValueFrom(ctx, types.StringType, *got.RedirectURIs)
		diags.Append(d...)
		m.RedirectURIs = uris
	}
	// The version observed by THIS read is what the next write is conditional on.
	m.ConfigVersion = types.Int64Value(version)
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

	applyServerState(ctx, &state, got, version, &resp.Diagnostics)
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

	// `enabled`, the name and the redirect URIs change in place, in one
	// conditional request; the id, organisation and client type replace the
	// client. Replacing it for a rename or a new redirect URI used to delete
	// every token issued under it and mint a new secret.
	uris := setToStrings(ctx, plan.RedirectURIs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	// The precondition, taken from the version the last READ observed. This is
	// the line that makes a concurrent change a failure rather than a silent
	// overwrite.
	err := r.data.write(state.ConfigVersion.ValueInt64(), func(ifMatch int64) (int64, error) {
		res, err := r.data.client.UpdateClient(ctx, plan.ClientID.ValueString(), signari.ClientUpdate{
			Enabled: plan.Enabled.ValueBool(), DisplayName: plan.DisplayName.ValueString(), RedirectURIs: uris,
		}, ifMatch)
		if err != nil {
			return 0, err
		}
		return res.Version, nil
	})

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
	r.readBack(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *clientResource) Delete(ctx context.Context, req resource.DeleteRequest,
	resp *resource.DeleteResponse) {

	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// A real delete: the client and every code, token, refresh family and
	// consent issued under it go together, and the audit trail keeps the
	// record that it existed. This used to disable the client and warn, from
	// before the Admin API had a delete, so a destroy left the row behind and a
	// replacement could not create its successor under the same client id.
	err := r.data.write(state.ConfigVersion.ValueInt64(), func(ifMatch int64) (int64, error) {
		res, err := r.data.client.DeleteClient(ctx, state.ClientID.ValueString(), ifMatch)
		if err != nil {
			return 0, err
		}
		return res.Version, nil
	})

	var conflict *signari.ErrConflict
	if errors.As(err, &conflict) {
		resp.Diagnostics.AddError("the configuration changed since this plan was made",
			conflict.Error())
		return
	}
	if err != nil && !errors.Is(err, signari.ErrNotFound) {
		resp.Diagnostics.AddError("deleting the client", err.Error())
	}
}

func (r *clientResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("client_id"), req, resp)
}
