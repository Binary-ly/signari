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
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// signari_organization manages a tenant: provisioning it, and suspending or
// reactivating it. It needs a token scoped to no organisation, since a tenant
// that could lift its own suspension would not be suspended.
//
// It is never deleted here. The Admin API has no deletion of an organisation,
// on purpose: it erases every person in it, and is done with
// `signari instance org-delete`, two steps, the database in front of you. A
// destroy refuses and says so, rather than leaving the tenant in place while
// reporting it gone.

func NewOrganizationResource() resource.Resource { return &organizationResource{} }

type organizationResource struct{ data *providerData }

type organizationModel struct {
	ID            types.String `tfsdk:"id"`
	Slug          types.String `tfsdk:"slug"`
	DisplayName   types.String `tfsdk:"display_name"`
	InstanceID    types.String `tfsdk:"instance_id"`
	Status        types.String `tfsdk:"status"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (r *organizationResource) Metadata(_ context.Context, req resource.MetadataRequest,
	resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_organization"
}

// oneOf refuses a value outside the listed ones, at plan.
type oneOf []string

func (o oneOf) Description(context.Context) string         { return "one of the listed values" }
func (o oneOf) MarkdownDescription(context.Context) string { return "one of the listed values" }
func (o oneOf) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	for _, v := range o {
		if req.ConfigValue.ValueString() == v {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(req.Path, "not a value this takes",
		"it must be one of "+join(o))
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += "`" + v + "`"
	}
	return out
}

func (r *organizationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An organisation, a tenant. Needs a token scoped to no organisation. Never " +
			"deleted by Terraform: a destroy refuses and names `signari instance org-delete`.",
		Attributes: map[string]schema.Attribute{
			"id":           idAttribute("organisation"),
			"slug":         replacing("The slug, as sign-in addresses name it."),
			"display_name": replacing("The name people see."),
			"instance_id": schema.StringAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "The instance it belongs to; needed only when the deployment has several. " +
					"Changing it replaces the organisation.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown()},
			},
			"status": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("active"),
				MarkdownDescription: "`active`, or `suspended`, which refuses it at every entry point from the " +
					"next request and ends nothing. Changed in place.",
				Validators: []validator.String{oneOf{"active", "suspended"}},
			},
			"config_version": versionAttribute(),
		},
	}
}

func (r *organizationResource) Configure(_ context.Context, req resource.ConfigureRequest,
	resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func organizationPath(id string) string { return "/admin/organizations/" + url.PathEscape(id) }

func (r *organizationResource) readOrganization(ctx context.Context, m *organizationModel,
	diags *diag.Diagnostics) bool {
	var o signari.Organization
	version, err := r.data.client.Get(ctx, organizationPath(m.ID.ValueString()), &o)
	if errors.Is(err, signari.ErrNotFound) {
		return false
	}
	if err != nil {
		diags.AddError("reading the organisation", err.Error())
		return true
	}
	m.Slug, m.DisplayName = types.StringValue(o.Slug), types.StringValue(o.DisplayName)
	m.InstanceID, m.Status = types.StringValue(o.InstanceID), types.StringValue(o.Status)
	m.ConfigVersion = types.Int64Value(version)
	return true
}

func (r *organizationResource) Create(ctx context.Context, req resource.CreateRequest,
	resp *resource.CreateResponse) {
	var plan organizationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]string{"slug": plan.Slug.ValueString(), "display_name": plan.DisplayName.ValueString()}
	if v := plan.InstanceID.ValueString(); !plan.InstanceID.IsUnknown() && v != "" {
		body["instance_id"] = v
	}
	id, version, err := r.data.create(ctx, "/admin/organizations", body)
	if err != nil {
		failed(&resp.Diagnostics, "creating the organisation", err)
		return
	}
	plan.ID = types.StringValue(id)
	// Made active; suspended from birth is a second write.
	if plan.Status.ValueString() == "suspended" {
		if _, err := r.data.change(ctx, http.MethodPatch, organizationPath(id),
			map[string]string{"status": "suspended"}, version); err != nil {
			failed(&resp.Diagnostics, "suspending the new organisation", err)
		}
	}
	r.readOrganization(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *organizationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state organizationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readOrganization(ctx, &state, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *organizationResource) Update(ctx context.Context, req resource.UpdateRequest,
	resp *resource.UpdateResponse) {
	var plan, state organizationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Status.ValueString() != state.Status.ValueString() {
		if _, err := r.data.change(ctx, http.MethodPatch, organizationPath(state.ID.ValueString()),
			map[string]string{"status": plan.Status.ValueString()}, state.ConfigVersion.ValueInt64()); err != nil {
			failed(&resp.Diagnostics, "changing the organisation's status", err)
			return
		}
	}
	plan.ID = state.ID
	r.readOrganization(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *organizationResource) Delete(_ context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state organizationModel
	resp.Diagnostics.Append(req.State.Get(context.Background(), &state)...)
	resp.Diagnostics.AddError("an organisation is not deleted through Terraform",
		"Deleting "+state.Slug.ValueString()+" erases every person in it, and the Admin API does not offer it. "+
			"Suspend it with status = \"suspended\", or delete it on the host with `signari instance org-delete "+
			"-org "+state.ID.ValueString()+"` and then `terraform state rm` this resource.")
}

func (r *organizationResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
