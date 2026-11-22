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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// signari_user manages a person.
//
// The password is write-only: sent when the person is made and whenever the
// configuration changes it, never read back, since the server holds only a
// hash. Left out, the person is made without one and signs in through
// recovery, the shape of an invitation. Destroying the user deletes them and
// ends their sessions, telling every application they reached.

func NewUserResource() resource.Resource { return &userResource{} }

type userResource struct{ data *providerData }

type userModel struct {
	ID            types.String `tfsdk:"id"`
	OrgID         types.String `tfsdk:"org_id"`
	Email         types.String `tfsdk:"email"`
	Username      types.String `tfsdk:"username"`
	DisplayName   types.String `tfsdk:"display_name"`
	GivenName     types.String `tfsdk:"given_name"`
	Surname       types.String `tfsdk:"surname"`
	Locale        types.String `tfsdk:"locale"`
	Active        types.Bool   `tfsdk:"active"`
	Password      types.String `tfsdk:"password"`
	Status        types.String `tfsdk:"status"`
	EmailVerified types.Bool   `tfsdk:"email_verified"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (r *userResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func optionalString(description string) schema.StringAttribute {
	return schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""),
		MarkdownDescription: description + " Empty clears it. Changed in place."}
}

func (r *userResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A person. At least one of `email` and `username`.",
		Attributes: map[string]schema.Attribute{
			"id":           idAttribute("user"),
			"org_id":       replacing("The organisation the person belongs to."),
			"email":        optionalString("The address. A change clears its verified mark, always."),
			"username":     optionalString("The username."),
			"display_name": optionalString("The name people see."),
			"given_name":   optionalString("The given name."),
			"surname":      optionalString("The surname."),
			"locale":       optionalString("The BCP 47 tag their notices and pages are written in."),
			"active": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				MarkdownDescription: "Whether they may sign in. False deactivates them; true activates them, " +
					"approving a sign-up waiting for approval.",
			},
			"password": schema.StringAttribute{
				Optional: true, Sensitive: true,
				MarkdownDescription: "Set when the person is made and whenever this changes; never read back. " +
					"Left out, they sign in through recovery.",
			},
			"status": schema.StringAttribute{Computed: true,
				MarkdownDescription: "`active`, `deactivated`, `locked` or `pending`, as the server holds it."},
			"email_verified": schema.BoolAttribute{Computed: true,
				MarkdownDescription: "Whether the address was proved, which only a sign-in flow can do."},
			"config_version": versionAttribute(),
		},
	}
}

func (r *userResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func userPath(id string) string { return "/admin/users/" + url.PathEscape(id) }

func (r *userResource) readUser(ctx context.Context, m *userModel, diags *diag.Diagnostics) bool {
	var u signari.User
	version, err := r.data.client.Get(ctx, userPath(m.ID.ValueString()), &u)
	if errors.Is(err, signari.ErrNotFound) {
		return false
	}
	if err != nil {
		diags.AddError("reading the user", err.Error())
		return true
	}
	m.OrgID, m.Email, m.Username = types.StringValue(u.OrgID), types.StringValue(u.Email), types.StringValue(u.Username)
	m.DisplayName, m.GivenName = types.StringValue(u.DisplayName), types.StringValue(u.GivenName)
	m.Surname, m.Locale = types.StringValue(u.Surname), types.StringValue(u.Locale)
	m.Status, m.Active = types.StringValue(u.Status), types.BoolValue(u.Status == "active")
	m.EmailVerified = types.BoolValue(u.EmailVerified)
	m.ConfigVersion = types.Int64Value(version)
	return true
}

// changes is what a PATCH sets of the person: each field the plan holds
// differently from was, and only those. An address sent back unchanged once
// cleared its verified mark (0.46), and an engine from before that fix still
// does, so what has not changed is not sent.
func (m userModel) changes(was userModel) map[string]any {
	out := map[string]any{}
	for name, f := range map[string][2]types.String{
		"email": {m.Email, was.Email}, "username": {m.Username, was.Username},
		"display_name": {m.DisplayName, was.DisplayName}, "given_name": {m.GivenName, was.GivenName},
		"surname": {m.Surname, was.Surname}, "locale": {m.Locale, was.Locale},
	} {
		if f[0].ValueString() != f[1].ValueString() {
			out[name] = f[0].ValueString()
		}
	}
	if m.Active.ValueBool() != was.Active.ValueBool() {
		out["active"] = m.Active.ValueBool()
	}
	return out
}

func (r *userResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan userModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Email.ValueString() == "" && plan.Username.ValueString() == "" {
		resp.Diagnostics.AddError("a user needs an email or a username", "set one of them, or both")
		return
	}
	id, version, err := r.data.create(ctx, "/admin/users", map[string]string{
		"org_id": plan.OrgID.ValueString(), "email": plan.Email.ValueString(),
		"username": plan.Username.ValueString(), "password": plan.Password.ValueString(),
	})
	if err != nil {
		failed(&resp.Diagnostics, "creating the user", err)
		return
	}
	plan.ID = types.StringValue(id)
	// The names, the locale and the state are a second write, conditional on
	// the one that made the person, as a client's `enabled = false` is: the
	// person is made active, with their identifiers and nothing else.
	made := userModel{Email: plan.Email, Username: plan.Username, DisplayName: types.StringValue(""),
		GivenName: types.StringValue(""), Surname: types.StringValue(""), Locale: types.StringValue(""),
		Active: types.BoolValue(true)}
	if body := plan.changes(made); len(body) > 0 {
		if _, err := r.data.change(ctx, http.MethodPatch, userPath(id), body, version); err != nil {
			failed(&resp.Diagnostics, "setting the new user's names", err)
		}
	}
	password := plan.Password
	r.readUser(ctx, &plan, &resp.Diagnostics)
	plan.Password = password
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *userResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state userModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readUser(ctx, &state, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *userResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state userModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := plan.changes(state)
	if !plan.Password.Equal(state.Password) && plan.Password.ValueString() != "" {
		body["password"] = plan.Password.ValueString()
	}
	if len(body) > 0 {
		if _, err := r.data.change(ctx, http.MethodPatch, userPath(state.ID.ValueString()), body,
			state.ConfigVersion.ValueInt64()); err != nil {
			failed(&resp.Diagnostics, "updating the user", err)
			return
		}
	}
	plan.ID = state.ID
	password := plan.Password
	r.readUser(ctx, &plan, &resp.Diagnostics)
	plan.Password = password
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *userResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state userModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.remove(ctx, userPath(state.ID.ValueString()), state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "deleting the user", err)
	}
}

func (r *userResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
