package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// The objects the Admin API writes with one PUT, made or replaced alike, and
// removes with a DELETE (6.17): an application's group release, a declared
// scope, a protected host. Each is read back from the server after a write.

// importPair sets two attributes from an import id `<a>/<b>`.
func importPair(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse,
	a, b string) {
	x, y, ok := strings.Cut(req.ID, "/")
	if !ok || x == "" || y == "" {
		resp.Diagnostics.AddError("not an import id this takes", "import one as <"+a+">/<"+b+">")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(a), x)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(b), y)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// --- signari_client_group_release ------------------------------------------

func NewGroupReleaseResource() resource.Resource { return &groupReleaseResource{} }

type groupReleaseResource struct{ data *providerData }

type groupReleaseModel struct {
	ID            types.String `tfsdk:"id"`
	ClientID      types.String `tfsdk:"client_id"`
	OnlyGroups    types.Set    `tfsdk:"only_groups"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (r *groupReleaseResource) Metadata(_ context.Context, req resource.MetadataRequest,
	resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_client_group_release"
}

func (r *groupReleaseResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Which of a person's groups an application is told of, in the `groups` claim. " +
			"Without one it is told of none. Imported by the client id.",
		Attributes: map[string]schema.Attribute{
			"id":        idAttribute("release, the client id,"),
			"client_id": replacing("The application."),
			"only_groups": schema.SetAttribute{
				Optional: true, ElementType: types.StringType,
				MarkdownDescription: "The groups it is told of, by name; left out, every group the person is in. " +
					"A name the organisation does not have is refused. Changed in place.",
			},
			"config_version": versionAttribute(),
		},
	}
}

func (r *groupReleaseResource) Configure(_ context.Context, req resource.ConfigureRequest,
	resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func releasePath(client string) string {
	return "/admin/clients/" + url.PathEscape(client) + "/group-release"
}

// readRelease answers false when the application is told of no group.
func (r *groupReleaseResource) readRelease(ctx context.Context, m *groupReleaseModel, diags *diag.Diagnostics) bool {
	var v struct {
		Released   bool     `json:"released"`
		OnlyGroups []string `json:"only_groups"`
	}
	version, err := r.data.client.Get(ctx, releasePath(m.ClientID.ValueString()), &v)
	if errors.Is(err, signari.ErrNotFound) || (err == nil && !v.Released) {
		return false
	}
	if err != nil {
		diags.AddError("reading the release", err.Error())
		return true
	}
	if len(v.OnlyGroups) == 0 {
		m.OnlyGroups = types.SetNull(types.StringType)
	} else {
		set, d := types.SetValueFrom(ctx, types.StringType, v.OnlyGroups)
		if d.HasError() {
			diags.AddError("reading the release", "its groups do not fit")
		}
		m.OnlyGroups = set
	}
	m.ID = types.StringValue(m.ClientID.ValueString())
	m.ConfigVersion = types.Int64Value(version)
	return true
}

func (r *groupReleaseResource) put(ctx context.Context, m *groupReleaseModel, read int64) error {
	only := []string{}
	if !m.OnlyGroups.IsNull() && !m.OnlyGroups.IsUnknown() {
		if d := m.OnlyGroups.ElementsAs(ctx, &only, false); d.HasError() {
			return errors.New("only_groups does not fit")
		}
	}
	_, err := r.data.change(ctx, http.MethodPut, releasePath(m.ClientID.ValueString()),
		map[string]any{"only_groups": only}, read)
	return err
}

func (r *groupReleaseResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupReleaseModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, &plan, 0); err != nil {
		failed(&resp.Diagnostics, "releasing the groups", err)
		return
	}
	r.readRelease(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupReleaseResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupReleaseModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readRelease(ctx, &state, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *groupReleaseResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state groupReleaseModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, &plan, state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "changing the release", err)
		return
	}
	r.readRelease(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupReleaseResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupReleaseModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.remove(ctx, releasePath(state.ClientID.ValueString()), state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "withdrawing the release", err)
	}
}

func (r *groupReleaseResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("client_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// --- signari_scope ---------------------------------------------------------

func NewScopeResource() resource.Resource { return &scopeResource{} }

type scopeResource struct{ data *providerData }

type scopeModel struct {
	ID            types.String `tfsdk:"id"`
	OrgID         types.String `tfsdk:"org_id"`
	Name          types.String `tfsdk:"name"`
	DisplayName   types.String `tfsdk:"display_name"`
	Description   types.String `tfsdk:"description"`
	Advertise     types.Bool   `tfsdk:"advertise"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (r *scopeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scope"
}

func (r *scopeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A scope the organisation's applications may ask for, beyond the standard ones. " +
			"Imported as `<org_id>/<name>`.",
		Attributes: map[string]schema.Attribute{
			"id":     idAttribute("scope, `<org_id>/<name>`,"),
			"org_id": replacing("The organisation."),
			"name": replacing("The scope: a letter, then letters, digits, underscores, colons, dots or " +
				"hyphens."),
			"display_name": schema.StringAttribute{Optional: true, Computed: true,
				Default: stringdefault.StaticString(""), MarkdownDescription: "What the consent screen shows."},
			"description": schema.StringAttribute{Optional: true, Computed: true,
				Default: stringdefault.StaticString(""), MarkdownDescription: "What it is for."},
			"advertise": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				MarkdownDescription: "Whether discovery lists it in `scopes_supported`."},
			"config_version": versionAttribute(),
		},
	}
}

func (r *scopeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func scopesPath(org string) string { return organizationPath(org) + "/scopes" }

func (r *scopeResource) readScope(ctx context.Context, m *scopeModel) (bool, error) {
	var page struct {
		Scopes []struct {
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
			Description string `json:"description"`
			Advertise   bool   `json:"advertise"`
		} `json:"scopes"`
	}
	version, err := r.data.client.Get(ctx, scopesPath(m.OrgID.ValueString()), &page)
	if err != nil {
		return !errors.Is(err, signari.ErrNotFound), err
	}
	for _, s := range page.Scopes {
		if s.Name == m.Name.ValueString() {
			m.DisplayName, m.Description = types.StringValue(s.DisplayName), types.StringValue(s.Description)
			m.Advertise = types.BoolValue(s.Advertise)
			m.ID = types.StringValue(m.OrgID.ValueString() + "/" + s.Name)
			m.ConfigVersion = types.Int64Value(version)
			return true, nil
		}
	}
	return false, nil
}

func (r *scopeResource) put(ctx context.Context, m scopeModel, read int64) error {
	_, err := r.data.change(ctx, http.MethodPut, scopesPath(m.OrgID.ValueString()), map[string]any{
		"name": m.Name.ValueString(), "display_name": m.DisplayName.ValueString(),
		"description": m.Description.ValueString(), "advertise": m.Advertise.ValueBool(),
	}, read)
	return err
}

func (r *scopeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scopeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, plan, 0); err != nil {
		failed(&resp.Diagnostics, "declaring the scope", err)
		return
	}
	if _, err := r.readScope(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("reading the scope back", err.Error())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *scopeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state scopeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	found, err := r.readScope(ctx, &state)
	if err != nil && found {
		resp.Diagnostics.AddError("reading the scope", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *scopeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state scopeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, plan, state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "changing the scope", err)
		return
	}
	if _, err := r.readScope(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("reading the scope back", err.Error())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *scopeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state scopeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.remove(ctx, scopesPath(state.OrgID.ValueString())+"/"+url.PathEscape(state.Name.ValueString()),
		state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "removing the scope", err)
	}
}

func (r *scopeResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	importPair(ctx, req, resp, "org_id", "name")
}

// --- signari_proxy_host ----------------------------------------------------

func NewProxyHostResource() resource.Resource { return &proxyHostResource{} }

type proxyHostResource struct{ data *providerData }

type proxyHostModel struct {
	ID            types.String `tfsdk:"id"`
	OrgID         types.String `tfsdk:"org_id"`
	Host          types.String `tfsdk:"host"`
	Enabled       types.Bool   `tfsdk:"enabled"`
	ConfigVersion types.Int64  `tfsdk:"config_version"`
}

func (r *proxyHostResource) Metadata(_ context.Context, req resource.MetadataRequest,
	resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_proxy_host"
}

func (r *proxyHostResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A host the forward-auth proxy protects. Imported as `<org_id>/<host>`.",
		Attributes: map[string]schema.Attribute{
			"id":     idAttribute("host, `<org_id>/<host>`,"),
			"org_id": replacing("The organisation."),
			"host": replacing("The host name, in lower case, with a port when it is not the default, as the " +
				"server holds it."),
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				MarkdownDescription: "Whether it is protected now. Changed in place."},
			"config_version": versionAttribute(),
		},
	}
}

func (r *proxyHostResource) Configure(_ context.Context, req resource.ConfigureRequest,
	resp *resource.ConfigureResponse) {
	if d := configured(req.ProviderData, &resp.Diagnostics); d != nil {
		r.data = d
	}
}

func hostsPath(org string) string { return organizationPath(org) + "/proxy-hosts" }

func (r *proxyHostResource) readHost(ctx context.Context, m *proxyHostModel) (bool, error) {
	var page struct {
		Hosts json.RawMessage `json:"proxy_hosts"`
	}
	version, err := r.data.client.Get(ctx, hostsPath(m.OrgID.ValueString()), &page)
	if err != nil {
		return !errors.Is(err, signari.ErrNotFound), err
	}
	var hosts []struct {
		Host    string `json:"host"`
		Enabled bool   `json:"enabled"`
	}
	_ = json.Unmarshal(page.Hosts, &hosts)
	for _, h := range hosts {
		if h.Host == m.Host.ValueString() {
			m.Enabled = types.BoolValue(h.Enabled)
			m.ID = types.StringValue(m.OrgID.ValueString() + "/" + h.Host)
			m.ConfigVersion = types.Int64Value(version)
			return true, nil
		}
	}
	return false, nil
}

func (r *proxyHostResource) put(ctx context.Context, m proxyHostModel, read int64) error {
	_, err := r.data.change(ctx, http.MethodPut, hostsPath(m.OrgID.ValueString()), map[string]any{
		"host": m.Host.ValueString(), "enabled": m.Enabled.ValueBool()}, read)
	return err
}

func (r *proxyHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan proxyHostModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, plan, 0); err != nil {
		failed(&resp.Diagnostics, "protecting the host", err)
		return
	}
	found, err := r.readHost(ctx, &plan)
	if err != nil || !found {
		resp.Diagnostics.AddError("reading the host back", "the server does not hold "+plan.Host.ValueString()+
			"; write it in lower case, as the server holds it")
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *proxyHostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state proxyHostModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	found, err := r.readHost(ctx, &state)
	if err != nil && found {
		resp.Diagnostics.AddError("reading the host", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *proxyHostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state proxyHostModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, plan, state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "changing the host", err)
		return
	}
	if _, err := r.readHost(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("reading the host back", err.Error())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *proxyHostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state proxyHostModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.remove(ctx, hostsPath(state.OrgID.ValueString())+"/"+url.PathEscape(state.Host.ValueString()),
		state.ConfigVersion.ValueInt64()); err != nil {
		failed(&resp.Diagnostics, "removing the host", err)
	}
}

func (r *proxyHostResource) ImportState(ctx context.Context, req resource.ImportStateRequest,
	resp *resource.ImportStateResponse) {
	importPair(ctx, req, resp, "org_id", "host")
}
