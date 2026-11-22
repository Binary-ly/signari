package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// The data sources (6.17): an organisation, a group and a user, each found by
// its id or by what people call it, so a configuration can refer to objects
// it does not manage.

var errNoneFound = errors.New("none found")

func lookup(computed bool, description string) schema.StringAttribute {
	return schema.StringAttribute{Optional: !computed, Computed: true, MarkdownDescription: description}
}

func reported(description string) schema.StringAttribute {
	return schema.StringAttribute{Computed: true, MarkdownDescription: description}
}

// --- signari_organization -------------------------------------------------

func NewOrganizationDataSource() datasource.DataSource { return &organizationDataSource{} }

type organizationDataSource struct{ data *providerData }

type organizationData struct {
	ID          types.String `tfsdk:"id"`
	Slug        types.String `tfsdk:"slug"`
	DisplayName types.String `tfsdk:"display_name"`
	InstanceID  types.String `tfsdk:"instance_id"`
	Status      types.String `tfsdk:"status"`
}

func (d *organizationDataSource) Metadata(_ context.Context, req datasource.MetadataRequest,
	resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_organization"
}

func (d *organizationDataSource) Schema(_ context.Context, _ datasource.SchemaRequest,
	resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An organisation, by `id` or by `slug`.",
		Attributes: map[string]schema.Attribute{
			"id":           lookup(false, "The organisation's id."),
			"slug":         lookup(false, "Its slug."),
			"display_name": reported("Its name."),
			"instance_id":  reported("Its instance."),
			"status":       reported("`active` or `suspended`."),
		},
	}
}

func (d *organizationDataSource) Configure(_ context.Context, req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse) {
	if p := configured(req.ProviderData, &resp.Diagnostics); p != nil {
		d.data = p
	}
}

func (d *organizationDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m organizationData
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var o signari.Organization
	var err error
	switch {
	case m.ID.ValueString() != "":
		_, err = d.data.client.Get(ctx, organizationPath(m.ID.ValueString()), &o)
	case m.Slug.ValueString() != "":
		err = errNoneFound
		_, lerr := d.data.client.List(ctx, "/admin/organizations", "organizations", func(raw json.RawMessage) error {
			var each signari.Organization
			if json.Unmarshal(raw, &each) == nil && each.Slug == m.Slug.ValueString() {
				o, err = each, nil
			}
			return nil
		})
		if lerr != nil {
			err = lerr
		}
	default:
		resp.Diagnostics.AddError("which organisation?", "set id or slug")
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("finding the organisation", err.Error())
		return
	}
	m.ID, m.Slug, m.DisplayName = types.StringValue(o.ID), types.StringValue(o.Slug), types.StringValue(o.DisplayName)
	m.InstanceID, m.Status = types.StringValue(o.InstanceID), types.StringValue(o.Status)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// --- signari_group --------------------------------------------------------

func NewGroupDataSource() datasource.DataSource { return &groupDataSource{} }

type groupDataSource struct{ data *providerData }

type groupData struct {
	ID          types.String `tfsdk:"id"`
	OrgID       types.String `tfsdk:"org_id"`
	Name        types.String `tfsdk:"name"`
	DisplayName types.String `tfsdk:"display_name"`
	Description types.String `tfsdk:"description"`
}

func (d *groupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest,
	resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (d *groupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A group, by `id`, or by `org_id` and `name`.",
		Attributes: map[string]schema.Attribute{
			"id":           lookup(false, "The group's id."),
			"org_id":       lookup(false, "Its organisation."),
			"name":         lookup(false, "Its name."),
			"display_name": reported("The name people see."),
			"description":  reported("Its description."),
		},
	}
}

func (d *groupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse) {
	if p := configured(req.ProviderData, &resp.Diagnostics); p != nil {
		d.data = p
	}
}

func (d *groupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m groupData
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var g signari.Group
	var err error
	switch {
	case m.ID.ValueString() != "":
		_, err = d.data.client.Get(ctx, groupPath(m.ID.ValueString()), &g)
	case m.OrgID.ValueString() != "" && m.Name.ValueString() != "":
		err = errNoneFound
		_, lerr := d.data.client.List(ctx, "/admin/groups", "groups", func(raw json.RawMessage) error {
			var each signari.Group
			if json.Unmarshal(raw, &each) == nil && each.OrgID == m.OrgID.ValueString() &&
				each.Name == m.Name.ValueString() {
				g, err = each, nil
			}
			return nil
		})
		if lerr != nil {
			err = lerr
		}
	default:
		resp.Diagnostics.AddError("which group?", "set id, or org_id and name")
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("finding the group", err.Error())
		return
	}
	m.ID, m.OrgID, m.Name = types.StringValue(g.ID), types.StringValue(g.OrgID), types.StringValue(g.Name)
	m.DisplayName, m.Description = types.StringValue(g.DisplayName), types.StringValue(g.Description)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// --- signari_user ---------------------------------------------------------

func NewUserDataSource() datasource.DataSource { return &userDataSource{} }

type userDataSource struct{ data *providerData }

type userData struct {
	ID          types.String `tfsdk:"id"`
	OrgID       types.String `tfsdk:"org_id"`
	Email       types.String `tfsdk:"email"`
	Username    types.String `tfsdk:"username"`
	DisplayName types.String `tfsdk:"display_name"`
	Status      types.String `tfsdk:"status"`
}

func (d *userDataSource) Metadata(_ context.Context, req datasource.MetadataRequest,
	resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (d *userDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A person, by `id`, or by `email` (and `org_id` when an address is held in " +
			"several organisations).",
		Attributes: map[string]schema.Attribute{
			"id":           lookup(false, "The person's id."),
			"org_id":       lookup(false, "Their organisation."),
			"email":        lookup(false, "Their address, in any case."),
			"username":     reported("Their username."),
			"display_name": reported("The name people see."),
			"status":       reported("`active`, `deactivated`, `locked` or `pending`."),
		},
	}
}

func (d *userDataSource) Configure(_ context.Context, req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse) {
	if p := configured(req.ProviderData, &resp.Diagnostics); p != nil {
		d.data = p
	}
}

func (d *userDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m userData
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := m.ID.ValueString()
	if id == "" && m.Email.ValueString() != "" {
		var found []signari.User
		_, err := d.data.client.List(ctx, "/admin/users?email="+url.QueryEscape(m.Email.ValueString()), "users",
			func(raw json.RawMessage) error {
				var each signari.User
				if json.Unmarshal(raw, &each) == nil && strings.EqualFold(each.Email, m.Email.ValueString()) &&
					(m.OrgID.ValueString() == "" || each.OrgID == m.OrgID.ValueString()) {
					found = append(found, each)
				}
				return nil
			})
		switch {
		case err != nil:
			resp.Diagnostics.AddError("finding the user", err.Error())
			return
		case len(found) == 0:
			resp.Diagnostics.AddError("finding the user", "nobody holds that address")
			return
		case len(found) > 1:
			resp.Diagnostics.AddError("finding the user", "that address is held in several organisations; set org_id")
			return
		}
		id = found[0].ID
	}
	if id == "" {
		resp.Diagnostics.AddError("which user?", "set id or email")
		return
	}
	var u signari.User
	if _, err := d.data.client.Get(ctx, userPath(id), &u); err != nil {
		resp.Diagnostics.AddError("reading the user", err.Error())
		return
	}
	m.ID, m.OrgID, m.Email = types.StringValue(u.ID), types.StringValue(u.OrgID), types.StringValue(u.Email)
	m.Username, m.DisplayName = types.StringValue(u.Username), types.StringValue(u.DisplayName)
	m.Status = types.StringValue(u.Status)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}
