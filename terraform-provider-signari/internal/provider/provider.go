// Package provider is the Terraform provider for Signari.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// New returns the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &signariProvider{version: version} }
}

type signariProvider struct{ version string }

func (p *signariProvider) Metadata(_ context.Context, _ provider.MetadataRequest,
	resp *provider.MetadataResponse) {
	resp.TypeName = "signari"
	resp.Version = p.version
}

func (p *signariProvider) Schema(_ context.Context, _ provider.SchemaRequest,
	resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Signari identity provider through its Admin API.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Base URL of the Admin API, for example " +
					"`https://admin.internal.example.com`. May also be set with " +
					"`SIGNARI_ADMIN_ENDPOINT`.",
			},
			"token": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "Admin API token from `signari admin-token create`. " +
					"May also be set with `SIGNARI_ADMIN_TOKEN`, which is the better " +
					"place for it: a token in a .tf file is a token in version control.",
			},
			"conditional_writes": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Send RFC 7232 `If-Match` preconditions on every " +
					"update, so an apply fails rather than silently overwriting a change " +
					"made after the plan was produced. **Defaults to true.** Turning it " +
					"off gives the last-write-wins behaviour usual elsewhere, and is " +
					"here only for a server too old to honour the header.",
			},
		},
	}
}

type providerModel struct {
	Endpoint          types.String `tfsdk:"endpoint"`
	Token             types.String `tfsdk:"token"`
	ConditionalWrites types.Bool   `tfsdk:"conditional_writes"`
}

// providerData is handed to every resource.
type providerData struct {
	client *signari.Client
	// conditional says whether writes carry If-Match. Kept beside the client
	// rather than inside it, because it is a policy about how to use the client
	// rather than a property of the connection.
	conditional bool
}

func (p *signariProvider) Configure(ctx context.Context, req provider.ConfigureRequest,
	resp *provider.ConfigureResponse) {

	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := os.Getenv("SIGNARI_ADMIN_ENDPOINT")
	if !cfg.Endpoint.IsNull() && cfg.Endpoint.ValueString() != "" {
		endpoint = cfg.Endpoint.ValueString()
	}
	token := os.Getenv("SIGNARI_ADMIN_TOKEN")
	if !cfg.Token.IsNull() && cfg.Token.ValueString() != "" {
		token = cfg.Token.ValueString()
	}

	if endpoint == "" {
		resp.Diagnostics.AddError("no Admin API endpoint",
			"Set `endpoint` on the provider, or SIGNARI_ADMIN_ENDPOINT in the environment.")
	}
	if token == "" {
		resp.Diagnostics.AddError("no Admin API token",
			"Set `token` on the provider, or SIGNARI_ADMIN_TOKEN in the environment. "+
				"The environment is the better place: a token in a .tf file is a token "+
				"in version control.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Conditional writes are ON unless explicitly disabled. A safety property
	// that has to be opted into is one most deployments never get.
	conditional := true
	if !cfg.ConditionalWrites.IsNull() {
		conditional = cfg.ConditionalWrites.ValueBool()
	}

	data := &providerData{
		client:      &signari.Client{Endpoint: endpoint, Token: token},
		conditional: conditional,
	}
	resp.DataSourceData = data
	resp.ResourceData = data
}

func (p *signariProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewClientResource}
}

func (p *signariProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
