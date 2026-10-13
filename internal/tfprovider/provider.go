// Package tfprovider is the Terraform provider for gatekeeper, built with
// terraform-plugin-framework on the same generated Go SDK as gkctl.
package tfprovider

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/adarsh-sgh/gatekeeper/sdk"
)

type gatekeeperProvider struct{ version string }

type providerModel struct {
	Address types.String `tfsdk:"address"`
	Token   types.String `tfsdk:"token"`
	TLSCA   types.String `tfsdk:"tls_ca"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &gatekeeperProvider{version: version} }
}

func (p *gatekeeperProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName, resp.Version = "gatekeeper", p.version
}

func (p *gatekeeperProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages gatekeeper tenants and their Rego policies over gRPC.",
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{Optional: true, Description: "gRPC address; defaults to $GATEKEEPER_ADDR, then localhost:9090."},
			"token":   schema.StringAttribute{Optional: true, Sensitive: true, Description: "Bearer token with tenants:admin and policy:write; defaults to $GATEKEEPER_TOKEN."},
			"tls_ca":  schema.StringAttribute{Optional: true, Description: "CA bundle path; enables TLS."},
		},
	}
}

func (p *gatekeeperProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	if resp.Diagnostics.Append(req.Config.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	addr := cmp.Or(m.Address.ValueString(), os.Getenv("GATEKEEPER_ADDR"), "localhost:9090")
	o := sdk.Options{Token: cmp.Or(m.Token.ValueString(), os.Getenv("GATEKEEPER_TOKEN"))}
	if ca := m.TLSCA.ValueString(); ca != "" {
		pem, err := os.ReadFile(ca)
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			resp.Diagnostics.AddError("invalid tls_ca", fmt.Sprintf("%s: %v", ca, err))
			return
		}
		o.TLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	c, err := sdk.Dial(addr, o)
	if err != nil {
		resp.Diagnostics.AddError("dial gatekeeper", err.Error())
		return
	}
	resp.ResourceData = c
}

func (p *gatekeeperProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newTenantResource, newPolicyResource}
}

func (p *gatekeeperProvider) DataSources(context.Context) []func() datasource.DataSource { return nil }

// client extracts the SDK client handed over by Configure.
func client(data any, diags *diag.Diagnostics) *sdk.Client {
	if data == nil {
		return nil // validation before Configure
	}
	c, ok := data.(*sdk.Client)
	if !ok {
		diags.AddError("unexpected provider data", fmt.Sprintf("%T", data))
	}
	return c
}
