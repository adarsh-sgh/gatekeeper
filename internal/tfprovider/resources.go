package tfprovider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/sdk"
)

// --- gatekeeper_tenant ---

type tenantResource struct{ c *sdk.Client }

type tenantModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	DisplayName types.String `tfsdk:"display_name"`
	Disabled    types.Bool   `tfsdk:"disabled"`
}

func newTenantResource() resource.Resource { return &tenantResource{} }

func (r *tenantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant"
}

func (r *tenantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A registered tenant. Destroying it clears the tenant's rollout state, so its checks deny.",
		Attributes: map[string]schema.Attribute{
			"id":           schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":         schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"display_name": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"disabled":     schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Kill switch: every Check denies."},
		},
	}
}

func (r *tenantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = client(req.ProviderData, &resp.Diagnostics)
}

func (r *tenantResource) put(ctx context.Context, m *tenantModel) error {
	t, err := r.c.PutTenant(ctx, &pb.PutTenantRequest{Tenant: &pb.Tenant{
		Name: m.Name.ValueString(), DisplayName: m.DisplayName.ValueString(), Disabled: m.Disabled.ValueBool()}})
	if err == nil {
		m.ID = types.StringValue(t.Name)
	}
	return err
}

func (r *tenantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m tenantModel
	if resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, &m); err != nil {
		resp.Diagnostics.AddError("create tenant", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *tenantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m tenantModel
	if resp.Diagnostics.Append(req.State.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	t, err := r.c.GetTenant(ctx, &pb.GetTenantRequest{Name: m.ID.ValueString()})
	if sdk.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	} else if err != nil {
		resp.Diagnostics.AddError("read tenant", err.Error())
		return
	}
	m.Name, m.DisplayName, m.Disabled = types.StringValue(t.Name), types.StringValue(t.DisplayName), types.BoolValue(t.Disabled)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *tenantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m tenantModel
	if resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, &m); err != nil {
		resp.Diagnostics.AddError("update tenant", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *tenantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m tenantModel
	if resp.Diagnostics.Append(req.State.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.c.DeleteTenant(ctx, &pb.DeleteTenantRequest{Name: m.ID.ValueString()}); err != nil && !sdk.IsNotFound(err) {
		resp.Diagnostics.AddError("delete tenant", err.Error())
	}
}

func (r *tenantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// --- gatekeeper_policy ---

// policyResource is the Rego in one rollout slot (active or shadow) of a
// registered tenant. Policy versions are immutable, so a rego change stores
// a new version; id is "<tenant>/active" or "<tenant>/shadow".
type policyResource struct{ c *sdk.Client }

type policyModel struct {
	ID      types.String `tfsdk:"id"`
	Tenant  types.String `tfsdk:"tenant"`
	Rego    types.String `tfsdk:"rego"`
	Shadow  types.Bool   `tfsdk:"shadow"`
	Version types.Int64  `tfsdk:"version"`
}

func newPolicyResource() resource.Resource { return &policyResource{} }

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The Rego served (or shadow-evaluated) for a tenant. Destroying an active policy makes the tenant's checks deny.",
		Attributes: map[string]schema.Attribute{
			"id":     schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"tenant": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"rego":   schema.StringAttribute{Required: true},
			"shadow": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
				Description:   "Evaluate on live traffic and log divergence without serving the decision."},
			"version": schema.Int64Attribute{Computed: true, Description: "Server-assigned version in the slot."},
		},
	}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = client(req.ProviderData, &resp.Diagnostics)
}

func slotName(shadow bool) string {
	if shadow {
		return "shadow"
	}
	return "active"
}

// slotVersion returns the version in the tenant's slot; found=false if the
// tenant is not registered.
func (r *policyResource) slotVersion(ctx context.Context, tenant string, shadow bool) (v int64, found bool, err error) {
	t, err := r.c.GetTenant(ctx, &pb.GetTenantRequest{Name: tenant})
	if sdk.IsNotFound(err) {
		return 0, false, nil
	} else if err != nil {
		return 0, false, err
	}
	if shadow {
		return t.ShadowVersion, true, nil
	}
	return t.ActiveVersion, true, nil
}

func (r *policyResource) put(ctx context.Context, m *policyModel) error {
	p, err := r.c.PutPolicy(ctx, &pb.PutPolicyRequest{Tenant: m.Tenant.ValueString(), Rego: m.Rego.ValueString(), Shadow: m.Shadow.ValueBool()})
	if err != nil {
		return err
	}
	m.Version = types.Int64Value(p.Version)
	m.ID = types.StringValue(m.Tenant.ValueString() + "/" + slotName(m.Shadow.ValueBool()))
	return nil
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m policyModel
	if resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	if _, found, err := r.slotVersion(ctx, m.Tenant.ValueString(), false); err != nil || !found {
		resp.Diagnostics.AddError("create policy", fmt.Sprintf("tenant %q must be registered (gatekeeper_tenant) first: %v", m.Tenant.ValueString(), err))
		return
	}
	if err := r.put(ctx, &m); err != nil {
		resp.Diagnostics.AddError("create policy", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// Read detects drift: an emptied slot removes the resource (plan recreates
// it); a different version in the slot loads that version's Rego, so the
// plan shows the change back to the configured Rego.
func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m policyModel
	if resp.Diagnostics.Append(req.State.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	v, found, err := r.slotVersion(ctx, m.Tenant.ValueString(), m.Shadow.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("read policy", err.Error())
		return
	}
	if !found || v == 0 {
		resp.State.RemoveResource(ctx)
		return
	}
	if v != m.Version.ValueInt64() || m.Rego.IsNull() {
		p, err := r.c.GetPolicy(ctx, &pb.GetPolicyRequest{Tenant: m.Tenant.ValueString(), Version: v})
		if err != nil {
			resp.Diagnostics.AddError("read policy", err.Error())
			return
		}
		m.Rego, m.Version = types.StringValue(p.Rego), types.Int64Value(v)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m policyModel
	if resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, &m); err != nil {
		resp.Diagnostics.AddError("update policy", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// Delete empties the slot only if it still holds this resource's version.
func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m policyModel
	if resp.Diagnostics.Append(req.State.Get(ctx, &m)...); resp.Diagnostics.HasError() {
		return
	}
	v, _, err := r.slotVersion(ctx, m.Tenant.ValueString(), m.Shadow.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("delete policy", err.Error())
		return
	}
	if v != 0 && v == m.Version.ValueInt64() {
		if _, err := r.c.UnsetPolicy(ctx, &pb.UnsetPolicyRequest{Tenant: m.Tenant.ValueString(), Shadow: m.Shadow.ValueBool()}); err != nil {
			resp.Diagnostics.AddError("delete policy", err.Error())
		}
	}
}

// ImportState takes "<tenant>/active" or "<tenant>/shadow".
func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tenant, slot, ok := strings.Cut(req.ID, "/")
	if !ok || (slot != "active" && slot != "shadow") {
		resp.Diagnostics.AddError("import policy", `id must be "<tenant>/active" or "<tenant>/shadow"`)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, policyModel{ID: types.StringValue(req.ID), Tenant: types.StringValue(tenant),
		Shadow: types.BoolValue(slot == "shadow"), Rego: types.StringNull(), Version: types.Int64Value(0)})...)
}
