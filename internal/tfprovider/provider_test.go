package tfprovider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/testserver"
	"github.com/adarsh-sgh/gatekeeper/sdk"
)

const (
	allowAll = "package gatekeeper\nallow := true\n"
	denyAll  = "package gatekeeper\nallow := false\n"
)

func config(displayName, rego string) string {
	return fmt.Sprintf(`
resource "gatekeeper_tenant" "acme" {
  name         = "acme"
  display_name = %q
}

resource "gatekeeper_policy" "acme" {
  tenant = gatekeeper_tenant.acme.name
  rego   = %q
}
`, displayName, rego)
}

// Acceptance test (TF_ACC=1, real terraform binary) against an in-process
// gatekeeper: create, update to a new immutable version, import both
// resources, detect an out-of-band policy change as drift and repair it, and
// destroy, after which the tenant is gone and its checks deny.
func TestAccTenantAndPolicy(t *testing.T) {
	srv := testserver.Start(t)
	t.Setenv("GATEKEEPER_ADDR", srv.Addr)
	t.Setenv("GATEKEEPER_TOKEN", srv.AdminToken)
	admin, err := sdk.Dial(srv.Addr, sdk.Options{Token: srv.AdminToken})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	svc, _ := sdk.Dial(srv.Addr, sdk.Options{Token: srv.Token("svc", "acme", auth.ScopeCheck)})
	defer svc.Close()

	decision := func(want bool) resource.TestCheckFunc {
		return func(*terraform.State) error {
			r, err := svc.Check(context.Background(), &pb.CheckRequest{Subject: &pb.Subject{Id: "u"}, Action: "read", Resource: &pb.Resource{Type: "doc"}})
			if err != nil || r.Allowed != want {
				return fmt.Errorf("check: %+v %v, want allowed=%v", r, err, want)
			}
			return nil
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"gatekeeper": providerserver.NewProtocol6WithError(New("test")()),
		},
		CheckDestroy: func(*terraform.State) error {
			if _, err := admin.GetTenant(context.Background(), &pb.GetTenantRequest{Name: "acme"}); !sdk.IsNotFound(err) {
				return fmt.Errorf("tenant still registered: %v", err)
			}
			return decision(false)(nil)
		},
		Steps: []resource.TestStep{
			{
				Config: config("Acme", allowAll),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("gatekeeper_tenant.acme", "id", "acme"),
					resource.TestCheckResourceAttr("gatekeeper_policy.acme", "id", "acme/active"),
					resource.TestCheckResourceAttr("gatekeeper_policy.acme", "version", "1"),
					decision(true)),
			},
			{
				Config: config("Acme Corp", denyAll),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("gatekeeper_tenant.acme", "display_name", "Acme Corp"),
					resource.TestCheckResourceAttr("gatekeeper_policy.acme", "version", "2"),
					decision(false)),
			},
			{ResourceName: "gatekeeper_tenant.acme", ImportState: true, ImportStateVerify: true},
			{ResourceName: "gatekeeper_policy.acme", ImportState: true, ImportStateId: "acme/active", ImportStateVerify: true},
			{
				PreConfig: func() {
					if _, err := admin.PutPolicy(context.Background(), &pb.PutPolicyRequest{Tenant: "acme", Rego: allowAll}); err != nil {
						t.Fatal(err)
					}
				},
				Config:             config("Acme Corp", denyAll),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true, // drift: v3 was put behind Terraform's back
			},
			{
				Config: config("Acme Corp", denyAll),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("gatekeeper_policy.acme", "version", "4"),
					decision(false)),
			},
			{
				Config: `
resource "gatekeeper_policy" "orphan" {
  tenant = "initech"
  rego   = "package gatekeeper"
}`,
				ExpectError: regexp.MustCompile(`must be registered`),
			},
		},
	})
}
