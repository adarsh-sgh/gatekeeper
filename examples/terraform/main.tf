# Build and point Terraform at the local provider:
#   go build -o ~/.terraform.d/plugins/registry.terraform.io/adarsh-sgh/gatekeeper/0.0.1/$(go env GOOS)_$(go env GOARCH)/terraform-provider-gatekeeper_v0.0.1 ./cmd/terraform-provider-gatekeeper
terraform {
  required_providers {
    gatekeeper = { source = "adarsh-sgh/gatekeeper", version = "0.0.1" }
  }
}

provider "gatekeeper" {} # GATEKEEPER_ADDR, GATEKEEPER_TOKEN

resource "gatekeeper_tenant" "edge" {
  name         = "edge"
  display_name = "Envoy-fronted apps"
}

resource "gatekeeper_policy" "edge" {
  tenant = gatekeeper_tenant.edge.name
  rego   = file("${path.module}/../../policies/http.rego")
}

# Candidate evaluated on live traffic; divergence lands in the audit log.
resource "gatekeeper_policy" "edge_next" {
  tenant = gatekeeper_tenant.edge.name
  rego   = file("${path.module}/../../policies/example.rego")
  shadow = true
}
