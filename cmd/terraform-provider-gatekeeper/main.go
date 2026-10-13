// Command terraform-provider-gatekeeper serves the provider over plugin protocol v6.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/adarsh-sgh/gatekeeper/internal/tfprovider"
)

var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers like delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), tfprovider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/adarsh-sgh/gatekeeper",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
