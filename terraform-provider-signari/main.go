// Command terraform-provider-signari serves the Signari Terraform provider.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"signari.dev/terraform-provider-signari/internal/provider"
)

// version is set at build time with -ldflags.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers")
	flag.Parse()

	if err := providerserver.Serve(context.Background(), provider.New(version),
		providerserver.ServeOpts{
			Address: "registry.terraform.io/binary-ly/signari",
			Debug:   debug,
		}); err != nil {
		log.Fatal(err)
	}
}
