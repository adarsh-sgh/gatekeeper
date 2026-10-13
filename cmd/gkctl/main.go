// Command gkctl syncs declarative tenant/policy config to gatekeeper.
//
//	gkctl diff -f gatekeeper.yaml    # exit 2 on drift
//	gkctl sync -f gatekeeper.yaml
//	gkctl dump --dir out > out/gatekeeper.yaml
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/adarsh-sgh/gatekeeper/internal/gkctl"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := gkctl.NewRoot().ExecuteContext(ctx); err != nil {
		if errors.Is(err, gkctl.ErrDrift) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "gkctl:", err)
		os.Exit(1)
	}
}
