// Package gkctl is the declarative CLI for gatekeeper, in the style of
// Kong's decK: a YAML file lists tenants and their Rego; `diff` shows drift
// against the server, `sync` makes the server match, `dump` exports it.
package gkctl

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adarsh-sgh/gatekeeper/sdk"
)

// ErrDrift is returned by `diff` when the server differs from the file;
// main maps it to exit status 2, like `terraform plan -detailed-exitcode`.
var ErrDrift = errors.New("drift detected")

func NewRoot() *cobra.Command {
	var addr, token, caFile string
	root := &cobra.Command{
		Use:           "gkctl",
		Short:         "Declarative config for gatekeeper tenants and policies",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&addr, "addr", envOr("GATEKEEPER_ADDR", "localhost:9090"), "gatekeeper gRPC address ($GATEKEEPER_ADDR)")
	root.PersistentFlags().StringVar(&token, "token", os.Getenv("GATEKEEPER_TOKEN"), "bearer token with tenants:admin ($GATEKEEPER_TOKEN)")
	root.PersistentFlags().StringVar(&caFile, "tls-ca", "", "CA bundle; enables TLS")

	dial := func() (*sdk.Client, error) {
		o := sdk.Options{Token: token}
		if caFile != "" {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("%s: no certificates", caFile)
			}
			o.TLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		return sdk.Dial(addr, o)
	}

	// planFor loads the file and the server state and returns the changes.
	planFor := func(cmd *cobra.Command, file string) ([]change, *sdk.Client, error) {
		desired, err := load(file)
		if err != nil {
			return nil, nil, err
		}
		c, err := dial()
		if err != nil {
			return nil, nil, err
		}
		current, err := fetch(cmd.Context(), c)
		if err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("read server state: %w", err)
		}
		return plan(desired, current), c, nil
	}

	var file string
	diff := &cobra.Command{
		Use:   "diff",
		Short: "Show what sync would change; exit 2 on drift",
		RunE: func(cmd *cobra.Command, _ []string) error {
			changes, c, err := planFor(cmd, file)
			if err != nil {
				return err
			}
			defer c.Close()
			if render(cmd.OutOrStdout(), changes); len(changes) > 0 {
				return ErrDrift
			}
			return nil
		},
	}
	sync := &cobra.Command{
		Use:   "sync",
		Short: "Create, update and delete server state to match the file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			changes, c, err := planFor(cmd, file)
			if err != nil {
				return err
			}
			defer c.Close()
			render(cmd.OutOrStdout(), changes)
			for i, ch := range changes {
				if err := ch.apply(cmd.Context(), c); err != nil {
					return fmt.Errorf("%c %s: %w (%d of %d changes applied)", ch.sign, ch.what, err, i, len(changes))
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Applied %d changes\n", len(changes))
			return nil
		},
	}
	for _, c := range []*cobra.Command{diff, sync} {
		c.Flags().StringVarP(&file, "file", "f", "gatekeeper.yaml", "declarative config file")
	}

	var dir string
	dumpCmd := &cobra.Command{
		Use:   "dump",
		Short: "Write server state as a config file to stdout and its Rego under --dir",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			defer c.Close()
			state, err := fetch(cmd.Context(), c)
			if err != nil {
				return err
			}
			out, err := dump(state, dir)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	dumpCmd.Flags().StringVar(&dir, "dir", ".", "directory for policies/*.rego (paths in the output are relative to it)")

	root.AddCommand(diff, sync, dumpCmd)
	return root
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
