package gkctl

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/pmezard/go-difflib/difflib"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/sdk"
)

// change is one step from current to desired state.
type change struct {
	sign  byte // + create, ~ update, ^ promote, - delete/unset
	what  string
	diff  string
	apply func(context.Context, *sdk.Client) error
}

// plan orders changes so they apply cleanly: per tenant, registry entry
// first, then the active slot, then shadow; deletions of tenants missing
// from the file come last.
func plan(desired, current map[string]tenant) []change {
	var out []change
	for _, name := range sortedKeys(desired) {
		d := desired[name]
		c, exists := current[name]
		switch {
		case !exists:
			out = append(out, change{sign: '+', what: "tenant " + name, apply: putTenant(d)})
		case d.displayName != c.displayName || d.disabled != c.disabled:
			out = append(out, change{sign: '~', what: fmt.Sprintf("tenant %s: display_name %q -> %q, disabled %v -> %v",
				name, c.displayName, d.displayName, c.disabled, d.disabled), apply: putTenant(d)})
		}
		out = append(out, planSlots(name, d, c)...)
	}
	for _, name := range sortedKeys(current) {
		if _, keep := desired[name]; !keep {
			out = append(out, change{sign: '-', what: "tenant " + name + " (not in file)", apply: func(ctx context.Context, c *sdk.Client) error {
				_, err := c.DeleteTenant(ctx, &pb.DeleteTenantRequest{Name: name})
				return err
			}})
		}
	}
	return out
}

func planSlots(name string, d, c tenant) []change {
	var out []change
	if !d.active.same(c.active) {
		switch {
		case !d.active.set():
			out = append(out, change{sign: '-', what: fmt.Sprintf("policy %s/active %s (checks will deny)", name, c.active.source), apply: unset(name, false)})
		case c.shadow.set() && d.active.same(c.shadow):
			// The file promotes what is already shadowing: keep its version and divergence history.
			v := c.shadow.version
			out = append(out, change{sign: '^', what: fmt.Sprintf("policy %s/active: promote shadow %s", name, c.shadow.source), apply: func(ctx context.Context, cl *sdk.Client) error {
				_, err := cl.PromotePolicy(ctx, &pb.PromotePolicyRequest{Tenant: name, Version: v})
				return err
			}})
			c.shadow = slot{}
		default:
			out = append(out, change{sign: sign(c.active), what: fmt.Sprintf("policy %s/active from %s", name, d.active.source),
				diff: udiff(name+"/active", c.active, d.active), apply: put(name, d.active.rego, false)})
			c.shadow = slot{} // a non-shadow put clears the shadow slot
		}
	}
	if !d.shadow.same(c.shadow) {
		if d.shadow.set() {
			out = append(out, change{sign: sign(c.shadow), what: fmt.Sprintf("policy %s/shadow from %s", name, d.shadow.source),
				diff: udiff(name+"/shadow", c.shadow, d.shadow), apply: put(name, d.shadow.rego, true)})
		} else {
			out = append(out, change{sign: '-', what: fmt.Sprintf("policy %s/shadow %s", name, c.shadow.source), apply: unset(name, true)})
		}
	}
	return out
}

func sign(current slot) byte {
	if current.set() {
		return '~'
	}
	return '+'
}

func putTenant(t tenant) func(context.Context, *sdk.Client) error {
	return func(ctx context.Context, c *sdk.Client) error {
		_, err := c.PutTenant(ctx, &pb.PutTenantRequest{Tenant: &pb.Tenant{Name: t.name, DisplayName: t.displayName, Disabled: t.disabled}})
		return err
	}
}

func put(tenant, rego string, shadow bool) func(context.Context, *sdk.Client) error {
	return func(ctx context.Context, c *sdk.Client) error {
		_, err := c.PutPolicy(ctx, &pb.PutPolicyRequest{Tenant: tenant, Rego: rego, Shadow: shadow})
		return err
	}
}

func unset(tenant string, shadow bool) func(context.Context, *sdk.Client) error {
	return func(ctx context.Context, c *sdk.Client) error {
		_, err := c.UnsetPolicy(ctx, &pb.UnsetPolicyRequest{Tenant: tenant, Shadow: shadow})
		return err
	}
}

// udiff is the Rego diff for an update; a create shows only the source.
func udiff(label string, from, to slot) string {
	if !from.set() {
		return ""
	}
	d, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(from.rego), B: difflib.SplitLines(to.rego),
		FromFile: label + " " + from.source + " (server)", ToFile: to.source, Context: 2,
	})
	return d
}

// render prints the plan and returns (creates, updates, deletes).
func render(w io.Writer, changes []change) (int, int, int) {
	var n [3]int
	for _, c := range changes {
		fmt.Fprintf(w, "%c %s\n", c.sign, c.what)
		for _, l := range strings.Split(strings.TrimRight(c.diff, "\n"), "\n") {
			if l != "" {
				fmt.Fprintf(w, "    %s\n", l)
			}
		}
		switch c.sign {
		case '+':
			n[0]++
		case '~', '^':
			n[1]++
		default:
			n[2]++
		}
	}
	fmt.Fprintf(w, "Summary: %d to create, %d to update, %d to delete\n", n[0], n[1], n[2])
	return n[0], n[1], n[2]
}
