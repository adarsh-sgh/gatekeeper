package gkctl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/sdk"
)

// File is the declarative config: every registered tenant and the Rego
// served (and shadowed) for it. Policy paths are relative to the file.
type File struct {
	Tenants []TenantSpec `yaml:"tenants"`
}

type TenantSpec struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"display_name,omitempty"`
	Disabled    bool   `yaml:"disabled,omitempty"`
	Policy      string `yaml:"policy,omitempty"`
	Shadow      string `yaml:"shadow,omitempty"`
}

// tenant is one side of a diff: desired (from the file) or current (from
// the server). Rego is "" for an empty slot.
type tenant struct {
	name, displayName string
	disabled          bool
	active, shadow    slot
}

type slot struct {
	rego    string
	version int64  // server side only
	source  string // file path (desired) or "vN" (current), for display
}

func (s slot) set() bool { return s.rego != "" }

// same compares Rego ignoring surrounding whitespace, so an editor's
// trailing newline is not drift.
func (s slot) same(o slot) bool { return strings.TrimSpace(s.rego) == strings.TrimSpace(o.rego) }

func load(path string) (map[string]tenant, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	dir := filepath.Dir(path)
	read := func(p string) (slot, error) {
		if p == "" {
			return slot{}, nil
		}
		b, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			return slot{}, err
		}
		if strings.TrimSpace(string(b)) == "" {
			return slot{}, fmt.Errorf("%s is empty", p)
		}
		return slot{rego: string(b), source: p}, nil
	}
	out := map[string]tenant{}
	for _, s := range f.Tenants {
		if _, dup := out[s.Name]; dup || s.Name == "" {
			return nil, fmt.Errorf("%s: tenant name %q empty or duplicated", path, s.Name)
		}
		t := tenant{name: s.Name, displayName: s.DisplayName, disabled: s.Disabled}
		if t.active, err = read(s.Policy); err != nil {
			return nil, err
		}
		if t.shadow, err = read(s.Shadow); err != nil {
			return nil, err
		}
		out[s.Name] = t
	}
	return out, nil
}

func fetch(ctx context.Context, c *sdk.Client) (map[string]tenant, error) {
	list, err := c.ListTenants(ctx, &pb.ListTenantsRequest{})
	if err != nil {
		return nil, err
	}
	get := func(name string, v int64) (slot, error) {
		if v == 0 {
			return slot{}, nil
		}
		p, err := c.GetPolicy(ctx, &pb.GetPolicyRequest{Tenant: name, Version: v})
		if err != nil {
			return slot{}, fmt.Errorf("tenant %s v%d: %w", name, v, err)
		}
		return slot{rego: p.Rego, version: v, source: fmt.Sprintf("v%d", v)}, nil
	}
	out := map[string]tenant{}
	for _, pt := range list.Tenants {
		t := tenant{name: pt.Name, displayName: pt.DisplayName, disabled: pt.Disabled}
		if t.active, err = get(pt.Name, pt.ActiveVersion); err != nil {
			return nil, err
		}
		if t.shadow, err = get(pt.Name, pt.ShadowVersion); err != nil {
			return nil, err
		}
		out[pt.Name] = t
	}
	return out, nil
}

// dump writes the server state as a config file plus one .rego per slot
// under dir, so `gkctl dump` output syncs back with no changes.
func dump(state map[string]tenant, dir string) ([]byte, error) {
	var f File
	write := func(s slot, name string) (string, error) {
		if !s.set() {
			return "", nil
		}
		rel := filepath.Join("policies", name)
		if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
			return "", err
		}
		return rel, os.WriteFile(filepath.Join(dir, rel), []byte(s.rego), 0o644)
	}
	for _, name := range sortedKeys(state) {
		t := state[name]
		spec := TenantSpec{Name: t.name, DisplayName: t.displayName, Disabled: t.disabled}
		var err error
		if spec.Policy, err = write(t.active, t.name+".rego"); err != nil {
			return nil, err
		}
		if spec.Shadow, err = write(t.shadow, t.name+".shadow.rego"); err != nil {
			return nil, err
		}
		f.Tenants = append(f.Tenants, spec)
	}
	return yaml.Marshal(f)
}

func sortedKeys(m map[string]tenant) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
