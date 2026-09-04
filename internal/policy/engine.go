// Package policy compiles and evaluates Rego policies with the embedded OPA
// engine. A policy is a single module in package "gatekeeper" that defines
// `allow` (bool) and optionally `reasons` (set of strings).
package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

const query = "data.gatekeeper"

type Input struct {
	Tenant   string         `json:"tenant"`
	Subject  audit.Subject  `json:"subject"`
	Action   string         `json:"action"`
	Resource audit.Resource `json:"resource"`
}

type Decision struct {
	Allowed bool
	Reason  string // sorted, comma-joined `reasons`, or "" if the policy defines none
}

// Compiled is a prepared, reusable query. Safe for concurrent Eval.
type Compiled struct{ pq rego.PreparedEvalQuery }

// Compile parses and prepares a Rego module. Errors surface syntax and
// type problems so PutPolicy can reject a bad policy before storing it.
func Compile(ctx context.Context, module string) (*Compiled, error) {
	pq, err := rego.New(rego.Query(query), rego.Module("policy.rego", module)).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Compiled{pq: pq}, nil
}

// Eval is fail-closed: a missing or non-boolean `allow` is a deny.
func (c *Compiled) Eval(ctx context.Context, in Input) (Decision, error) {
	rs, err := c.pq.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return Decision{}, fmt.Errorf("eval policy: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{}, nil
	}
	doc, _ := rs[0].Expressions[0].Value.(map[string]any)
	d := Decision{}
	d.Allowed, _ = doc["allow"].(bool)
	if rs, ok := doc["reasons"].([]any); ok {
		parts := make([]string, 0, len(rs))
		for _, r := range rs {
			parts = append(parts, fmt.Sprint(r))
		}
		sort.Strings(parts)
		d.Reason = strings.Join(parts, ",")
	}
	return d, nil
}

// Cache memoises compiled policies by (tenant, version). Versions are
// immutable so entries never need invalidation.
type Cache struct {
	mu   sync.RWMutex
	byID map[string]*Compiled
}

func NewCache() *Cache { return &Cache{byID: map[string]*Compiled{}} }

func (c *Cache) Get(ctx context.Context, tenant string, version int64, load func() (string, error)) (*Compiled, error) {
	key := fmt.Sprintf("%s:%d", tenant, version)
	c.mu.RLock()
	cp, ok := c.byID[key]
	c.mu.RUnlock()
	if ok {
		return cp, nil
	}
	src, err := load()
	if err != nil {
		return nil, err
	}
	cp, err = Compile(ctx, src)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.byID[key] = cp
	c.mu.Unlock()
	return cp, nil
}
