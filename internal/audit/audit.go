// Package audit defines the audit event model and its hash chain.
//
// Each tenant has an independent chain: event N's hash covers event N's
// content plus event N-1's hash, so editing or deleting any row changes every
// hash after it and Verify reports the first break.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type Subject struct {
	ID    string         `json:"id"`
	Roles []string       `json:"roles,omitempty"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

type Resource struct {
	Type  string         `json:"type"`
	ID    string         `json:"id"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Event is one decision. Seq, PrevHash and Hash are assigned by the store at
// append time; everything else is filled by the caller.
type Event struct {
	Seq           int64     `json:"seq"`
	TS            time.Time `json:"ts"`
	Tenant        string    `json:"tenant"`
	Caller        string    `json:"caller"`
	Subject       Subject   `json:"subject"`
	Action        string    `json:"action"`
	Resource      Resource  `json:"resource"`
	PolicyVersion int64     `json:"policy_version"`
	Allowed       bool      `json:"allowed"`
	Reason        string    `json:"reason"`
	ShadowVersion int64     `json:"shadow_version"`
	ShadowAllowed bool      `json:"shadow_allowed"`
	ShadowDiverge bool      `json:"shadow_diverged"`
	PrevHash      string    `json:"-"`
	Hash          string    `json:"-"`
}

// Genesis is the PrevHash of the first event in every chain.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Hash returns hex(sha256(prevHash || canonical JSON of e)). encoding/json
// writes struct fields in declaration order and map keys sorted, so the
// encoding is canonical without extra work. TS is truncated to microseconds
// to match Postgres timestamptz precision.
func Hash(prevHash string, e Event) string {
	e.TS = e.TS.UTC().Truncate(time.Microsecond)
	body, err := json.Marshal(e)
	if err != nil {
		panic(fmt.Sprintf("audit: marshal event: %v", err)) // only on unsupported attr types
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{'\n'})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify walks events (ascending seq, starting at the chain head) and returns
// the seq of the first event whose links do not hold, or 0 if all are intact.
func Verify(events []Event) (brokenAt int64) {
	prev := Genesis
	for i, e := range events {
		if e.PrevHash != prev || e.Hash != Hash(prev, e) || (i > 0 && e.Seq != events[i-1].Seq+1) {
			return e.Seq
		}
		prev = e.Hash
	}
	return 0
}
