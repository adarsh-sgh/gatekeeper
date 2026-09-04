package audit

import (
	"testing"
	"time"
)

func chain(n int) []Event {
	prev := Genesis
	out := make([]Event, 0, n)
	for i := 1; i <= n; i++ {
		e := Event{Seq: int64(i), TS: time.Now(), Tenant: "acme", Caller: "svc",
			Subject: Subject{ID: "u1", Roles: []string{"dev"}, Attrs: map[string]any{"z": 1, "a": "x"}},
			Action:  "read", Resource: Resource{Type: "doc", ID: "d1"}, Allowed: i%2 == 0, Reason: "r"}
		e.PrevHash = prev
		e.Hash = Hash(prev, e)
		prev = e.Hash
		out = append(out, e)
	}
	return out
}

func TestChainDetectsTampering(t *testing.T) {
	if got := Verify(chain(5)); got != 0 {
		t.Fatalf("intact chain reported broken at %d", got)
	}
	if got := Verify(nil); got != 0 {
		t.Fatalf("empty chain broken at %d", got)
	}

	// Editing content mid-chain breaks at that event.
	ev := chain(5)
	ev[2].Allowed = !ev[2].Allowed
	if got := Verify(ev); got != 3 {
		t.Fatalf("edited event: broken at %d, want 3", got)
	}
	// Re-hashing the edited event without fixing successors breaks at the next one.
	ev[2].Hash = Hash(ev[2].PrevHash, ev[2])
	if got := Verify(ev); got != 4 {
		t.Fatalf("rehashed event: broken at %d, want 4", got)
	}
	// Deleting a row is caught by the seq gap / prev link.
	ev = chain(5)
	ev = append(ev[:1], ev[2:]...)
	if got := Verify(ev); got != 3 {
		t.Fatalf("deleted event: broken at %d, want 3", got)
	}
}

func TestHashIsCanonical(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 123456100, time.UTC)
	a := Event{Seq: 1, TS: ts, Subject: Subject{ID: "u", Attrs: map[string]any{"z": 1, "a": "x"}}}
	b := a
	b.TS = ts.Add(400 * time.Nanosecond).In(time.FixedZone("x", 3600)) // below Postgres precision, other zone
	b.Subject.Attrs = map[string]any{"a": "x", "z": 1}                 // other insertion order
	if Hash(Genesis, a) != Hash(Genesis, b) {
		t.Fatal("hash not stable under ts precision/zone and map order")
	}
	b.Subject.Attrs["a"] = "y"
	if Hash(Genesis, a) == Hash(Genesis, b) {
		t.Fatal("hash ignored attr change")
	}
}
