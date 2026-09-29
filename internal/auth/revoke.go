package auth

import (
	"sync"
	"time"
)

// RevocationList holds revoked token ids (jti) and session ids (sid) until
// the tokens they cover would have expired anyway, so it stays bounded by
// the number of live revoked tokens.
type RevocationList struct {
	mu  sync.RWMutex
	ids map[string]time.Time
	Now func() time.Time
}

func NewRevocationList() *RevocationList {
	return &RevocationList{ids: map[string]time.Time{}, Now: time.Now}
}

func (l *RevocationList) Revoke(id string, until time.Time) {
	l.mu.Lock()
	if until.After(l.ids[id]) {
		l.ids[id] = until
	}
	l.mu.Unlock()
}

// Revoked reports whether any non-empty id is revoked.
func (l *RevocationList) Revoked(ids ...string) bool {
	now := l.Now()
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, id := range ids {
		if until, ok := l.ids[id]; ok && id != "" && now.Before(until) {
			return true
		}
	}
	return false
}

// Sweep drops entries whose tokens have expired.
func (l *RevocationList) Sweep() {
	now := l.Now()
	l.mu.Lock()
	for id, until := range l.ids {
		if !now.Before(until) {
			delete(l.ids, id)
		}
	}
	l.mu.Unlock()
}
