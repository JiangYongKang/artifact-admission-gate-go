// Package audit provides an append-only, sequentially ordered in-memory
// audit trail. Every admission decision and every policy change is recorded.
package audit

import (
	"sync"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
)

// Log is an append-only audit trail. It is safe for concurrent use; the
// assigned sequence numbers establish a total order across all writers.
type Log struct {
	mu      sync.Mutex
	entries []model.AuditEntry
}

// NewLog creates an empty audit log.
func NewLog() *Log { return &Log{} }

// Append records e, assigning it the next monotonically increasing sequence
// number and stamping the current time when Timestamp is zero.
func (l *Log) Append(e model.AuditEntry) model.AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = int64(len(l.entries) + 1)
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	l.entries = append(l.entries, e)
	return e
}

// Entries returns a copy of all entries in sequence order.
func (l *Log) Entries() []model.AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]model.AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Len returns the number of recorded entries.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Filter returns copies of entries for the given action in sequence order.
func (l *Log) Filter(action model.AuditAction) []model.AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []model.AuditEntry
	for _, e := range l.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}
