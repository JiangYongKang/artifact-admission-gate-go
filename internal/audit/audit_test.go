package audit_test

import (
	"sync"
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
)

func TestAppendSequencesAndCopies(t *testing.T) {
	l := audit.NewLog()
	e1 := l.Append(model.AuditEntry{Action: model.AuditAdmit, Actor: "a"})
	e2 := l.Append(model.AuditEntry{Action: model.AuditAdmit, Actor: "b"})
	if e1.Seq != 1 || e2.Seq != 2 || e1.Timestamp.IsZero() || e2.Timestamp.IsZero() {
		t.Fatalf("unexpected entries: %+v %+v", e1, e2)
	}

	entries := l.Entries()
	entries[0].Actor = "mutated"
	if l.Entries()[0].Actor != "a" {
		t.Fatal("Entries() must return copies")
	}
	if len(l.Filter(model.AuditPolicyPublish)) != 0 {
		t.Fatal("unexpected publish entries")
	}
}

func TestConcurrentAppendAssignsDenseSequence(t *testing.T) {
	l := audit.NewLog()
	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Append(model.AuditEntry{Action: model.AuditAdmit})
		}()
	}
	wg.Wait()

	entries := l.Entries()
	if len(entries) != n {
		t.Fatalf("len=%d want %d", len(entries), n)
	}
	seen := map[int64]bool{}
	for _, e := range entries {
		if seen[e.Seq] {
			t.Fatalf("duplicate seq %d", e.Seq)
		}
		seen[e.Seq] = true
	}
	for i := int64(1); i <= n; i++ {
		if !seen[i] {
			t.Fatalf("missing seq %d", i)
		}
	}
}
