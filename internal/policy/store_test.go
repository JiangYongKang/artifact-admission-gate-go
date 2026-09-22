package policy_test

import (
	"testing"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

func at(y int, mo time.Month, d int) time.Time {
	return time.Date(y, mo, d, 0, 0, 0, 0, time.UTC)
}

func TestPublishVersioningAndEffectiveAt(t *testing.T) {
	s := policy.NewStore()

	v1 := model.Policy{Version: 1, Name: "p1", EffectiveFrom: at(2026, 1, 1), AllowedBuilders: []string{"b1"}, RequiredMinChainLength: 1}
	v2 := model.Policy{Version: 2, Name: "p2", EffectiveFrom: at(2026, 3, 1), AllowedBuilders: []string{"b1", "b2"}, RequiredMinChainLength: 2}
	if err := s.Publish(v1); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(v2); err != nil {
		t.Fatal(err)
	}

	// Versions must be strictly increasing.
	dup := v1
	if err := s.Publish(dup); err == nil {
		t.Fatal("republishing version 1 should fail")
	}
	if err := s.Publish(model.Policy{Version: 2}); err == nil {
		t.Fatal("publishing an existing version should fail")
	}

	got, err := s.Effective()
	if err != nil || got.Version != 2 {
		t.Fatalf("effective = %v, err=%v, want v2", got.Version, err)
	}

	// Historical point-in-time lookups reproduce the governing version.
	for _, tc := range []struct {
		when time.Time
		want int
	}{
		{at(2026, 2, 15), 1},
		{at(2026, 3, 1), 2},
		{at(2026, 5, 1), 2},
	} {
		p, err := s.EffectiveAt(tc.when)
		if err != nil || p.Version != tc.want {
			t.Fatalf("EffectiveAt(%v) = v%v err=%v, want v%d", tc.when, p.Version, err, tc.want)
		}
	}

	if _, err := s.EffectiveAt(at(2025, 1, 1)); err == nil {
		t.Fatal("EffectiveAt before any activation should fail")
	}
}

func TestRollbackPreservesHistoryAndReproducesConclusions(t *testing.T) {
	s := policy.NewStore()
	v1 := model.Policy{Version: 1, Name: "p1", EffectiveFrom: at(2026, 1, 1), AllowedBuilders: []string{"b1"}}
	v2 := model.Policy{Version: 2, Name: "p2", EffectiveFrom: at(2026, 2, 1), AllowedBuilders: []string{"b2"}}
	mustPublish(t, s, v1)
	mustPublish(t, s, v2)

	// While v2 is effective, b1-built artifact is policy-unsatisfied.
	if v := policy.Evaluate(mustEffective(t, s), "digestA", "b1", 3, nil); len(v) == 0 {
		t.Fatal("b1 should violate v2")
	}

	// Roll back to v1.
	if _, err := s.Rollback(1); err != nil {
		t.Fatal(err)
	}
	eff, _ := s.Effective()
	if eff.Version != 1 {
		t.Fatalf("after rollback effective=%d, want 1", eff.Version)
	}
	if v := policy.Evaluate(eff, "digestA", "b1", 3, nil); len(v) != 0 {
		t.Fatalf("b1 should satisfy rolled-back v1, got %v", v)
	}

	// History is intact and still ordered 1,2.
	hist := s.History()
	if len(hist) != 2 || hist[0].Version != 1 || hist[1].Version != 2 {
		t.Fatalf("history after rollback = %v", hist)
	}

	// A new version after rollback must outnumber the latest published.
	if err := s.Publish(model.Policy{Version: 2, Name: "again"}); err == nil {
		t.Fatal("reusing old version after rollback must be rejected")
	}
	v3 := model.Policy{Version: 3, Name: "p3", EffectiveFrom: at(2026, 3, 1)}
	mustPublish(t, s, v3)
	if n, _ := s.EffectiveVersion(); n != 3 {
		t.Fatalf("effective=%d, want 3", n)
	}
}

func TestRollbackUnknownVersion(t *testing.T) {
	s := policy.NewStore()
	mustPublish(t, s, model.Policy{Version: 1, Name: "p1"})
	if _, err := s.Rollback(99); err == nil {
		t.Fatal("rollback to unknown version should fail")
	}
}

func mustPublish(t *testing.T, s *policy.Store, p model.Policy) {
	t.Helper()
	if err := s.Publish(p); err != nil {
		t.Fatalf("publish v%d: %v", p.Version, err)
	}
}

func mustEffective(t *testing.T, s *policy.Store) model.Policy {
	t.Helper()
	p, err := s.Effective()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
