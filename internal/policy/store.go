// Package policy manages an append-only, versioned policy history with
// rollback and selects the policy effective at a given time.
package policy

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
)

// NotFoundError indicates that no policy version matched a request.
type NotFoundError struct{ Message string }

func (e *NotFoundError) Error() string { return e.Message }

// activation records when a policy version became effective. Rollback
// appends a new activation pointing at an older version; it never mutates
// or removes history.
type activation struct {
	from    time.Time
	version int
}

// Store keeps the complete immutable policy history and tracks which
// version is currently effective. It is safe for concurrent use.
type Store struct {
	mu          sync.RWMutex
	versions    map[int]model.Policy
	order       []int // strictly increasing published version numbers
	activations []activation
}

// NewStore creates an empty policy store.
func NewStore() *Store {
	return &Store{versions: map[int]model.Policy{}}
}

// Publish appends a new immutable policy version. The version must be
// greater than every previously published version. It becomes effective
// immediately, and the activation is timestamped with EffectiveFrom when it
// is non-zero (tests use this for deterministic historical replay).
func (s *Store) Publish(p model.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.Version <= 0 {
		return fmt.Errorf("policy version must be positive, got %d", p.Version)
	}
	if _, exists := s.versions[p.Version]; exists {
		return fmt.Errorf("policy version %d already exists", p.Version)
	}
	if len(s.order) > 0 && p.Version <= s.order[len(s.order)-1] {
		return fmt.Errorf("policy version %d is not greater than latest version %d",
			p.Version, s.order[len(s.order)-1])
	}
	if p.EffectiveFrom.IsZero() {
		p.EffectiveFrom = time.Now().UTC()
	}
	s.versions[p.Version] = p
	s.order = append(s.order, p.Version)
	s.activations = append(s.activations, activation{
		from:    p.EffectiveFrom,
		version: p.Version,
	})
	return nil
}

// Effective returns the currently effective policy.
func (s *Store) Effective() (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.activations) == 0 {
		return model.Policy{}, &NotFoundError{Message: "no policy has been published"}
	}
	cur := s.activations[len(s.activations)-1].version
	return s.versions[cur], nil
}

// EffectiveAt returns the policy that governed decisions at time t: the
// latest activation whose start time is not after t. After a rollback this
// still reproduces the version governing any past point in time.
func (s *Store) EffectiveAt(t time.Time) (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Activations are appended in event order; find the last one at or
	// before t.
	idx := -1
	for i, act := range s.activations {
		if !act.from.After(t) {
			idx = i
		}
	}
	if idx < 0 {
		return model.Policy{}, &NotFoundError{
			Message: fmt.Sprintf("no policy was effective at %s", t.Format(time.RFC3339Nano))}
	}
	return s.versions[s.activations[idx].version], nil
}

// Get returns a published policy by version number.
func (s *Store) Get(version int) (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.versions[version]
	if !ok {
		return model.Policy{}, &NotFoundError{
			Message: fmt.Sprintf("policy version %d not found", version)}
	}
	return p, nil
}

// Rollback makes a previously published version effective again. History is
// never rewritten: a new activation is appended, so future EffectiveAt
// lookups still reproduce the version governing any point in time.
func (s *Store) Rollback(version int) (model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.versions[version]
	if !ok {
		return model.Policy{}, &NotFoundError{
			Message: fmt.Sprintf("cannot roll back to unknown version %d", version)}
	}
	cur := 0
	if len(s.activations) > 0 {
		cur = s.activations[len(s.activations)-1].version
	}
	if cur == version {
		return p, nil // already effective; no new activation
	}
	s.activations = append(s.activations, activation{
		from:    time.Now().UTC(),
		version: version,
	})
	return p, nil
}

// History returns copies of all published policies in version order.
func (s *Store) History() []model.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Policy, 0, len(s.order))
	versions := append([]int(nil), s.order...)
	sort.Ints(versions)
	for _, v := range versions {
		out = append(out, s.versions[v])
	}
	return out
}

// EffectiveVersion returns the currently effective version number.
func (s *Store) EffectiveVersion() (int, error) {
	p, err := s.Effective()
	if err != nil {
		return 0, err
	}
	return p.Version, nil
}
