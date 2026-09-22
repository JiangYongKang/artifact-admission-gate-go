// Package app wires the policy store, RBAC enforcer, audit trail and
// admission gate into one local, concurrency-safe facade.
package app

import (
	"fmt"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

// Principal is the caller identity presented to the facade.
type Principal struct {
	Name string
	Role model.Role
}

// App is the entry point for admission checks and policy administration.
type App struct {
	policies *policy.Store
	authz    *authz.Enforcer
	audit    *audit.Log
	gate     *gate.Gate
}

// New wires the given components into an application facade.
func New(policies *policy.Store, az *authz.Enforcer, log *audit.Log, g *gate.Gate) *App {
	return &App{policies: policies, authz: az, audit: log, gate: g}
}

// ErrPermissionDenied is returned when a principal lacks the required
// permission. Such requests are rejected before any stateful operation and
// never mutate store or audit log.
type ErrPermissionDenied struct {
	Role  model.Role
	Perm  model.Permission
	Actor string
}

func (e *ErrPermissionDenied) Error() string {
	return fmt.Sprintf("permission denied: actor %q with role %q lacks %s",
		e.Actor, e.Role, e.Perm)
}

func (a *App) require(who Principal, p model.Permission) error {
	if !a.authz.Allow(who.Role, p) {
		return &ErrPermissionDenied{Role: who.Role, Perm: p, Actor: who.Name}
	}
	return nil
}

// Admit verifies the principal may admit artifacts, snapshots the effective
// policy, evaluates the request deterministically and appends one audit
// entry. Concurrent calls never change each other's conclusion: each call
// snapshots the policy and runs a stateless evaluation, so admission results
// depend only on the request and the snapshot, not on scheduling order.
func (a *App) Admit(who Principal, req gate.Request) (model.Decision, error) {
	if err := a.require(who, model.PermArtifactAdmit); err != nil {
		return model.Decision{}, err
	}

	p, err := a.policies.Effective()
	if err != nil {
		return model.Decision{}, err
	}

	d := a.gate.Evaluate(req, p)

	a.audit.Append(model.AuditEntry{
		Action:        model.AuditAdmit,
		Role:          who.Role,
		Actor:         who.Name,
		PolicyVersion: d.PolicyVersion,
		ArtifactID:    d.ArtifactID,
		Verdict:       d.Verdict,
		Reason:        d.Reason,
		Detail:        d.Message,
	})
	return d, nil
}

// PublishPolicy authorizes the caller, appends a new immutable policy
// version and records the change in the audit trail.
func (a *App) PublishPolicy(who Principal, p model.Policy) (model.Policy, error) {
	if err := a.require(who, model.PermPolicyWrite); err != nil {
		return model.Policy{}, err
	}
	if err := a.policies.Publish(p); err != nil {
		return model.Policy{}, err
	}
	a.audit.Append(model.AuditEntry{
		Action:        model.AuditPolicyPublish,
		Role:          who.Role,
		Actor:         who.Name,
		PolicyVersion: p.Version,
		Verdict:       model.VerdictAllow,
		Reason:        model.ReasonAdmitted,
		Detail:        fmt.Sprintf("policy version %d (%s) published", p.Version, p.Name),
	})
	return p, nil
}

// RollbackPolicy authorizes the caller, makes a historical version effective
// again (without rewriting history) and records the rollback in the audit
// trail.
func (a *App) RollbackPolicy(who Principal, version int) (model.Policy, error) {
	if err := a.require(who, model.PermPolicyRollback); err != nil {
		return model.Policy{}, err
	}
	p, err := a.policies.Rollback(version)
	if err != nil {
		return model.Policy{}, err
	}
	a.audit.Append(model.AuditEntry{
		Action:        model.AuditPolicyRollback,
		Role:          who.Role,
		Actor:         who.Name,
		PolicyVersion: version,
		Verdict:       model.VerdictAllow,
		Reason:        model.ReasonAdmitted,
		Detail:        fmt.Sprintf("effective policy rolled back to version %d (%s)", version, p.Name),
	})
	return p, nil
}

// EffectivePolicy returns the currently effective policy (requires read).
func (a *App) EffectivePolicy(who Principal) (model.Policy, error) {
	if err := a.require(who, model.PermPolicyRead); err != nil {
		return model.Policy{}, err
	}
	return a.policies.Effective()
}

// PolicyHistory returns all published policy versions (requires read).
func (a *App) PolicyHistory(who Principal) ([]model.Policy, error) {
	if err := a.require(who, model.PermPolicyRead); err != nil {
		return nil, err
	}
	return a.policies.History(), nil
}

// AuditTrail returns the ordered audit entries (requires audit read).
func (a *App) AuditTrail(who Principal) ([]model.AuditEntry, error) {
	if err := a.require(who, model.PermAuditRead); err != nil {
		return nil, err
	}
	return a.audit.Entries(), nil
}

// ReplayAt re-evaluates a request under the policy that was effective at t,
// reproducing a historical conclusion after a rollback. It is a read-only
// operation: it requires artifact:admit permission and writes no audit
// entry and no policy state.
func (a *App) ReplayAt(who Principal, req gate.Request, t time.Time) (model.Decision, error) {
	if err := a.require(who, model.PermArtifactAdmit); err != nil {
		return model.Decision{}, err
	}
	p, err := a.policies.EffectiveAt(t)
	if err != nil {
		return model.Decision{}, err
	}
	return a.gate.Evaluate(req, p), nil
}
