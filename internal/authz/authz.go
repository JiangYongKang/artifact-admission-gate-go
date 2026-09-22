// Package authz implements role-based, least-privilege access control.
package authz

import "github.com/highcumontoa/artifact-admission-gate-go/internal/model"

// Enforcer maps roles to granted permissions. It is safe for concurrent use
// (grants are configured at construction time and never mutated except
// through the locked Grant/Revoke test helpers).
type Enforcer struct {
	grants map[model.Role]map[model.Permission]bool
}

// NewEnforcer creates an Enforcer with the default least-privilege grants:
//
//	admin    : policy read/write/rollback, audit read (no artifact admission)
//	operator : artifact admit, policy read, audit read
//	viewer   : policy read
//
// anonymous gets no grants, so every request from that role is denied.
func NewEnforcer() *Enforcer {
	e := &Enforcer{grants: map[model.Role]map[model.Permission]bool{}}
	grant := func(r model.Role, perms ...model.Permission) {
		set := map[model.Permission]bool{}
		for _, p := range perms {
			set[p] = true
		}
		e.grants[r] = set
	}
	grant(model.RoleAdmin,
		model.PermPolicyRead, model.PermPolicyWrite,
		model.PermPolicyRollback, model.PermAuditRead)
	grant(model.RoleOperator,
		model.PermArtifactAdmit, model.PermPolicyRead, model.PermAuditRead)
	grant(model.RoleViewer, model.PermPolicyRead)
	grant(model.RoleAnonymous)
	return e
}

// Grant adds a permission to a role (used by tests for custom matrices).
func (e *Enforcer) Grant(r model.Role, p model.Permission) {
	set, ok := e.grants[r]
	if !ok {
		set = map[model.Permission]bool{}
		e.grants[r] = set
	}
	set[p] = true
}

// Revoke removes a permission from a role.
func (e *Enforcer) Revoke(r model.Role, p model.Permission) {
	if set, ok := e.grants[r]; ok {
		delete(set, p)
	}
}

// Allow reports whether the role holds the permission.
func (e *Enforcer) Allow(r model.Role, p model.Permission) bool {
	return e.grants[r][p]
}
