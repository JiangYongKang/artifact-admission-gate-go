package authz_test

import (
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/model"
)

func TestDefaultGrantsAreLeastPrivilege(t *testing.T) {
	e := authz.NewEnforcer()
	cases := []struct {
		role model.Role
		perm model.Permission
		want bool
	}{
		{model.RoleAdmin, model.PermPolicyWrite, true},
		{model.RoleAdmin, model.PermPolicyRollback, true},
		{model.RoleAdmin, model.PermAuditRead, true},
		{model.RoleAdmin, model.PermArtifactAdmit, false}, // separation of duties
		{model.RoleOperator, model.PermArtifactAdmit, true},
		{model.RoleOperator, model.PermPolicyWrite, false},
		{model.RoleOperator, model.PermPolicyRollback, false},
		{model.RoleOperator, model.PermAuditRead, true},
		{model.RoleViewer, model.PermPolicyRead, true},
		{model.RoleViewer, model.PermArtifactAdmit, false},
		{model.RoleViewer, model.PermAuditRead, false},
		{model.RoleAnonymous, model.PermArtifactAdmit, false},
		{model.RoleAnonymous, model.PermPolicyRead, false},
	}
	for _, tc := range cases {
		if got := e.Allow(tc.role, tc.perm); got != tc.want {
			t.Errorf("Allow(%s,%s)=%v want %v", tc.role, tc.perm, got, tc.want)
		}
	}

	// Grant/revoke helpers.
	e.Grant(model.RoleViewer, model.PermArtifactAdmit)
	if !e.Allow(model.RoleViewer, model.PermArtifactAdmit) {
		t.Fatal("grant did not take effect")
	}
	e.Revoke(model.RoleViewer, model.PermArtifactAdmit)
	if e.Allow(model.RoleViewer, model.PermArtifactAdmit) {
		t.Fatal("revoke did not take effect")
	}
}
