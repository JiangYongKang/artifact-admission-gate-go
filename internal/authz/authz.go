// Package authz 提供基于角色的最小权限控制。
//
// 角色与权限边界：
//   - admin：提交策略版本、回滚策略；
//   - releaser：执行制品准入校验；
//   - auditor：读取审计日志。
//
// 未授权请求返回 ErrUnauthorized，调用方必须保证不改变任何状态。
package authz

import (
	"errors"
	"fmt"
)

// ErrUnauthorized 表示越权请求。
var ErrUnauthorized = errors.New("authz: 越权请求被拒绝")

// Role 表示操作者角色。
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleReleaser Role = "releaser"
	RoleAuditor  Role = "auditor"
)

// Permission 表示一项可授予的操作权限。
type Permission string

const (
	PermAdmit          Permission = "admit"          // 制品准入校验
	PermPolicyCommit   Permission = "policy_commit"  // 提交策略版本
	PermPolicyRollback Permission = "policy_rollback" // 回滚策略
	PermAuditRead      Permission = "audit_read"     // 读取审计日志
)

// grants 是角色到权限的静态映射（最小权限）。
var grants = map[Role]map[Permission]bool{
	RoleAdmin: {
		PermPolicyCommit:   true,
		PermPolicyRollback: true,
	},
	RoleReleaser: {
		PermAdmit: true,
	},
	RoleAuditor: {
		PermAuditRead: true,
	},
}

// Principal 表示一个发起请求的主体。
type Principal struct {
	Name string
	Role Role
}

// Authorize 校验主体是否拥有指定权限，越权返回 ErrUnauthorized。
func Authorize(p Principal, perm Permission) error {
	if grants[p.Role][perm] {
		return nil
	}
	return fmt.Errorf("%w: 角色 %q 无权执行 %q", ErrUnauthorized, p.Role, perm)
}
