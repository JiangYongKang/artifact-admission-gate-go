// Package gate 编排签名、溯源与策略校验，给出制品准入结论。
//
// 判定顺序固定：签名 → 溯源链 → 当前生效策略；
// 任一环节失败即拒绝，且不同环节给出互相可区分的原因。
// 批量校验并发执行，但结论只依赖输入与生效策略，与并发顺序无关。
package gate

import (
	"errors"
	"fmt"
	"sync"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

// Reason 是准入结论的分类原因，互相可区分。
type Reason string

const (
	ReasonAllowed           Reason = "allowed"            // 放行
	ReasonMissingSignature  Reason = "missing_signature"  // 签名缺失
	ReasonInvalidSignature  Reason = "invalid_signature"  // 签名无效/内容被篡改
	ReasonBrokenProvenance  Reason = "broken_provenance"  // 溯源断链
	ReasonPolicyViolation   Reason = "policy_violation"   // 不满足生效策略
)

// Decision 是一次准入判定的结论。
type Decision struct {
	Artifact      string // 制品名
	Allowed       bool   // 是否放行
	Reason        Reason // 分类原因
	Detail        string // 判定依据（人类可读）
	PolicyVersion int    // 命中的策略版本
}

// Gate 是制品准入判定器。
type Gate struct {
	signer  *artifact.Signer
	policies *policy.Store
	audit   *audit.Logger
}

// NewGate 创建准入判定器。
func NewGate(signer *artifact.Signer, policies *policy.Store, logger *audit.Logger) *Gate {
	return &Gate{signer: signer, policies: policies, audit: logger}
}

// Admit 对单个制品包做准入判定。需要 PermAdmit 权限；
// 越权请求只记录审计，不改变任何状态。
func (g *Gate) Admit(p authz.Principal, b artifact.Bundle) (Decision, error) {
	if err := authz.Authorize(p, authz.PermAdmit); err != nil {
		g.audit.Append(audit.Record{
			Type:   audit.EventAccessDenied,
			Actor:  p.Name,
			Reason: err.Error(),
		})
		return Decision{}, err
	}
	d := g.evaluate(b)
	g.audit.Append(audit.Record{
		Type:          audit.EventAdmission,
		Actor:         p.Name,
		Artifact:      b.Artifact.Name,
		PolicyVersion: d.PolicyVersion,
		Allowed:       d.Allowed,
		Reason:        fmt.Sprintf("%s: %s", d.Reason, d.Detail),
	})
	return d, nil
}

// evaluate 执行实际判定（不含权限与审计），供批量并发复用。
func (g *Gate) evaluate(b artifact.Bundle) Decision {
	d := Decision{Artifact: b.Artifact.Name}

	// 1. 签名校验：缺失与无效（篡改）区分。
	err := g.signer.Verify(b.Artifact, b.Signature)
	switch {
	case errors.Is(err, artifact.ErrMissingSignature):
		d.Reason, d.Detail = ReasonMissingSignature, err.Error()
	case errors.Is(err, artifact.ErrInvalidSignature):
		d.Reason, d.Detail = ReasonInvalidSignature, err.Error()
	case err != nil:
		d.Reason, d.Detail = ReasonInvalidSignature, err.Error()
	}
	if d.Reason != "" {
		return d
	}

	// 2. 溯源链完整性校验。
	if err := artifact.VerifyProvenance(b.Artifact, b.Provenance); err != nil {
		d.Reason, d.Detail = ReasonBrokenProvenance, err.Error()
		return d
	}

	// 3. 当前生效策略校验（快照读取，单次判定内版本一致）。
	pol := g.policies.Current()
	d.PolicyVersion = pol.Version
	if pol.RequireSignature && b.Signature == nil {
		d.Reason, d.Detail = ReasonMissingSignature, "策略要求签名但签名缺失"
		return d
	}
	if vs := pol.Violations(b); len(vs) > 0 {
		d.Reason = ReasonPolicyViolation
		d.Detail = fmt.Sprintf("违反策略 v%d: %v", pol.Version, vs)
		return d
	}

	d.Allowed = true
	d.Reason = ReasonAllowed
	d.Detail = fmt.Sprintf("签名有效、溯源完整、满足策略 v%d", pol.Version)
	return d
}

// AdmitBatch 并发校验同批次制品。返回结果按下标与输入一一对应，
// 结论不随并发顺序变化。任一越权则整批拒绝。
func (g *Gate) AdmitBatch(p authz.Principal, bundles []artifact.Bundle) ([]Decision, error) {
	if err := authz.Authorize(p, authz.PermAdmit); err != nil {
		g.audit.Append(audit.Record{
			Type:   audit.EventAccessDenied,
			Actor:  p.Name,
			Reason: err.Error(),
		})
		return nil, err
	}
	decisions := make([]Decision, len(bundles))
	var wg sync.WaitGroup
	for i := range bundles {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := g.evaluate(bundles[i])
			decisions[i] = d
			g.audit.Append(audit.Record{
				Type:          audit.EventAdmission,
				Actor:         p.Name,
				Artifact:      bundles[i].Artifact.Name,
				PolicyVersion: d.PolicyVersion,
				Allowed:       d.Allowed,
				Reason:        fmt.Sprintf("%s: %s", d.Reason, d.Detail),
			})
		}(i)
	}
	wg.Wait()
	return decisions, nil
}

// CommitPolicy 提交新策略版本并使其生效。需要 PermPolicyCommit 权限。
func (g *Gate) CommitPolicy(p authz.Principal, pol policy.Policy) (policy.Policy, error) {
	if err := authz.Authorize(p, authz.PermPolicyCommit); err != nil {
		g.audit.Append(audit.Record{Type: audit.EventAccessDenied, Actor: p.Name, Reason: err.Error()})
		return policy.Policy{}, err
	}
	committed, err := g.policies.Commit(pol)
	if err != nil {
		return policy.Policy{}, err
	}
	g.audit.Append(audit.Record{
		Type:          audit.EventPolicyCommit,
		Actor:         p.Name,
		PolicyVersion: committed.Version,
		Allowed:       true,
		Reason:        fmt.Sprintf("策略 v%d 生效", committed.Version),
	})
	return committed, nil
}

// RollbackPolicy 将生效策略回滚到历史版本。需要 PermPolicyRollback 权限。
// 回滚后历史版本内容不变，同一输入可复现该版本的结论。
func (g *Gate) RollbackPolicy(p authz.Principal, version int) (policy.Policy, error) {
	if err := authz.Authorize(p, authz.PermPolicyRollback); err != nil {
		g.audit.Append(audit.Record{Type: audit.EventAccessDenied, Actor: p.Name, Reason: err.Error()})
		return policy.Policy{}, err
	}
	pol, err := g.policies.Rollback(version)
	if err != nil {
		return policy.Policy{}, err
	}
	g.audit.Append(audit.Record{
		Type:          audit.EventPolicyRollback,
		Actor:         p.Name,
		PolicyVersion: pol.Version,
		Allowed:       true,
		Reason:        fmt.Sprintf("回滚到策略 v%d", pol.Version),
	})
	return pol, nil
}

// AuditRecords 读取审计日志。需要 PermAuditRead 权限。
func (g *Gate) AuditRecords(p authz.Principal) ([]audit.Record, error) {
	if err := authz.Authorize(p, authz.PermAuditRead); err != nil {
		g.audit.Append(audit.Record{Type: audit.EventAccessDenied, Actor: p.Name, Reason: err.Error()})
		return nil, err
	}
	return g.audit.Records(), nil
}
