// Package gate 编排签名、溯源与策略校验，给出制品准入结论。
//
// 判定顺序固定：签名 -> 溯源链完整性/连贯性 -> 当前生效策略；
// 任一环节失败即拒绝，且不同环节给出互相可区分、可机读的分诊类别。
// 批量校验并发执行，但结论只依赖输入与生效策略，与并发顺序、并发度无关。
package gate

import (
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

// Reason 是准入结论的分诊类别，稳定、可机读、互相不混淆。
type Reason string

const (
	ReasonAllowed              Reason = "allowed"               // 放行
	ReasonMissingSignature     Reason = "missing_signature"     // 根本没提供签名材料
	ReasonUntrustedSignature   Reason = "untrusted_signature"   // 签名本身不可信（密钥未知/不匹配、签名值错误）
	ReasonTamperedContent      Reason = "tampered_content"      // 签名后制品内容被改过（摘要不匹配）
	ReasonIncompleteProvenance Reason = "incomplete_provenance" // 溯源被截断或缺了声明的关键环节
	ReasonBrokenProvenance     Reason = "broken_provenance"     // 溯源哈希链不连贯（换序/篡改/锚点不匹配）
	ReasonPolicyViolation      Reason = "policy_violation"      // 不满足生效策略
)

// ReasonInvalidSignature 是旧版笼统类别，现等价于 ReasonUntrustedSignature。
//
// Deprecated: 签名本身问题请用 ReasonUntrustedSignature，
// 内容篡改请用 ReasonTamperedContent，两类必须分开分诊。
const ReasonInvalidSignature Reason = ReasonUntrustedSignature

// Decision 是一次准入判定的结论。
type Decision struct {
	Artifact      string // 制品名
	Allowed       bool   // 是否放行
	Reason        Reason // 分诊类别
	Detail        string // 判定依据（人类可读，含具体不匹配的摘要/环节/条款）
	PolicyVersion int    // 命中的策略版本；0 表示在到达策略评估前已被拒绝或当时无生效策略
}

// defaultBatchWorkers 是批量校验的默认并发上限：并发数不随批次规模失控，
// 结论正确性与并发度无关，只影响耗时。
func defaultBatchWorkers() int {
	n := runtime.NumCPU()
	if n < 2 {
		return 2
	}
	if n > 32 {
		return 32
	}
	return n
}

// Gate 是制品准入判定器。
type Gate struct {
	signer   *artifact.Signer
	policies *policy.Store
	audit    *audit.Logger
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
	pol := g.policies.Current()
	d := g.evaluateBundle(b, pol, pol.Version != 0)
	g.appendAdmissionAudit(p.Name, b, d)
	return d, nil
}

// appendAdmissionAudit 追加一条准入审计记录。
func (g *Gate) appendAdmissionAudit(actor string, b artifact.Bundle, d Decision) {
	g.audit.Append(audit.Record{
		Type:          audit.EventAdmission,
		Actor:         actor,
		Artifact:      b.Artifact.Name,
		PolicyVersion: d.PolicyVersion,
		Allowed:       d.Allowed,
		Reason:        fmt.Sprintf("%s: %s", d.Reason, d.Detail),
	})
}

// evaluateBundle 执行实际判定（不含权限与审计），是单次判定与历史复核共用的
// 唯一判定路径，保证"当时怎么判、复核就怎么判"。
//
// applyPolicy 为 false 时（尚未提交任何策略）只做签名与溯源判定，
// 通过即放行，PolicyVersion 保持 0。
func (g *Gate) evaluateBundle(b artifact.Bundle, pol policy.Policy, applyPolicy bool) Decision {
	d := Decision{Artifact: b.Artifact.Name}

	// 1. 签名校验：材料缺失 / 签名不可信 / 内容被篡改 三类稳定分开。
	err := g.signer.Verify(b.Artifact, b.Signature)
	switch {
	case errors.Is(err, artifact.ErrMissingSignature):
		d.Reason, d.Detail = ReasonMissingSignature, err.Error()
		return d
	case errors.Is(err, artifact.ErrTamperedContent):
		d.Reason, d.Detail = ReasonTamperedContent, err.Error()
		return d
	case errors.Is(err, artifact.ErrUntrustedSignature):
		d.Reason, d.Detail = ReasonUntrustedSignature, err.Error()
		return d
	case err != nil:
		d.Reason, d.Detail = ReasonUntrustedSignature, err.Error()
		return d
	}

	// 2. 溯源校验：截断/缺关键环节（incomplete）与哈希断链（broken）分开。
	if err := artifact.VerifyProvenance(b.Artifact, b.Provenance); err != nil {
		if errors.Is(err, artifact.ErrIncompleteProvenance) {
			d.Reason, d.Detail = ReasonIncompleteProvenance, err.Error()
		} else {
			d.Reason, d.Detail = ReasonBrokenProvenance, err.Error()
		}
		return d
	}

	// 3. 策略校验：无生效策略时不评估策略条款。
	if !applyPolicy {
		d.Allowed = true
		d.Reason = ReasonAllowed
		d.Detail = "签名有效、溯源完整；当前无生效策略，跳过策略评估"
		return d
	}
	d.PolicyVersion = pol.Version
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

// BatchOptions 控制批量校验的执行方式。零值即可用；结论与这些选项无关，
// 选项只影响资源占用与耗时。
type BatchOptions struct {
	// Workers 为并发 worker 上限；<=0 时取默认值（不超过 CPU 数，封顶 32）。
	Workers int
}

// AdmitBatch 并发校验同批次制品。返回结果按下标与输入一一对应：
// 不漏条、不重复、与输入顺序/打乱方式/并发度无关。任一越权则整批拒绝。
func (g *Gate) AdmitBatch(p authz.Principal, bundles []artifact.Bundle) ([]Decision, error) {
	return g.AdmitBatchWith(p, bundles, BatchOptions{})
}

// AdmitBatchWith 与 AdmitBatch 相同，但允许指定并发上限。
func (g *Gate) AdmitBatchWith(p authz.Principal, bundles []artifact.Bundle, opts BatchOptions) ([]Decision, error) {
	report, err := g.AdmitBatchReport(p, bundles, opts)
	if err != nil {
		return nil, err
	}
	return report.Decisions(), nil
}

// runBatch 是批量校验的共享实现：鉴权一次、生效策略快照一次、
// 有界 worker 池并发判定，审计按判定完成顺序追加（记录内容仍确定）。
func (g *Gate) runBatch(p authz.Principal, bundles []artifact.Bundle, opts BatchOptions, buildReport bool) ([]Decision, *BatchReport, error) {
	if err := authz.Authorize(p, authz.PermAdmit); err != nil {
		g.audit.Append(audit.Record{
			Type:   audit.EventAccessDenied,
			Actor:  p.Name,
			Reason: err.Error(),
		})
		return nil, nil, err
	}

	// 生效策略在整批开始时快照一次：同批所有条目命中同一版本，
	// 判定过程中即使策略被提交/回滚也不影响本批结论。
	pol := g.policies.Current()
	applyPolicy := pol.Version != 0

	decisions := make([]Decision, len(bundles))
	workers := opts.Workers
	if workers <= 0 {
		workers = defaultBatchWorkers()
	}
	if workers > len(bundles) {
		workers = len(bundles)
	}
	if workers < 1 && len(bundles) > 0 {
		workers = 1
	}

	if len(bundles) > 0 {
		jobs := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					b := bundles[i]
					d := g.evaluateBundle(b, pol, applyPolicy)
					decisions[i] = d
					g.appendAdmissionAudit(p.Name, b, d)
				}
			}()
		}
		for i := range bundles {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
	}

	var report *BatchReport
	if buildReport {
		report = NewBatchReport(pol.Version, bundles, decisions)
	}
	return decisions, report, nil
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
