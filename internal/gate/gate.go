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
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/report"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/verdict"
)

// Reason 与 Decision 通过 verdict 叶子包别名提供，保持本包既有 API 不变，
// 同时让 report 包可在不形成循环依赖的前提下引用分诊类型。
type (
	// Reason 是准入结论的分诊类别，稳定、可机读、互相不混淆。
	//
	// 类别一旦发布即为契约：同一份输入无论何时、何种并发顺序、在哪个进程校验，
	// 得到的 Reason 与依据都必须一致。
	Reason   = verdict.Reason
	Decision = verdict.Decision
)

const (
	ReasonAllowed = verdict.Allowed

	ReasonInvalidInput         = verdict.InvalidInput
	ReasonMissingSignature     = verdict.MissingSignature
	ReasonUntrustedSignature   = verdict.UntrustedSignature
	ReasonTamperedContent      = verdict.TamperedContent
	ReasonIncompleteProvenance = verdict.IncompleteProvenance
	ReasonBrokenProvenance     = verdict.BrokenProvenance
	ReasonPolicyViolation      = verdict.PolicyViolation

	// ReasonInvalidSignature 是上一版类别的兼容别名：
	// 旧语义"签名无效或内容被篡改"已拆分为 untrusted_signature 与 tampered_content，
	// 内容被改动这一类保持旧常量名可被旧代码引用。
	ReasonInvalidSignature = verdict.TamperedContent
)

// Decision 是一次准入判定的结论。

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
			Type:       audit.EventAccessDenied,
			Actor:      p.Name,
			Reason:     err.Error(),
			EntryIndex: -1,
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
		EntryIndex:    -1,
	})
	return d, nil
}

// evaluate 执行实际判定（不含权限与审计），供批量并发复用。
// 使用当前生效策略；单条与批量对策略都做快照读取，判定内版本一致。
func (g *Gate) evaluate(b artifact.Bundle) Decision {
	return g.evaluateWithPolicy(b, g.policies.Current())
}

// evaluateWithPolicy 在指定策略快照下执行纯判定：同样的输入与策略必定得到
// 同样的结论，与时间、并发顺序、进程无关。历史复核也复用本函数。
//
// 分诊顺序固定，先到先返，类别因此互相不混淆：
//  0. 空输入 → invalid_input
//  1. 没给签名材料 → missing_signature
//  2. 签名本身不可信 → untrusted_signature
//  3. 签名有效但内容被改 → tampered_content
//  4. 溯源缺失/截断 → incomplete_provenance
//  5. 溯源链断裂 → broken_provenance
//  6. 不满足策略 → policy_violation
//  7. 全部通过 → allowed
func (g *Gate) evaluateWithPolicy(b artifact.Bundle, pol policy.Policy) Decision {
	d := Decision{Artifact: b.Artifact.Name}

	// 0. 空输入稳定分诊，不发生 panic。
	if isEmptyBundle(b) {
		d.Reason = ReasonInvalidInput
		d.Detail = "空输入：制品名为空、内容为空且未提供签名/溯源"
		return d
	}

	// 1-3. 签名分诊：缺失 / 签名不可信 / 内容被篡改，三类严格分开。
	err := g.signer.Verify(b.Artifact, b.Signature)
	switch {
	case errors.Is(err, artifact.ErrMissingSignature):
		d.Reason, d.Detail = ReasonMissingSignature, err.Error()
	case errors.Is(err, artifact.ErrUntrustedSignature):
		d.Reason, d.Detail = ReasonUntrustedSignature, err.Error()
	case errors.Is(err, artifact.ErrTamperedContent):
		d.Reason, d.Detail = ReasonTamperedContent, err.Error()
	case err != nil:
		// 未预期的签名错误一律按"签名不可信"分诊，绝不静默吞掉。
		d.Reason, d.Detail = ReasonUntrustedSignature, err.Error()
	}
	if d.Reason != "" {
		return d
	}

	// 4-5. 溯源链分诊：不完整（空/截断/封存不符）与断裂（换序/伪造）分开。
	if err := artifact.VerifyProvenance(b.Artifact, b.Provenance); err != nil {
		switch {
		case errors.Is(err, artifact.ErrIncompleteProvenance):
			d.Reason, d.Detail = ReasonIncompleteProvenance, err.Error()
		default:
			d.Reason, d.Detail = ReasonBrokenProvenance, err.Error()
		}
		return d
	}

	// 6. 指定策略快照下的条款校验。
	d.PolicyVersion = pol.Version
	if vs := pol.Violations(b); len(vs) > 0 {
		d.Reason = ReasonPolicyViolation
		d.Detail = fmt.Sprintf("违反策略 v%d: %v", pol.Version, vs)
		return d
	}

	// 7. 全部通过。
	d.Allowed = true
	d.Reason = ReasonAllowed
	d.Detail = fmt.Sprintf("签名有效、溯源完整、满足策略 v%d", pol.Version)
	return d
}

// isEmptyBundle 判断是否为完全没有实质内容的输入。
// 仅有名字或仅有内容不算空输入；四要素全空才算空输入。
func isEmptyBundle(b artifact.Bundle) bool {
	return b.Artifact.Name == "" &&
		len(b.Artifact.Content) == 0 &&
		(b.Signature == nil || len(b.Signature.Value) == 0) &&
		len(b.Provenance.Links) == 0 &&
		len(b.SBOM.Components) == 0
}

// EvaluateWithVersion 按指定历史策略版本对输入做只读复算，
// 供 report.Replay 使用。不写审计、不移动生效指针；
// ok=false 表示该版本不存在（由复核方稳定分诊为 version_missing）。
func (g *Gate) EvaluateWithVersion(b artifact.Bundle, version int) (Decision, bool) {
	pol, ok := g.policies.Get(version)
	if !ok {
		return Decision{}, false
	}
	return g.evaluateWithPolicy(b, pol), true
}

// EvaluateCurrent 按当前生效策略对输入做只读复算，
// 返回结论与当前生效版本号（尚无生效策略时版本为 0）。
func (g *Gate) EvaluateCurrent(b artifact.Bundle) (Decision, int) {
	pol := g.policies.Current()
	return g.evaluateWithPolicy(b, pol), pol.Version
}

// CurrentVersion 返回当前生效版本号。
func (g *Gate) CurrentVersion() int { return g.policies.CurrentVersion() }

// defaultConcurrency 限制批量校验的并发度，避免上万条输入时 goroutine 数量
// 随批次规模失控；耗时与内存因此有上界，而结论与并发度无关。
const defaultConcurrency = 64

// AdmitBatch 并发校验同批次制品。返回结果按下标与输入一一对应，
// 结论只依赖输入与批开始时快照的生效策略，与并发顺序、打乱方式、并发度无关。
// 任一越权则整批拒绝且不产生任何审计。
//
// 空批次返回长度为 0 的结果与 nil 错误（稳定行为，不报错）。
func (g *Gate) AdmitBatch(p authz.Principal, bundles []artifact.Bundle) ([]Decision, error) {
	decisions, _, err := g.admitBatch(p, bundles)
	return decisions, err
}

// AdmitBatchReport 与 AdmitBatch 等价，但额外返回一份可离线保存的批次报告，
// 记录每条输入、命中策略版本、结论、分诊类别与判定依据。
func (g *Gate) AdmitBatchReport(p authz.Principal, bundles []artifact.Bundle) ([]Decision, report.BatchReport, error) {
	return g.admitBatch(p, bundles)
}

// admitBatch 是批量准入的共用实现：鉴权 → 策略快照 → 有界并发判定
// → 逐条审计 → 生成报告。审计写入与判定分离，但每条都带批次 ID 与下标。
func (g *Gate) admitBatch(p authz.Principal, bundles []artifact.Bundle) ([]Decision, report.BatchReport, error) {
	if err := authz.Authorize(p, authz.PermAdmit); err != nil {
		g.audit.Append(audit.Record{
			Type:       audit.EventAccessDenied,
			Actor:      p.Name,
			EntryIndex: -1,
			Reason:     err.Error(),
		})
		return nil, report.BatchReport{}, err
	}

	// 整批只快照一次生效策略：判定期间即使有提交/回滚，本批结论仍一致。
	pol := g.policies.Current()

	decisions := make([]Decision, len(bundles))
	if len(bundles) == 0 {
		// 空批次：生成空报告，审计留痕，返回空切片而非 nil。
		r, err := report.NewBatchReport(pol.Version, bundles, decisions, time.Now())
		if err != nil {
			return nil, report.BatchReport{}, err
		}
		g.audit.Append(audit.Record{
			Type:          audit.EventAdmission,
			Actor:         p.Name,
			PolicyVersion: pol.Version,
			Allowed:       true,
			Reason:        fmt.Sprintf("空批次报告 %s（0 条）", r.ID),
			ReportID:      r.ID,
			EntryIndex:    -1,
		})
		return decisions, r, nil
	}

	// 有界工作池：信号量控制并发上限，每个输入恰被处理一次，结果按下标写回。
	sem := make(chan struct{}, defaultConcurrency)
	var wg sync.WaitGroup
	for i := range bundles {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			decisions[i] = g.evaluateWithPolicy(bundles[i], pol)
		}(i)
	}
	wg.Wait()

	r, err := report.NewBatchReport(pol.Version, bundles, decisions, time.Now())
	if err != nil {
		return nil, report.BatchReport{}, err
	}

	// 逐条审计，按下标顺序追加，每条都能对应回报告记录。
	for i, d := range decisions {
		g.audit.Append(audit.Record{
			Type:          audit.EventAdmission,
			Actor:         p.Name,
			Artifact:      d.Artifact,
			PolicyVersion: d.PolicyVersion,
			Allowed:       d.Allowed,
			Reason:        fmt.Sprintf("%s: %s", d.Reason, d.Detail),
			ReportID:      r.ID,
			EntryIndex:    i,
		})
	}
	g.audit.Append(audit.Record{
		Type:          audit.EventAdmission,
		Actor:         p.Name,
		PolicyVersion: pol.Version,
		Allowed:       true,
		Reason:        fmt.Sprintf("批次报告 %s 完成（%d 条）", r.ID, len(bundles)),
		ReportID:      r.ID,
		EntryIndex:    -1,
	})

	return decisions, r, nil
}

// ReviewBatch 对一份离线历史报告做只读复核。
//
// 需要 PermAuditRead 权限；复核过程不修改现行策略、不改动任何制品状态、
// 不追加审计记录（连越权都在鉴权层直接拒绝，不进入复核）。
// 历史结论与当前结论在结果中分列，各自标明策略版本与差异。
func (g *Gate) ReviewBatch(p authz.Principal, r report.BatchReport) (report.ReviewResult, error) {
	if err := authz.Authorize(p, authz.PermReview); err != nil {
		// 只读复核的越权不写审计之外的任何状态；为与其它越权路径保持一致，
		// 这里仍仅追加一条 access_denied，不触碰策略与制品。
		g.audit.Append(audit.Record{
			Type:       audit.EventAccessDenied,
			Actor:      p.Name,
			EntryIndex: -1,
			Reason:     err.Error(),
		})
		return report.ReviewResult{}, err
	}
	// Replay 只调用三个只读求值方法，保证复核不产生任何副作用。
	return report.Replay(g, r), nil
}

// CommitPolicy 提交新策略版本并使其生效。需要 PermPolicyCommit 权限。
func (g *Gate) CommitPolicy(p authz.Principal, pol policy.Policy) (policy.Policy, error) {
	if err := authz.Authorize(p, authz.PermPolicyCommit); err != nil {
		g.audit.Append(audit.Record{Type: audit.EventAccessDenied, Actor: p.Name, EntryIndex: -1, Reason: err.Error()})
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
		EntryIndex:    -1,
	})
	return committed, nil
}

// RollbackPolicy 将生效策略回滚到历史版本。需要 PermPolicyRollback 权限。
// 回滚后历史版本内容不变，同一输入可复现该版本的结论。
func (g *Gate) RollbackPolicy(p authz.Principal, version int) (policy.Policy, error) {
	if err := authz.Authorize(p, authz.PermPolicyRollback); err != nil {
		g.audit.Append(audit.Record{Type: audit.EventAccessDenied, Actor: p.Name, EntryIndex: -1, Reason: err.Error()})
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
		EntryIndex:    -1,
	})
	return pol, nil
}

// AuditRecords 读取审计日志。需要 PermAuditRead 权限。
func (g *Gate) AuditRecords(p authz.Principal) ([]audit.Record, error) {
	if err := authz.Authorize(p, authz.PermAuditRead); err != nil {
		g.audit.Append(audit.Record{Type: audit.EventAccessDenied, Actor: p.Name, EntryIndex: -1, Reason: err.Error()})
		return nil, err
	}
	return g.audit.Records(), nil
}
