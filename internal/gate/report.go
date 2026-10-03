// 批次报告与历史复核/重放。
//
// 批量准入结束后得到一份可 JSON 序列化离线保存的 BatchReport：记录批次当时的
// 生效策略版本，以及每条制品当时的完整输入、结论、分诊类别与判定依据。
//
// 历史复核（Replay）完全只读：
//   - 不改生效策略、不改任何制品状态、不写审计；
//   - 用报告内嵌的原始输入重新判定，报告记录的策略版本若仍存在，
//     必须复现出报告记录的历史结论与类别；
//   - 同时给出当前生效策略下的结论，两条结论各自标明策略版本，绝不混成一条；
//   - 报告引用的历史策略版本已不存在、空批次、重复复核等异常链路
//     都返回稳定、可解释的结构化结果，不 panic、不静默吞掉。
package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

// Verdict 是一条结论的可机读快照，离线报告与复核结果共用该结构。
type Verdict struct {
	Allowed       bool   `json:"allowed"`
	Reason        Reason `json:"reason"`
	Detail        string `json:"detail"`
	PolicyVersion int    `json:"policy_version"` // 0：在策略评估前已拒绝，或当时无生效策略
}

func verdictFromDecision(d Decision) Verdict {
	return Verdict{
		Allowed:       d.Allowed,
		Reason:        d.Reason,
		Detail:        d.Detail,
		PolicyVersion: d.PolicyVersion,
	}
}

// ItemReport 是批次报告中的单条记录：输入与当时的结论成对保存。
type ItemReport struct {
	Index       int             `json:"index"`        // 条目在批次中的下标（与输入顺序一一对应）
	Name        string          `json:"name"`         // 制品名（仅便于人读）
	InputDigest string          `json:"input_digest"` // 完整输入（含内容/签名/溯源/SBOM）的稳定摘要
	Input       artifact.Bundle `json:"input"`        // 当时的完整输入，离线复核即重放它
	Verdict     Verdict         `json:"verdict"`      // 当时的结论、分诊类别与依据
}

// BatchReport 是一次批量准入结束后可离线保存的批次报告。
type BatchReport struct {
	ID            string       `json:"id"`             // 批次稳定标识：由条目输入与版本确定性派生
	PolicyVersion int          `json:"policy_version"` // 本批当时统一命中的生效策略版本
	Total         int          `json:"total"`          // 条目总数
	AllowedCount  int          `json:"allowed_count"`  // 放行数
	RejectedCount int          `json:"rejected_count"` // 拒绝数
	Items         []ItemReport `json:"items"`          // 按下标排列，不漏条、不重复
}

// Decisions 返回按下标排列的结论，与直接调用 AdmitBatch 的返回等价。
func (r *BatchReport) Decisions() []Decision {
	out := make([]Decision, len(r.Items))
	for i, it := range r.Items {
		out[i] = Decision{
			Artifact:      it.Name,
			Allowed:       it.Verdict.Allowed,
			Reason:        it.Verdict.Reason,
			Detail:        it.Verdict.Detail,
			PolicyVersion: it.Verdict.PolicyVersion,
		}
	}
	return out
}

// canonicalDigest 对任意可 JSON 序列化的值计算稳定摘要：字段顺序固定、
// 同输入永远同摘要，因此同一份输入在任何时间/进程得到相同结果。
func canonicalDigest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		// 参与摘要的类型都由本模块定义且确定可序列化，走到这里属于编程错误。
		panic(fmt.Sprintf("gate: 输入无法序列化: %v", err))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// NewBatchReport 由批次输入与对应结论构造报告。结论必须与输入按下标一一对应，
// 长度不一致视为编程错误直接报错，避免生成漏条/错位的报告。
func NewBatchReport(policyVersion int, bundles []artifact.Bundle, decisions []Decision) *BatchReport {
	if len(bundles) != len(decisions) {
		panic(fmt.Sprintf("gate: 输入 %d 条与结论 %d 条数量不一致", len(bundles), len(decisions)))
	}
	r := &BatchReport{
		PolicyVersion: policyVersion,
		Total:         len(bundles),
		Items:         make([]ItemReport, len(bundles)),
	}
	for i := range bundles {
		d := decisions[i]
		r.Items[i] = ItemReport{
			Index:       i,
			Name:        bundles[i].Artifact.Name,
			InputDigest: canonicalDigest(bundles[i]),
			Input:       bundles[i],
			Verdict:     verdictFromDecision(d),
		}
		if d.Allowed {
			r.AllowedCount++
		} else {
			r.RejectedCount++
		}
	}
	// 批次 ID 不含时间/随机量：同样的条目集与版本得到同样的 ID，
	// 便于识别"同一份报告被反复复核"。
	r.ID = "batch-" + canonicalDigest(struct {
		PolicyVersion int          `json:"policy_version"`
		Items         []ItemReport `json:"items"`
	}{PolicyVersion: policyVersion, Items: r.Items})[:16]
	return r
}

// AdmitBatchReport 执行批量准入并返回可离线保存的批次报告。
// 需要 PermAdmit 权限；报告本身不含时间戳，结论完全由输入与策略版本决定。
func (g *Gate) AdmitBatchReport(p authz.Principal, bundles []artifact.Bundle, opts BatchOptions) (*BatchReport, error) {
	_, report, err := g.runBatch(p, bundles, opts, true)
	if err != nil {
		return nil, err
	}
	return report, nil
}

// ---- 历史复核 / 重放 ----

// 复核结论相对历史记录的状态，稳定可机读。
const (
	// ReproducedExact：历史版本仍存在，重新判定的结论与类别与报告记录完全一致。
	ReproducedExact = "reproduced"
	// VersionMissing：报告引用的策略版本已不存在，无法重算，历史结论原样保留。
	VersionMissing = "history_version_missing"
	// ReplayMismatch：历史版本仍存在，但重新判定与报告记录不一致
	// （正常离线确定性下不应出现，出现即说明报告被破坏或判定代码变更）。
	ReplayMismatch = "history_replay_mismatch"
	// VersionZero：历史结论产生于策略评估之前（签名/溯源环节即被拒），与版本无关。
	VersionZero = "pre_policy"
	// CurrentEvaluated：当前结论是在某个生效策略版本下评估得到。
	CurrentEvaluated = "evaluated"
	// CurrentNoPolicy：当前没有任何生效策略，只做签名与溯源判定。
	CurrentNoPolicy = "no_current_policy"
)

// ItemReplay 是单条历史记录的复核结果：历史结论与当前结论分列，不合并。
type ItemReplay struct {
	Index            int     `json:"index"`
	Name             string  `json:"name"`
	InputDigest      string  `json:"input_digest"`
	Historical       Verdict `json:"historical"`        // 报告记录的当时结论（原样保留）
	HistoricalStatus string  `json:"historical_status"` // reproduced / pre_policy / history_version_mismatch / history_replay_mismatch
	Replayed         Verdict `json:"replayed"`          // 用报告记录的策略版本重算的结论
	Current          Verdict `json:"current"`           // 用当前生效策略重算的结论
	CurrentVersion   int     `json:"current_version"`   // 当前生效策略版本（0 表示无生效策略）
	CurrentStatus    string  `json:"current_status"`    // evaluated / no_current_policy
	Differs          bool    `json:"differs"`           // 历史结论与当前结论的放行/类别是否不同
	DiffSummary      string  `json:"diff_summary"`      // 差异的人类可读说明（一致时为空）
}

// ReplayReport 是整份历史报告的复核结果，字段顺序与原报告一致。
type ReplayReport struct {
	ID                  string       `json:"id"`
	OriginalPolicyVer   int          `json:"original_policy_version"`
	CurrentPolicyVer    int          `json:"current_policy_version"`
	Total               int          `json:"total"`
	DifferingCount      int          `json:"differing_count"` // 历史与当前结论不同的条目数
	MissingVersionCount int          `json:"missing_version_count"`
	Items               []ItemReplay `json:"items"`
}

// ErrMalformedReport 表示历史报告结构不合法（如条目数量字段与实际不符）。
var ErrMalformedReport = errors.New("gate: 历史批次报告结构不合法")

// evaluateAt 在指定策略版本下做一次只读判定：版本不存在时返回 ok=false。
// version==0 表示不应用任何策略（对应策略评估前即被拒的历史条目）。
func (g *Gate) evaluateAt(version int, b artifact.Bundle) (Decision, bool) {
	if version == 0 {
		return g.evaluateBundle(b, policy.Policy{}, false), true
	}
	pol, ok := g.policies.Get(version)
	if !ok {
		return Decision{}, false
	}
	return g.evaluateBundle(b, pol, true), true
}

// Replay 对一份历史批次报告做只读复核。
//
// 需要 PermAdmit 权限；整个过程不写审计、不改策略、不改任何输入。
// 同一份报告重复复核得到逐字节一致的结构化结果（除 JSON 序列化本身无时间字段外）。
func (g *Gate) Replay(p authz.Principal, report *BatchReport) (*ReplayReport, error) {
	if err := authz.Authorize(p, authz.PermAdmit); err != nil {
		// 复核是只读操作：越权同样只追加 access_denied，不产生其他副作用。
		g.audit.Append(audit.Record{Type: audit.EventAccessDenied, Actor: p.Name, Reason: err.Error()})
		return nil, err
	}
	if report == nil {
		return nil, fmt.Errorf("%w: 报告为空", ErrMalformedReport)
	}
	if report.Total != len(report.Items) {
		return nil, fmt.Errorf("%w: total=%d 但实际条目 %d", ErrMalformedReport, report.Total, len(report.Items))
	}

	curPol := g.policies.Current()
	currentVersion := curPol.Version
	out := &ReplayReport{
		ID:                report.ID,
		OriginalPolicyVer: report.PolicyVersion,
		CurrentPolicyVer:  currentVersion,
		Total:             report.Total,
		Items:             make([]ItemReplay, len(report.Items)),
	}

	for i, item := range report.Items {
		if item.Index != i {
			return nil, fmt.Errorf("%w: 第 %d 条记录下标为 %d", ErrMalformedReport, i, item.Index)
		}
		// 输入完整性校验：离线报告可能被截断或手工改动，摘要不符直接报错，
		// 绝不拿被篡改的输入静默重放。
		if got := canonicalDigest(item.Input); got != item.InputDigest {
			return nil, fmt.Errorf("%w: 第 %d 条 (%s) 输入摘要不一致: 记录=%s 实际=%s",
				ErrMalformedReport, i, item.Name, item.InputDigest, got)
		}

		ir := ItemReplay{
			Index:       i,
			Name:        item.Name,
			InputDigest: item.InputDigest,
			Historical:  item.Verdict,
		}

		// 历史版本下重算（必须复现报告记录的结论与类别）。
		// 每条记录按其当时命中的版本取：策略前被拒的条目版本为 0，与批次头版本无关。
		itemVersion := item.Verdict.PolicyVersion
		replayed, versionOK := g.evaluateAt(itemVersion, item.Input)
		switch {
		case itemVersion == 0:
			// 仍重算一次填入 Replayed，便于直接核对策略前结论的可复现性。
			ir.Replayed = verdictFromDecision(replayed)
			ir.HistoricalStatus = VersionZero
		case !versionOK:
			ir.HistoricalStatus = VersionMissing
			out.MissingVersionCount++
		default:
			rv := verdictFromDecision(replayed)
			ir.Replayed = rv
			if rv == item.Verdict {
				ir.HistoricalStatus = ReproducedExact
			} else {
				ir.HistoricalStatus = ReplayMismatch
			}
		}

		// 当前生效版本下重算；两条结论始终分列、各带版本号。
		if currentVersion == 0 {
			ir.CurrentStatus = CurrentNoPolicy
			now := g.evaluateBundle(item.Input, policy.Policy{}, false)
			ir.Current = verdictFromDecision(now)
			ir.CurrentVersion = 0
		} else {
			ir.CurrentStatus = CurrentEvaluated
			now := g.evaluateBundle(item.Input, curPol, true)
			ir.Current = verdictFromDecision(now)
			ir.CurrentVersion = currentVersion
		}

		ir.Differs = ir.Historical.Allowed != ir.Current.Allowed ||
			ir.Historical.Reason != ir.Current.Reason
		if ir.Differs {
			out.DifferingCount++
			ir.DiffSummary = fmt.Sprintf("历史(v%d): allowed=%v reason=%s；当前(v%d): allowed=%v reason=%s",
				ir.Historical.PolicyVersion, ir.Historical.Allowed, ir.Historical.Reason,
				ir.CurrentVersion, ir.Current.Allowed, ir.Current.Reason)
		}
		out.Items[i] = ir
	}
	return out, nil
}

// MarshalReport 将批次报告序列化为可离线保存的 JSON。
func MarshalReport(r *BatchReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// UnmarshalReport 从离线 JSON 恢复批次报告。
func UnmarshalReport(data []byte) (*BatchReport, error) {
	var r BatchReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedReport, err)
	}
	if r.Total != len(r.Items) {
		return nil, fmt.Errorf("%w: total=%d 但实际条目 %d", ErrMalformedReport, r.Total, len(r.Items))
	}
	return &r, nil
}
