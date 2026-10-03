// Package report 定义可离线保存的历史批次报告，并提供只读复核编排。
//
// 报告在批量准入结束时生成，完整记录该批每条制品当时的输入、命中的策略版本、
// 结论、分诊类别与判定依据。报告是纯数据结构，可序列化为 JSON 离线保存、
// 反复加载复核，不依赖任何外部服务。
//
// 复核（Replay）严格只读：不移动生效策略指针、不改动制品状态、不写审计。
// 报告引用的历史策略版本若已不存在，对应条目稳定返回 version_missing，
// 而不是偶发报错；历史结论与当前结论始终分列呈现、各自标明策略版本。
package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/verdict"
)

// Entry 记录一条制品当时的准入快照。
type Entry struct {
	Index         int             `json:"index"`          // 批次内下标（从 0 开始，稳定）
	Input         artifact.Bundle `json:"input"`          // 当时的完整输入
	Allowed       bool            `json:"allowed"`        // 当时结论：是否放行
	Reason        verdict.Reason  `json:"reason"`         // 当时分诊类别
	Detail        string          `json:"detail"`         // 当时判定依据
	PolicyVersion int             `json:"policy_version"` // 当时命中的策略版本
}

// BatchReport 是一次批量准入的可离线保存报告。
type BatchReport struct {
	ID            string    `json:"id"`             // 批次标识（由输入与策略版本确定性生成）
	GeneratedAt   time.Time `json:"generated_at"`   // 生成时刻（仅元数据，不参与判定与 ID）
	PolicyVersion int       `json:"policy_version"` // 该批快照的生效策略版本
	Entries       []Entry   `json:"entries"`        // 按下标排列，与输入一一对应
}

// HistoryStatus 表示报告引用的历史策略版本当前是否可用于复算。
type HistoryStatus string

const (
	// HistoryAvailable：报告记录的策略版本仍存在，已用其复算历史结论。
	HistoryAvailable HistoryStatus = "available"
	// HistoryVersionMissing：报告引用的策略版本现在已不存在，
	// 无法复算历史结论；这是稳定、可解释的结果而非偶发错误。
	HistoryVersionMissing HistoryStatus = "version_missing"
)

// EntryReview 是一条历史记录的复核结论：历史与当前分列，绝不混成一条。
type EntryReview struct {
	Index         int               `json:"index"`
	Artifact      string            `json:"artifact"`
	Recorded      Entry             `json:"recorded"`             // 报告里记录的当时快照
	Historical    *verdict.Decision `json:"historical,omitempty"` // 用记录版本复算出的结论
	Current       *verdict.Decision `json:"current,omitempty"`    // 用当前生效版本复算出的结论
	HistoryStatus HistoryStatus     `json:"history_status"`       // 历史版本是否可用
	Diverged      bool              `json:"diverged"`             // 历史结论与当前结论是否不同
	Note          string            `json:"note,omitempty"`       // 可读说明（含差异）
}

// ReviewResult 是整份报告的只读复核结果，与报告条目一一对应。
type ReviewResult struct {
	ReportID       string        `json:"report_id"`
	CurrentVersion int           `json:"current_version"` // 复核时当前生效版本；0 表示尚无生效策略
	Reviews        []EntryReview `json:"reviews"`         // 与报告条目一一对应，不漏不重
}

// Evaluator 抽象只读判定能力，由 *gate.Gate 实现。
// 复核只通过这三个方法读取状态，因此不可能改动现行策略或写审计。
type Evaluator interface {
	// EvaluateWithVersion 按指定历史策略版本复算一条输入；
	// ok=false 表示该版本不存在。
	EvaluateWithVersion(b artifact.Bundle, version int) (verdict.Decision, bool)
	// EvaluateCurrent 按当前生效策略复算一条输入；
	// version 为当前生效版本号（0 表示尚无生效策略）。
	EvaluateCurrent(b artifact.Bundle) (d verdict.Decision, version int)
	// CurrentVersion 返回当前生效版本号。
	CurrentVersion() int
}

// canonicalDigest 对报告的决定性内容做稳定摘要，用于生成批次 ID。
// 只纳入策略版本与每条输入的规范化 JSON；time.Time 不参与，
// 因此同批输入 + 同一策略版本在任何时间/进程都得到同一 ID。
func canonicalDigest(policyVersion int, bundles []artifact.Bundle) string {
	h := sha256.New()
	fmt.Fprintf(h, "batch|v%d|n=%d\n", policyVersion, len(bundles))
	for i, b := range bundles {
		raw, err := json.Marshal(struct {
			Index int             `json:"index"`
			Input artifact.Bundle `json:"input"`
		}{Index: i, Input: b})
		if err != nil {
			// 本项目所有字段均为可确定序列化的内建类型，走到这里属于编程错误。
			panic(fmt.Errorf("report: 输入无法规范化: %w", err))
		}
		h.Write(raw)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewBatchReport 由批次输入与按下标对齐的结论构造离线报告。
//
// decisions 长度必须与 bundles 完全一致（一一对应），否则返回错误，
// 避免漏条目或错配。ID 由输入与策略版本确定性生成。
func NewBatchReport(policyVersion int, bundles []artifact.Bundle, decisions []verdict.Decision, at time.Time) (BatchReport, error) {
	if len(bundles) != len(decisions) {
		return BatchReport{}, fmt.Errorf(
			"report: 输入 %d 条与结论 %d 条数量不一致", len(bundles), len(decisions))
	}
	entries := make([]Entry, len(bundles))
	for i := range bundles {
		entries[i] = Entry{
			Index:         i,
			Input:         bundles[i],
			Allowed:       decisions[i].Allowed,
			Reason:        decisions[i].Reason,
			Detail:        decisions[i].Detail,
			PolicyVersion: decisions[i].PolicyVersion,
		}
	}
	return BatchReport{
		ID:            "batch-" + canonicalDigest(policyVersion, bundles)[:16],
		GeneratedAt:   at.UTC(),
		PolicyVersion: policyVersion,
		Entries:       entries,
	}, nil
}

// JSON 将报告序列化为缩进 JSON，便于离线保存与人工检查。
func (r BatchReport) JSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, fmt.Errorf("report: 序列化失败: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseJSON 从离线 JSON 恢复报告，并做结构校验：
// 下标必须连续、条目数字段自洽。损坏/截断的报告会得到明确错误而非静默接受。
func ParseJSON(data []byte) (BatchReport, error) {
	var r BatchReport
	if err := json.Unmarshal(data, &r); err != nil {
		return BatchReport{}, fmt.Errorf("report: 报告 JSON 无效: %w", err)
	}
	if r.ID == "" {
		return BatchReport{}, fmt.Errorf("report: 报告缺少批次 id")
	}
	for i, e := range r.Entries {
		if e.Index != i {
			return BatchReport{}, fmt.Errorf(
				"report: 条目下标不连续: 位置 %d 记录 index=%d", i, e.Index)
		}
	}
	return r, nil
}

// sameDecision 判断两个分诊结论的业务结论是否一致：只比较放行结果与分诊类别。
// 策略版本号不同不属于结论分歧（版本各自在字段中呈现），因此不纳入比较；
// Detail 为人类可读依据，其差异也不改变业务结论。
func sameDecision(a, b *verdict.Decision) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Allowed == b.Allowed && a.Reason == b.Reason
}

// Replay 用判定器对一份历史报告做只读复核。
//
// 每条记录同时得到：
//   - historical：用报告记录的策略版本复算的结论；版本已不存在时为 nil 且
//     HistoryStatus=version_missing（稳定可解释，不报错、不静默）；
//   - current：用当前生效策略复算的结论；尚无生效策略时为 nil。
//
// 两者各自标明策略版本；Diverged 表示结论类别或放行结果不同，差异写入 Note。
// 复核过程不调用任何写接口，因此现行策略、制品状态与审计记录都不受影响；
// 同一份报告反复复核得到完全一致的结果。
func Replay(ev Evaluator, r BatchReport) ReviewResult {
	currentVersion := ev.CurrentVersion()
	out := ReviewResult{
		ReportID:       r.ID,
		CurrentVersion: currentVersion,
		Reviews:        make([]EntryReview, len(r.Entries)),
	}
	for i, rec := range r.Entries {
		rv := EntryReview{Index: rec.Index, Artifact: rec.Input.Artifact.Name, Recorded: rec}

		// 历史版本复算。
		hd, ok := ev.EvaluateWithVersion(rec.Input, rec.PolicyVersion)
		if ok {
			h := hd
			rv.Historical = &h
			rv.HistoryStatus = HistoryAvailable
		} else {
			rv.HistoryStatus = HistoryVersionMissing
			rv.Note = fmt.Sprintf("报告引用的策略 v%d 现已不存在，无法复算历史结论",
				rec.PolicyVersion)
		}

		// 当前生效版本复算。
		if currentVersion > 0 {
			cd, _ := ev.EvaluateCurrent(rec.Input)
			rv.Current = &cd
		}

		// 差异判定与可读说明：历史/当前分列，不合并。
		switch {
		case rv.Historical != nil && rv.Current != nil:
			if !sameDecision(rv.Historical, rv.Current) {
				rv.Diverged = true
				rv.Note = fmt.Sprintf(
					"历史 v%d: allowed=%v reason=%s；当前 v%d: allowed=%v reason=%s",
					rv.Historical.PolicyVersion, rv.Historical.Allowed, rv.Historical.Reason,
					rv.Current.PolicyVersion, rv.Current.Allowed, rv.Current.Reason)
			} else {
				rv.Note = fmt.Sprintf("历史 v%d 与当前 v%d 结论一致（%s）",
					rv.Historical.PolicyVersion, rv.Current.PolicyVersion, rv.Historical.Reason)
			}
		case rv.Historical != nil && rv.Current == nil:
			rv.Note = "当前尚无生效策略，仅复算了历史结论"
		case rv.Historical == nil && rv.Current != nil:
			rv.Note = fmt.Sprintf("历史版本缺失；当前 v%d 结论: allowed=%v reason=%s",
				rv.Current.PolicyVersion, rv.Current.Allowed, rv.Current.Reason)
		default:
			rv.Note = "历史版本缺失且当前无生效策略"
		}

		out.Reviews[i] = rv
	}
	return out
}
