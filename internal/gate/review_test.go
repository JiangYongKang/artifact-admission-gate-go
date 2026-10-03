package gate_test

import (
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/report"
)

// TestBatchReportRoundTrip 验证报告可离线序列化往返，内容不失真；空批次稳定。
func TestBatchReportRoundTrip(t *testing.T) {
	g, signer, _ := newGate(t)

	// 空批次：不报错，返回空切片与空报告。
	empty, emptyRep, err := g.AdmitBatchReport(releaser, nil)
	if err != nil {
		t.Fatalf("空批次不应报错: %v", err)
	}
	if len(empty) != 0 || len(emptyRep.Entries) != 0 {
		t.Fatalf("空批次结果应为空")
	}
	t.Logf("业务=空批次 报告=%s 条目=%d", emptyRep.ID, len(emptyRep.Entries))

	good := goodBundle(signer, "app", []byte("v1"))
	tampered := goodBundle(signer, "app2", []byte("v2"))
	tampered.Artifact.Content = []byte("evil")

	dec, rep, err := g.AdmitBatchReport(releaser, []artifact.Bundle{good, tampered})
	if err != nil {
		t.Fatalf("批量报告失败: %v", err)
	}
	raw, err := rep.JSON()
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	restored, err := report.ParseJSON(raw)
	if err != nil {
		t.Fatalf("离线加载失败: %v", err)
	}
	if restored.ID != rep.ID {
		t.Fatalf("报告 ID 往返不一致")
	}
	if len(restored.Entries) != 2 || len(dec) != 2 {
		t.Fatalf("条目数应为 2")
	}
	for i := range rep.Entries {
		a, b := rep.Entries[i], restored.Entries[i]
		if a.Reason != b.Reason || a.Allowed != b.Allowed || a.PolicyVersion != b.PolicyVersion {
			t.Fatalf("条目 %d 往返失真: %+v vs %+v", i, a, b)
		}
		if b.Input.Artifact.Name != a.Input.Artifact.Name {
			t.Fatalf("条目 %d 输入往返失真", i)
		}
		t.Logf("业务=报告往返 #%d 制品=%s 输入摘要=%s 命中策略=v%d 类别=%s 依据=%s",
			i, b.Input.Artifact.Name, b.Input.Artifact.Digest()[:12],
			b.PolicyVersion, b.Reason, b.Detail)
	}

	// 损坏/被截断的报告必须明确报错，不能静默接受。
	if _, err := report.ParseJSON([]byte("{not-json")); err == nil {
		t.Fatal("损坏 JSON 应返回错误")
	}
	bad := raw
	if len(bad) > 40 {
		if _, err := report.ParseJSON(bad[:40]); err == nil {
			t.Fatal("截断 JSON 应返回错误")
		}
	}
}

// TestReviewReplaysHistoricalVerdict 策略演进后复核必须复现历史结论，
// 并同时给出当前版本结论，分列标明版本与差异；回滚后两侧一致。
func TestReviewReplaysHistoricalVerdict(t *testing.T) {
	signer := artifact.NewSigner("release-key", []byte("test-secret"))
	logger := audit.NewLogger()
	g := gate.NewGate(signer, policy.NewStore(), logger)

	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	b := goodBundle(signer, "app", []byte("v1"))

	dec1, rep, err := g.AdmitBatchReport(releaser, []artifact.Bundle{b})
	if err != nil {
		t.Fatal(err)
	}
	if !dec1[0].Allowed || dec1[0].PolicyVersion != 1 {
		t.Fatalf("v1 下应放行, 得到 %+v", dec1[0])
	}
	t.Logf("业务=历史批次 报告=%s 命中策略=v%d 类别=%s",
		rep.ID, rep.PolicyVersion, rep.Entries[0].Reason)

	// 演进到 v2：收紧构建者。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"release-builder"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	d2, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Allowed || d2.Reason != gate.ReasonPolicyViolation || d2.PolicyVersion != 2 {
		t.Fatalf("v2 下应违规, 得到 %+v", d2)
	}

	res, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatalf("复核失败: %v", err)
	}
	rv := res.Reviews[0]
	if rv.Historical == nil || !rv.Historical.Allowed || rv.Historical.PolicyVersion != 1 {
		t.Fatalf("历史结论未复现 v1 放行: %+v", rv.Historical)
	}
	if rv.Current == nil || rv.Current.Allowed || rv.Current.PolicyVersion != 2 {
		t.Fatalf("当前结论应为 v2 违规: %+v", rv.Current)
	}
	if !rv.Diverged || rv.HistoryStatus != report.HistoryAvailable {
		t.Fatalf("应标记可用且有差异, diverged=%v status=%s", rv.Diverged, rv.HistoryStatus)
	}
	t.Logf("业务=跨版本复核 %s", rv.Note)

	// 回滚到 v1 后复核：两侧一致。
	if _, err := g.RollbackPolicy(admin, 1); err != nil {
		t.Fatal(err)
	}
	res2, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatal(err)
	}
	rv2 := res2.Reviews[0]
	if rv2.Diverged {
		t.Fatalf("回滚后历史与当前应一致: %s", rv2.Note)
	}
	if !rv2.Historical.Allowed || !rv2.Current.Allowed {
		t.Fatalf("两侧都应放行, 历史=%+v 当前=%+v", rv2.Historical, rv2.Current)
	}
	t.Logf("业务=回滚后复核 %s", rv2.Note)
}

// TestReviewMissingVersion 报告引用的历史策略版本现已不存在时，
// 复核稳定返回 version_missing，不整批报错也不静默。
func TestReviewMissingVersion(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app", []byte("v1"))
	_, rep, err := g.AdmitBatchReport(releaser, []artifact.Bundle{b})
	if err != nil {
		t.Fatal(err)
	}
	rep.PolicyVersion = 99
	for i := range rep.Entries {
		rep.Entries[i].PolicyVersion = 99
	}

	res, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatalf("版本缺失不应让整批复核报错: %v", err)
	}
	rv := res.Reviews[0]
	if rv.Historical != nil || rv.HistoryStatus != report.HistoryVersionMissing {
		t.Fatalf("历史版本应标记缺失, historical=%+v status=%s", rv.Historical, rv.HistoryStatus)
	}
	if rv.Current == nil || rv.Current.PolicyVersion != 1 || !rv.Current.Allowed {
		t.Fatalf("当前 v1 结论仍应给出, 得到 %+v", rv.Current)
	}
	t.Logf("业务=历史版本缺失 %s | 当前 v%d allowed=%v reason=%s",
		rv.Note, rv.Current.PolicyVersion, rv.Current.Allowed, rv.Current.Reason)
}

// TestReviewReadOnlyAndIdempotent 复核严格只读且幂等：
// 不写审计、不改生效版本；反复复核结果一致；越权被拒。
func TestReviewReadOnlyAndIdempotent(t *testing.T) {
	g, signer, logger := newGate(t)
	b := goodBundle(signer, "app", []byte("v1"))
	_, rep, err := g.AdmitBatchReport(releaser, []artifact.Bundle{b})
	if err != nil {
		t.Fatal(err)
	}
	before := len(logger.Records())
	beforeVer := g.CurrentVersion()

	var first report.ReviewResult
	for i := 0; i < 5; i++ {
		res, err := g.ReviewBatch(auditor, rep)
		if err != nil {
			t.Fatalf("第 %d 次复核失败: %v", i, err)
		}
		if i == 0 {
			first = res
		} else if !reviewsEqual(first, res) {
			t.Fatalf("第 %d 次复核结果与首次不一致", i)
		}
	}
	if len(logger.Records()) != before {
		t.Fatalf("复核不得写审计: 之前 %d 之后 %d", before, len(logger.Records()))
	}
	if g.CurrentVersion() != beforeVer {
		t.Fatalf("复核不得改动生效版本")
	}
	t.Logf("业务=只读幂等复核 重复5次一致, 审计保持 %d 条未增加, 生效版本仍为 v%d",
		before, beforeVer)

	// releaser 无权复核（越权被拒，不进入复核）。
	if _, err := g.ReviewBatch(releaser, rep); err == nil {
		t.Fatal("releaser 复核应被拒绝")
	}
}

func reviewsEqual(a, b report.ReviewResult) bool {
	if len(a.Reviews) != len(b.Reviews) || a.CurrentVersion != b.CurrentVersion {
		return false
	}
	for i := range a.Reviews {
		x, y := a.Reviews[i], b.Reviews[i]
		if x.Diverged != y.Diverged || x.HistoryStatus != y.HistoryStatus {
			return false
		}
		if (x.Historical == nil) != (y.Historical == nil) {
			return false
		}
		if x.Historical != nil &&
			(x.Historical.Allowed != y.Historical.Allowed || x.Historical.Reason != y.Historical.Reason) {
			return false
		}
		if (x.Current == nil) != (y.Current == nil) {
			return false
		}
		if x.Current != nil &&
			(x.Current.Allowed != y.Current.Allowed || x.Current.Reason != y.Current.Reason) {
			return false
		}
	}
	return true
}
