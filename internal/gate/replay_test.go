package gate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

// 本组覆盖历史批次报告与只读复核：
// 报告字段完整性、离线 JSON 往返、历史结论复现、策略演进/回滚后
// 历史结论与当前结论分列、引用版本不存在、重复复核幂等且只读、异常报告。

// mixedBatch 构造一批混合输入：合规/篡改/截断/策略违规/缺签名各一条，
// 每条都确定可复现。
func mixedBatch(signer *artifact.Signer) []artifact.Bundle {
	good := goodBundle(signer, "good", []byte("g"))
	tampered := goodBundle(signer, "tampered", []byte("t"))
	tampered.Artifact.Content = []byte("t-evil")
	trunc := goodBundle(signer, "truncated", []byte("p"))
	trunc.Provenance.Links = trunc.Provenance.Links[:1] // 哈希连贯但缺 test 环
	banned := goodBundle(signer, "banned", []byte("b"))
	banned.SBOM.Components = append(banned.SBOM.Components, "openssl-1.0")
	unsigned := goodBundle(signer, "unsigned", []byte("u"))
	unsigned.Signature = nil
	return []artifact.Bundle{good, tampered, trunc, banned, unsigned}
}

func logReplay(t *testing.T, ir gate.ItemReplay) {
	t.Helper()
	t.Logf("业务=历史复核 输入=%-9s 历史[v%d]=%s(%v) 状态=%s | 当前[v%d]=%s(%v) 状态=%s 差异=%v %s",
		ir.Name, ir.Historical.PolicyVersion, ir.Historical.Reason, ir.Historical.Allowed,
		ir.HistoricalStatus, ir.CurrentVersion, ir.Current.Reason, ir.Current.Allowed,
		ir.CurrentStatus, ir.Differs, ir.DiffSummary)
}

func TestBatchReportContentsAndAudit(t *testing.T) {
	g, signer, logger := newGate(t)
	bundles := mixedBatch(signer)
	before := len(logger.Records())

	report, err := g.AdmitBatchReport(releaser, bundles, gate.BatchOptions{Workers: 3})
	if err != nil {
		t.Fatal(err)
	}
	if report.PolicyVersion != 1 || report.Total != 5 ||
		report.AllowedCount != 1 || report.RejectedCount != 4 {
		t.Fatalf("报告统计错误: %+v", report)
	}
	// 每条都能对应到一条 admission 审计，且下标、名称、类别一一对应。
	recs := logger.Records()[before:]
	if len(recs) != 5 {
		t.Fatalf("应有 5 条准入审计, 得到 %d", len(recs))
	}
	for i, it := range report.Items {
		if it.Index != i || it.Name != bundles[i].Artifact.Name || it.InputDigest == "" {
			t.Fatalf("第 %d 条报告字段错误: %+v", i, it)
		}
		// 审计按完成顺序写入，这里只校验存在性与内容，不依赖顺序。
		found := false
		for _, r := range recs {
			if r.Artifact == it.Name {
				found = true
				if r.Allowed != it.Verdict.Allowed {
					t.Fatalf("%s 审计结论与报告不一致", it.Name)
				}
			}
		}
		if !found {
			t.Fatalf("%s 在审计中找不到对应记录", it.Name)
		}
		t.Logf("业务=批次报告 下标=%d 输入=%s 输入摘要=%s 命中策略=v%d 类别=%s 依据=%s",
			it.Index, it.Name, it.InputDigest[:12], it.Verdict.PolicyVersion,
			it.Verdict.Reason, it.Verdict.Detail)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	g, signer, _ := newGate(t)
	report, err := g.AdmitBatchReport(releaser, mixedBatch(signer), gate.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := gate.MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := gate.UnmarshalReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID != report.ID || restored.Total != report.Total ||
		restored.PolicyVersion != report.PolicyVersion {
		t.Fatal("离线往返后报告头不一致")
	}
	for i := range report.Items {
		a, b := report.Items[i], restored.Items[i]
		if a.InputDigest != b.InputDigest || a.Verdict != b.Verdict {
			t.Fatalf("第 %d 条离线往返后不一致", i)
		}
	}
	t.Logf("业务=报告离线JSON往返 报告ID=%s 条目=%d 版本=v%d", restored.ID, restored.Total, restored.PolicyVersion)
}

func TestReplayReproducesHistoricalVerdict(t *testing.T) {
	g, signer, _ := newGate(t)
	report, err := g.AdmitBatchReport(releaser, mixedBatch(signer), gate.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := g.Replay(releaser, report)
	if err != nil {
		t.Fatal(err)
	}
	for _, ir := range replay.Items {
		logReplay(t, ir)
		// 策略未演进：历史可复现，且历史与当前一致、无差异。
		if ir.HistoricalStatus != gate.ReproducedExact && ir.HistoricalStatus != gate.VersionZero {
			t.Fatalf("%s 历史结论未复现: %s", ir.Name, ir.HistoricalStatus)
		}
		if ir.Differs || ir.CurrentVersion != 1 {
			t.Fatalf("%s 策略未演进时不应有差异", ir.Name)
		}
	}
}

// TestReplayAfterPolicyEvolutionShowsBoth 策略演进后复核：
// 历史版本结论原样复现，当前版本结论并列给出，各自带版本号与差异说明。
func TestReplayAfterPolicyEvolutionShowsBoth(t *testing.T) {
	signer := artifact.NewSigner("release-key", []byte("test-secret"))
	logger := audit.NewLogger()
	g := gate.NewGate(signer, policy.NewStore(), logger)

	// v1：链长 >=2、允许 ci-builder、禁 openssl-1.0。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	bundles := mixedBatch(signer)
	report, err := g.AdmitBatchReport(releaser, bundles, gate.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// v2：放开构建者与链长、不再禁 openssl -> banned 在 v2 下放行。
	if _, err := g.CommitPolicy(admin, policy.Policy{RequireSignature: true}); err != nil {
		t.Fatal(err)
	}
	replay, err := g.Replay(releaser, report)
	if err != nil {
		t.Fatal(err)
	}
	if replay.OriginalPolicyVer != 1 || replay.CurrentPolicyVer != 2 {
		t.Fatalf("版本标注错误: 原=%v 现=%v", replay.OriginalPolicyVer, replay.CurrentPolicyVer)
	}
	var banned *gate.ItemReplay
	var good *gate.ItemReplay
	for i := range replay.Items {
		ir := &replay.Items[i]
		logReplay(t, *ir)
		if ir.Name == "banned" {
			banned = ir
		}
		if ir.Name == "good" {
			good = ir
		}
	}
	// 历史结论必须复现：banned 在 v1 下仍是 policy_violation。
	if banned.Historical.Reason != gate.ReasonPolicyViolation ||
		banned.Historical.PolicyVersion != 1 || banned.Historical.Allowed {
		t.Fatalf("历史结论未复现: %+v", banned.Historical)
	}
	if banned.HistoricalStatus != gate.ReproducedExact {
		t.Fatalf("历史应可复现, 状态=%s", banned.HistoricalStatus)
	}
	// 当前结论：v2 下放行，两条结论不能混成一条。
	if !banned.Current.Allowed || banned.CurrentVersion != 2 {
		t.Fatalf("当前 v2 下应放行: %+v", banned.Current)
	}
	if !banned.Differs || banned.DiffSummary == "" {
		t.Fatal("历史与当前不同必须标差异并给出说明")
	}
	if replay.DifferingCount < 1 {
		t.Fatal("应至少统计出 1 条差异")
	}
	// 合规制品两个版本都放行，不算差异。
	if good.Differs {
		t.Fatal("good 两版都放行，不应算差异")
	}
}

// TestReplayAfterRollback 回滚不影响历史复核：报告记录 v1，先演进到 v2，
// 再回滚到 v1，复核仍复现 v1 结论。
func TestReplayAfterRollback(t *testing.T) {
	signer := artifact.NewSigner("release-key", []byte("test-secret"))
	logger := audit.NewLogger()
	g := gate.NewGate(signer, policy.NewStore(), logger)
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	report, err := g.AdmitBatchReport(releaser, mixedBatch(signer), gate.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.CommitPolicy(admin, policy.Policy{RequireSignature: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.RollbackPolicy(admin, 1); err != nil {
		t.Fatal(err)
	}
	replay, err := g.Replay(releaser, report)
	if err != nil {
		t.Fatal(err)
	}
	for _, ir := range replay.Items {
		if ir.CurrentVersion != 1 || ir.Differs {
			t.Fatalf("回滚到 v1 后历史与当前应一致, 得到 %+v", ir)
		}
	}
	t.Logf("业务=回滚后复核 当前=v%d 差异条目=%d", replay.CurrentPolicyVer, replay.DifferingCount)
}

// TestReplayReferencedVersionMissing 报告引用的策略版本已不存在：
// 历史结论原样保留并显式标注，当前结论照常给出，不报错、不静默吞掉。
func TestReplayReferencedVersionMissing(t *testing.T) {
	signer := artifact.NewSigner("release-key", []byte("test-secret"))
	logger := audit.NewLogger()
	g := gate.NewGate(signer, policy.NewStore(), logger)
	// v1 严格策略。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	// v2 放开策略，报告在 v2 下产生：策略相关条目记录命中 v2。
	if _, err := g.CommitPolicy(admin, policy.Policy{RequireSignature: true}); err != nil {
		t.Fatal(err)
	}
	report, err := g.AdmitBatchReport(releaser, mixedBatch(signer), gate.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.PolicyVersion != 2 {
		t.Fatalf("前置条件：报告应在 v2 下产生, 得到 v%d", report.PolicyVersion)
	}

	// 用一个只有 v1 的全新策略存储复核，模拟报告引用的 v2 已不存在。
	g2 := gate.NewGate(signer, policy.NewStore(), audit.NewLogger())
	if _, err := g2.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	replay, err := g2.Replay(releaser, report)
	if err != nil {
		t.Fatalf("引用版本不存在时复核不应报错: %v", err)
	}
	// 只有命中 v2 的策略相关条目（good/banned 两条）应标注版本缺失；
	// 签名/溯源环节即被拒的条目版本为 0，与策略版本无关。
	if replay.MissingVersionCount != 2 {
		t.Fatalf("应有 2 条命中 v2 的条目标注缺失, 得到 %d", replay.MissingVersionCount)
	}
	for _, ir := range replay.Items {
		logReplay(t, ir)
		// 历史结论一律原样保留。
		if ir.Historical != report.Items[ir.Index].Verdict {
			t.Fatalf("%s 历史结论被改动", ir.Name)
		}
		switch ir.Historical.PolicyVersion {
		case 2:
			if ir.HistoricalStatus != gate.VersionMissing {
				t.Fatalf("%s 命中 v2 应标注版本缺失", ir.Name)
			}
			// v2 缺失但当前 v1 存在：当前结论照常给出并分列。
			if ir.CurrentVersion != 1 || ir.CurrentStatus != "evaluated" {
				t.Fatalf("%s 当前结论缺失: %+v", ir.Name, ir)
			}
		case 0:
			if ir.HistoricalStatus != gate.VersionZero {
				t.Fatalf("%s 策略前被拒应为 pre_policy", ir.Name)
			}
		}
	}
	// banned：历史 v2 放行（记录保留），当前 v1 拒绝，差异必须可见。
	var banned *gate.ItemReplay
	for i := range replay.Items {
		if replay.Items[i].Name == "banned" {
			banned = &replay.Items[i]
		}
	}
	if banned == nil || !banned.Historical.Allowed || !banned.Differs ||
		banned.Current.Reason != gate.ReasonPolicyViolation {
		t.Fatalf("banned 历史v2放行/当前v1违规的分列结论错误: %+v", banned)
	}
}

// TestReplayReadOnlyAndIdempotent 复核只读、可重复：
// 不改审计、不改生效策略；同一份报告反复复核结果一致。
func TestReplayReadOnlyAndIdempotent(t *testing.T) {
	signer := artifact.NewSigner("release-key", []byte("test-secret"))
	logger := audit.NewLogger()
	g := gate.NewGate(signer, policy.NewStore(), logger)
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	report, err := g.AdmitBatchReport(releaser, mixedBatch(signer), gate.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	auditBefore := len(logger.Records())

	var first *gate.ReplayReport
	for n := 0; n < 5; n++ {
		r, err := g.Replay(releaser, report)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = r
			continue
		}
		if replayDigestForTest(r) != replayDigestForTest(first) {
			t.Fatalf("第 %d 次复核结果与首次不一致", n)
		}
	}
	if got := len(logger.Records()) - auditBefore; got != 0 {
		t.Fatalf("复核不得写审计, 新增 %d 条", got)
	}
	probe, err := g.Admit(releaser, goodBundle(signer, "probe", []byte("z")))
	if err != nil {
		t.Fatal(err)
	}
	cur := probe.PolicyVersion
	if cur != 1 {
		t.Fatalf("复核不得改动生效策略, 当前 v%d", cur)
	}
	t.Logf("业务=重复复核只读 复核5次 审计新增=0 生效策略=v%d 差异条目=%d",
		cur, first.DifferingCount)

	// 越权复核：返回 ErrUnauthorized，且仍是只读。
	if _, err := g.Replay(authz.Principal{Name: "dave", Role: authz.RoleAuditor}, report); !errors.Is(err, authz.ErrUnauthorized) {
		t.Fatalf("auditor 复核应被拒绝, 得到 %v", err)
	}
}

// TestReplayMalformedInputs 空报告、nil、计数不符、输入被篡改都稳定报错，不 panic。
func TestReplayMalformedInputs(t *testing.T) {
	g, signer, _ := newGate(t)
	if _, err := g.Replay(releaser, nil); !errors.Is(err, gate.ErrMalformedReport) {
		t.Fatalf("nil 报告应报 ErrMalformedReport, 得到 %v", err)
	}
	report, err := g.AdmitBatchReport(releaser, mixedBatch(signer), gate.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bad := *report
	bad.Total = 99
	if _, err := g.Replay(releaser, &bad); !errors.Is(err, gate.ErrMalformedReport) {
		t.Fatalf("计数不符应报 ErrMalformedReport, 得到 %v", err)
	}
	tampered := *report
	tampered.Items[0].Input.Artifact.Content = []byte("changed")
	if _, err := g.Replay(releaser, &tampered); !errors.Is(err, gate.ErrMalformedReport) {
		t.Fatalf("输入摘要不符应报 ErrMalformedReport, 得到 %v", err)
	}
	if _, err := gate.UnmarshalReport([]byte("{not-json")); !errors.Is(err, gate.ErrMalformedReport) {
		t.Fatalf("坏 JSON 应报 ErrMalformedReport")
	}
	t.Log("业务=复核异常输入 nil/计数不符/输入被改/坏JSON 均稳定返回结构化错误")
}

// digestJSONForTest 对任意值做稳定 JSON 摘要。
func digestJSONForTest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// replayDigestForTest 对复核结果做稳定摘要，用于"重复复核必须一致"校验。
func replayDigestForTest(r *gate.ReplayReport) string {
	return digestJSONForTest(r)
}

// TestReplayAcrossProcesses 模拟跨进程离线复核：一个"进程"产生报告并序列化为 JSON，
// 另一个全新"进程"（新 Gate、新审计、相同密钥）恢复后复核，历史结论必须逐字复现。
func TestReplayAcrossProcesses(t *testing.T) {
	signerA := artifact.NewSigner("release-key", []byte("test-secret"))
	gA := gate.NewGate(signerA, policy.NewStore(), audit.NewLogger())
	if _, err := gA.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	report, err := gA.AdmitBatchReport(releaser, mixedBatch(signerA), gate.BatchOptions{Workers: 5})
	if err != nil {
		t.Fatal(err)
	}
	data, err := gate.MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}

	// 全新"进程"：重建相同的策略历史（v1），从 JSON 恢复报告。
	signerB := artifact.NewSigner("release-key", []byte("test-secret"))
	loggerB := audit.NewLogger()
	gB := gate.NewGate(signerB, policy.NewStore(), loggerB)
	if _, err := gB.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	restored, err := gate.UnmarshalReport(data)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := gB.Replay(releaser, restored)
	if err != nil {
		t.Fatal(err)
	}
	for _, ir := range replay.Items {
		if ir.HistoricalStatus != gate.ReproducedExact && ir.HistoricalStatus != gate.VersionZero {
			t.Fatalf("%s 跨进程未复现: %s", ir.Name, ir.HistoricalStatus)
		}
		if ir.Differs {
			t.Fatalf("%s 相同策略历史下跨进程不应有差异: %s", ir.Name, ir.DiffSummary)
		}
	}
	if n := len(loggerB.Records()); n != 1 { // 只有一次 policy_commit，复核不写审计
		t.Fatalf("新进程复核应只读不写审计, 记录数=%d", n)
	}
	t.Logf("业务=跨进程离线复核 JSON=%d字节 条目=%d 全部复现 新进程审计仅%d条(复核不留痕)",
		len(data), replay.Total, len(loggerB.Records()))
}
