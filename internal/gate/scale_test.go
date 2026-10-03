package gate_test

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
)

// 本组覆盖真实规模与边界：
//   - 上万条混合制品并发判定，结论与顺序/打乱/并发度无关；
//   - 不漏条、不重复计数，每条对应报告与审计；
//   - 空批次、重复条目、空输入制品都有稳定可解释结果。

// largeMixedBatch 构造 n 条确定性混合批次：按固定比例生成各分诊类别的制品，
// 每条带唯一名字与输入，重复比例由 dupEvery 控制（>0 时每隔若干条插一条重复）。
func largeMixedBatch(signer *artifact.Signer, n, dupEvery int) ([]artifact.Bundle, []gate.Reason) {
	mk := func(i int) artifact.Bundle {
		switch i % 5 {
		case 0:
			return goodBundle(signer, fmt.Sprintf("good-%d", i), []byte(fmt.Sprintf("good-content-%d", i)))
		case 1:
			b := goodBundle(signer, fmt.Sprintf("tampered-%d", i), []byte(fmt.Sprintf("tamper-%d", i)))
			b.Artifact.Content = []byte(fmt.Sprintf("tampered-evil-%d", i))
			return b
		case 2:
			b := goodBundle(signer, fmt.Sprintf("trunc-%d", i), []byte(fmt.Sprintf("trunc-%d", i)))
			b.Provenance.Links = b.Provenance.Links[:1]
			return b
		case 3:
			b := goodBundle(signer, fmt.Sprintf("banned-%d", i), []byte(fmt.Sprintf("ban-%d", i)))
			b.SBOM.Components = append(b.SBOM.Components, "openssl-1.0")
			return b
		default:
			b := goodBundle(signer, fmt.Sprintf("unsigned-%d", i), []byte(fmt.Sprintf("unsigned-%d", i)))
			b.Signature = nil
			return b
		}
	}
	out := make([]artifact.Bundle, 0, n)
	reasons := make([]gate.Reason, 0, n)
	add := func(i int) {
		out = append(out, mk(i))
		reasons = append(reasons, reasonForIndex(i))
	}
	for i := 0; i < n; i++ {
		add(i)
		if dupEvery > 0 && i > 0 && i%dupEvery == 0 {
			add(i) // 与上一条完全相同的输入（同类同结论）
		}
		if len(out) >= n {
			break
		}
	}
	return out[:n], reasons[:n]
}

// reasonForIndex 是构造批次时第 i 个唯一输入应命中的分诊类别。
func reasonForIndex(i int) gate.Reason {
	switch i % 5 {
	case 0:
		return gate.ReasonAllowed
	case 1:
		return gate.ReasonTamperedContent
	case 2:
		return gate.ReasonIncompleteProvenance
	case 3:
		return gate.ReasonPolicyViolation
	default:
		return gate.ReasonMissingSignature
	}
}

// decisionSignature 是一条结论的稳定可比签名（忽略耗时等非确定字段）。
func decisionSignature(d gate.Decision) string {
	return fmt.Sprintf("%s|%v|%s|%d", d.Artifact, d.Allowed, d.Reason, d.PolicyVersion)
}

func TestLargeBatchOrderAndConcurrencyIndependent(t *testing.T) {
	g, signer, logger := newGate(t)
	const n = 12000
	bundles, wantReasons := largeMixedBatch(signer, n, 77) // 含重复输入
	auditBefore := len(logger.Records())

	// 基线：默认并发、原始顺序。
	baseReport, err := g.AdmitBatchReport(releaser, bundles, gate.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if baseReport.Total != n {
		t.Fatalf("报告总数应为 %d, 得到 %d", n, baseReport.Total)
	}

	// 1) 不漏条、不重排：下标 i 的名字必须对应输入 i。
	names := make([]string, n)
	for i, it := range baseReport.Items {
		if it.Index != i {
			t.Fatalf("报告下标错位: 位置 %d 记录 index=%d", i, it.Index)
		}
		names[i] = it.Name
		if it.Verdict.Reason != wantReasons[i] {
			t.Fatalf("位置 %d (%s) 类别错误: %s", i, it.Name, it.Verdict.Reason)
		}
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	// 重复输入会产生重复名字，名字总数必须仍等于 n（不丢、不去重）。
	if len(names) != n {
		t.Fatalf("条目数变化: %d", len(names))
	}

	// 2) 每条对应一条审计，且按名字统计的类别计数与报告一致。
	recs := logger.Records()[auditBefore:]
	if len(recs) != n {
		t.Fatalf("审计应恰好新增 %d 条, 得到 %d（漏记或重复）", n, len(recs))
	}
	auditReasonByName := map[string]int{}
	for _, r := range recs {
		auditReasonByName[r.Artifact]++
	}
	reportCountByName := map[string]int{}
	for _, it := range baseReport.Items {
		reportCountByName[it.Name]++
	}
	for name, c := range reportCountByName {
		if auditReasonByName[name] != c {
			t.Fatalf("%s 审计条数 %d 与报告条数 %d 不一致", name, auditReasonByName[name], c)
		}
	}

	// 3) 不同并发度（1/2/16/64）与乱序下，按名字聚合的结论集合必须与基线完全一致。
	baseline := map[string]string{}
	for _, d := range baseReport.Decisions() {
		baseline[d.Artifact] = decisionSignature(d)
	}
	workerCases := []int{1, 2, 16, 64}
	for round, workers := range workerCases {
		bs, _ := largeMixedBatch(signer, n, 77)
		// 每个并发度用不同种子打乱，且打乱方式逐轮不同。
		r := rand.New(rand.NewSource(int64(round*1000 + workers)))
		r.Shuffle(len(bs), func(i, j int) { bs[i], bs[j] = bs[j], bs[i] })

		rep, err := g.AdmitBatchReport(releaser, bs, gate.BatchOptions{Workers: workers})
		if err != nil {
			t.Fatalf("workers=%d 批量失败: %v", workers, err)
		}
		got := map[string]string{}
		for _, d := range rep.Decisions() {
			got[d.Artifact] = decisionSignature(d)
		}
		if len(got) != len(baseline) {
			t.Fatalf("workers=%d 名字聚合数 %d != 基线 %d", workers, len(got), len(baseline))
		}
		for name, sig := range baseline {
			if got[name] != sig {
				t.Fatalf("workers=%d 下 %s 结论漂移: 基线=%s 本轮=%s", workers, name, sig, got[name])
			}
		}
		// 统计计数恒定。
		if rep.AllowedCount != baseReport.AllowedCount ||
			rep.RejectedCount != baseReport.RejectedCount {
			t.Fatalf("workers=%d 统计漂移: %d/%d vs %d/%d", workers,
				rep.AllowedCount, rep.RejectedCount,
				baseReport.AllowedCount, baseReport.RejectedCount)
		}
	}

	// 4) 重复输入：同输入摘要相同，结论也相同；报告不去重，计数稳定。
	dupBundles, _ := largeMixedBatch(signer, 100, 10) // 含 9 条重复
	dupReport, err := g.AdmitBatchReport(releaser, dupBundles, gate.BatchOptions{Workers: 8})
	if err != nil {
		t.Fatal(err)
	}
	if dupReport.Total != 100 || dupReport.AllowedCount+dupReport.RejectedCount != 100 {
		t.Fatalf("含重复批次计数错误: %+v", dupReport)
	}
	byDigest := map[string]gate.Verdict{}
	for _, it := range dupReport.Items {
		if v, ok := byDigest[it.InputDigest]; ok && v != it.Verdict {
			t.Fatalf("相同输入摘要 %s 得到不同结论: %+v vs %+v", it.InputDigest, v, it.Verdict)
		}
		byDigest[it.InputDigest] = it.Verdict
	}

	t.Logf("业务=大规模并发稳定 规模=%d(含重复) 并发度=%v 放行=%d 拒绝=%d 审计新增=%d 结论零漂移",
		n, workerCases, baseReport.AllowedCount, baseReport.RejectedCount, len(recs))
}

func TestEmptyBatchStable(t *testing.T) {
	g, _, logger := newGate(t)
	before := len(logger.Records())

	rep, err := g.AdmitBatchReport(releaser, nil, gate.BatchOptions{Workers: 4})
	if err != nil {
		t.Fatalf("空批次不应报错: %v", err)
	}
	if rep.Total != 0 || rep.AllowedCount != 0 || rep.RejectedCount != 0 || len(rep.Items) != 0 {
		t.Fatalf("空批次报告应为空: %+v", rep)
	}
	// 空批次不产生任何 admission 审计（但仍受鉴权约束）。
	if got := len(logger.Records()) - before; got != 0 {
		t.Fatalf("空批次不应写准入审计, 新增 %d", got)
	}
	// 空批次也能离线保存与复核，复核结果稳定。
	data, err := gate.MarshalReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := gate.UnmarshalReport(data)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := g.Replay(releaser, restored)
	if err != nil {
		t.Fatalf("空批次复核不应报错: %v", err)
	}
	if replay.Total != 0 || replay.DifferingCount != 0 || len(replay.Items) != 0 {
		t.Fatalf("空批次复核结果应为空: %+v", replay)
	}
	// 越权空批次仍被拒绝。
	if _, err := g.AdmitBatchReport(admin, nil, gate.BatchOptions{}); err == nil {
		t.Fatal("越权空批次应返回错误")
	}
	t.Log("业务=边界/空批次 报告为空且可离线复核 不写准入审计 越权仍拒绝")
}

func TestEmptyContentArtifactClassified(t *testing.T) {
	g, signer, _ := newGate(t)

	// 空输入制品（名字在、内容为 nil）：有合法签名与完整溯源时应放行，
	// 不能因内容为空而偶发报错或静默吞掉。
	a := artifact.Artifact{Name: "empty.bin", Content: nil}
	sig := signer.Sign(a)
	prov := artifact.BuildProvenance(a,
		artifact.Link{Builder: "ci-builder", Note: "compile"},
		artifact.Link{Builder: "ci-builder", Note: "test"},
	)
	goodEmpty := artifact.Bundle{Artifact: a, Signature: &sig, Provenance: prov}

	// 空内容且无签名：稳定落到 missing_signature。
	unsignedEmpty := goodEmpty
	unsignedEmpty.Signature = nil

	decisions, err := g.AdmitBatchWith(releaser,
		[]artifact.Bundle{goodEmpty, unsignedEmpty}, gate.BatchOptions{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 2 {
		t.Fatalf("应返回 2 条结论, 得到 %d", len(decisions))
	}
	if !decisions[0].Allowed || decisions[0].Reason != gate.ReasonAllowed {
		t.Fatalf("空内容合规制品应放行, 得到 %+v", decisions[0])
	}
	if decisions[1].Reason != gate.ReasonMissingSignature {
		t.Fatalf("空内容无签名应 missing_signature, 得到 %+v", decisions[1])
	}
	for _, d := range decisions {
		t.Logf("业务=边界/空输入制品 输入=%s 命中策略=v%d 类别=%s 依据=%s",
			d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	}
}

// TestLargeBatchAbsurdConcurrencyBounded 并发度远大于批次规模或远超 CPU 时，
// 结论仍正确、不漏不重，资源由有界 worker 池兜底，不随并发数字失控。
func TestLargeBatchAbsurdConcurrencyBounded(t *testing.T) {
	g, signer, logger := newGate(t)
	const n = 3000
	bundles, wants := largeMixedBatch(signer, n, 0)
	before := len(logger.Records())

	rep, err := g.AdmitBatchReport(releaser, bundles, gate.BatchOptions{Workers: 1_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != n {
		t.Fatalf("条目数应为 %d, 得到 %d", n, rep.Total)
	}
	for i, it := range rep.Items {
		if it.Verdict.Reason != wants[i] {
			t.Fatalf("位置 %d 类别漂移: 期望 %s 得到 %s", i, wants[i], it.Verdict.Reason)
		}
	}
	if added := len(logger.Records()) - before; added != n {
		t.Fatalf("审计应新增 %d 条, 得到 %d", n, added)
	}

	// 串行（workers=1）结果必须一致。
	serial, err := g.AdmitBatchReport(releaser, bundles, gate.BatchOptions{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := range rep.Items {
		if rep.Items[i].Verdict != serial.Items[i].Verdict {
			t.Fatalf("位置 %d 高并发与串行结论不一致", i)
		}
	}
	t.Logf("业务=边界/极端并发度 规模=%d 请求workers=1000000(内部收敛) 对比串行结论零差异 审计=%d",
		n, n)
}
