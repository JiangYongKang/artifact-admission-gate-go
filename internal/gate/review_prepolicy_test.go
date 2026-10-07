package gate_test

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/report"
)

// prePolicyBundles 构造一批"策略评估前就被拒"的制品包，外加一条合规、
// 一条策略违规，用于生成覆盖各阶段的历史批次报告。
// 返回 bundle 与每条期望的记录类别。
func prePolicyBundles(signer *artifact.Signer) ([]artifact.Bundle, []gate.Reason) {
	mk := func(name, content string) artifact.Bundle {
		return goodBundle(signer, name, []byte(content))
	}
	unsigned := mk("unsigned", "u1")
	unsigned.Signature = nil // 签名材料缺失

	untrusted := mk("untrusted", "u2")
	untrusted.Signature.Value[0] ^= 0xFF // 签名值损坏 -> 签名本身不可信

	tampered := mk("tampered", "u3")
	tampered.Artifact.Content = []byte("evil") // 签名后内容被改

	truncated := mk("truncated", "u4")
	truncated.Provenance = artifact.Provenance{Links: truncated.Provenance.Links[:1]} // 溯源截断

	gapped := mk("gapped", "u5")
	full := artifact.BuildProvenance(gapped.Artifact,
		artifact.Link{Builder: "ci-builder", Note: "compile"},
		artifact.Link{Builder: "ci-builder", Note: "test"},
		artifact.Link{Builder: "ci-builder", Note: "release"})
	gapped.Provenance = artifact.Provenance{
		Links: []artifact.Link{full.Links[0], full.Links[2]}, // 抽掉中间环节
		Seal:  full.Seal,
	}

	broken := mk("broken", "u6")
	broken.Provenance.Links[0], broken.Provenance.Links[1] =
		broken.Provenance.Links[1], broken.Provenance.Links[0] // 换序 -> 断裂

	violating := mk("violating", "u7")
	violating.SBOM.Components = append(violating.SBOM.Components, "openssl-1.0") // 策略违规

	bundles := []artifact.Bundle{
		unsigned, untrusted, tampered, truncated, gapped, broken,
		violating, mk("good", "u8"), {}, // 末尾一条空输入
	}
	want := []gate.Reason{
		gate.ReasonMissingSignature, gate.ReasonUntrustedSignature,
		gate.ReasonTamperedContent, gate.ReasonIncompleteProvenance,
		gate.ReasonIncompleteProvenance, gate.ReasonBrokenProvenance,
		gate.ReasonPolicyViolation, gate.ReasonAllowed, gate.ReasonInvalidInput,
	}
	return bundles, want
}

// isPrePolicy 判断类别是否属于"策略评估前被拒"（与 report 侧规则对应）。
func isPrePolicy(r gate.Reason) bool {
	switch r {
	case gate.ReasonInvalidInput, gate.ReasonMissingSignature,
		gate.ReasonUntrustedSignature, gate.ReasonTamperedContent,
		gate.ReasonIncompleteProvenance, gate.ReasonBrokenProvenance:
		return true
	}
	return false
}

// TestReviewPrePolicyRejectionsReproduced 报告里含签名/溯源阶段就被拒的条目时，
// 复核必须把报告记录的当时结论与类别原样复现（not_applicable），
// 绝不能报成历史策略版本缺失；策略演进到 v2 后结论依然稳定。
func TestReviewPrePolicyRejectionsReproduced(t *testing.T) {
	g, signer, _ := newGate(t)
	bundles, want := prePolicyBundles(signer)

	_, rep, err := g.AdmitBatchReport(releaser, bundles)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range rep.Entries {
		if e.Reason != want[i] {
			t.Fatalf("条目 %d 记录类别应为 %s, 得到 %s", i, want[i], e.Reason)
		}
		if isPrePolicy(e.Reason) && e.PolicyVersion != 0 {
			t.Fatalf("策略前被拒条目 %d 的命中版本应为 0, 得到 v%d", i, e.PolicyVersion)
		}
	}

	// 策略演进到 v2，模拟"复核时现行策略已不同于报告生成时"。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}

	res, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatalf("复核失败: %v", err)
	}
	if len(res.Reviews) != len(rep.Entries) {
		t.Fatalf("复核条目数 %d != 报告条目数 %d", len(res.Reviews), len(rep.Entries))
	}
	for i, rv := range res.Reviews {
		rec := rep.Entries[i]
		t.Logf("业务=策略前拒绝复核 #%d 输入手法→类别=%s 记录命中策略=v%d 复核状态=%s 历史=%v/%s 当前=v%d/%s 差异=%v",
			i, rec.Reason, rec.PolicyVersion, rv.HistoryStatus,
			rv.Historical.Allowed, rv.Historical.Reason,
			rv.Current.PolicyVersion, rv.Current.Reason, rv.Diverged)

		if rv.Historical == nil {
			t.Fatalf("条目 %d(%s) 历史结论为空", i, rec.Reason)
		}
		if rv.HistoryStatus == report.HistoryVersionMissing {
			t.Fatalf("条目 %d(%s) 被误报为历史版本缺失", i, rec.Reason)
		}
		if rv.Current == nil {
			t.Fatalf("条目 %d(%s) 当前结论为空", i, rec.Reason)
		}
		if isPrePolicy(rec.Reason) {
			if rv.HistoryStatus != report.HistoryNotApplicable {
				t.Fatalf("条目 %d(%s) 状态应为 not_applicable, 得到 %s",
					i, rec.Reason, rv.HistoryStatus)
			}
			// 历史结论与类别必须按报告记录原样复现。
			if rv.Historical.Reason != rec.Reason || rv.Historical.Allowed != rec.Allowed ||
				rv.Historical.Detail != rec.Detail {
				t.Fatalf("条目 %d 历史结论未原样复现: 记录=%s/%v/%q 复现=%s/%v/%q",
					i, rec.Reason, rec.Allowed, rec.Detail,
					rv.Historical.Reason, rv.Historical.Allowed, rv.Historical.Detail)
			}
			// 与策略版本无关：当前 v2 复算类别必须一致，无差异。
			if rv.Current.Reason != rec.Reason || rv.Diverged {
				t.Fatalf("条目 %d(%s) 当前复算应一致且无差异: 当前=%s 差异=%v",
					i, rec.Reason, rv.Current.Reason, rv.Diverged)
			}
		} else if rv.HistoryStatus != report.HistoryAvailable {
			t.Fatalf("条目 %d(%s) 状态应为 available, 得到 %s",
				i, rec.Reason, rv.HistoryStatus)
		}
	}
}

// TestReviewMixedMissingVersionStable 混合报告：既有策略前被拒的条目，
// 也有引用了从未存在过的策略版本的条目。整批复核不报错、不静默：
// 版本缺失条目单列 version_missing 且仍给出当前版本结论，
// 策略前被拒条目不受干扰仍按记录复现。
func TestReviewMixedMissingVersionStable(t *testing.T) {
	g, signer, _ := newGate(t)
	bundles, _ := prePolicyBundles(signer)
	_, rep, err := g.AdmitBatchReport(releaser, bundles)
	if err != nil {
		t.Fatal(err)
	}

	// 把"合规"与"策略违规"两条（到达过策略评估）改成引用不存在的 v99。
	for i := range rep.Entries {
		if rep.Entries[i].Reason == gate.ReasonAllowed ||
			rep.Entries[i].Reason == gate.ReasonPolicyViolation {
			rep.Entries[i].PolicyVersion = 99
		}
	}
	rep.PolicyVersion = 99

	res, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatalf("含缺失版本的报告不应让整批复核报错: %v", err)
	}
	missing, notApplicable := 0, 0
	for i, rv := range res.Reviews {
		rec := rep.Entries[i]
		t.Logf("业务=混合报告复核 #%d 类别=%s 记录版本=v%d 状态=%s 说明=%s",
			i, rec.Reason, rec.PolicyVersion, rv.HistoryStatus, rv.Note)

		if rv.Current == nil {
			t.Fatalf("条目 %d 仍应给出当前结论", i)
		}
		// 当前结论命中的版本：到达策略评估的条目为当前生效 v1，
		// 策略前被拒的条目为 0（未命中任何策略），两者都必须分列标明。
		if wantCur := 1; isPrePolicy(rec.Reason) {
			if rv.Current.PolicyVersion != 0 {
				t.Fatalf("条目 %d 策略前被拒，当前结论版本应为 0, 得到 v%d",
					i, rv.Current.PolicyVersion)
			}
		} else if rv.Current.PolicyVersion != wantCur {
			t.Fatalf("条目 %d 当前结论应命中 v1, 得到 v%d", i, rv.Current.PolicyVersion)
		}
		switch rv.HistoryStatus {
		case report.HistoryVersionMissing:
			missing++
			if rec.PolicyVersion != 99 {
				t.Fatalf("条目 %d 并未引用缺失版本却被标记缺失", i)
			}
			if rv.Historical != nil {
				t.Fatalf("条目 %d 版本缺失时历史结论应为空", i)
			}
		case report.HistoryNotApplicable:
			notApplicable++
			if !isPrePolicy(rec.Reason) {
				t.Fatalf("条目 %d(%s) 不是策略前拒绝却标记 not_applicable", i, rec.Reason)
			}
		}
	}
	if missing != 2 {
		t.Fatalf("应有 2 条 version_missing, 得到 %d", missing)
	}
	if notApplicable != 7 {
		t.Fatalf("应有 7 条 not_applicable, 得到 %d", notApplicable)
	}
	t.Logf("业务=混合报告复核汇总 version_missing=%d not_applicable=%d 整批未报错", missing, notApplicable)
}

// TestReviewConcurrentRepeatAndShuffleStable 同一报告反复复核、多 goroutine
// 并发复核、条目乱序后复核，每条制品的结论都必须一致，且全程零副作用。
func TestReviewConcurrentRepeatAndShuffleStable(t *testing.T) {
	g, signer, logger := newGate(t)
	bundles, _ := prePolicyBundles(signer)
	_, rep, err := g.AdmitBatchReport(releaser, bundles)
	if err != nil {
		t.Fatal(err)
	}
	before := len(logger.Records())

	base, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatal(err)
	}

	// 1) 并发复核：16 个 goroutine 各复核 5 次，结果都与基准一致。
	var wg sync.WaitGroup
	errs := make(chan error, 16*5)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for k := 0; k < 5; k++ {
				res, err := g.ReviewBatch(auditor, rep)
				if err != nil {
					errs <- fmt.Errorf("goroutine %d 第 %d 次复核失败: %w", w, k, err)
					return
				}
				if !reviewsEqual(base, res) {
					errs <- fmt.Errorf("goroutine %d 第 %d 次复核结果与基准不一致", w, k)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	t.Logf("业务=并发复核 16协程x5次 结论全部一致")

	// 2) 条目乱序：多种子打乱报告条目，按制品名比较每条结论不漂移。
	type key struct {
		allowed bool
		reason  gate.Reason
	}
	baseByName := map[string]key{}
	for _, rv := range base.Reviews {
		baseByName[rv.Artifact] = key{rv.Historical.Allowed, rv.Historical.Reason}
	}
	for round := 0; round < 5; round++ {
		shuffled := rep
		shuffled.Entries = append([]report.Entry(nil), rep.Entries...)
		rand.New(rand.NewSource(int64(round + 1))).Shuffle(len(shuffled.Entries),
			func(i, j int) { shuffled.Entries[i], shuffled.Entries[j] = shuffled.Entries[j], shuffled.Entries[i] })
		res, err := g.ReviewBatch(auditor, shuffled)
		if err != nil {
			t.Fatalf("第 %d 轮乱序复核失败: %v", round, err)
		}
		if len(res.Reviews) != len(base.Reviews) {
			t.Fatalf("第 %d 轮复核条目数漂移", round)
		}
		for _, rv := range res.Reviews {
			want := baseByName[rv.Artifact]
			if rv.Historical == nil || rv.Historical.Allowed != want.allowed ||
				rv.Historical.Reason != want.reason {
				t.Fatalf("第 %d 轮 %s 结论漂移: 基准=%v/%s 本轮=%+v",
					round, rv.Artifact, want.allowed, want.reason, rv.Historical)
			}
		}
		t.Logf("业务=乱序复核 round=%d 全部 %d 条结论随制品一致", round, len(res.Reviews))
	}

	// 3) 零副作用：审计不增加、生效版本不变。
	if len(logger.Records()) != before {
		t.Fatalf("复核不得写审计: 之前 %d 之后 %d", before, len(logger.Records()))
	}
	if g.CurrentVersion() != 1 {
		t.Fatalf("复核不得改动生效版本, 当前 v%d", g.CurrentVersion())
	}
	t.Logf("业务=复核零副作用 审计保持 %d 条 生效版本仍为 v1", before)
}
