package gate_test

import (
	"fmt"
	"math/rand"
	"sync"
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

// TestReviewPrePolicyRejectionsReproduced 报告中含签名/溯源阶段就被拒的条目时，
// 复核必须按报告记录原样复现其历史结论与类别（pre_policy_reject），
// 不得报成历史版本缺失；走到策略评估的条目仍按记录版本复算。
func TestReviewPrePolicyRejectionsReproduced(t *testing.T) {
	g, signer, _ := newGate(t)

	good := goodBundle(signer, "good", []byte("ok"))
	unsigned := goodBundle(signer, "unsigned", []byte("u"))
	unsigned.Signature = nil // 签名阶段被拒
	tampered := goodBundle(signer, "tampered", []byte("t"))
	tampered.Artifact.Content = []byte("evil") // 签名有效但内容被改
	truncated := goodBundle(signer, "truncated", []byte("p"))
	truncated.Provenance = artifact.Provenance{Links: truncated.Provenance.Links[:1]} // 溯源阶段被拒
	violating := goodBundle(signer, "violating", []byte("v"))
	violating.SBOM.Components = append(violating.SBOM.Components, "openssl-1.0") // 策略阶段被拒

	dec, rep, err := g.AdmitBatchReport(releaser,
		[]artifact.Bundle{good, unsigned, tampered, truncated, violating})
	if err != nil {
		t.Fatal(err)
	}
	// 预检：三条在策略评估前被拒，报告中策略版本应为 0。
	for i, idx := range []int{1, 2, 3} {
		if dec[idx].Allowed || rep.Entries[idx].PolicyVersion != 0 {
			t.Fatalf("条目 %d 应在策略评估前被拒且不引用策略版本, 得到 %+v", idx, dec[idx])
		}
		t.Logf("业务=策略前拒绝条目 制品=%s 记录类别=%s 记录策略版本=v%d",
			rep.Entries[idx].Input.Artifact.Name, rep.Entries[idx].Reason,
			rep.Entries[idx].PolicyVersion)
		_ = i
	}

	// 策略演进到 v2（收紧构建者），模拟"历史批次在新版本下复核"。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"release-builder"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}

	res, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatalf("复核失败: %v", err)
	}
	if len(res.Reviews) != 5 {
		t.Fatalf("复核条目应为 5, 得到 %d", len(res.Reviews))
	}
	for i, rv := range res.Reviews {
		rec := rep.Entries[i]
		t.Logf("业务=复核条目 #%d 制品=%s 输入手法=记录类别%s 历史状态=%s 命中策略=历史v%d/当前v%d 说明=%s",
			i, rv.Artifact, rec.Reason, rv.HistoryStatus,
			func() int {
				if rv.Historical != nil {
					return rv.Historical.PolicyVersion
				}
				return -1
			}(),
			func() int {
				if rv.Current != nil {
					return rv.Current.PolicyVersion
				}
				return -1
			}(), rv.Note)

		if rv.HistoryStatus == report.HistoryVersionMissing {
			t.Fatalf("条目 %d(%s) 不应报历史版本缺失", i, rec.Reason)
		}
		if rv.Historical == nil {
			t.Fatalf("条目 %d(%s) 历史结论应被复现", i, rec.Reason)
		}
		// 历史结论必须与报告记录的当时结论、类别一致。
		if rv.Historical.Allowed != rec.Allowed || rv.Historical.Reason != rec.Reason {
			t.Fatalf("条目 %d 历史结论未原样复现: 记录=%v/%s 复现=%v/%s",
				i, rec.Allowed, rec.Reason, rv.Historical.Allowed, rv.Historical.Reason)
		}
		if rv.Current == nil {
			t.Fatalf("条目 %d 应同时给出当前版本结论", i)
		}
	}

	// 策略前被拒的三条：状态为 pre_policy_reject，历史结论不引用策略版本。
	for _, idx := range []int{1, 2, 3} {
		rv := res.Reviews[idx]
		if rv.HistoryStatus != report.HistoryPrePolicy {
			t.Fatalf("条目 %d 历史状态应为 pre_policy_reject, 得到 %s", idx, rv.HistoryStatus)
		}
		if rv.Historical.PolicyVersion != 0 {
			t.Fatalf("条目 %d 历史结论不应引用策略版本, 得到 v%d", idx, rv.Historical.PolicyVersion)
		}
		if rv.Diverged {
			t.Fatalf("条目 %d 历史与当前复算应一致（同一分诊阶段）: %s", idx, rv.Note)
		}
	}
	// 策略阶段的条目：仍按记录版本 v1 复算，状态 available。
	for _, idx := range []int{0, 4} {
		rv := res.Reviews[idx]
		if rv.HistoryStatus != report.HistoryAvailable || rv.Historical.PolicyVersion != 1 {
			t.Fatalf("条目 %d 应按 v1 复算且状态 available, 得到 %s/v%d",
				idx, rv.HistoryStatus, rv.Historical.PolicyVersion)
		}
	}
	// 合规条目在 v2 下变为违规，应标记差异；策略违规条目在 v2 下放行（构建者限制变化不影响 SBOM 禁令缺失）。
	if !res.Reviews[0].Diverged {
		t.Fatalf("合规条目在 v1/v2 下结论不同，应标记差异: %s", res.Reviews[0].Note)
	}
}

// TestReviewMixedMissingAndPrePolicy 同一份报告里既有"策略前被拒"的条目，
// 又有引用不存在策略版本的条目：整批不报错，前者原样复现，
// 后者稳定 version_missing 且仍给出当前版本结论。
func TestReviewMixedMissingAndPrePolicy(t *testing.T) {
	g, signer, _ := newGate(t)

	unsigned := goodBundle(signer, "unsigned", []byte("u"))
	unsigned.Signature = nil
	good := goodBundle(signer, "good", []byte("ok"))

	_, rep, err := g.AdmitBatchReport(releaser, []artifact.Bundle{unsigned, good})
	if err != nil {
		t.Fatal(err)
	}
	// 把策略阶段条目的版本改成从未存在过的 v99（异常输入）。
	rep.Entries[1].PolicyVersion = 99
	rep.PolicyVersion = 99

	res, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatalf("异常输入不应让整批复核报错: %v", err)
	}
	pre := res.Reviews[0]
	if pre.HistoryStatus != report.HistoryPrePolicy || pre.Historical == nil ||
		pre.Historical.Reason != gate.ReasonMissingSignature {
		t.Fatalf("策略前被拒条目应原样复现, 得到 status=%s historical=%+v",
			pre.HistoryStatus, pre.Historical)
	}
	missing := res.Reviews[1]
	if missing.HistoryStatus != report.HistoryVersionMissing || missing.Historical != nil {
		t.Fatalf("引用不存在版本的条目应稳定 version_missing, 得到 status=%s", missing.HistoryStatus)
	}
	if missing.Current == nil || !missing.Current.Allowed || missing.Current.PolicyVersion != 1 {
		t.Fatalf("版本缺失条目仍应给出当前 v1 结论, 得到 %+v", missing.Current)
	}
	t.Logf("业务=混合异常复核 策略前条目=%s(%s) 缺失版本条目=%s | 当前结论 v%d %s",
		pre.HistoryStatus, pre.Historical.Reason, missing.HistoryStatus,
		missing.Current.PolicyVersion, missing.Current.Reason)
}

// TestReviewConcurrentAndShuffled 同一份报告在并发复核与条目乱序下，
// 每条结论必须一致；且全程只读（不写审计、不动生效版本）。
func TestReviewConcurrentAndShuffled(t *testing.T) {
	g, signer, logger := newGate(t)

	var bundles []artifact.Bundle
	bundles = append(bundles, goodBundle(signer, "good", []byte("ok")))
	unsigned := goodBundle(signer, "unsigned", []byte("u"))
	unsigned.Signature = nil
	bundles = append(bundles, unsigned)
	tampered := goodBundle(signer, "tampered", []byte("t"))
	tampered.Artifact.Content = []byte("evil")
	bundles = append(bundles, tampered)
	violating := goodBundle(signer, "violating", []byte("v"))
	violating.SBOM.Components = append(violating.SBOM.Components, "openssl-1.0")
	bundles = append(bundles, violating)

	_, rep, err := g.AdmitBatchReport(releaser, bundles)
	if err != nil {
		t.Fatal(err)
	}
	before := len(logger.Records())

	base, err := g.ReviewBatch(auditor, rep)
	if err != nil {
		t.Fatal(err)
	}

	// 并发复核：32 个 goroutine 同时复核同一报告，结果必须与基线一致。
	const workers = 32
	errs := make(chan string, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			res, err := g.ReviewBatch(auditor, rep)
			if err != nil {
				errs <- fmt.Sprintf("协程 %d 复核失败: %v", w, err)
				return
			}
			if !reviewsEqual(base, res) {
				errs <- fmt.Sprintf("协程 %d 复核结果与基线不一致", w)
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
	t.Logf("业务=并发复核 %d 个协程结论全部一致", workers)

	// 乱序复核：打乱报告条目顺序，按制品名比较每条结论必须一致。
	byName := map[string]report.EntryReview{}
	for _, rv := range base.Reviews {
		byName[rv.Artifact] = rv
	}
	for round := 0; round < 5; round++ {
		shuffled := rep
		shuffled.Entries = append([]report.Entry(nil), rep.Entries...)
		rand.New(rand.NewSource(int64(round))).Shuffle(len(shuffled.Entries), func(i, j int) {
			shuffled.Entries[i], shuffled.Entries[j] = shuffled.Entries[j], shuffled.Entries[i]
		})
		res, err := g.ReviewBatch(auditor, shuffled)
		if err != nil {
			t.Fatalf("第 %d 轮乱序复核失败: %v", round, err)
		}
		for _, rv := range res.Reviews {
			want := byName[rv.Artifact]
			if rv.HistoryStatus != want.HistoryStatus || rv.Diverged != want.Diverged ||
				rv.Historical.Reason != want.Historical.Reason ||
				rv.Current.Reason != want.Current.Reason {
				t.Fatalf("第 %d 轮 %s 结论漂移: %+v vs %+v", round, rv.Artifact, rv, want)
			}
		}
		t.Logf("业务=乱序复核 round=%d 全部 %d 条结论一致", round, len(res.Reviews))
	}

	// 只读：并发+乱序复核后审计不增加、生效版本不变。
	if len(logger.Records()) != before {
		t.Fatalf("复核不得写审计: 之前 %d 之后 %d", before, len(logger.Records()))
	}
	if g.CurrentVersion() != 1 {
		t.Fatalf("复核不得改动生效版本, 得到 v%d", g.CurrentVersion())
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
