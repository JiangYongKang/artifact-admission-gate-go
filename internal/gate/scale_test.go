package gate_test

import (
	"fmt"
	"math/rand"
	"runtime"
	"testing"
	"time"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/report"
)

// mixedBundles 构造含合规、各类失败、重复、空输入的大规模混合批次。
func mixedBundles(t *testing.T, signer *artifact.Signer, n int) []artifact.Bundle {
	t.Helper()
	out := make([]artifact.Bundle, 0, n)
	for i := 0; i < n; i++ {
		var b artifact.Bundle
		switch i % 8 {
		case 0: // 合规
			b = goodBundle(signer, fmt.Sprintf("good-%d", i), []byte(fmt.Sprintf("ok-%d", i)))
		case 1: // 重复上一条合规输入（同名同内容），用于验证重复条目不漏计
			b = goodBundle(signer, fmt.Sprintf("good-%d", i-1), []byte(fmt.Sprintf("ok-%d", i-1)))
		case 2: // 内容篡改
			b = goodBundle(signer, fmt.Sprintf("tamper-%d", i), []byte(fmt.Sprintf("t-%d", i)))
			b.Artifact.Content = []byte(fmt.Sprintf("evil-%d", i))
		case 3: // 签名不可信：改签名值
			b = goodBundle(signer, fmt.Sprintf("badsig-%d", i), []byte(fmt.Sprintf("s-%d", i)))
			b.Signature.Value[0] ^= 0xFF
		case 4: // 缺签名
			b = goodBundle(signer, fmt.Sprintf("unsigned-%d", i), []byte(fmt.Sprintf("u-%d", i)))
			b.Signature = nil
		case 5: // 溯源截断
			b = goodBundle(signer, fmt.Sprintf("trunc-%d", i), []byte(fmt.Sprintf("p-%d", i)))
			b.Provenance = artifact.Provenance{Links: b.Provenance.Links[:1]}
		case 6: // 溯源断裂
			b = goodBundle(signer, fmt.Sprintf("broken-%d", i), []byte(fmt.Sprintf("b-%d", i)))
			b.Provenance.Links[0], b.Provenance.Links[1] =
				b.Provenance.Links[1], b.Provenance.Links[0]
		case 7: // 空输入
			b = artifact.Bundle{}
		}
		out = append(out, b)
	}
	return out
}

// fingerprint 生成"按输入内容归纳的期望结论键"，用于跨乱序比较。
func fingerprint(b artifact.Bundle) string {
	return b.Artifact.Name + "|" + b.Artifact.Digest()
}

// TestLargeBatchStable 上万条混合制品：结论与输入顺序、打乱方式无关，
// 不漏条、不重复计数，每条都对应报告与审计。
func TestLargeBatchStable(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过大批量用例")
	}
	g, signer, logger := newGate(t)
	const n = 10000
	bundles := mixedBundles(t, signer, n)

	var ms1, ms2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms1)
	start := time.Now()

	base, rep, err := g.AdmitBatchReport(releaser, bundles)
	if err != nil {
		t.Fatalf("大批量准入失败: %v", err)
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&ms2)

	if len(base) != n {
		t.Fatalf("结论条数应为 %d, 得到 %d（漏条/重复）", n, len(base))
	}
	if len(rep.Entries) != n {
		t.Fatalf("报告条目应为 %d, 得到 %d", n, len(rep.Entries))
	}

	// 分类计数，确认每种分诊类别都在大规模批次中出现。
	counts := map[gate.Reason]int{}
	for i, d := range base {
		counts[d.Reason]++
		if rep.Entries[i].Reason != d.Reason {
			t.Fatalf("条目 %d 报告类别与结论不一致", i)
		}
		if rep.Entries[i].Index != i {
			t.Fatalf("条目 %d 下标错位", i)
		}
	}
	t.Logf("业务=大批量 n=%d 耗时=%s 并发上限=64 堆增量≈%dMB 分类计数=%v",
		n, elapsed, (ms2.TotalAlloc-ms1.TotalAlloc)/1024/1024, counts)
	for _, want := range []gate.Reason{
		gate.ReasonAllowed, gate.ReasonTamperedContent, gate.ReasonUntrustedSignature,
		gate.ReasonMissingSignature, gate.ReasonIncompleteProvenance,
		gate.ReasonBrokenProvenance, gate.ReasonInvalidInput,
	} {
		if counts[want] == 0 {
			t.Fatalf("大批量中缺少类别 %s 的条目", want)
		}
	}

	// 每条都要有对应审计（按 ReportID + EntryIndex 精确匹配，不漏不重）。
	seenIndex := map[int]bool{}
	matched := 0
	for _, r := range logger.Records() {
		if r.ReportID == rep.ID && r.EntryIndex >= 0 {
			if seenIndex[r.EntryIndex] {
				t.Fatalf("审计中下标 %d 重复计数", r.EntryIndex)
			}
			seenIndex[r.EntryIndex] = true
			matched++
		}
	}
	if matched != n {
		t.Fatalf("审计应匹配 %d 条, 实际 %d", n, matched)
	}

	// 期望映射：按输入指纹记录基线结论，供多轮乱序比较。
	wantByFP := map[string]gate.Reason{}
	for i, b := range bundles {
		wantByFP[fingerprint(b)] = base[i].Reason
	}

	// 多轮不同种子打乱，结论必须随输入一致，与位置无关。
	for round := 0; round < 4; round++ {
		shuffled := mixedBundles(t, signer, n)
		rnd := rand.New(rand.NewSource(int64(100 + round)))
		rnd.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got, _, err := g.AdmitBatchReport(releaser, shuffled)
		if err != nil {
			t.Fatalf("第 %d 轮失败: %v", round, err)
		}
		if len(got) != n {
			t.Fatalf("第 %d 轮条数漂移", round)
		}
		for i, b := range shuffled {
			if got[i].Reason != wantByFP[fingerprint(b)] {
				t.Fatalf("第 %d 轮 位置 %d(%s) 结论漂移: %s vs %s",
					round, i, b.Artifact.Name, got[i].Reason, wantByFP[fingerprint(b)])
			}
		}
		t.Logf("业务=乱序稳定性 round=%d 种子=%d 全部 %d 条结论随输入一致", round, 100+round, n)
	}
}

// TestLargeBatchReportDeterministic 验证报告 ID 对同输入同版本是确定的，
// 且报告经 JSON 往返后大批量复核不丢条。
func TestLargeBatchReportDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过大批量用例")
	}
	g, signer, _ := newGate(t)
	bundles := mixedBundles(t, signer, 2000)

	_, rep1, err := g.AdmitBatchReport(releaser, bundles)
	if err != nil {
		t.Fatal(err)
	}
	// 用相同输入再跑一批（不同时间），ID 应相同（时间不参与）。
	_, rep2, err := g.AdmitBatchReport(releaser, mixedBundles(t, signer, 2000))
	if err != nil {
		t.Fatal(err)
	}
	if rep1.ID != rep2.ID {
		t.Fatalf("同输入同策略批次 ID 应确定一致: %s vs %s", rep1.ID, rep2.ID)
	}

	// 不同顺序的批次 ID 应不同（顺序是输入的一部分）。
	rev := append([]artifact.Bundle(nil), bundles...)
	for i := 0; i < len(rev)/2; i++ {
		rev[i], rev[len(rev)-1-i] = rev[len(rev)-1-i], rev[i]
	}
	_, repRev, err := g.AdmitBatchReport(releaser, rev)
	if err != nil {
		t.Fatal(err)
	}
	if repRev.ID == rep1.ID {
		t.Fatalf("打乱顺序后批次 ID 应不同")
	}

	// 报告离线往返后复核，条目一一对应、无丢失。
	raw, err := rep1.JSON()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := report.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := g.ReviewBatch(auditor, restored)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Reviews) != len(rep1.Entries) {
		t.Fatalf("复核条目数 %d != 报告条目数 %d", len(res.Reviews), len(rep1.Entries))
	}
	t.Logf("业务=大批量报告复核 报告=%s 条目=%d 全部复核成功",
		rep1.ID, len(res.Reviews))
}

// TestDuplicatesCountedSeparately 重复输入必须按条目分别计数，不去重也不漏。
func TestDuplicatesCountedSeparately(t *testing.T) {
	g, signer, logger := newGate(t)
	b := goodBundle(signer, "dup", []byte("same"))
	const dup = 50
	bundles := make([]artifact.Bundle, dup)
	for i := range bundles {
		bundles[i] = b
	}
	dec, rep, err := g.AdmitBatchReport(releaser, bundles)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != dup || len(rep.Entries) != dup {
		t.Fatalf("重复条目应各计一次: 结论 %d 报告 %d", len(dec), len(rep.Entries))
	}
	idx := map[int]bool{}
	auditCount := 0
	for _, r := range logger.Records() {
		if r.ReportID == rep.ID && r.EntryIndex >= 0 {
			if idx[r.EntryIndex] {
				t.Fatalf("下标 %d 重复", r.EntryIndex)
			}
			idx[r.EntryIndex] = true
			auditCount++
		}
	}
	if auditCount != dup {
		t.Fatalf("审计应计 %d 条, 得到 %d", dup, auditCount)
	}
}
