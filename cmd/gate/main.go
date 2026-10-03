// 命令 gate 在本地演示制品准入校验流程：
// 细粒度失败分诊、批量批次报告离线保存、策略演进/回滚后的历史复核、
// 引用策略版本缺失等异常链路、越权拒绝与审计输出。全程离线可复现。
package main

import (
	"fmt"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

func main() {
	signer := artifact.NewSigner("release-key", []byte("local-demo-secret"))
	otherSigner := artifact.NewSigner("rogue-key", []byte("rogue-secret"))
	logger := audit.NewLogger()
	g := gate.NewGate(signer, policy.NewStore(), logger)

	admin := authz.Principal{Name: "alice", Role: authz.RoleAdmin}
	releaser := authz.Principal{Name: "bob", Role: authz.RoleReleaser}
	auditor := authz.Principal{Name: "carol", Role: authz.RoleAuditor}

	// 策略 v1：要求签名、溯源至少两环、允许 ci-builder、禁止 openssl-1.0。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true,
		AllowedBuilders:  []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"},
		MinChainLength:   2,
	}); err != nil {
		panic(err)
	}

	// 构造覆盖全部分诊类别的混合批次。
	good := buildGood(signer, "app-1.0.tar.gz", []byte("build output v1"))

	tampered := buildGood(signer, "tampered.tar.gz", []byte("orig"))
	tampered.Artifact.Content = []byte("malicious output") // 签名后内容被改

	rogue := buildGood(otherSigner, "rogue.tar.gz", []byte("rogue build")) // 未知密钥签名

	unsigned := buildGood(signer, "unsigned.tar.gz", []byte("unsigned build"))
	unsigned.Signature = nil

	truncated := buildGood(signer, "truncated.tar.gz", []byte("trunc build"))
	truncated.Provenance.Links = truncated.Provenance.Links[:1] // 尾部截断，哈希仍连贯

	swapped := buildGood(signer, "swapped.tar.gz", []byte("swap build"))
	swapped.Provenance.Links[0], swapped.Provenance.Links[1] =
		swapped.Provenance.Links[1], swapped.Provenance.Links[0] // 换序断链

	banned := buildGood(signer, "banned.tar.gz", []byte("ban build"))
	banned.SBOM.Components = append(banned.SBOM.Components, "openssl-1.0")

	bundles := []artifact.Bundle{good, tampered, rogue, unsigned, truncated, swapped, banned}

	fmt.Println("== 1) 批量准入：细粒度分诊（命中 v1） ==")
	report, err := g.AdmitBatchReport(releaser, bundles, gate.BatchOptions{Workers: 4})
	if err != nil {
		panic(err)
	}
	for _, it := range report.Items {
		v := it.Verdict
		fmt.Printf("  %-16s 类别=%-22s allowed=%-5v 版本=v%d 依据=%s\n",
			it.Name, v.Reason, v.Allowed, v.PolicyVersion, v.Detail)
	}
	fmt.Printf("  批次=%s 总数=%d 放行=%d 拒绝=%d\n\n",
		report.ID, report.Total, report.AllowedCount, report.RejectedCount)

	// 批次报告离线保存（JSON），可在任意进程/时间恢复并复核。
	data, err := gate.MarshalReport(report)
	if err != nil {
		panic(err)
	}
	saved, err := gate.UnmarshalReport(data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("== 2) 批次报告已离线保存并恢复：%s（%d 条，JSON %d 字节）==\n\n",
		saved.ID, saved.Total, len(data))

	// 策略演进到 v2：放开构建者、链长与禁含成分。
	if _, err := g.CommitPolicy(admin, policy.Policy{RequireSignature: true}); err != nil {
		panic(err)
	}
	fmt.Println("== 3) 策略演进到 v2 后复核历史批次：历史结论与当前结论分列 ==")
	replay, err := g.Replay(releaser, saved)
	if err != nil {
		panic(err)
	}
	for _, ir := range replay.Items {
		line := fmt.Sprintf("  %-16s 历史[v%d]=%-20s %-5v 复现=%-12s | 当前[v%d]=%s",
			ir.Name, ir.Historical.PolicyVersion, ir.Historical.Reason, ir.Historical.Allowed,
			ir.HistoricalStatus, ir.CurrentVersion, ir.Current.Reason)
		if ir.Differs {
			line += "  ★差异: " + ir.DiffSummary
		}
		fmt.Println(line)
	}
	fmt.Printf("  历史版本=v%d 当前版本=v%d 差异条目=%d\n\n",
		replay.OriginalPolicyVer, replay.CurrentPolicyVer, replay.DifferingCount)

	// 再复核一次：结果必须一致，且不写审计、不动策略。
	replay2, err := g.Replay(releaser, saved)
	if err != nil {
		panic(err)
	}
	fmt.Printf("== 4) 同一份报告重复复核：差异条目 %d→%d（幂等）==\n\n",
		replay.DifferingCount, replay2.DifferingCount)

	// 异常链路：历史报告引用的 v1 在一个全新存储里不存在（当前只有另一版本）。
	other := gate.NewGate(signer, policy.NewStore(), audit.NewLogger())
	if _, err := other.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"}, MinChainLength: 2,
	}); err != nil {
		panic(err)
	}
	// 构造一份引用 v2 的报告，再到只有 v1 的存储里复核。
	if _, err := g.CommitPolicy(admin, policy.Policy{RequireSignature: true, MinChainLength: 1}); err != nil {
		panic(err)
	}
	reportV3, err := g.AdmitBatchReport(releaser, []artifact.Bundle{good, banned}, gate.BatchOptions{})
	if err != nil {
		panic(err)
	}
	missing, err := other.Replay(releaser, reportV3)
	if err != nil {
		panic(err)
	}
	fmt.Println("== 5) 历史引用版本当前不存在：历史结论保留，当前结论照给 ==")
	for _, ir := range missing.Items {
		fmt.Printf("  %-16s 历史版本状态=%-24s 历史=%-18s 当前[v%d]=%s 差异=%v\n",
			ir.Name, ir.HistoricalStatus, ir.Historical.Reason, ir.CurrentVersion,
			ir.Current.Reason, ir.Differs)
	}

	// 越权：releaser 不能改策略，auditor 不能复核（复核需要 admit 权限）。
	fmt.Println("\n== 6) 越权边界 ==")
	if _, err := g.CommitPolicy(releaser, policy.Policy{}); err != nil {
		fmt.Printf("  releaser 提交策略被拒: %v\n", err)
	}
	if _, err := g.Replay(auditor, saved); err != nil {
		fmt.Printf("  auditor 复核被拒: %v\n", err)
	}

	// 审计：复核不写记录，准入/策略/越权记录都在。
	records, err := g.AuditRecords(auditor)
	if err != nil {
		panic(err)
	}
	fmt.Println("\n== 7) 审计记录（复核不留痕） ==")
	for _, r := range records {
		fmt.Printf("  #%02d %-16s actor=%-6s artifact=%-16s 版本=v%d allowed=%-5v %s\n",
			r.Seq, r.Type, r.Actor, r.Artifact, r.PolicyVersion, r.Allowed, r.Reason)
	}
}

// buildGood 构造一个在默认 v1 策略下合规的制品包。
func buildGood(s *artifact.Signer, name string, content []byte) artifact.Bundle {
	a := artifact.Artifact{Name: name, Content: content}
	sig := s.Sign(a)
	prov := artifact.BuildProvenance(a,
		artifact.Link{Builder: "ci-builder", Note: "compile"},
		artifact.Link{Builder: "ci-builder", Note: "test"},
	)
	return artifact.Bundle{
		Artifact:   a,
		Signature:  &sig,
		Provenance: prov,
		SBOM:       artifact.SBOM{Components: []string{"zlib-1.3"}},
	}
}
