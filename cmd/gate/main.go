// 命令 gate 在本地演示制品准入校验流程：
// 细粒度失败分诊、批量离线报告、策略演进后的历史复核（历史/当前分列）、
// 引用版本缺失处理、越权拒绝与审计输出。全程离线，无外部服务或真实凭据。
package main

import (
	"fmt"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/report"
)

func main() {
	signer := artifact.NewSigner("release-key", []byte("local-demo-secret"))
	store := policy.NewStore()
	logger := audit.NewLogger()
	g := gate.NewGate(signer, store, logger)

	admin := authz.Principal{Name: "alice", Role: authz.RoleAdmin}
	releaser := authz.Principal{Name: "bob", Role: authz.RoleReleaser}
	auditor := authz.Principal{Name: "carol", Role: authz.RoleAuditor}

	// 策略 v1：要求签名、溯源至少两环、仅允许 ci-builder、禁止 openssl-1.0。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true,
		AllowedBuilders:  []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"},
		MinChainLength:   2,
	}); err != nil {
		panic(err)
	}

	good := buildGood(signer, "app-1.0.tar.gz", []byte("build output v1"))

	// 构造覆盖各类分诊的故障输入。
	tampered := good
	tampered.Artifact.Content = []byte("malicious output") // 签名后内容被改

	untrusted := buildGood(signer, "app-badsig.tar.gz", []byte("build output v2"))
	untrusted.Signature.Value[0] ^= 0xFF // 签名值被改 -> 签名本身不可信

	unsigned := buildGood(signer, "app-unsigned.tar.gz", []byte("build output v3"))
	unsigned.Signature = nil // 签名材料缺失

	truncated := buildGood(signer, "app-trunc.tar.gz", []byte("build output v4"))
	truncated.Provenance = artifact.Provenance{Links: truncated.Provenance.Links[:1]} // 溯源截断

	broken := buildGood(signer, "app-broken.tar.gz", []byte("build output v5"))
	broken.Provenance.Links[0], broken.Provenance.Links[1] =
		broken.Provenance.Links[1], broken.Provenance.Links[0] // 溯源断裂

	violating := buildGood(signer, "app-banned.tar.gz", []byte("build output v6"))
	violating.SBOM.Components = append(violating.SBOM.Components, "openssl-1.0") // 策略违规

	fmt.Println("== 一、细粒度失败分诊（批量并发） ==")
	bundles := []artifact.Bundle{good, tampered, untrusted, unsigned, truncated, broken, violating, {}}
	decisions, rep, err := g.AdmitBatchReport(releaser, bundles)
	if err != nil {
		panic(err)
	}
	for _, d := range decisions {
		fmt.Printf("  %-20s 放行=%-5v 类别=%-22s 策略=v%d 依据=%s\n",
			d.Artifact, d.Allowed, d.Reason, d.PolicyVersion, d.Detail)
	}

	// 离线保存报告（这里打印字节数，真实场景可写入文件长期保存）。
	raw, err := rep.JSON()
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n== 二、批次报告（可离线保存） ==\n  报告ID=%s 策略版本=v%d 条目=%d JSON=%d 字节\n",
		rep.ID, rep.PolicyVersion, len(rep.Entries), len(raw))

	// 策略演进到 v2：放开构建者限制。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, MinChainLength: 2,
	}); err != nil {
		panic(err)
	}
	fmt.Println("\n== 三、策略已演进到 v2，复核 v1 历史报告（历史/当前分列） ==")
	restored, err := report.ParseJSON(raw)
	if err != nil {
		panic(err)
	}
	res, err := g.ReviewBatch(auditor, restored)
	if err != nil {
		panic(err)
	}
	for _, rv := range res.Reviews {
		hist, cur := "-", "-"
		if rv.Historical != nil {
			hist = fmt.Sprintf("v%d:%s", rv.Historical.PolicyVersion, rv.Historical.Reason)
		}
		if rv.Current != nil {
			cur = fmt.Sprintf("v%d:%s", rv.Current.PolicyVersion, rv.Current.Reason)
		}
		fmt.Printf("  #%d %-20s 历史=%-18s 当前=%-18s 差异=%v\n    └ %s\n",
			rv.Index, rv.Artifact, hist, cur, rv.Diverged, rv.Note)
	}

	// 引用不存在的历史版本：稳定、可解释。
	missing := restored
	missing.PolicyVersion = 404
	for i := range missing.Entries {
		missing.Entries[i].PolicyVersion = 404
	}
	res2, err := g.ReviewBatch(auditor, missing)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n== 四、历史报告引用的 v404 已不存在 ==\n  %s\n",
		res2.Reviews[0].Note)

	// 越权：releaser 尝试提交策略；releaser 尝试只读复核。
	fmt.Println("\n== 五、最小权限 ==")
	if _, err := g.CommitPolicy(releaser, policy.Policy{}); err != nil {
		fmt.Printf("  拒绝 releaser 提交策略: %v\n", err)
	}
	if _, err := g.ReviewBatch(releaser, restored); err != nil {
		fmt.Printf("  拒绝 releaser 复核报告: %v\n", err)
	}

	// 审计追溯。
	records, err := g.AuditRecords(auditor)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n== 六、审计（%d 条，复核不留痕）==\n", len(records))
	for _, r := range records {
		fmt.Printf("  #%02d %-15s actor=%-6s artifact=%-20s report=%-20s idx=%-3d policy=v%d %s\n",
			r.Seq, r.Type, r.Actor, r.Artifact, r.ReportID, r.EntryIndex, r.PolicyVersion, r.Reason)
	}
}

// buildGood 构造一个合规制品包。
func buildGood(signer *artifact.Signer, name string, content []byte) artifact.Bundle {
	a := artifact.Artifact{Name: name, Content: content}
	sig := signer.Sign(a)
	return artifact.Bundle{
		Artifact:  a,
		Signature: &sig,
		Provenance: artifact.BuildProvenance(a,
			artifact.Link{Builder: "ci-builder", Note: "compile"},
			artifact.Link{Builder: "ci-builder", Note: "test"},
		),
		SBOM: artifact.SBOM{Components: []string{"zlib-1.3"}},
	}
}
