// 命令 gate 在本地演示制品准入校验流程：
// 构造已签名制品、提交策略、执行准入与批量并发校验、演示回滚与越权拒绝。
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
	store := policy.NewStore()
	logger := audit.NewLogger()
	g := gate.NewGate(signer, store, logger)

	admin := authz.Principal{Name: "alice", Role: authz.RoleAdmin}
	releaser := authz.Principal{Name: "bob", Role: authz.RoleReleaser}
	auditor := authz.Principal{Name: "carol", Role: authz.RoleAuditor}

	// 策略 v1：要求签名、溯源至少两环、禁止组件 openssl-1.0。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true,
		AllowedBuilders:  []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"},
		MinChainLength:   2,
	}); err != nil {
		panic(err)
	}

	// 构造一个合规制品。
	a := artifact.Artifact{Name: "app-1.0.tar.gz", Content: []byte("build output v1")}
	sig := signer.Sign(a)
	prov := artifact.BuildProvenance(a,
		artifact.Link{Builder: "ci-builder", Note: "compile"},
		artifact.Link{Builder: "ci-builder", Note: "test"},
	)
	good := artifact.Bundle{
		Artifact: a, Signature: &sig, Provenance: prov,
		SBOM: artifact.SBOM{Components: []string{"zlib-1.3"}},
	}

	// 构造一个被篡改的制品（签名后内容被修改）。
	tampered := good
	tampered.Artifact = artifact.Artifact{Name: "app-1.0.tar.gz", Content: []byte("malicious output")}

	decisions, err := g.AdmitBatch(releaser, []artifact.Bundle{good, tampered})
	if err != nil {
		panic(err)
	}
	for _, d := range decisions {
		fmt.Printf("[admit] %-18s allowed=%-5v reason=%-18s policy=v%d detail=%s\n",
			d.Artifact, d.Allowed, d.Reason, d.PolicyVersion, d.Detail)
	}

	// 越权演示：releaser 尝试提交策略，应被拒绝且不改变状态。
	if _, err := g.CommitPolicy(releaser, policy.Policy{}); err != nil {
		fmt.Printf("[deny ] %v\n", err)
	}

	// 策略演进与回滚：v2 放开构建者限制，随后回滚到 v1。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, MinChainLength: 2,
	}); err != nil {
		panic(err)
	}
	if _, err := g.RollbackPolicy(admin, 1); err != nil {
		panic(err)
	}
	d, err := g.Admit(releaser, good)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[admit] 回滚后复验: allowed=%v policy=v%d\n", d.Allowed, d.PolicyVersion)

	// 审计追溯：auditor 读取全部记录。
	records, err := g.AuditRecords(auditor)
	if err != nil {
		panic(err)
	}
	fmt.Println("[audit]")
	for _, r := range records {
		fmt.Printf("  #%02d %-15s actor=%-6s artifact=%-18s policy=v%d allowed=%-5v %s\n",
			r.Seq, r.Type, r.Actor, r.Artifact, r.PolicyVersion, r.Allowed, r.Reason)
	}
}
