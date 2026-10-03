package gate_test

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/audit"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/authz"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/policy"
)

var (
	admin    = authz.Principal{Name: "alice", Role: authz.RoleAdmin}
	releaser = authz.Principal{Name: "bob", Role: authz.RoleReleaser}
	auditor  = authz.Principal{Name: "carol", Role: authz.RoleAuditor}
)

// newGate 构造带默认策略 v1 的准入判定器。
func newGate(t *testing.T) (*gate.Gate, *artifact.Signer, *audit.Logger) {
	t.Helper()
	signer := artifact.NewSigner("release-key", []byte("test-secret"))
	logger := audit.NewLogger()
	g := gate.NewGate(signer, policy.NewStore(), logger)
	_, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true,
		AllowedBuilders:  []string{"ci-builder"},
		BannedComponents: []string{"openssl-1.0"},
		MinChainLength:   2,
	})
	if err != nil {
		t.Fatalf("提交默认策略失败: %v", err)
	}
	return g, signer, logger
}

// goodBundle 构造一个合规制品包。
func goodBundle(signer *artifact.Signer, name string, content []byte) artifact.Bundle {
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

func logDecision(t *testing.T, input string, d gate.Decision) {
	t.Helper()
	t.Logf("输入=%s 命中策略=v%d 放行=%v 原因=%s 依据=%s",
		input, d.PolicyVersion, d.Allowed, d.Reason, d.Detail)
}

func TestAdmitGoodArtifact(t *testing.T) {
	g, signer, _ := newGate(t)
	d, err := g.Admit(releaser, goodBundle(signer, "app.tar.gz", []byte("v1")))
	if err != nil {
		t.Fatalf("准入失败: %v", err)
	}
	logDecision(t, "合规制品", d)
	if !d.Allowed || d.Reason != gate.ReasonAllowed {
		t.Fatalf("合规制品应放行, 得到 %+v", d)
	}
	if d.PolicyVersion != 1 {
		t.Fatalf("应命中策略 v1, 得到 v%d", d.PolicyVersion)
	}
}

func TestRejectTamperedContent(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app.tar.gz", []byte("v1"))
	// 签名之后篡改内容：必须落到独立的 tampered_content，
	// 不能与"签名本身不可信"混为一类。
	b.Artifact.Content = []byte("malicious")
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatalf("准入失败: %v", err)
	}
	logDecision(t, "内容被篡改", d)
	if d.Allowed || d.Reason != gate.ReasonTamperedContent {
		t.Fatalf("篡改制品应因 tampered_content 被拒绝, 得到 %+v", d)
	}
}

func TestRejectMissingSignature(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app.tar.gz", []byte("v1"))
	b.Signature = nil
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatalf("准入失败: %v", err)
	}
	logDecision(t, "签名缺失", d)
	if d.Allowed || d.Reason != gate.ReasonMissingSignature {
		t.Fatalf("应因 missing_signature 被拒绝, 得到 %+v", d)
	}
}

func TestRejectBrokenProvenance(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app.tar.gz", []byte("v1"))
	// 断链：交换两环顺序，哈希链不再连贯。
	b.Provenance.Links[0], b.Provenance.Links[1] = b.Provenance.Links[1], b.Provenance.Links[0]
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatalf("准入失败: %v", err)
	}
	logDecision(t, "溯源断链(换序)", d)
	if d.Allowed || d.Reason != gate.ReasonBrokenProvenance {
		t.Fatalf("应因 broken_provenance 被拒绝, 得到 %+v", d)
	}
}

func TestRejectPolicyViolation(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app.tar.gz", []byte("v1"))
	b.SBOM.Components = append(b.SBOM.Components, "openssl-1.0")
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatalf("准入失败: %v", err)
	}
	logDecision(t, "含被禁成分", d)
	if d.Allowed || d.Reason != gate.ReasonPolicyViolation {
		t.Fatalf("应因 policy_violation 被拒绝, 得到 %+v", d)
	}
}

func TestRejectUnauthorized(t *testing.T) {
	g, signer, logger := newGate(t)
	before := len(logger.Records())

	// releaser 越权提交策略。
	if _, err := g.CommitPolicy(releaser, policy.Policy{}); !errors.Is(err, authz.ErrUnauthorized) {
		t.Fatalf("应返回 ErrUnauthorized, 得到 %v", err)
	}
	// admin 越权执行准入。
	if _, err := g.Admit(admin, goodBundle(signer, "a", []byte("x"))); !errors.Is(err, authz.ErrUnauthorized) {
		t.Fatalf("应返回 ErrUnauthorized, 得到 %v", err)
	}
	// auditor 越权回滚。
	if _, err := g.RollbackPolicy(auditor, 1); !errors.Is(err, authz.ErrUnauthorized) {
		t.Fatalf("应返回 ErrUnauthorized, 得到 %v", err)
	}

	// 越权不得改变状态：生效策略仍是 v1，审计只新增 access_denied 记录。
	if got := len(logger.Records()) - before; got != 3 {
		t.Fatalf("越权应只产生 3 条 access_denied 审计, 得到 %d 条", got)
	}
	for _, r := range logger.Records()[before:] {
		t.Logf("越权审计 #%d type=%s actor=%s reason=%s", r.Seq, r.Type, r.Actor, r.Reason)
		if r.Type != audit.EventAccessDenied {
			t.Fatalf("越权记录类型应为 access_denied, 得到 %s", r.Type)
		}
	}
	d, err := g.Admit(releaser, goodBundle(signer, "app.tar.gz", []byte("v1")))
	if err != nil {
		t.Fatalf("准入失败: %v", err)
	}
	if !d.Allowed || d.PolicyVersion != 1 {
		t.Fatalf("越权后状态不应变化, 得到 %+v", d)
	}
}

func TestConcurrentBatchDeterministic(t *testing.T) {
	g, signer, _ := newGate(t)

	// 构造混合批次：合规、篡改、断链、违规、缺签名各若干。
	mk := func() []artifact.Bundle {
		var out []artifact.Bundle
		for i := 0; i < 4; i++ {
			out = append(out, goodBundle(signer, fmt.Sprintf("good-%d", i), []byte(fmt.Sprintf("ok-%d", i))))
		}
		tampered := goodBundle(signer, "tampered", []byte("v1"))
		tampered.Artifact.Content = []byte("evil")
		broken := goodBundle(signer, "broken", []byte("v2"))
		broken.Provenance.Links = broken.Provenance.Links[:1] // 链长不足且仍完整? 截断后链本身完整但长度不足 -> 策略违规
		broken.Provenance.Links[0].Hash = "deadbeef"          // 直接断链
		violating := goodBundle(signer, "violating", []byte("v3"))
		violating.SBOM.Components = append(violating.SBOM.Components, "openssl-1.0")
		unsigned := goodBundle(signer, "unsigned", []byte("v4"))
		unsigned.Signature = nil
		return append(out, tampered, broken, violating, unsigned)
	}
	base := mk()
	want, err := g.AdmitBatch(releaser, base)
	if err != nil {
		t.Fatalf("批量准入失败: %v", err)
	}
	for _, d := range want {
		logDecision(t, "基线批次/"+d.Artifact, d)
	}

	// 多轮乱序并发校验，同一制品结论必须一致。
	for round := 0; round < 10; round++ {
		bundles := mk()
		rand.New(rand.NewSource(int64(round))).Shuffle(len(bundles), func(i, j int) {
			bundles[i], bundles[j] = bundles[j], bundles[i]
		})
		got, err := g.AdmitBatch(releaser, bundles)
		if err != nil {
			t.Fatalf("批量准入失败: %v", err)
		}
		byName := map[string]gate.Decision{}
		for _, d := range got {
			byName[d.Artifact] = d
		}
		for _, w := range want {
			d := byName[w.Artifact]
			if d.Allowed != w.Allowed || d.Reason != w.Reason || d.PolicyVersion != w.PolicyVersion {
				t.Fatalf("第 %d 轮 %s 结论漂移: 基线=%+v 本轮=%+v", round, w.Artifact, w, d)
			}
		}
	}
}

func TestPolicyRollbackReproduces(t *testing.T) {
	signer := artifact.NewSigner("release-key", []byte("test-secret"))
	logger := audit.NewLogger()
	g := gate.NewGate(signer, policy.NewStore(), logger)

	// v1：允许 ci-builder；v2：收紧为仅允许 release-builder。
	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"ci-builder"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	b := goodBundle(signer, "app.tar.gz", []byte("v1"))
	d1, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	logDecision(t, "策略v1下", d1)
	if !d1.Allowed {
		t.Fatalf("v1 下应放行, 得到 %+v", d1)
	}

	if _, err := g.CommitPolicy(admin, policy.Policy{
		RequireSignature: true, AllowedBuilders: []string{"release-builder"}, MinChainLength: 2,
	}); err != nil {
		t.Fatal(err)
	}
	d2, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	logDecision(t, "策略v2下", d2)
	if d2.Allowed || d2.Reason != gate.ReasonPolicyViolation || d2.PolicyVersion != 2 {
		t.Fatalf("v2 下应因策略违规被拒, 得到 %+v", d2)
	}

	// 回滚到 v1 后，同一输入必须复现 v1 的结论。
	if _, err := g.RollbackPolicy(admin, 1); err != nil {
		t.Fatal(err)
	}
	d3, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	logDecision(t, "回滚到v1后", d3)
	if d3.Allowed != d1.Allowed || d3.Reason != d1.Reason || d3.PolicyVersion != d1.PolicyVersion {
		t.Fatalf("回滚后结论未复现: 历史=%+v 复验=%+v", d1, d3)
	}
}

func TestAuditTrailOrdered(t *testing.T) {
	g, signer, _ := newGate(t)
	if _, err := g.Admit(releaser, goodBundle(signer, "a", []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if _, err := g.RollbackPolicy(admin, 1); err != nil {
		t.Fatal(err)
	}
	records, err := g.AuditRecords(auditor)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range records {
		t.Logf("审计 #%d type=%s actor=%s artifact=%s policy=v%d allowed=%v",
			r.Seq, r.Type, r.Actor, r.Artifact, r.PolicyVersion, r.Allowed)
		if r.Seq != i+1 {
			t.Fatalf("审计序号应单调递增连续: 第 %d 条序号为 %d", i, r.Seq)
		}
	}
	// releaser 无权读取审计。
	if _, err := g.AuditRecords(releaser); !errors.Is(err, authz.ErrUnauthorized) {
		t.Fatalf("releaser 读取审计应被拒绝, 得到 %v", err)
	}
}
