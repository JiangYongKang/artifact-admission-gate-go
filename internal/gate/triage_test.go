package gate_test

import (
	"sync"
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
)

// 本组覆盖失败分诊粒度：每个类别独立用例，重点验证
// 内容篡改 / 签名不可信 / 溯源截断三类互不混淆，且依据可机读、可复现。

// signedByOtherKey 用另一把密钥签名，模拟"签名本身不可信（密钥不匹配）"。
func signedByOtherKey(name string, content []byte) artifact.Bundle {
	other := artifact.NewSigner("rogue-key", []byte("rogue-secret"))
	b := goodBundle(other, name, content)
	return b
}

func TestTriageMissingSignature(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app", []byte("c"))
	b.Signature = nil
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/签名材料未提供 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonMissingSignature {
		t.Fatalf("期望 missing_signature, 得到 %s", d.Reason)
	}
}

func TestTriageUntrustedSignatureUnknownKey(t *testing.T) {
	g, _, _ := newGate(t)
	// 签名由未知密钥签发：密钥 ID 对不上，属于签名本身不可信。
	b := signedByOtherKey("app", []byte("c"))
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/签名不可信(未知密钥) 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonUntrustedSignature {
		t.Fatalf("期望 untrusted_signature, 得到 %s (%s)", d.Reason, d.Detail)
	}
}

func TestTriageUntrustedSignatureBadValue(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app", []byte("c"))
	// 密钥 ID 正确、绑定摘要正确，但签名值被改坏：HMAC 比对失败，
	// 仍属于签名本身不可信，而不是内容篡改。
	b.Signature.Value[0] ^= 0xFF
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/签名不可信(签名值错误) 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonUntrustedSignature {
		t.Fatalf("期望 untrusted_signature, 得到 %s (%s)", d.Reason, d.Detail)
	}
}

func TestTriageTamperedContentDistinctFromUntrusted(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app", []byte("c"))
	b.Artifact.Content = []byte("c-tampered")
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/签名后内容被改 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonTamperedContent {
		t.Fatalf("内容被改必须是 tampered_content, 得到 %s (%s)", d.Reason, d.Detail)
	}
	// 与"签名不可信"必须是两类，不能互相混淆。
	if d.Reason == gate.ReasonUntrustedSignature {
		t.Fatal("tampered_content 不得与 untrusted_signature 同类")
	}
}

func TestTriageProvenanceTruncatedTail(t *testing.T) {
	g, signer, _ := newGate(t)
	a := artifact.Artifact{Name: "app", Content: []byte("c")}
	sig := signer.Sign(a)
	p := artifact.BuildProvenance(a,
		artifact.Link{Builder: "ci-builder", Note: "compile"},
		artifact.Link{Builder: "ci-builder", Note: "test"},
		artifact.Link{Builder: "ci-builder", Note: "release"},
	)
	// 尾部截断：剩余两环哈希仍然连贯，但声明的 release 环节缺失。
	p.Links = p.Links[:2]
	b := artifact.Bundle{Artifact: a, Signature: &sig, Provenance: p}
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/溯源尾部截断(哈希仍连贯) 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonIncompleteProvenance {
		t.Fatalf("截断必须是 incomplete_provenance, 得到 %s (%s)", d.Reason, d.Detail)
	}
}

func TestTriageProvenanceMissingKeyStage(t *testing.T) {
	g, signer, _ := newGate(t)
	a := artifact.Artifact{Name: "app", Content: []byte("c")}
	sig := signer.Sign(a)
	p := artifact.BuildProvenance(a,
		artifact.Link{Builder: "ci-builder", Note: "compile"},
		artifact.Link{Builder: "ci-builder", Note: "test"},
		artifact.Link{Builder: "ci-builder", Note: "release"},
	)
	// 缺关键环节：声明 compile/test/release，但链上只有 compile+release
	// （各自哈希都重新连贯，缺的是 test 这一环）。
	kept := []artifact.Link{p.Links[0]}
	// 以 compile 环哈希为前值重建 release 环，链仍连贯但缺 test。
	kept = append(kept, artifact.BuildLink(p.Links[0].Hash,
		artifact.Link{Builder: "ci-builder", Note: "release"}))
	b := artifact.Bundle{
		Artifact:   a,
		Signature:  &sig,
		Provenance: artifact.Provenance{Links: kept, DeclaredStages: p.DeclaredStages},
	}
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/溯源缺关键test环节 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonIncompleteProvenance {
		t.Fatalf("缺关键环节必须是 incomplete_provenance, 得到 %s (%s)", d.Reason, d.Detail)
	}
}

func TestTriageProvenanceEmpty(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app", []byte("c"))
	b.Provenance = artifact.Provenance{DeclaredStages: []string{"compile", "test"}}
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/溯源为空 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonIncompleteProvenance {
		t.Fatalf("空溯源必须归入 incomplete_provenance, 得到 %s", d.Reason)
	}
}

func TestTriageBrokenProvenanceDistinctFromIncomplete(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app", []byte("c"))
	// 换序：环数没少、声明环节都在，但哈希链不连贯 -> broken，而非 incomplete。
	b.Provenance.Links[0], b.Provenance.Links[1] = b.Provenance.Links[1], b.Provenance.Links[0]
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/溯源换序断链 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonBrokenProvenance {
		t.Fatalf("换序断链必须是 broken_provenance, 得到 %s", d.Reason)
	}
}

func TestTriagePolicyViolationDistinct(t *testing.T) {
	g, signer, _ := newGate(t)
	b := goodBundle(signer, "app", []byte("c"))
	b.SBOM.Components = append(b.SBOM.Components, "openssl-1.0")
	d, err := g.Admit(releaser, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("业务=分诊/命中策略禁含成分 输入=%s 命中策略=v%d 类别=%s 依据=%s",
		d.Artifact, d.PolicyVersion, d.Reason, d.Detail)
	if d.Reason != gate.ReasonPolicyViolation || d.PolicyVersion != 1 {
		t.Fatalf("应 policy_violation@v1, 得到 %s@v%d", d.Reason, d.PolicyVersion)
	}
}

// TestTriageStableAcrossConcurrency 同一份输入反复、并发判定，
// 类别与依据必须逐字一致，不随时间/并发顺序/进程内调度漂移。
func TestTriageStableAcrossConcurrency(t *testing.T) {
	g, signer, _ := newGate(t)

	inputs := map[string]artifact.Bundle{}
	tampered := goodBundle(signer, "tampered", []byte("c"))
	tampered.Artifact.Content = []byte("c2")
	trunc := goodBundle(signer, "trunc", []byte("c"))
	trunc.Provenance.Links = trunc.Provenance.Links[:1]
	rogue := signedByOtherKey("rogue", []byte("c"))
	good := goodBundle(signer, "good", []byte("c"))
	inputs["tampered"] = tampered
	inputs["trunc"] = trunc
	inputs["rogue"] = rogue
	inputs["good"] = good

	want := map[string]gate.Decision{}
	for k, b := range inputs {
		d, err := g.Admit(releaser, b)
		if err != nil {
			t.Fatal(err)
		}
		want[k] = d
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]map[string]bool{} // key -> "reason|detail" 集合
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k, b := range inputs {
				d, err := g.Admit(releaser, b)
				if err != nil {
					t.Errorf("并发判定失败: %v", err)
					return
				}
				mu.Lock()
				sig := string(d.Reason) + "|" + d.Detail
				if seen[k] == nil {
					seen[k] = map[string]bool{}
				}
				seen[k][sig] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	for k, sigs := range seen {
		if len(sigs) != 1 {
			t.Fatalf("%s 的分诊结论在并发下出现漂移: %v", k, sigs)
		}
		d := want[k]
		t.Logf("业务=分诊/并发稳定性 输入=%s 类别=%s 命中策略=v%d 依据=%s",
			k, d.Reason, d.PolicyVersion, d.Detail)
	}

	// 显式确认三类互不相同。
	categories := []gate.Reason{want["tampered"].Reason, want["trunc"].Reason, want["rogue"].Reason, want["good"].Reason}
	distinct := map[gate.Reason]bool{}
	for _, c := range categories {
		distinct[c] = true
	}
	if len(distinct) != 4 {
		t.Fatalf("篡改/截断/不可信/合规四类应互不相同, 得到 %v", categories)
	}
	if want["tampered"].Reason != gate.ReasonTamperedContent ||
		want["trunc"].Reason != gate.ReasonIncompleteProvenance ||
		want["rogue"].Reason != gate.ReasonUntrustedSignature ||
		want["good"].Reason != gate.ReasonAllowed {
		t.Fatalf("分诊类别错误: %+v", want)
	}
}
