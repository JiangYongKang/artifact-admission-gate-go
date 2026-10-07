package gate_test

import (
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
	"github.com/highcumontoa/artifact-admission-gate-go/internal/gate"
)

// TestTriageCategories 用同一批基线制品逐一制造不同故障，
// 验证端到端分诊类别各归其类、互不混淆。
func TestTriageCategories(t *testing.T) {
	g, signer, _ := newGate(t)
	base := func() artifact.Bundle {
		return goodBundle(signer, "app", []byte("payload"))
	}

	cases := []struct {
		biz   string // 覆盖的业务类别
		input string // 故障手法
		want  gate.Reason
		alter func(b artifact.Bundle) artifact.Bundle
	}{
		{"合规", "签名/溯源/SBOM 全满足", gate.ReasonAllowed,
			func(b artifact.Bundle) artifact.Bundle { return b }},
		{"空输入", "零值 Bundle", gate.ReasonInvalidInput,
			func(b artifact.Bundle) artifact.Bundle { return artifact.Bundle{} }},
		{"签名材料缺失", "Signature=nil", gate.ReasonMissingSignature,
			func(b artifact.Bundle) artifact.Bundle { b.Signature = nil; return b }},
		{"签名本身不可信", "使用未登记密钥重签", gate.ReasonUntrustedSignature,
			func(b artifact.Bundle) artifact.Bundle {
				rogue := artifact.NewSigner("rogue-key", []byte("other"))
				s := rogue.Sign(b.Artifact)
				b.Signature = &s
				return b
			}},
		{"签名本身不可信", "改签名值一个字节", gate.ReasonUntrustedSignature,
			func(b artifact.Bundle) artifact.Bundle {
				b.Signature.Value[0] ^= 0x01
				return b
			}},
		{"内容被篡改", "签名后替换 Content", gate.ReasonTamperedContent,
			func(b artifact.Bundle) artifact.Bundle {
				b.Artifact.Content = []byte("malicious-after-sign")
				return b
			}},
		{"溯源不完整", "截断为单环前缀", gate.ReasonIncompleteProvenance,
			func(b artifact.Bundle) artifact.Bundle {
				b.Provenance = artifact.Provenance{Links: b.Provenance.Links[:1]}
				return b
			}},
		{"溯源不完整", "封存值置空", gate.ReasonIncompleteProvenance,
			func(b artifact.Bundle) artifact.Bundle {
				b.Provenance.Seal = ""
				return b
			}},
		{"溯源不完整", "三环链去掉中间环节", gate.ReasonIncompleteProvenance,
			func(b artifact.Bundle) artifact.Bundle {
				full := artifact.BuildProvenance(b.Artifact,
					artifact.Link{Builder: "ci-builder", Note: "compile"},
					artifact.Link{Builder: "ci-builder", Note: "test"},
					artifact.Link{Builder: "ci-builder", Note: "release"},
				)
				// 抽掉第 2 环，保留其余环节与原封存值：属于少了关键环节。
				b.Provenance = artifact.Provenance{
					Links: []artifact.Link{full.Links[0], full.Links[2]},
					Seal:  full.Seal,
				}
				return b
			}},
		{"溯源不完整", "三环链去掉首环节", gate.ReasonIncompleteProvenance,
			func(b artifact.Bundle) artifact.Bundle {
				full := artifact.BuildProvenance(b.Artifact,
					artifact.Link{Builder: "ci-builder", Note: "compile"},
					artifact.Link{Builder: "ci-builder", Note: "test"},
					artifact.Link{Builder: "ci-builder", Note: "release"},
				)
				b.Provenance = artifact.Provenance{
					Links: []artifact.Link{full.Links[1], full.Links[2]},
					Seal:  full.Seal,
				}
				return b
			}},
		{"溯源断裂", "交换两环顺序", gate.ReasonBrokenProvenance,
			func(b artifact.Bundle) artifact.Bundle {
				b.Provenance.Links[0], b.Provenance.Links[1] =
					b.Provenance.Links[1], b.Provenance.Links[0]
				return b
			}},
		{"策略违规", "SBOM 加入被禁成分", gate.ReasonPolicyViolation,
			func(b artifact.Bundle) artifact.Bundle {
				b.SBOM.Components = append(b.SBOM.Components, "openssl-1.0")
				return b
			}},
	}

	seen := map[gate.Reason]bool{}
	for _, tc := range cases {
		t.Run(tc.biz+"/"+tc.input, func(t *testing.T) {
			d, err := g.Admit(releaser, tc.alter(base()))
			if err != nil {
				t.Fatalf("准入返回错误: %v", err)
			}
			t.Logf("业务=%s 输入=%s 命中策略=v%d 类别=%s 放行=%v 依据=%s",
				tc.biz, tc.input, d.PolicyVersion, d.Reason, d.Allowed, d.Detail)
			if d.Reason != tc.want {
				t.Fatalf("业务=%s 期望类别=%s 得到=%s（%s）",
					tc.biz, tc.want, d.Reason, d.Detail)
			}
			seen[tc.want] = true
		})
	}

	// 关键三类必须各自有用例且互不相同。
	key3 := []gate.Reason{gate.ReasonTamperedContent,
		gate.ReasonUntrustedSignature, gate.ReasonIncompleteProvenance}
	for _, r := range key3 {
		if !seen[r] {
			t.Fatalf("缺少分诊类别用例: %s", r)
		}
	}
	if gate.ReasonTamperedContent == gate.ReasonUntrustedSignature {
		t.Fatal("内容篡改与签名不可信必须是两个不同类别")
	}
}

// TestTriageStableAcrossProcesses 模拟"不同进程"：用相同密钥库反复新建 Gate，
// 同一份故障输入必须得到相同类别与依据。
func TestTriageStableAcrossProcesses(t *testing.T) {
	var ref gate.Decision
	scenarios := []struct {
		name  string
		build func(s *artifact.Signer) artifact.Bundle
		want  gate.Reason
	}{
		{"内容篡改", func(s *artifact.Signer) artifact.Bundle {
			b := goodBundle(s, "a", []byte("v"))
			b.Artifact.Content = []byte("v-evil")
			return b
		}, gate.ReasonTamperedContent},
		{"签名不可信", func(s *artifact.Signer) artifact.Bundle {
			b := goodBundle(s, "a", []byte("v"))
			b.Signature.Value[0] ^= 0x02
			return b
		}, gate.ReasonUntrustedSignature},
		{"溯源截断", func(s *artifact.Signer) artifact.Bundle {
			b := goodBundle(s, "a", []byte("v"))
			b.Provenance = artifact.Provenance{Links: b.Provenance.Links[:1]}
			return b
		}, gate.ReasonIncompleteProvenance},
	}

	for iter := 0; iter < 10; iter++ {
		g2, signer2, _ := newGate(t)
		for _, sc := range scenarios {
			d, err := g2.Admit(releaser, sc.build(signer2))
			if err != nil {
				t.Fatalf("iter=%d %s: %v", iter, sc.name, err)
			}
			if d.Reason != sc.want {
				t.Fatalf("iter=%d %s 类别漂移: %s", iter, sc.name, d.Reason)
			}
			if iter == 0 && sc.name == "内容篡改" {
				ref = d
			}
			if sc.name == "内容篡改" && d.Detail != ref.Detail {
				t.Fatalf("iter=%d 依据漂移: %q vs %q", iter, d.Detail, ref.Detail)
			}
		}
	}
	t.Logf("业务=跨进程稳定性 内容篡改依据=%s", ref.Detail)
}
