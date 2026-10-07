package artifact_test

import (
	"errors"
	"testing"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
)

// TestSignatureTriageDistinct 覆盖签名侧三类分诊必须互相区分：
// 没给材料 / 签名本身不可信（密钥或签名值不对）/ 签名后内容被改。
func TestSignatureTriageDistinct(t *testing.T) {
	signer := artifact.NewSigner("release-key", []byte("secret"))
	a := artifact.Artifact{Name: "app", Content: []byte("payload")}
	sig := signer.Sign(a)

	cases := []struct {
		name string
		sig  *artifact.Signature
		mod  func(*artifact.Artifact, *artifact.Signature)
		want error
	}{
		{"签名材料缺失", nil, nil, artifact.ErrMissingSignature},
		{
			"签名值为空", &artifact.Signature{},
			func(_ *artifact.Artifact, s *artifact.Signature) { *s = artifact.Signature{KeyID: "k", Digest: "d"} },
			artifact.ErrMissingSignature,
		},
		{
			"密钥不在信任列表", &sig,
			func(_ *artifact.Artifact, s *artifact.Signature) { s.KeyID = "rogue-key" },
			artifact.ErrUntrustedSignature,
		},
		{
			"签名值被改(签名本身不可信)", &sig,
			func(_ *artifact.Artifact, s *artifact.Signature) { s.Value[0] ^= 0xFF },
			artifact.ErrUntrustedSignature,
		},
		{
			"所声明摘要被改但签名值未重算(签名本身不可信)", &sig,
			func(_ *artifact.Artifact, s *artifact.Signature) { s.Digest = "00" },
			artifact.ErrUntrustedSignature,
		},
		{
			"签名有效但内容被篡改(tampered)", &sig,
			func(a *artifact.Artifact, _ *artifact.Signature) { a.Content = []byte("evil") },
			artifact.ErrTamperedContent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			art := a
			var s *artifact.Signature
			if tc.sig != nil {
				fresh := signer.Sign(art) // 每个子用例独立签名，避免相互污染
				s = &fresh
			}
			if tc.mod != nil {
				if s == nil {
					s = &artifact.Signature{}
				}
				tc.mod(&art, s)
			}
			err := signer.Verify(art, s)
			t.Logf("业务=签名分诊 输入=%q 依据=%v", tc.name, err)
			if !errors.Is(err, tc.want) {
				t.Fatalf("%s: 期望 %v, 得到 %v", tc.name, tc.want, err)
			}
		})
	}

	// 未被篡改的原始签名必须通过，确保三类失败与正常路径分离。
	if err := signer.Verify(a, &sig); err != nil {
		t.Fatalf("正常签名应通过, 得到 %v", err)
	}
}

// TestSignatureTriageDeterministic 验证同一输入多次、跨"进程"（新实例同密钥库）分诊一致。
func TestSignatureTriageDeterministic(t *testing.T) {
	a := artifact.Artifact{Name: "app", Content: []byte("payload")}
	sig := artifact.NewSigner("k", []byte("secret")).Sign(a)
	tampered := a
	tampered.Content = []byte("evil")

	for i := 0; i < 20; i++ {
		// 每次新建签名器模拟不同进程，信任库一致。
		s := artifact.NewSigner("k", []byte("secret"))
		err := s.Verify(tampered, &sig)
		if !errors.Is(err, artifact.ErrTamperedContent) {
			t.Fatalf("第 %d 次分诊漂移: %v", i, err)
		}
	}
}

// TestProvenanceTriageDistinct 覆盖溯源侧两类必须互相区分：
// 不完整（空/截断/封存缺失）与断裂（换序/哈希伪造）。
func TestProvenanceTriageDistinct(t *testing.T) {
	a := artifact.Artifact{Name: "app", Content: []byte("payload")}
	good := artifact.BuildProvenance(a,
		artifact.Link{Builder: "ci", Note: "build"},
		artifact.Link{Builder: "ci", Note: "test"},
		artifact.Link{Builder: "ci", Note: "release"},
	)

	t.Run("溯源为空→不完整", func(t *testing.T) {
		err := artifact.VerifyProvenance(a, artifact.Provenance{})
		t.Logf("业务=溯源分诊 输入=空链 依据=%v", err)
		if !errors.Is(err, artifact.ErrIncompleteProvenance) {
			t.Fatalf("期望 incomplete, 得到 %v", err)
		}
	})

	t.Run("截断末环→不完整(封存不符)", func(t *testing.T) {
		trunc := artifact.Provenance{Links: good.Links[:2]} // 前缀哈希仍连贯
		err := artifact.VerifyProvenance(a, trunc)
		t.Logf("业务=溯源分诊 输入=截断为2环 依据=%v", err)
		if !errors.Is(err, artifact.ErrIncompleteProvenance) {
			t.Fatalf("截断应分诊为不完整, 得到 %v", err)
		}
	})

	t.Run("封存值缺失→不完整", func(t *testing.T) {
		noSeal := artifact.Provenance{Links: good.Links}
		err := artifact.VerifyProvenance(a, noSeal)
		t.Logf("业务=溯源分诊 输入=缺封存值 依据=%v", err)
		if !errors.Is(err, artifact.ErrIncompleteProvenance) {
			t.Fatalf("缺封存应分诊为不完整, 得到 %v", err)
		}
	})

	t.Run("换序→断裂", func(t *testing.T) {
		swapped := artifact.Provenance{Seal: good.Seal, Links: append([]artifact.Link(nil), good.Links...)}
		swapped.Links[0], swapped.Links[1] = swapped.Links[1], swapped.Links[0]
		err := artifact.VerifyProvenance(a, swapped)
		t.Logf("业务=溯源分诊 输入=环换序 依据=%v", err)
		if !errors.Is(err, artifact.ErrBrokenProvenance) {
			t.Fatalf("换序应分诊为断裂, 得到 %v", err)
		}
	})

	t.Run("中间环节被抽→不完整", func(t *testing.T) {
		gapped := artifact.Provenance{
			Links: []artifact.Link{good.Links[0], good.Links[2]},
			Seal:  good.Seal,
		}
		err := artifact.VerifyProvenance(a, gapped)
		t.Logf("业务=溯源分诊 输入=抽掉中环 依据=%v", err)
		if !errors.Is(err, artifact.ErrIncompleteProvenance) {
			t.Fatalf("缺中环属于少了关键环节，应分诊为不完整, 得到 %v", err)
		}
	})

	t.Run("环内容被改→断裂", func(t *testing.T) {
		modified := artifact.Provenance{Seal: good.Seal, Links: append([]artifact.Link(nil), good.Links...)}
		modified.Links[1].Note = "tampered"
		err := artifact.VerifyProvenance(a, modified)
		t.Logf("业务=溯源分诊 输入=环内容被改 依据=%v", err)
		if !errors.Is(err, artifact.ErrBrokenProvenance) {
			t.Fatalf("改环内容应分诊为断裂, 得到 %v", err)
		}
	})

	t.Run("完整链通过", func(t *testing.T) {
		if err := artifact.VerifyProvenance(a, good); err != nil {
			t.Fatalf("完整链应通过, 得到 %v", err)
		}
	})
}

// TestTruncationStableAcrossBuilders 验证任何"截断的连贯前缀"都稳定落在不完整类。
func TestTruncationStableAcrossBuilders(t *testing.T) {
	for n := 1; n <= 5; n++ {
		a := artifact.Artifact{Name: "x", Content: []byte("c")}
		steps := make([]artifact.Link, n)
		for i := range steps {
			steps[i] = artifact.Link{Builder: "b", Note: "n"}
		}
		full := artifact.BuildProvenance(a, steps...)
		for cut := 0; cut < n; cut++ {
			p := artifact.Provenance{Links: full.Links[:cut]}
			err := artifact.VerifyProvenance(a, p)
			if !errors.Is(err, artifact.ErrIncompleteProvenance) {
				t.Fatalf("n=%d cut=%d 应稳定为不完整, 得到 %v", n, cut, err)
			}
		}
	}
}
