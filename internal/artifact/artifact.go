// Package artifact 提供本地制品、签名与溯源声明的类型与校验能力。
//
// 全部流程离线可复现：签名以 HMAC-SHA256 模拟，溯源链以哈希链模拟。
//
// 失败分诊（类别稳定、互相不混淆）：
//   - 签名材料缺失：ErrMissingSignature；
//   - 签名本身不可信（密钥未知/密钥不匹配/签名值错误）：ErrUntrustedSignature；
//   - 签名后制品内容被篡改（签名绑定的摘要与当前内容不一致）：ErrTamperedContent；
//   - 溯源被截断或缺了声明的关键环节：ErrIncompleteProvenance；
//   - 溯源哈希链不连贯（换序、篡改哈希、锚点不匹配）：ErrBrokenProvenance。
package artifact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// 校验失败的分类原因，互相可区分。
var (
	// ErrMissingSignature：根本没有提供签名材料。
	ErrMissingSignature = errors.New("artifact: 签名材料缺失")
	// ErrUntrustedSignature：签名材料提供了，但密钥未知/不匹配或签名值错误。
	ErrUntrustedSignature = errors.New("artifact: 签名不可信（密钥或签名值不匹配）")
	// ErrTamperedContent：签名本身格式正常，但制品内容与签名绑定的摘要不一致。
	ErrTamperedContent = errors.New("artifact: 制品内容在签名后被篡改（摘要不匹配）")
	// ErrIncompleteProvenance：溯源链哈希连贯，但被截断或缺了声明的关键环节。
	ErrIncompleteProvenance = errors.New("artifact: 溯源链不完整（关键环节缺失或被截断）")
	// ErrBrokenProvenance：溯源链哈希不连贯（空链之外的断链、换序、锚点不匹配）。
	ErrBrokenProvenance = errors.New("artifact: 溯源链断裂（哈希不连贯）")

	// ErrInvalidSignature 是 ErrUntrustedSignature 的旧名别名，保持向后兼容。
	//
	// Deprecated: 新代码请使用 ErrUntrustedSignature；内容篡改请使用 ErrTamperedContent。
	ErrInvalidSignature = ErrUntrustedSignature
)

// Artifact 表示一个待准入的构建制品。
type Artifact struct {
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

// Digest 返回制品内容的 SHA-256 摘要（hex）。空内容与非空内容摘要不同，
// 因此"空输入制品"也有稳定、可复现的摘要。
func (a Artifact) Digest() string {
	sum := sha256.Sum256(a.Content)
	return hex.EncodeToString(sum[:])
}

// Signature 表示对制品内容摘要的签名（本地以 HMAC 模拟）。
//
// Digest 是签名时绑定的制品内容摘要：验签时若它与当前内容摘要不一致，
// 说明内容在签名之后被改过（ErrTamperedContent）；Digest 一致但 HMAC
// 比对失败，则是签名本身不可信（ErrUntrustedSignature）。两类因此可稳定区分。
type Signature struct {
	KeyID  string `json:"key_id"`
	Value  []byte `json:"value"`
	Digest string `json:"digest"`
}

// Signer 使用本地密钥对制品签名与验签。
type Signer struct {
	KeyID string
	key   []byte
}

// NewSigner 创建签名器。
func NewSigner(keyID string, key []byte) *Signer {
	return &Signer{KeyID: keyID, key: key}
}

// Sign 对制品内容生成签名，同时绑定签名时的内容摘要。
func (s *Signer) Sign(a Artifact) Signature {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(a.Content)
	return Signature{KeyID: s.KeyID, Value: mac.Sum(nil), Digest: a.Digest()}
}

// Verify 校验制品签名，分诊顺序固定：
//  1. 没有签名材料 -> ErrMissingSignature；
//  2. 密钥 ID 未知 -> ErrUntrustedSignature；
//  3. 签名绑定的摘要与当前内容不一致 -> ErrTamperedContent；
//  4. HMAC 比对失败（密钥材料或签名值不对）-> ErrUntrustedSignature。
func (s *Signer) Verify(a Artifact, sig *Signature) error {
	if sig == nil || len(sig.Value) == 0 {
		return fmt.Errorf("%w: 未提供签名值", ErrMissingSignature)
	}
	if sig.KeyID != s.KeyID {
		return fmt.Errorf("%w: 未知密钥 %q（期望 %q）", ErrUntrustedSignature, sig.KeyID, s.KeyID)
	}
	current := a.Digest()
	if sig.Digest != "" && sig.Digest != current {
		return fmt.Errorf("%w: 签名绑定摘要 %s，当前内容摘要 %s",
			ErrTamperedContent, sig.Digest, current)
	}
	expect := s.Sign(a)
	if !hmac.Equal(expect.Value, sig.Value) {
		return fmt.Errorf("%w: 签名值与密钥 %q 计算结果不一致", ErrUntrustedSignature, s.KeyID)
	}
	return nil
}

// Link 表示溯源链中的一环，Hash 由本环内容与上一环哈希推导。
type Link struct {
	Builder string `json:"builder"` // 本环节的构建者
	Note    string `json:"note"`    // 本环节说明（如 build/test/release）
	Hash    string `json:"hash"`    // 本环节哈希
}

// Provenance 表示制品的溯源声明：一条以制品摘要为起点的哈希链。
//
// DeclaredStages 声明该制品溯源本应包含的关键环节（按顺序的 Note 列表，
// 例如 build/test/release）。它只描述"完整链应有的样子"，不参与哈希推导：
//   - 哈希链连贯但缺了声明中的环节（如尾部被截断）-> ErrIncompleteProvenance；
//   - 哈希链本身不连贯 -> ErrBrokenProvenance。
//
// DeclaredStages 为空表示不提供完整性声明，此时只校验哈希连贯性。
type Provenance struct {
	Links          []Link   `json:"links"`
	DeclaredStages []string `json:"declared_stages,omitempty"`
}

// linkHash 计算单环哈希。
func linkHash(prev, builder, note string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write([]byte(builder))
	h.Write([]byte{0})
	h.Write([]byte(note))
	return hex.EncodeToString(h.Sum(nil))
}

// BuildLink 以上一环哈希为前值构造一个哈希连贯的链环。
//
// 首环的前值应取制品摘要（Artifact.Digest）。该原语便于在重建/裁剪溯源链时
// 保持哈希连贯，从而把"链连贯但缺环节（incomplete）"与"链不连贯（broken）"
// 两类输入稳定构造出来。
func BuildLink(prevHash string, l Link) Link {
	l.Hash = linkHash(prevHash, l.Builder, l.Note)
	return l
}

// BuildProvenance 以制品摘要为链起点，按顺序生成溯源链。
//
// 默认把传入环节的 Note 顺序登记为 DeclaredStages，即"这些环节缺一不可"。
// 这样对生成后的链做尾部截断即可被稳定识别为 ErrIncompleteProvenance。
func BuildProvenance(a Artifact, steps ...Link) Provenance {
	prev := a.Digest()
	links := make([]Link, 0, len(steps))
	stages := make([]string, 0, len(steps))
	for _, s := range steps {
		links = append(links, Link{
			Builder: s.Builder,
			Note:    s.Note,
			Hash:    linkHash(prev, s.Builder, s.Note),
		})
		stages = append(stages, s.Note)
		prev = links[len(links)-1].Hash
	}
	return Provenance{Links: links, DeclaredStages: stages}
}

// VerifyProvenance 校验溯源链，分诊顺序固定：
//  1. 链为空（关键环节全部缺失）-> ErrIncompleteProvenance；
//  2. 任一环哈希与"上一环哈希+本环内容"推导结果不一致
//     （换序、篡改、起点锚点不匹配）-> ErrBrokenProvenance；
//  3. 哈希连贯但声明的关键环节未按顺序全部出现（截断/缺环）
//     -> ErrIncompleteProvenance。
func VerifyProvenance(a Artifact, p Provenance) error {
	if len(p.Links) == 0 {
		return fmt.Errorf("%w: 溯源链为空，声明的关键环节 %v 全部缺失",
			ErrIncompleteProvenance, p.DeclaredStages)
	}
	prev := a.Digest()
	for i, l := range p.Links {
		if l.Hash != linkHash(prev, l.Builder, l.Note) {
			return fmt.Errorf("%w: 第 %d 环（%s/%s）哈希不匹配，链起点摘要 %s",
				ErrBrokenProvenance, i, l.Builder, l.Note, a.Digest())
		}
		prev = l.Hash
	}
	if missing, ok := missingStages(p); !ok {
		return fmt.Errorf("%w: 声明的关键环节 %v 中 %v 缺失（实际环节 %v）",
			ErrIncompleteProvenance, p.DeclaredStages, missing, stageNotes(p.Links))
	}
	return nil
}

// stageNotes 按顺序列出链上各环的 Note。
func stageNotes(links []Link) []string {
	out := make([]string, 0, len(links))
	for _, l := range links {
		out = append(out, l.Note)
	}
	return out
}

// missingStages 检查声明的关键环节是否作为实际链环节的子序列按顺序出现；
// 返回缺失环节列表。全部齐备时 ok 为 true。
func missingStages(p Provenance) (missing []string, ok bool) {
	if len(p.DeclaredStages) == 0 {
		return nil, true
	}
	i := 0
	for _, l := range p.Links {
		if i < len(p.DeclaredStages) && l.Note == p.DeclaredStages[i] {
			i++
		}
	}
	if i == len(p.DeclaredStages) {
		return nil, true
	}
	return p.DeclaredStages[i:], false
}

// SBOM 表示软件成分信息。
type SBOM struct {
	Components []string `json:"components"`
}

// Contains 判断成分表中是否包含指定组件。
func (s SBOM) Contains(component string) bool {
	for _, c := range s.Components {
		if c == component {
			return true
		}
	}
	return false
}

// Bundle 将一个制品及其签名、溯源与成分信息打包用于准入判定，可直接 JSON 序列化离线保存。
type Bundle struct {
	Artifact   Artifact   `json:"artifact"`
	Signature  *Signature `json:"signature,omitempty"`
	Provenance Provenance `json:"provenance"`
	SBOM       SBOM       `json:"sbom"`
}
