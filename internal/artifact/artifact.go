// Package artifact 提供本地制品、签名与溯源声明的类型与校验能力。
//
// 全部流程离线可复现：签名以 HMAC-SHA256 模拟，溯源链以哈希链模拟。
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
	ErrMissingSignature = errors.New("artifact: 签名缺失")
	ErrInvalidSignature = errors.New("artifact: 签名无效（内容可能被篡改）")
	ErrBrokenProvenance = errors.New("artifact: 溯源链断裂")
)

// Artifact 表示一个待准入的构建制品。
type Artifact struct {
	Name    string
	Content []byte
}

// Digest 返回制品内容的 SHA-256 摘要（hex）。
func (a Artifact) Digest() string {
	sum := sha256.Sum256(a.Content)
	return hex.EncodeToString(sum[:])
}

// Signature 表示对制品内容摘要的签名（本地以 HMAC 模拟）。
type Signature struct {
	KeyID string
	Value []byte
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

// Sign 对制品内容生成签名。
func (s *Signer) Sign(a Artifact) Signature {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(a.Content)
	return Signature{KeyID: s.KeyID, Value: mac.Sum(nil)}
}

// Verify 校验制品签名。签名缺失与签名无效返回不同错误。
func (s *Signer) Verify(a Artifact, sig *Signature) error {
	if sig == nil || len(sig.Value) == 0 {
		return ErrMissingSignature
	}
	if sig.KeyID != s.KeyID {
		return fmt.Errorf("%w: 未知密钥 %q", ErrInvalidSignature, sig.KeyID)
	}
	expect := s.Sign(a)
	if !hmac.Equal(expect.Value, sig.Value) {
		return ErrInvalidSignature
	}
	return nil
}

// Link 表示溯源链中的一环，Hash 由本环内容与上一环哈希推导。
type Link struct {
	Builder string // 本环节的构建者
	Note    string // 本环节说明（如 build/test/release）
	Hash    string // 本环节哈希
}

// Provenance 表示制品的溯源声明：一条以制品摘要为起点的哈希链。
type Provenance struct {
	Links []Link
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

// BuildProvenance 以制品摘要为链起点，按顺序生成溯源链。
func BuildProvenance(a Artifact, steps ...Link) Provenance {
	prev := a.Digest()
	links := make([]Link, 0, len(steps))
	for _, s := range steps {
		links = append(links, Link{
			Builder: s.Builder,
			Note:    s.Note,
			Hash:    linkHash(prev, s.Builder, s.Note),
		})
		prev = links[len(links)-1].Hash
	}
	return Provenance{Links: links}
}

// VerifyProvenance 校验溯源链：起点必须是制品当前摘要，且每环哈希连贯。
// 任何断链、换序或内容篡改都会导致校验失败。
func VerifyProvenance(a Artifact, p Provenance) error {
	if len(p.Links) == 0 {
		return fmt.Errorf("%w: 溯源链为空", ErrBrokenProvenance)
	}
	prev := a.Digest()
	for i, l := range p.Links {
		if l.Hash != linkHash(prev, l.Builder, l.Note) {
			return fmt.Errorf("%w: 第 %d 环哈希不匹配", ErrBrokenProvenance, i)
		}
		prev = l.Hash
	}
	return nil
}

// SBOM 表示软件成分信息。
type SBOM struct {
	Components []string
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

// Bundle 将一个制品及其签名、溯源与成分信息打包用于准入校验。
type Bundle struct {
	Artifact   Artifact
	Signature  *Signature
	Provenance Provenance
	SBOM       SBOM
}
