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
	"sync"
)

// 校验失败的分类原因，互相可区分、稳定可机读。
var (
	// ErrMissingSignature：根本没有提供签名材料。
	ErrMissingSignature = errors.New("artifact: 签名缺失")
	// ErrUntrustedSignature：提供了签名，但签名本身不可信
	//（密钥不在信任列表、密钥标识缺失，或签名值与密钥/所声明摘要对不上）。
	ErrUntrustedSignature = errors.New("artifact: 签名不可信")
	// ErrTamperedContent：签名本身有效（可信密钥、签名值与所声明摘要一致），
	// 但所声明摘要与制品当前内容不一致，即签名之后内容被改动。
	ErrTamperedContent = errors.New("artifact: 制品内容在签名后被篡改")
	// ErrIncompleteProvenance：溯源信息缺失或被截断
	//（链路为空、或呈现为连贯前缀但未通过封存校验）。
	ErrIncompleteProvenance = errors.New("artifact: 溯源链不完整")
	// ErrBrokenProvenance：溯源链结构被破坏（环哈希不连贯、换序、伪造）。
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

// Signature 表示一份分离式签名（本地以 HMAC 模拟）。
//
// 签名值只覆盖 Digest（所声明的制品摘要），这让分诊可以稳定区分两类问题：
//   - 签名值与密钥/所声明摘要对不上 → 签名本身不可信（ErrUntrustedSignature）；
//   - 签名有效但所声明摘要与制品当前内容对不上 → 签名后内容被改（ErrTamperedContent）。
type Signature struct {
	KeyID  string // 签名所用密钥标识
	Digest string // 签名时制品内容的摘要（hex）
	Value  []byte // 对 Digest 的签名值
}

// Signer 使用本地密钥对制品签名与验签，并持有一个可信密钥库。
type Signer struct {
	KeyID string
	key   []byte

	trustMu sync.RWMutex
	keys    map[string][]byte // 可信密钥标识 -> 密钥
}

// NewSigner 创建签名器，并把自身密钥登记为可信密钥。
func NewSigner(keyID string, key []byte) *Signer {
	s := &Signer{KeyID: keyID, key: key, keys: make(map[string][]byte)}
	s.keys[keyID] = key
	return s
}

// Trust 登记一个额外的可信密钥。返回签名器自身以便链式调用。
func (s *Signer) Trust(keyID string, key []byte) *Signer {
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	s.keys[keyID] = key
	return s
}

// trustedKey 读取可信密钥，ok 为 false 表示该密钥标识不受信任。
func (s *Signer) trustedKey(keyID string) ([]byte, bool) {
	s.trustMu.RLock()
	defer s.trustMu.RUnlock()
	k, ok := s.keys[keyID]
	return k, ok
}

// signDigest 对摘要字符串生成 HMAC。
func signDigest(key []byte, digest string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(digest))
	return mac.Sum(nil)
}

// Sign 对制品内容生成分离式签名。
func (s *Signer) Sign(a Artifact) Signature {
	digest := a.Digest()
	return Signature{KeyID: s.KeyID, Digest: digest, Value: signDigest(s.key, digest)}
}

// verify 按"先验签名、再比内容"的固定顺序对分离式签名做分诊。
//
// 同一输入在任何时间、任何并发顺序、任何进程下都得到同一个错误类别：
//  1. 没有签名材料（nil 或空签名值）→ ErrMissingSignature；
//  2. 密钥不受信任、密钥标识缺失、签名值为空、签名值长度不一致
//     或与所声明摘要对不上 → ErrUntrustedSignature；
//  3. 签名有效但所声明摘要与当前内容不一致 → ErrTamperedContent。
func (s *Signer) verify(a Artifact, sig *Signature) error {
	if sig == nil || len(sig.Value) == 0 {
		return fmt.Errorf("%w: 未提供签名材料", ErrMissingSignature)
	}
	if sig.KeyID == "" {
		return fmt.Errorf("%w: 签名缺少密钥标识", ErrUntrustedSignature)
	}
	key, ok := s.trustedKey(sig.KeyID)
	if !ok {
		return fmt.Errorf("%w: 未知密钥 %q 不在信任列表中", ErrUntrustedSignature, sig.KeyID)
	}
	if !hmac.Equal(signDigest(key, sig.Digest), sig.Value) {
		return fmt.Errorf("%w: 密钥 %q 的签名值与所声明摘要 %q 不一致",
			ErrUntrustedSignature, sig.KeyID, sig.Digest)
	}
	if digest := a.Digest(); digest != sig.Digest {
		return fmt.Errorf("%w: 所声明摘要 %s 与当前内容摘要 %s 不一致",
			ErrTamperedContent, sig.Digest, digest)
	}
	return nil
}

// Verify 校验制品签名。分诊语义见 verify。
func (s *Signer) Verify(a Artifact, sig *Signature) error {
	return s.verify(a, sig)
}

// Link 表示溯源链中的一环。Hash 由本环内容、环序号与上一环哈希推导。
//
// Step 是该环节在完整链中的 1 基序号，并参与哈希计算，
// 因此换序、抽掉中间环节都会造成哈希不连贯。
type Link struct {
	Step    int    // 1 基环序号
	Builder string // 本环节的构建者
	Note    string // 本环节说明（如 build/test/release）
	Hash    string // 本环节哈希
}

// Provenance 表示制品的溯源声明：一条以制品摘要为起点的哈希链。
//
// Seal 是构建时对"起点摘要 + 末环哈希 + 环节总数"的封存值。
// 一条被截断的链其前缀哈希仍然连贯，仅凭环哈希无法识别截断，
// 因此用封存值把"链不完整（缺失/截断）"与"链断裂（伪造/换序）"分开分诊。
type Provenance struct {
	Links []Link
	Seal  string
}

// linkHash 计算单环哈希（环序号参与，防换序）。
func linkHash(prev string, step int, builder, note string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", step)))
	h.Write([]byte{0})
	h.Write([]byte(builder))
	h.Write([]byte{0})
	h.Write([]byte(note))
	return hex.EncodeToString(h.Sum(nil))
}

// sealHash 计算整条链的封存值。
func sealHash(start, last string, count int) string {
	h := sha256.New()
	h.Write([]byte("seal"))
	h.Write([]byte{0})
	h.Write([]byte(start))
	h.Write([]byte{0})
	h.Write([]byte(last))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", count)))
	return hex.EncodeToString(h.Sum(nil))
}

// BuildProvenance 以制品摘要为链起点，按顺序生成带封存值的溯源链。
func BuildProvenance(a Artifact, steps ...Link) Provenance {
	prev := a.Digest()
	links := make([]Link, 0, len(steps))
	for i, s := range steps {
		step := i + 1
		links = append(links, Link{
			Step:    step,
			Builder: s.Builder,
			Note:    s.Note,
			Hash:    linkHash(prev, step, s.Builder, s.Note),
		})
		prev = links[len(links)-1].Hash
	}
	p := Provenance{Links: links}
	if len(links) > 0 {
		p.Seal = sealHash(a.Digest(), links[len(links)-1].Hash, len(links))
	}
	return p
}

// VerifyProvenance 按固定顺序分诊溯源问题：
//
//  1. 链路为空，或封存值缺失/与"起点+末环+总数"对不上
//     → ErrIncompleteProvenance（溯源缺失或被截断，输入稳定落这一类）；
//  2. 环哈希不连贯、环序号错误/换序、内容被改 → ErrBrokenProvenance。
//
// 判定只依赖输入，与调用时间、并发顺序、进程无关。
func VerifyProvenance(a Artifact, p Provenance) error {
	if len(p.Links) == 0 {
		return fmt.Errorf("%w: 溯源链为空，缺少构建环节", ErrIncompleteProvenance)
	}
	start := a.Digest()
	prev := start
	for i, l := range p.Links {
		if l.Step != i+1 {
			return fmt.Errorf("%w: 第 %d 环序号为 %d，期望 %d（疑似换序或缺环）",
				ErrBrokenProvenance, i, l.Step, i+1)
		}
		if want := linkHash(prev, l.Step, l.Builder, l.Note); l.Hash != want {
			return fmt.Errorf("%w: 第 %d 环(%s/%s)哈希不匹配",
				ErrBrokenProvenance, i, l.Builder, l.Note)
		}
		prev = l.Hash
	}
	if p.Seal == "" {
		return fmt.Errorf("%w: 缺少封存值，溯源声明未完整封存（共 %d 环）",
			ErrIncompleteProvenance, len(p.Links))
	}
	if want := sealHash(start, prev, len(p.Links)); p.Seal != want {
		return fmt.Errorf("%w: 封存值不匹配，声明 %d 环但期望完整链路（疑似截断）",
			ErrIncompleteProvenance, len(p.Links))
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
