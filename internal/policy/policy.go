// Package policy 提供按版本生效、可回滚的准入策略存储。
//
// 语义：
//   - 策略以单调递增的版本号提交，任一时刻只有一个生效版本；
//   - 回滚把生效指针切回历史版本，历史本身不被修改，
//     因此对同一输入可复现该历史版本的结论；
//   - 并发读取使用 RWMutex，校验期间生效版本保持一致。
package policy

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/highcumontoa/artifact-admission-gate-go/internal/artifact"
)

// ErrVersionNotFound 表示回滚目标版本不存在。
var ErrVersionNotFound = errors.New("policy: 目标版本不存在")

// Policy 表示一个版本的准入策略。
type Policy struct {
	Version          int      // 版本号（单调递增）
	RequireSignature bool     // 是否要求签名有效
	AllowedBuilders  []string // 允许出现在溯源链中的构建者；空表示不限制
	BannedComponents []string // 禁止出现在 SBOM 中的组件
	MinChainLength   int      // 溯源链最小长度
}

// allows 判断构建者是否在允许列表中。
func (p Policy) allows(builder string) bool {
	for _, b := range p.AllowedBuilders {
		if b == builder {
			return true
		}
	}
	return false
}

// Violations 返回制品包违反本策略的条款列表（为空表示满足策略）。
// 判定只依赖策略内容与输入，与并发顺序无关。
func (p Policy) Violations(b artifact.Bundle) []string {
	var out []string
	if p.MinChainLength > 0 && len(b.Provenance.Links) < p.MinChainLength {
		out = append(out, fmt.Sprintf("溯源链长度 %d 小于策略要求 %d",
			len(b.Provenance.Links), p.MinChainLength))
	}
	for _, l := range b.Provenance.Links {
		if len(p.AllowedBuilders) > 0 && !p.allows(l.Builder) {
			out = append(out, fmt.Sprintf("构建者 %q 不在允许列表中", l.Builder))
		}
	}
	for _, banned := range p.BannedComponents {
		if b.SBOM.Contains(banned) {
			out = append(out, fmt.Sprintf("成分 %q 被策略禁止", banned))
		}
	}
	return out
}

// Store 保存策略历史并跟踪当前生效版本。
type Store struct {
	mu       sync.RWMutex
	versions map[int]Policy
	current  int
}

// NewStore 创建空策略存储。
func NewStore() *Store {
	return &Store{versions: make(map[int]Policy)}
}

// Commit 以新版本号提交策略并使其生效，返回生效版本。
// 版本号必须严格递增，保证历史顺序可追溯。
func (s *Store) Commit(p Policy) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.current + 1
	if p.Version != 0 && p.Version != next {
		return Policy{}, fmt.Errorf("policy: 版本号必须递增为 %d，得到 %d", next, p.Version)
	}
	p.Version = next
	s.versions[next] = p
	s.current = next
	return p, nil
}

// Current 返回当前生效策略。
func (s *Store) Current() Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.versions[s.current]
}

// Get 按版本号返回历史策略（不移动生效指针、不修改任何状态）。
// ok 为 false 表示该版本从未存在（可能已从存档中缺失）。
// 供历史批次复核按报告记录的版本复算使用。
func (s *Store) Get(version int) (Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.versions[version]
	return p, ok
}

// CurrentVersion 返回当前生效版本号。
func (s *Store) CurrentVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Rollback 将生效版本回滚到指定历史版本，返回回滚后的生效策略。
// 历史版本不被修改，因此回滚后对同一输入可复现该版本的结论。
func (s *Store) Rollback(version int) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.versions[version]
	if !ok {
		return Policy{}, fmt.Errorf("%w: v%d", ErrVersionNotFound, version)
	}
	s.current = version
	return p, nil
}

// Versions 按版本号升序列出全部历史版本。
func (s *Store) Versions() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]int, 0, len(s.versions))
	for v := range s.versions {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}
