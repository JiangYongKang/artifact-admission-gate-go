// Package audit 提供顺序可追溯的审计日志。
//
// 日志只追加、不修改；每条记录带单调递增的序号与时间戳，
// 并发写入由互斥锁保证顺序。
package audit

import (
	"sync"
	"time"
)

// EventType 区分审计事件类别。
type EventType string

const (
	EventAdmission     EventType = "admission"      // 制品准入判定
	EventPolicyCommit  EventType = "policy_commit"  // 策略版本提交
	EventPolicyRollback EventType = "policy_rollback" // 策略回滚
	EventAccessDenied  EventType = "access_denied"  // 越权请求被拒绝
)

// Record 表示一条审计记录。
type Record struct {
	Seq           int       // 单调递增序号
	Time          time.Time // 记录时间
	Type          EventType // 事件类别
	Actor         string    // 操作者
	Artifact      string    // 相关制品（策略事件为空）
	PolicyVersion int       // 命中/变更的策略版本
	Allowed       bool      // 是否放行/成功
	Reason        string    // 判定依据
}

// Logger 是追加式审计日志。
type Logger struct {
	mu      sync.Mutex
	records []Record
}

// NewLogger 创建空审计日志。
func NewLogger() *Logger { return &Logger{} }

// Append 追加一条记录并返回其序号。序号即写入顺序，可追溯。
func (l *Logger) Append(r Record) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Seq = len(l.records) + 1
	r.Time = time.Now()
	l.records = append(l.records, r)
	return r.Seq
}

// Records 返回全部记录的副本（按写入顺序）。
func (l *Logger) Records() []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Record, len(l.records))
	copy(out, l.records)
	return out
}
