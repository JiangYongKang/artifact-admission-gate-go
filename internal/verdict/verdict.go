// Package verdict 是准入分诊类别的叶子包，供 gate 与 report 共同引用，
// 避免 gate ↔ report 之间的包循环。
//
// 分诊类别（Reason）是对外契约：稳定、可机读、互相不混淆。
// 同一份输入无论何时、何种并发顺序、在哪个进程校验，
// 得到的 Reason 与依据 Detail 都必须一致。
package verdict

// Reason 是准入结论的分诊类别。
type Reason string

const (
	Allowed Reason = "allowed" // 放行

	InvalidInput         Reason = "invalid_input"         // 空输入/无效输入
	MissingSignature     Reason = "missing_signature"     // 根本没有提供签名材料
	UntrustedSignature   Reason = "untrusted_signature"   // 签名本身不可信（密钥/签名值不对）
	TamperedContent      Reason = "tampered_content"      // 签名有效但签名后内容被改动
	IncompleteProvenance Reason = "incomplete_provenance" // 溯源缺失或被截断
	BrokenProvenance     Reason = "broken_provenance"     // 溯源链结构断裂（换序/伪造/篡改）
	PolicyViolation      Reason = "policy_violation"      // 不满足生效策略
)

// Decision 是一次准入判定的结论。
type Decision struct {
	Artifact      string // 制品名
	Allowed       bool   // 是否放行
	Reason        Reason // 分诊类别
	Detail        string // 判定依据（人类可读，内容确定、可复现）
	PolicyVersion int    // 命中的策略版本；到达策略评估前被拒时为 0
}
