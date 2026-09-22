# artifact-admission-gate-go

本地的制品准入校验流程：用本地内容模拟已签名的构建制品、溯源声明（provenance）与软件成分信息（SBOM），在不同签名状态、策略版本与角色权限下给出一致且可解释的放行结论。仅依赖 Go 标准库，全部流程离线可复现。

## 准入规则

判定顺序固定，任一环节失败即拒绝，原因互相可区分：

| 顺序 | 环节 | 拒绝原因（`gate.Reason`） | 说明 |
|---|---|---|---|
| 1 | 签名校验 | `missing_signature` | 签名缺失 |
| 1 | 签名校验 | `invalid_signature` | 签名无效或签名后内容被篡改（HMAC-SHA256 比对失败） |
| 2 | 溯源链校验 | `broken_provenance` | 溯源链为空、哈希不连贯、环节被换序或篡改 |
| 3 | 策略校验 | `policy_violation` | 不满足当前生效策略（链长不足、构建者不在允许列表、含被禁成分） |
| — | 全部通过 | `allowed` | 放行 |

- 签名以本地密钥的 HMAC-SHA256 模拟；溯源链以制品摘要为起点的哈希链模拟（`artifact.BuildProvenance` / `VerifyProvenance`）。
- 每次判定的结论 `gate.Decision` 包含：是否放行、分类原因、人类可读依据、命中的策略版本。`PolicyVersion=0` 表示判定在到达策略评估前已被拒绝（签名或溯源环节失败）。

## 策略版本与回滚语义

- 策略通过 `CommitPolicy` 提交，版本号严格递增，任一时刻只有一个生效版本。
- 历史版本不可变；`RollbackPolicy(v)` 只移动生效指针，不修改历史。因此回滚后对同一输入可复现该历史版本的结论（见 `TestPolicyRollbackReproduces`）。
- 单次判定对生效策略做快照读取，判定过程中版本保持一致；批量并发校验的结论只依赖输入与生效策略，与并发顺序无关（见 `TestConcurrentBatchDeterministic`，`-race` 通过）。

## 角色权限边界（最小权限）

| 角色 | 权限 |
|---|---|
| `admin` | 提交策略版本、回滚策略 |
| `releaser` | 执行制品准入校验（单个/批量） |
| `auditor` | 读取审计日志 |

越权请求返回 `authz.ErrUnauthorized`，只追加一条 `access_denied` 审计记录，不改变任何状态（生效策略、制品结论均不受影响，见 `TestRejectUnauthorized`）。

## 审计追溯

每次准入判定、策略提交、策略回滚、越权拒绝都会追加一条审计记录（`internal/audit`）。记录带单调递增的连续序号与时间戳，日志只追加不修改，并发写入由互斥锁保证顺序。

## 本地验证方法

```bash
# 运行全部测试（含竞态检测）
go test -race -count=1 ./...

# 查看判定日志（输入、命中的策略版本、判定依据）
go test -v ./internal/gate/

# 运行端到端演示：合规/篡改制品、越权拒绝、策略演进与回滚、审计输出
go run ./cmd/gate
```

## 目录结构

```
internal/artifact  # 制品、签名（HMAC 模拟）、溯源哈希链、SBOM
internal/policy    # 版本化策略存储：提交、生效、回滚
internal/audit     # 追加式有序审计日志
internal/authz     # 角色-权限映射与越权判定
internal/gate      # 准入编排：鉴权 → 签名 → 溯源 → 策略 → 审计
cmd/gate           # 本地演示入口
```
