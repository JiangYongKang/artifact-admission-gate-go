# artifact-admission-gate-go

本地的制品准入校验流程：用本地内容模拟已签名的构建制品、溯源声明（provenance）与软件成分信息（SBOM），在不同签名状态、策略版本与角色权限下给出一致且可解释的放行结论。仅依赖 Go 标准库，全部流程离线可复现，不依赖外部服务或真实凭据。

## 失败分诊类别（稳定、可机读、互不混淆）

判定顺序固定为 **签名 → 溯源 → 策略**，任一环节失败即拒绝。类别（`gate.Reason`）是稳定字符串，同一份输入无论何时、以何种并发顺序、在哪个进程校验，类别与判定依据都一致：

| 类别 | 常量 | 什么时候命中 | 判定依据包含 |
|---|---|---|---|
| `allowed` | `ReasonAllowed` | 签名有效、溯源完整、满足生效策略 | 命中的策略版本 |
| `missing_signature` | `ReasonMissingSignature` | 根本没提供签名材料（签名为空/无签名值），包括空输入制品未签名 | — |
| `untrusted_signature` | `ReasonUntrustedSignature` | **签名本身不可信**：密钥 ID 未知、密钥不匹配，或签名值与密钥计算结果对不上 | 期望/实际密钥 ID |
| `tampered_content` | `ReasonTamperedContent` | **签名后制品内容被改过**：签名绑定的内容摘要与当前内容摘要不一致 | 签名绑定摘要 vs 当前摘要 |
| `incomplete_provenance` | `ReasonIncompleteProvenance` | 溯源**被截断或缺了声明的关键环节**：链为空、哈希仍连贯但声明的环节（`DeclaredStages`）未按顺序全部出现 | 缺失环节与实际环节列表 |
| `broken_provenance` | `ReasonBrokenProvenance` | 溯源**哈希链不连贯**：换序、哈希被改、链起点锚点与当前制品摘要不匹配 | 第几环、构建者/环节、链起点摘要 |
| `policy_violation` | `ReasonPolicyViolation` | 签名与溯源都过，但不满足生效策略（链长不足、构建者不在允许列表、含被禁成分） | 命中版本与具体违反条款 |

关键区分点：

- **`tampered_content` 与 `untrusted_signature` 是两类**。签名结构里记录了签名时绑定的内容摘要：摘要对不上 = 内容被动过；摘要一致但 HMAC 对不上（密钥或签名值问题）= 签名不可信。
- **`incomplete_provenance` 与 `broken_provenance` 是两类**。哈希链连贯但少了声明环节（干净的尾部截断、中间缺环后重新成链）→ 不完整；哈希链本身对不上（换序、篡改、锚点漂移）→ 断裂。
- 旧名 `ReasonInvalidSignature` / `artifact.ErrInvalidSignature` 保留为 `untrusted_signature` 的弃用别名，仅为向后兼容。

> 说明：`tampered_content` 优先于溯源判定——内容一旦被改，签名锚定的摘要先对不上，直接归到内容篡改，不会再落到溯源类别。

## 历史批次报告与复核（离线、只读）

### 批次报告 `gate.BatchReport`

每次批量准入（`AdmitBatchReport`）结束后得到一份可 JSON 序列化、可离线保存的报告：

- 批次标识 `ID`：由条目输入与策略版本**确定性派生**（无时间/随机量），同样的输入+版本得到同样的 ID；
- `PolicyVersion`：本批开始时对生效策略做一次快照，全批命中同一版本；
- 每条 `ItemReport`：下标、制品名、**完整输入**（内容/签名/溯源/SBOM）、输入稳定摘要 `InputDigest`、当时结论（放行/类别/依据/命中版本）；
- `AllowedCount` / `RejectedCount` 与条目一一对应，不漏条、不去重、不重复计数。

用 `MarshalReport` / `UnmarshalReport` 做离线 JSON 保存与恢复。

### 复核 / 重放 `Gate.Replay`

拿历史报告即可在之后（策略已演进甚至回滚过）重新复核，**全程只读**：不改现行策略、不改任何输入、**不写审计**。每条给出两份分列结论，各自带策略版本，绝不混成一条：

- `Historical`：报告记录的当时结论（原样保留）；
- `Replayed`：用报告记录的策略版本重算的结论；
- `Current`：用当前生效策略重算的结论；
- `Differs` / `DiffSummary`：历史与当前结论的放行结果或类别是否不同及差异说明。

`HistoricalStatus` 可机读：

| 状态 | 含义 |
|---|---|
| `reproduced` | 历史版本仍存在，重算结论与报告记录**完全一致**（类别+依据+版本） |
| `pre_policy` | 该条目在到达策略评估前就被拒（签名/溯源环节），版本为 0，与策略版本无关 |
| `history_version_missing` | 报告引用的策略版本当前已不存在，无法重算；历史结论原样保留，当前结论仍照常给出 |
| `history_replay_mismatch` | 版本存在但重算与记录不符（确定性下不应出现，出现即报告被破坏或判定逻辑变更） |

兼容范围与异常链路（均返回稳定、可解释的结果，不 panic、不静默吞掉）：

- **跨策略版本**：演进后历史条目复现历史结论，同时并列当前结论并标差异（见演示第 3 段）；回滚同理。
- **重复复核**：同一份报告反复复核，结果逐字节一致（`TestReplayReadOnlyAndIdempotent`），幂等且只读。
- **引用版本不存在**：历史结论保留并标 `history_version_missing`，当前版本结论照常计算（见演示第 5 段）。
- **空批次**：报告为空、可保存可复核，不写任何准入审计；越权仍被拒绝。
- **报告被篡改/截断**：条目计数不符或 `InputDigest` 与内嵌输入不一致时，返回 `ErrMalformedReport`，不拿被改输入静默重放。
- **当前无生效策略**：当前结论 `CurrentStatus` 标 `no_current_policy`（常量 `CurrentNoPolicy`），仅做签名与溯源判定；正常评估为 `evaluated`（常量 `CurrentEvaluated`）。

复核需要 `PermAdmit` 权限（`releaser`）；`auditor`/`admin` 复核会被拒绝并只追加一条 `access_denied`。

## 规模与边界语义

- 一次调用可并发处理上万条混合（合规/各类失败/重复）制品，使用**有界 worker 池**（默认不超过 CPU 数、封顶 32，可用 `BatchOptions.Workers` 指定，内部按批次规模收敛），并发数不随批次规模膨胀，内存与耗时可控。
- 结论只依赖输入与策略快照，**与输入顺序、打乱方式、并发度无关**：结果按下标写回，不漏条、不重排；每条制品都能对应到一条审计记录和一条报告记录（`TestLargeBatchOrderAndConcurrencyIndependent`，12000 条 × 并发度 1/2/16/64 零漂移）。
- 审计在 worker 内按完成顺序加锁追加，记录内容确定；批次报告不依赖审计写入顺序。
- 重复输入不去重：相同输入得到相同 `InputDigest` 与相同结论，但作为独立条目计数。
- 空输入制品（内容为空）有稳定摘要：签名/溯源齐全则放行，未签名则落 `missing_signature`，不会偶发报错。

## 策略版本与回滚语义

- 策略通过 `CommitPolicy` 提交，版本号严格递增，任一时刻只有一个生效版本。
- 历史版本不可变；`RollbackPolicy(v)` 只移动生效指针，不修改历史。因此回滚后对同一输入可复现该历史版本的结论。
- 单次判定/整批判定对生效策略做快照读取，判定过程中版本保持一致。

## 角色权限边界（最小权限）

| 角色 | 权限 |
|---|---|
| `admin` | 提交策略版本、回滚策略 |
| `releaser` | 执行制品准入校验（单个/批量）、历史批次复核 |
| `auditor` | 读取审计日志 |

越权请求返回 `authz.ErrUnauthorized`，只追加一条 `access_denied` 审计记录，不改变任何状态。

## 审计追溯

每次准入判定、策略提交、策略回滚、越权拒绝都会追加一条审计记录（`internal/audit`）。记录带单调递增的连续序号与时间戳，日志只追加不修改，并发写入由互斥锁保证顺序。**历史复核是只读操作，不写审计**。

## 本地验证方法

```bash
# 运行全部测试（含竞态检测）
go test -race -count=1 ./...

# 查看每条用例覆盖的业务类别、输入、命中策略版本与判定依据
go test -v ./internal/gate/

# 只看新增能力：分诊粒度 / 历史复核 / 大规模与边界
go test -v -run 'TestTriage' ./internal/gate/
go test -v -run 'TestReplay|TestBatchReport|TestReportJSON' ./internal/gate/
go test -v -run 'TestLargeBatch|TestEmptyBatch|TestEmptyContent' ./internal/gate/

# 端到端演示：全类别分诊、批次报告离线保存/恢复、策略演进后双结论复核、
# 引用版本缺失、重复复核只读、越权拒绝、审计输出
go run ./cmd/gate
```

## 目录结构

```
internal/artifact  # 制品、签名（HMAC+内容摘要绑定）、溯源哈希链与关键环节声明、SBOM
internal/policy    # 版本化策略存储：提交、生效、回滚、只读 Get(version)
internal/audit     # 追加式有序审计日志
internal/authz     # 角色-权限映射与越权判定
internal/gate      # 准入编排、细粒度分诊、批量有界并发、批次报告与只读复核
  gate.go          #   判定顺序、分诊类别映射、批量 worker 池、策略/审计入口
  report.go        #   BatchReport/ItemReport、离线 JSON、Replay 复核
  *_test.go        #   分诊/复核/规模边界用例（triage_test/replay_test/scale_test）
cmd/gate           # 本地演示入口
```
