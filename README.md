# artifact-admission-gate-go

本地的制品准入校验流程：用本地内容模拟已签名的构建制品、溯源声明（provenance）与软件成分信息（SBOM），给出**可指导排障的细粒度失败分诊**、**可离线保存与跨策略版本复核的历史批次报告**，以及在上万条混合输入下结论稳定的并发批量校验。仅依赖 Go 标准库，全部流程离线可复现，不依赖外部服务或真实凭据。

## 一、失败分诊类别（稳定、可机读、互相不混淆）

判定顺序固定，先到先返，因此类别互斥。类别字符串（`verdict.Reason`）是对外契约：同一份输入无论何时、何种并发顺序、在哪个进程校验，类别与依据都一致。

| 顺序 | 类别（JSON 取值） | 含义 | 什么时候命中 | 排障指向 |
|---|---|---|---|---|
| 0 | `invalid_input` | 空/无效输入 | 制品名、内容、签名、溯源、SBOM 全空的零值条目 | 上游没传东西，先查调用方 |
| 1 | `missing_signature` | 根本没提供签名材料 | `Signature` 为 nil 或签名值为空 | 补签名流程是否执行 |
| 2 | `untrusted_signature` | **签名本身不可信** | 密钥标识不在信任列表、缺少密钥标识、签名值与密钥/所声明摘要对不上 | 查用错密钥还是签名值损坏/伪造 |
| 3 | `tampered_content` | **签名有效但内容在签名后被改** | 可信密钥且签名值与"所声明摘要"一致，但该摘要与制品当前内容不一致 | 签名之后制品被人动过，查交付链篡改 |
| 4 | `incomplete_provenance` | **溯源缺失/截断/缺环节/封存不完整** | 溯源链为空；环序号严格递增但不从 1 开始或中间有缺口（被截去首环、抽掉中间环节）；封存值缺失或与"起点+末环+总数"对不上（尾部被截、未完整封存） | 溯源材料没传全或被截断，补齐完整声明 |
| 5 | `broken_provenance` | 溯源链结构断裂 | 环序号出现回退/重复（换序、重复拼装）；环哈希不连贯（环节内容被改、环被伪造） | 溯源声明被伪造、换序或重新拼装 |
| 6 | `policy_violation` | 不满足（指定版本的）策略 | 链长不足、构建者不在允许列表、含被禁成分 | 对照命中策略版本的具体条款 |
| — | `allowed` | 放行 | 以上全部通过 | — |

> “内容被改过”（`tampered_content`）与“签名本身不可信”（`untrusted_signature`）是**两个不同类别**。实现上采用分离式签名：签名值只覆盖“所声明的制品摘要”。验签先证明签名值确由可信密钥对该摘要签发（否则为不可信），再比对摘要与当前内容（不一致即为内容被改）。
>
> “溯源不完整”与“溯源断裂”也是**两个不同类别**，判定边界如下（按固定顺序检查，先到先返）：
>
> 1. **空链** → 不完整；
> 2. **环序号单调性**：序号序列出现回退或重复（换序、重复环、重新拼装）→ 断裂。必须先整序列确认单调，否则"前两环互换"(2,1,3) 会被误判成缺环；
> 3. **环序号连续性**：序号严格递增但不从 1 开始、或中间有缺口（截去首环、抽掉中间环节）→ 不完整。缺环与换序的关键区别：缺环时剩余序号仍是严格递增的子序列，换序时必然出现回退；
> 4. **环哈希**：序号连续但某环哈希对不上（环节内容被改、环被伪造）→ 断裂；
> 5. **封存值（Seal）**：缺失或与"起点摘要+末环哈希+环节总数"对不上（尾部被截、未完整封存）→ 不完整。被截断的链其前缀哈希依旧连贯，必须靠封存值识别。
>
> 一句话：**"没给全"（截断、缺环节、封存不完整）落 `incomplete_provenance`；"被改过"（伪造、换序、改环节内容、重新拼装）落 `broken_provenance`**。

在到达策略评估前被拒（0–5 类）时，结论中的 `PolicyVersion=0`。

## 二、历史批次报告与复核（离线、只读）

### 批次报告

`Gate.AdmitBatchReport` 在批量准入结束时返回一份 `report.BatchReport`，可 `JSON()` 离线保存、`report.ParseJSON` 重新加载。报告记录：

- 确定性批次 `ID`：由“整批策略版本 + 每条输入的规范化 JSON”哈希得到，**不含时间**，同输入同版本任意时间/进程 ID 相同；输入顺序变化则 ID 不同。
- 每条制品的：批内下标、当时完整输入（含内容、签名、溯源、SBOM）、命中策略版本、放行结论、分诊类别、判定依据。
- 每条准入审计记录都带 `ReportID` 与 `EntryIndex`，可从审计精确回溯到报告中的具体条目。

### 复核（Replay）

`Gate.ReviewBatch`（`auditor` 权限）对历史报告做**严格只读**复算：不移动生效策略指针、不改制品状态、**不写任何审计记录**（连越权也只在鉴权层拒绝）。每条记录同时给出两份结论，各自标明策略版本、绝不合并：

- `historical`：当时结论的复现，分两种情形——
  - **策略评估前就被拒的条目**（`invalid_input` / `missing_signature` / `untrusted_signature` / `tampered_content` / `incomplete_provenance` / `broken_provenance`）：当时的结论与类别由签名/溯源/输入校验决定，**与策略版本无关**（记录中 `policy_version` 为 0）。复核**按报告记录原样复现**其结论与类别，`history_status=not_applicable`，复现结论的版本统一标 0，**绝不误报历史版本缺失**；
  - **到达策略评估的条目**（`allowed` / `policy_violation`）：用报告记录的历史策略版本复算，`history_status=available`；只有这类条目引用的版本**从未存在过**时，才是真的历史版本缺失（`history_status=version_missing`）；
- `current`：用**当前生效策略版本**复算；
- `diverged`：两份结论的“放行结果 + 分诊类别”是否不同（版本号不同不算分歧），差异写入可读 `note`。

兼容范围与边界行为：

| 场景 | 行为 |
|---|---|
| 跨策略版本复核（策略已演进） | 历史结论按旧版本复现，当前结论按新版本给出，`diverged=true` 时分列差异 |
| 策略回滚后复核 | 历史与当前版本一致时 `diverged=false`，历史结论仍可复现 |
| 报告含签名/溯源阶段就被拒的条目 | 按记录原样复现历史结论与类别，`history_status=not_applicable`，与策略版本无关（见 `TestReviewPrePolicyRejectionsReproduced`） |
| 同一份报告反复复核 / 并发复核 / 条目乱序 | 完全幂等：结果一致、零副作用（见 `TestReviewReadOnlyAndIdempotent`、`TestReviewConcurrentRepeatAndShuffleStable`） |
| 报告引用的策略版本现已不存在 | 仅到达过策略评估的条目才可能命中：该条 `historical=null`、`history_status=version_missing`，`current` 照常给出；整批**不报错、不静默**，附明确说明（见 `TestReviewMissingVersion`、`TestReviewMixedMissingVersionStable`） |
| 报告 JSON 损坏/被截断 | `ParseJSON` 返回明确错误；条目下标不连续也会报错，不接受残缺报告 |
| 空批次 | 返回空切片与一份 0 条目的报告，不报错 |

## 三、规模与并发语义

- 批量校验对生效策略**整批快照一次**，判定期间发生提交/回滚不影响本批结论。
- 有界工作池（默认并发上限 64），goroutine 数量不随批次规模膨胀；每个输入恰好处理一次，结果按下标写回，因此**结论与输入顺序、打乱方式、并发度无关，不漏条、不重复计数**。
- 实测参考（`go test -run TestLargeBatchStable -v`）：10000 条七类混合输入约 300ms、堆增量数十 MB，4 轮不同种子打乱结论全部随输入一致。
- 重复输入按条目分别计数；审计按 `ReportID + EntryIndex` 精确一一对应。
- 空输入（零值 Bundle）稳定落 `invalid_input`，不会 panic 或被静默丢弃。

## 四、策略版本与回滚语义

- 策略通过 `CommitPolicy` 提交，版本号严格递增，任一时刻只有一个生效版本；历史版本不可变。
- `RollbackPolicy(v)` 只移动生效指针，不修改历史；`Store.Get(v)` 支持按版本只读读取，供复核复算。

## 五、角色权限边界（最小权限）

| 角色 | 权限 |
|---|---|
| `admin` | 提交策略版本、回滚策略 |
| `releaser` | 执行制品准入校验（单个/批量、生成报告） |
| `auditor` | 读取审计日志、**只读复核历史批次**（`review`） |

越权请求返回 `authz.ErrUnauthorized`，只追加一条 `access_denied` 审计，不改变任何状态。复核路径本身不写审计，因此重复复核不会污染日志。

## 六、本地验证方法

```bash
# 全部测试（含竞态检测）
go test -race -count=1 ./...

# 仅分诊粒度用例（内容篡改 / 签名不可信 / 溯源截断、缺环、换序等互相区分）
go test -v ./internal/artifact/ -run Triage
go test -v ./internal/gate/    -run TestTriage

# 历史复核 / 跨版本分列 / 策略前拒绝复现 / 版本缺失 / 只读幂等 / 并发乱序一致
go test -v ./internal/gate/    -run 'TestBatchReport|TestReview'

# 上万条并发与边界稳定性
go test -v ./internal/gate/    -run 'TestLargeBatch|TestDuplicates'

# 端到端演示：七类分诊、离线报告、演进后双版本复核、版本缺失、越权、审计
go run ./cmd/gate
```

`-v` 日志中每条用例都打印：覆盖的业务类别、输入故障手法、命中的策略版本、分诊类别与判定依据。

## 七、目录结构

```
internal/verdict   # 分诊类别 Reason 与 Decision（叶子包，供 gate/report 共用）
internal/artifact  # 制品、分离式签名（HMAC 模拟）、带环序号与封存值的溯源哈希链、SBOM
internal/policy    # 版本化策略存储：提交、生效、回滚、按版本只读
internal/report    # 离线批次报告：JSON 序列化/校验、只读复核（历史/当前分列）
internal/audit     # 追加式有序审计日志（带批次 ID 与批内下标）
internal/authz     # 角色-权限映射与越权判定（含 review 权限）
internal/gate      # 准入编排：鉴权 → 分诊 → 策略 → 审计；有界并发批量与复核入口
cmd/gate           # 本地演示入口
```
