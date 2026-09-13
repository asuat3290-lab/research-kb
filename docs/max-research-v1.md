# Max Research v1：MR-0 协议冻结

状态：MR-0 已冻结，本文只描述纯契约和确定性校验。MR-0 不启动 Max
runner，不创建数据库表，不执行迁移，不调用模型，不联网，也不改变现有
research-kb MCP 工具。

## 1. 设计边界

Max Research 是一个固定模型在多个 bounded iteration 中反复从持久化
Research State 和 canonical evidence 恢复工作的协议。长对话摘要不是
状态源；Research State 必须能从 canonical objects、版本和 relations
确定性重建。报告只是 Research State 的版本化投影。

MR-0 只提供 `research_kb.max_research` 下的纯 Python 值模型、规范化 hash、
stable ID grammar、状态机和 validator。模块不导入 SQLite、MCP、网络库、
模型 SDK 或项目运行时配置。

以下边界不可被 MR-0 改写：

- 主研究运行由一个冻结的 `model_identity` 完成；多模型只是未来审计选项。
- 研究者侧 MCP 仍严格是现有 12 个工具，Max 不通过注册第 13 个工具实现。
- Document、Passage、Evidence、Citation、Research Item 等既有对象优先复用。
- Source 文本是不可信数据，不能改变协议或系统指令。
- Agent 不能自动批准启动、预算扩展、evidence、report 或最终成果。
- token、密钥、绝对路径、源文全文和研究正文不进入默认日志或错误 envelope。

## 2. Charter、hash 与启动批准

`MaxResearchCharter` 的必需字段为：

`question`、`scope`、`invariants`、`non_goals`、`deliverables`、
`model_identity`、`budget`、`source_policy`、`quality_gates`。

Charter hash 先对完整契约值做以下规范化，再计算不带前缀的 64 位小写
SHA-256：

1. dataclass、Enum 和 mapping 转换为 JSON 值；
2. mapping key 排序；
3. 字符串做 Unicode NFC；
4. list 保持顺序，set 做稳定排序；
5. JSON 使用 UTF-8、无空白、`ensure_ascii=False`、禁止 NaN/Infinity。

因此 mapping 插入顺序不影响 hash，任何语义字段变化都会改变 hash。

`StartApproval` 必须同时绑定 `run_id`、`project_id`、`charter_hash`、
`model_identity`、完整 `budget` 和 `source_policy_hash`，并包含明确的
`decision=approved`、批准人和批准时间。过期、已消费、重放或任一绑定值不
一致时必须 fail closed。

`MaxRunState` 的启动路径只有：

```text
AWAITING_START_APPROVAL -> APPROVED -> RUNNING
```

没有匹配批准时，不能进入 `APPROVED` 或 `RUNNING`。运行后的暂停、失败、
取消和完成均是显式状态转换；终态不可继续转换。model identity、budget、
source policy 或 charter hash 变化会使旧批准失效。

## 3. Canonical object 与既有系统的映射

MR-0 的 ID 形式为 `mr1:<kind>:<opaque-id>`。`opaque-id` 复用服务拥有的
稳定 ID，不使用路径、标题或摘要。project scope 单独存储在 object/relation
上，所有 relation 必须同 project；没有显式跨项目 relation，跨项目引用一律
拒绝。

| Max kind | 现有稳定对象/字段 | 说明 |
| --- | --- | --- |
| Source / Document | `documents.document_id` | Source 是研究角色视角，Document 是完整来源身份 |
| Document Version | `documents.document_id` + `source_version`/`content_hash` | 版本身份不能由文件名推断 |
| Passage | `passages.passage_id` | 必须仍能回到 Document Version |
| Quote | quote verification event 的稳定事件 ID + quote hash | Quote 不是自由文本 ID |
| Evidence | `verified_evidence.verified_evidence_id` | candidate evidence 与 accepted evidence 分开 |
| Evidence Link | `research_item_evidence_links.link_id` 或等价 version link | 连接 Claim 与 Evidence |
| Claim / Hypothesis / Objection | `research_items.item_id` + `research_item_versions.version_id` | 版本追加写，不静默覆盖 |
| Research Question / Decision / Report | `research_items.item_id` + version | 不创建第二套事实表 |
| Citation | 服务返回的 citation identity / version link | citation metadata 仍由 server owning |
| Source Role | Document/Version stable ID 上的 Max relation | 角色、证据功能和完整性分开 |

表中未出现的 Max 对象（Iteration、Discussion Session、Acquisition Request、
Speculative Idea、Completion Gate 等）是 MR-0 的纯契约对象，不写入真实 pilot。

正式 Claim 的最小可追溯链为：

```text
Claim -> Evidence Link -> Evidence -> Passage -> Document Version
```

只继承 summary 的 Claim、没有 canonical evidence 的 Claim、或跳过 Passage
和 Document Version 的 Claim 均不能进入 formal report projection。

## 4. Research State 与 checkpoint

Canonical objects、object versions 和 relations 是事实源。`ResearchState`
中的 `latest_by_id`、`active_leading_hypothesis_id` 和 `state_hash` 是
materialized view，必须可以由 `rebuild_research_state()` 重算；它们不是
独立事实源。

对象版本规则：版本从 1 连续递增；版本 1 没有 predecessor；后续版本必须
`supersedes_version_id` 指向紧邻的上一版本。同一 stable identity + version
不能用新 payload 覆盖。状态变化采用 successor/version 或事件，不采用静默
更新。

Max checkpoint 只携带 Working State、budget snapshot、iteration pointer、
canonical IDs、运行/项目绑定和兼容现有生命周期的 `supersedes_item_id`。
它不能嵌入 formal Claim/Evidence payload。标准 checkpoint 仍保持 one-current
与 successor 不变量；legacy note 不能由 MR-0 自动转换。

## 5. Rehydration、讨论与收敛

每轮恢复都重新校验 checkpoint、canonical graph 和 evidence trace。working
summary 只能提供导航信息，不能新增 canonical membership、Claim、Evidence、
meaning 或 status。validator 明确标记：summary-only inheritance、orphan
claim、meaning drift、status drift、missing object 和 cross-project reference。

Iteration kind 冻结为：

`socratic_exploration`、`targeted_retrieval`、`acquisition_request`、
`adversarial_attack`、`habermasian_adjudication`、`rehydration_review`、
`state_update`、`synthesis`、`cold_review`。

Discussion Session 保存独立立场、交叉质询、修正立场、validity audit、
adjudication 和 minority report。裁决值冻结为：

`reasoned_consensus`、`qualified_consensus`、`reasoned_dissensus`、
`underdetermined`、`rejected`。reasoned dissensus 必须保留 minority report；
裁决必须有 rival、canonical evidence 和 rationale。

Evidence saturation、search-strategy saturation、claim stability 是三个
独立布尔结果。相同 family/query/targets/filters 的重复策略只记录为 duplicate，
不能产生新的 strategy saturation。

Acquisition Request 以 information gain 和可证伪性为中心，必须说明
`research_gap`、target IDs、`why_needed`、`expected_information_gain`、
`possible_falsification`、desired source role、偏好与排除条件、
`max_candidates`。它是请求契约，不是联网执行器。

Speculative Idea 的合法生命周期为：

```text
speculative -> candidate -> supported | weakened | rejected
```

speculative 不能直接成为 supported Claim，也不能直接成为正式报告中心结论。

## 6. Completion Gate 与 report projection

Completion Gate 需要共同满足 attack、adjudication、rehydration、citation
traceability、无 Critical/Major 未决项、cold review、budget、source policy、
model identity 和 required strategy families。存在 active leading hypothesis
时，未达到最少 adversarial attack 次数必须失败。

Report projection 只能选择当前 Research State 中已存在且可追溯的 Claim ID，
并携带 state hash、Evidence IDs 和 source links。projection 不得制造 state 中
没有的新 Claim；projection 校验失败时不生成正式报告。

## 7. 明确留给 MR-1 的内容

MR-1 才能讨论 Max Run 持久化表/事件、iteration runner、scheduler、acquisition
provider、真实模型 adapter、持久化 coverage ledger、cold-context 服务和
新的运行期权限。MR-0 不创建 migration，不改变 12 个 MCP schema，不创建默认
Max Run，也不向真实 pilot 写入测试记录。

## 8. MR-0A contract invariant freeze

MR-0A is a repair of the pure contract boundary. It does not add a runner,
scheduler, model call, network access, database write, migration, MCP tool, or
research result. Mapping constructors are fail-closed: required fields must be
present and unknown fields are rejected. Contract values recursively freeze
mapping/list inputs before they participate in a hash or authorization decision.

Stable IDs have declared namespaces. Global source/document identities remain
distinct from project-local identities. A canonical object version ID is a
deterministic function of `(project_id, stable_id, kind, version)`, and a
relation ID is a deterministic function of `(project_id, source_id,
target_id, relation, source_version_id, target_version_id)`. Request IDs,
speculative-idea IDs, checkpoint IDs, role-packet IDs and completion IDs include
their complete semantic boundary; a project-only fallback is invalid.

The start approval record must explicitly contain `approval_id`, `decision`,
`approved_by`, `approved_at`, and `decision_authority=human`, in addition to
run, project, charter, model, budget and source-policy bindings. The only
approval-consuming transition is `AWAITING_START_APPROVAL -> APPROVED`.
Consumption is recorded once. `APPROVED -> RUNNING` and
`PAUSED -> RUNNING` resume from the consumed state and do not consume or request
the approval again. `COMPLETED` requires a recomputed, passing CompletionResult.

Formal Claim evidence is relation-only and version-bound:

```text
Claim --has_evidence_link--> Evidence Link
      --links_evidence-----> Evidence
      --derived_from--------> Passage
      --located_in----------> Document Version
```

Direct claim `evidence_ids` are rejected. Candidate/unverified evidence cannot
qualify a final claim. Report and cold-review source links are recomputed from
the current Research State and must match exactly; fabricated, missing,
cross-project, or summary-derived links fail closed. Completion booleans are
observations only: the gate must be recomputed from bound state, attack
records, adjudication records, accepted rehydration, a cold-review packet,
source policy and formal completion evidence.

All of these changes remain pure Python contract code, tests and the four
Max-Research documents. MR-0A stops after validation and waits for human
approval before MR-1.
## MR-0B Contract Closure

MR-0B keeps the MR-0A pure value-model boundary and closes the remaining
completion and authorization bypasses. Completion is evaluated only from a
typed `CompletionEvaluationInput`. A `CompletionGateResult` and
`CompletionResult` are deterministic projections of that input; a caller
supplied `passed=true`, empty hash, or self-consistent attacker state is not
completion evidence.

The evaluation input binds the Charter, Run State, canonical Research State,
typed Attack Records, state-bound Discussion Sessions, rehydration result,
final Report Projection, Cold Review Packet and Cold Review Result, typed
Claim/Evidence snapshots, budget snapshot, source-policy snapshot, and model
identity. The evaluator recomputes the input hash, all four saturation
dimensions, the gate hash, and the result ID. Validators compare the complete
recomputed value rather than trusting individual booleans.

Evidence status is a closed eligibility vocabulary. Missing status is
`unknown`, never `verified`. Final reports require explicit final claims and
verified/accepted/exact-quote-verified evidence with canonical verification
records and source-version bindings. Provisional evidence belongs in a
provisional or limitations projection and cannot enter final claims.
## MR-1 persistence boundary

MR-1 persists the MR-0B contract in an independent Max control SQLite
database with its own schema version (1, advanced to 2 by MR-1A, 3 by MR-2A,
and 4 by MR-2A.1). The existing core research database
and core migrations 001-005 remain unchanged. The control plane stores stable
source references, not source text, PDF bytes, or copied citation metadata.

Approval consumption, event hash chains, leases/fencing, budget ledger,
canonical versions, checkpoint lineage, and iteration history are server-owned
and append-oriented. Every authoritative Run State version has an immutable
`RunTransitionResult` binding in the control store. Completion is still
recomputed by the MR-0B pure gate;
MR-1 only persists a result after the historical iteration record proves the
required attack, adjudication, rehydration, and stability conditions.

## MR-1A persistence closure

MR-1A closes the first persistence-boundary audit findings. Canonical objects
and relations are scoped to an explicit run membership, and all graph changes
use an atomic, lease-fenced change set. A same-project run cannot observe or
mutate another run's canonical frontier. Source/version references are
resolved by the server and their normalized reference hash is recomputed.

The control migration `002_run_scoped_history.sql` adds run-scoped membership,
change-set, iteration-outcome, typed artifact, and usage-receipt records. A
schema-1 upgrade derives legacy membership only from immutable canonical events;
ambiguous or unbound histories fail closed. Iterations persist authoritative
input/output state hashes and exact snapshots, including a real S0-to-S1
transition. Completion history is rebuilt from persisted outcomes and typed
artifacts, not from a caller's boolean or payload.

Budget usage is accepted only through a server-verified `UsageReceipt`, and an
idempotency key is bound to the full request. Pausing releases the lease;
resuming after expiry acquires a higher fencing token. MR-1A still contains no
runner, model adapter, scheduler, network access, acquisition worker, or real
Max Run.

## MR-2A bounded runner kernel

MR-2A turns the approved persistence boundary into a recoverable, single-model
bounded runner without adding a thirteenth MCP tool. A deterministic planner
persists one plan and one model-call intent before dispatch; the adapter call
is outside the SQLite transaction; results, authoritative usage, canonical
change sets, and iteration outcomes are appended exactly once. Dispatch
attempt records distinguish pre-dispatch crashes from an external call whose
result is unknown.

Only an explicitly handed-off non-admin runner with the current lease and
fencing token may write runner records. The first dispatch acknowledgement is
immutable. A provider query or the same provider idempotency key may resolve
an unknown call; if neither safe primitive exists, recovery pauses the Run for
an administrator decision. Model proposals are strict and cannot assert
final, verified, approved, or completed state, source metadata, source text,
paths, or secrets.

Rehydration packets are built from canonical graph and source references and
exclude summaries and discussion history. MR-2A has no model provider, network
access, scheduler, daemon, acquisition worker, real run, or `max complete`
command. Completion remains an MR-0B evaluation and persistence concern for a
later approved phase.

## MR-2A.1 runner authority closure

MR-2A.1 is a bounded-runner correction round, not a new research phase. It
adds the independent Max migration `004_mr2a1_runner_closure.sql` and leaves
core schema 5, core migrations 001-005, Max migrations 001-003, and the exact
12 research MCP tools unchanged.

The runner has a strict production boundary. No fixture dependency is
installed by a service default; fixture simulation requires a newly marked
temporary control database and the explicit `max simulate-next --fixture`
command. Durable intent manifests contain only server IDs, hashes, plan
metadata, role/phase, and canonical frontier references. Prompts, raw model
responses, source text, citation metadata, secrets, tokens, and absolute
paths are rejected before persistence.

The authority chain is append-only and recoverable: invocation claims are
serialized by `BEGIN IMMEDIATE`, call groups bind each independent role call,
usage is accepted only from the configured authoritative verifier, and
`verify` includes runner plans, manifests, results, claims, recovery
consumptions, cognitive artifacts, and links. The deterministic planner reads
persisted iteration outcomes. Adjudication makes separate lead/rival calls;
rehydration rebuilds from canonical objects and exact relations before any
model call; and only exact counter relations create counterevidence.

MR-2A.1 does not add a provider, runner scheduler, network access, source
acquisition worker, completion command, or real Max Run. It stops and waits
for human approval before MR-2B.

## Current implementation boundary: MR-2A.2

The approved implementation has reached MR-2A.2. The independent Max control
database is schema 5; core schema 5 and core migrations 001-005 are unchanged.
MR-2A.2 closes the multi-call deliberation and per-call usage authority chain
with five persisted adjudication calls, exact provider receipts, immutable
result/usage/artifact bindings, deterministic conflict escalation, and strict
fixture creation semantics.

This stage still does not include a real provider, model adapter, scheduler,
network access, source acquisition worker, completion command, or real Max
Run. It does not add a thirteenth research MCP tool. The implementation stops
after MR-2A.2 and waits for human approval before MR-2B.

MR-2A.2R closes the nested-contract and terminal-recovery correction. Provider
payload validation is fail-closed at the runner trust boundary; a malformed
five-call adjudication is an audited aborted/paused envelope, never an escaped
Python validation exception. Public verification rejects terminal-ready open
groups without a live claim, while allowing a genuinely in-flight group with a
valid lease and fencing token. This correction adds no migration, provider,
network, scheduler, acquisition worker, or real Max Run and stops pending
human re-verification for MR-2B.

## Current implementation boundary: MR-2B0

MR-2B0R2 adds the independent Max control schema 8 migrations
`006_mr2b0_provider_scheduler.sql`, `007_mr2b0r_authority_budget_closure.sql`, and
`008_mr2b0r2_physical_dispatch_budget.sql`. Core research schema 5 and Max
migrations 001-005 remain byte-for-byte unchanged. Provider profiles,
pricing snapshots, run bindings, one-time execution grants, provider-call
records, usage attestations, scheduler sessions, durable ticks, and the
current foreground pointer are control-plane metadata only; they do not copy
the corpus, PDF, passage, or source text.

Only an injected hermetic transport is dispatchable. No API key, environment
secret, `.env` value, network socket, provider SDK, real model, or real Max
Run is used. The adapter recomputes server-priced usage and binds it to the
existing receipt/ledger chain. An explicit admin grant is required and is
consumed at most once; propose/approve/start do not self-grant.

MR-2B0R2 requires explicit provider token caps. Input plus cache-read and
output plus reasoning are checked as aggregate dimensions. Every physical
transport send is preceded by a durable dispatch-attempt slot, so recovery
cannot bypass the physical-call cap and settled idempotent calls replay
without sending. Character-to-token fallback is not execution authority;
legacy profiles fail closed at scheduler preflight.

The bounded scheduler is a foreground service: one call owns at most one
`run_next`, `run_bounded` is finite, and lease/fencing plus durable session,
tick, current-pointer, and stop-reason records make restart/handoff
auditable. A 48-tick hermetic fixture covers the frozen cognitive cycle and
four rehydrations with network and credential reads equal to zero. MR-2B0R2
does not include MR-2B1, MR-3, a daemon, acquisition worker, or real provider
execution, and stops pending human re-verification.

## MR-2B1A pre-live execution boundary

MR-2B1 added independent Max control schema 9 through migration 009. MR-2B1A
adds schema 10 through migration 010 while leaving core schema 5 and Max
migrations 001-009 unchanged. It persists
hash-only `LiveNetworkAuthorization` and its one-time consumption, event-chain,
and attempt facts. Authority is administrator-issued and bound to the exact
run, project, charter, provider/profile/model, endpoint/network policy,
pricing/budget, caps, expiry, and lease fence. A consumed StartApproval and
execution grant are required before use.

The default live factory is fail-closed and read-only preflight has no DNS,
credential, or network side effect. An injected HTTPS boundary is tested for
exact endpoint policy, DNS rebinding/SSRF, redirect, header, payload,
credential, expiry, replay, and cross-binding rejection. This phase has no
real API key, network connection, provider call, charge, or real Max Run; a
future real HTTPS phase requires separate explicit approval and a rollback
plan.

## Current implementation boundary: MR-2B2 and MR-3

The independent Max control database is schema 12. Schema 11 provides ordered
per-call live authority bundles and one human approval for the exact next
state-bound iteration. Schema 12 provides restartable foreground-worker
commands/heartbeats and a separately authorized acquisition staging chain.
All historical authority and receipts are append-only; current projections
are verified against their histories. The research MCP surface remains
exact-12 and core research schema remains 5.

The acquisition path ends at a server-generated, independently validated
dry-run ingest projection. It does not download, OCR, accept evidence, or call
core ingest. The live runner acceptance uses injected components and performs
no real DNS, credential read, HTTPS request, provider call, or charge. Because
provider wire input still forbids source bodies, passages, citations, and
local paths, the system is not yet claiming a useful real source-grounded Max
Run. That requires a separately reviewed source-egress gateway and a
human-approved bounded canary.
