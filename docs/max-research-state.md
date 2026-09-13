# Max Research State 与 checkpoint 契约

## 1. 事实源与视图

| 层 | MR-0 角色 | 是否事实源 |
| --- | --- | --- |
| Canonical Object | stable identity、project、kind、payload | 是 |
| Object Version | append-only revision、version_id、predecessor | 是 |
| Canonical Relation | 同 project 的有向关系 | 是 |
| ResearchState.objects/relations | 已排序的输入集合 | 是输入，不是额外副本 |
| `latest_by_id` | 每个 identity 的最新版本 | 否，materialized view |
| `active_leading_hypothesis_id` | 从 object payload 推导 | 否，materialized view |
| `state_hash` | 规范化 graph digest | 否，materialized view |
| Working summary | 人类/Agent 导航文本 | 否 |
| Report projection | 当前 State 的版本化输出 | 否 |

任何视图丢失后都应能从 canonical objects、versions、relations 重建。视图
不能反向成为 Claim 或 Evidence 的来源。

## 2. Object 与 relation 不变量

每个 object 必须有 `mr1:<kind>:<opaque-id>` stable ID、合法 project ID、正的
version、version ID 和 payload。后续版本必须指向紧邻前版本；禁止 gap、同版本
重复、self supersedes 和跨项目 object。

Relation 具备 source、target、relation kind 和 project。source/target 必须是
当前 graph 中的 stable identity 或 version ID；关系 project 必须与两端 object
相同。默认不支持跨项目关系。

Formal Claim 的 evidence trace 由 validator 逐边检查：

```text
claim relation/payload
  -> Evidence Link
  -> Evidence / verified_evidence_id
  -> Passage / passage_id
  -> Document Version / source version + content hash
```

没有这条链时，Claim 是 orphan 或 incomplete，不能被 Research State 接受为
可报告结论。

## 3. Snapshot/rebuild 算法

`rebuild_research_state(objects, relations, project_id, run_id)` 执行以下确定性
步骤：

1. 校验所有 object、relation、project binding 和 ID grammar；
2. 按 stable identity 分组，检查版本连续性和 predecessor；
3. 选出每个 identity 的最新版本；
4. 检查所有关系端点存在且不跨项目；
5. 检查每个 Claim 的完整 evidence trace；
6. 检查 active leading hypothesis 至多一个；
7. 按 stable ID/version、relation ID 排序；
8. 对规范化 graph 计算 state hash，返回 materialized view。

该函数只操作传入值，不修改输入集合。重复运行、改变 mapping 插入顺序或
经过 100 轮 summary rehydration 都不能改变 canonical objects 或 state hash。

## 4. Working State 与 checkpoint

Working State 允许保存：

- project/run binding、iteration index；
- budget remaining；
- active leading hypothesis ID；
- Claim/Evidence/strategy/unresolved issue 的 canonical IDs；
- pending questions 和简短导航 summary。

Checkpoint 另外保存 schema/version、budget snapshot、iteration pointer、
canonical ID 集合和兼容既有系统的 predecessor/successor 信息。以下内容一律
禁止嵌入：

- 无 canonical ID 的正式 Claim 或 Evidence；
- 以 summary 文本继承的 Claim/Evidence payload；
- 用旧 summary 覆盖 canonical meaning/status 的指令；
- 跨项目 canonical reference。

`validate_checkpoint_lineage()` 保持 one-current、每个 predecessor 至多一个
successor、无孤立 successor、无环。空集合可以是“尚未开始”，非空集合必须
恰有一个 current。

## 5. Rehydration drift taxonomy

`rehydrate()` 首先校验 checkpoint，再重建 State，最后对工作 summary 和 prior
State 做只读比较：

| flag | 触发条件 |
| --- | --- |
| `summary_only_inheritance` | summary 嵌入 formal Claim/Evidence 或重定义 canonical IDs |
| `orphan_claim` | Claim 没有完整 evidence trace |
| `meaning_drift` | 同一 stable/version 的 payload/leading meaning 改变 |
| `status_drift` | status 在没有 successor 的情况下改变 |
| `missing_canonical_object` | checkpoint 引用的 object 无法恢复 |
| `cross_project_reference` | object、relation、summary reference 的 project 不一致 |
| `checkpoint_contract` | checkpoint schema/Working State 违反 MR-0 规则 |

恢复结果包含 `accepted`、重建 State、flags、issues 和 canonical IDs；不会写入
数据库，也不会自动修复历史 checkpoint。

## 6. MR-0A exact frontier and rehydration policy

The checkpoint frontier is an exact set. `WorkingState.canonical_object_ids`
must equal `Checkpoint.canonical_ids` as a set; Claim, Evidence, hypothesis,
strategy and unresolved-issue references must be members of that frontier.
Formal payloads are never copied into a checkpoint. A new object outside the
frontier is accepted only when its stable ID is explicitly listed in
`frontier_extension_ids`; otherwise rehydration emits
`unexpected_frontier_object`.

Checkpoint IDs are stable checkpoint IDs. A non-empty lineage is one monotonic
project/run chain: iterations strictly increase, every successor names the
immediately preceding checkpoint, numeric budget values never increase, there
is one current record, and there are no branches, orphan successors or cycles.

`RehydrationPolicy` requests review at the default twelve-iteration interval
and on `leading_hypothesis_changed`, `major_counterevidence`, `recovery`, or
`before_completion` triggers. `rehydrate()` compares every prior canonical
object/version and every prior relation, including objects not named by the
current checkpoint. Missing objects, same-version meaning/status changes,
version-chain changes, stale relations, summary meaning changes and
unapproved frontier extensions are all recorded; no missing prior entry is
silently skipped.

The MR-0A regression suite executes a real 100-round synthetic loop. Clean
rounds must reproduce the same state hash. Injected meaning/status drift,
relation deletion, frontier extension and leading-summary drift must be
rejected with deterministic flags. This loop is synthetic and does not touch
the pilot database, corpus, catalog or research outputs.
## MR-0B State and Authorization Bindings

Active and terminal Max Run states bind `current_state_hash` and retain the
completion state hash. Completion must recompute the supplied Research State
and match the Run State binding. A stale Completion Result, stale checkpoint
binding, mismatched Charter, budget, source policy, or model identity fails
closed.

Start approval consumption is an immutable `ApprovalConsumption` value. It
binds approval ID, project, run, Charter hash, prior and resulting Run State
versions, and timestamp. `transition_run_state` returns a
`RunTransitionResult(new_state, approval_consumption)` and never mutates the
frozen `StartApproval`. A read-only consumption ledger is required for an
approval transition; replaying the same approval ID, including after mapping
reconstruction or clearing `consumed_at`, is rejected.

`ResearchState` remains canonical and server-owned. Rehydration, checkpoint
lineage, version chains, relation endpoints, and source links are recomputed
from canonical objects and exact endpoint versions.
## MR-1 durable control state

The Max control database is separate from `research.db`. It stores the current
Research State hash, canonical frontier, working state, checkpoint pointer,
rehydration hashes, lease fencing token, and budget snapshot hash. Checkpoint
successors and iteration records are immutable and are advanced in
`BEGIN IMMEDIATE` transactions; each authoritative Run State version is also
bound to an immutable `RunTransitionResult`. Rehydration is rebuilt from canonical object
versions and exact relations; a working summary cannot substitute for the
canonical graph.

## MR-1A run-scoped recovery

The durable graph is additionally partitioned by `(project_id, run_id)`
membership. An object or relation is not visible to a run merely because it
shares a project, and membership is appended only by a validated canonical
change set. Each change set binds its input state hash, open iteration, lease
fencing token, exact endpoint versions, and server-resolved source references.
The graph, Research State successor, checkpoint successor, transition result,
and event are committed in one immediate transaction.

Iteration outcomes are immutable records rather than caller assertions. They
store exact input/output hashes, Claim/Evidence/counterevidence snapshots,
strategy ledger and typed artifact links. Recomputed completion history
requires contiguous completed rounds, actual attack/adjudication/rehydration
and cold-review artifacts, and two persisted stable rounds. Aborted rounds do
not count. A typed `UsageReceipt` is the only way a trusted authority can add
authoritative usage to the budget ledger; conflicting idempotency retries are
rejected.

Pause releases the active lease. Resume after a pause or expiry obtains a new
monotonic fencing token, and every state-changing write checks that token in
the same transaction. This makes crash recovery explicit while keeping
canonical state and working summary separate.

## MR-2A runner state boundary

The bounded runner persists a deterministic plan, model-call intent, dispatch
attempt history, authoritative result, recovery decision, canonical change
set, and iteration outcome against the exact input/output state hashes. The
begin row is immutable; completion is an appended outcome. Rehydration is
reconstructed from canonical objects, versions, relations, and source
references and never from a prior summary or role-discussion narrative.

Runner lease ownership and fencing are server facts. A stale worker cannot
write a result, checkpoint, canonical change, usage record, or outcome. MR-2A
does not persist completion or start a real model; the next approved phase
must supply any authoritative provider and completion workflow.

## MR-2A.1 authoritative runner and cognitive history

Runner working state is not an authority source. The authoritative sequence
is:

```text
canonical objects/versions/relations
        -> Research State hash and checkpoint
        -> persisted iteration outcome
        -> deterministic next-round plan
        -> metadata-only intent manifest
        -> isolated role result and authoritative usage receipt
```

Every `run-next` invocation first claims a server-owned, TTL-bounded mutex
with the current lease fencing token. The claim is append-only and released
even when pause releases the underlying lease. Concurrent claims therefore
produce at most one dispatch; expiry permits a later owner to acquire a new
fence.

An adjudication iteration has separate lead and rival role packets and
separate call records. The server combines only their typed, independently
persisted outputs into a `DiscussionSession`; role packets never see the
other role's output. The session carries a cross-examination and validity
audit and is validated against the exact pre-iteration Research State.

Rehydration is a repository operation, not a model artifact. It rebuilds from
canonical graph membership, exact versions and relations, and the current
checkpoint before dispatch. A missing object, version/relation drift, or
working-summary meaning drift pauses the run. A model cannot assert an
accepted rehydration result. Likewise, supporting evidence is included in
counterevidence snapshots only when an exact `counters` relation exists.

The planner's round choice is derived from immutable `max_iteration_outcomes`
and server policy triggers. A single completion payload cannot manufacture
stable rounds, attack history, adjudication, rehydration, or saturation
facts. The MR-2A.1 fixture loop is synthetic and does not touch the pilot
database, corpus, catalog, or research results.

## MR-2A.2 state and authority lineage

An adjudication iteration is a single historical outcome with five logical
call records. The two position calls bind only the canonical frontier; the
cross-examination, response, and adjudicator calls bind exact normalized
public predecessors. Their result IDs, usage receipts, artifact bindings,
and request/intent hashes are all retained separately. The aggregate
DiscussionSession is a projection of those typed facts, never a replacement
for them.

Working summaries remain navigational state. Rehydration and conflict review
use canonical object/version/relation hashes and the exact Research State hash;
summary-to-summary inheritance cannot create a new authoritative state. A
verified provider receipt charges one logical call once, while the service
adds one iteration-count charge for the terminal iteration. A failed call with
no verified receipt releases its unused reservation; a known-call receipt
dispute pauses with the reservation retained.

The immutable `EpistemicConflictRecord` binds a logical call, request and
proposal hashes, validator hash, canonical state/version hashes, issue codes,
and a semantic fingerprint. Repeated fingerprints deterministically progress
from rejection to rehydration-required and then pause; the record contains no
mentalistic or model-self-authorizing fields.

## MR-2B0 provider and scheduler state

The core research DB remains schema 5. MR-2B0R2's independent control DB is
schema 8 and stores only provider/grant/usage metadata plus scheduler state
and hashes. The canonical graph, working state, source references, and
rehydration rules remain separate: scheduler pointers never replace
canonical objects or exact relation/version bindings.

Provider calls are bound to one immutable profile/model and one hermetic
transport response. Server pricing produces a ProviderUsageAttestation before
the existing receipt and budget ledger are settled. A one-time admin grant
and the run lease/fencing token are required for a tick. Sessions and ticks
are append-only, while the current pointer records the authoritative state
hash, next action, and stop reason. Reusing a consumed grant during an
expired-lease handoff is allowed; stale workers cannot write.

MR-2B0's finite scheduler has no hidden loop and no model/network default. A
48-tick hermetic fixture crosses the frozen exploration, acquisition review,
adjudication, attack, and four rehydration boundaries. It remains a test of
recoverable control state, not a real research run or completion decision.

## MR-2B1A live authority and permit state

The independent schema 9/10 control state keeps live-network authority separate
from canonical research state and from the working summary. An authorization
is a hash-bound capability, not a model assertion: its exact run/project,
charter, profile/model, endpoint/network policy, budget/pricing, caps, expiry,
and administrator are stored as server-owned metadata. Its one-time
consumption and current pointer are advanced atomically with a lease fence.

The per-authorization access-event chain and attempt audit are immutable. A
rehydrated or restarted worker must present the same binding and a non-stale
fencing token; it cannot recreate authority from a summary or replay a used
record. Schema 10 adds a server-owned `LiveDispatchPermit` that binds one
claim and physical attempt to one request and one worker fence. Its current
projection and event chain are verified separately; durable settled replay
does not consume new authority, and send-started recovery is `unknown` rather
than an automatic retry. Read-only preflight does not change the state or
touch DNS, credentials, or the network. MR-2B1A is an offline/control-plane
acceptance only and does not send a real provider request.
