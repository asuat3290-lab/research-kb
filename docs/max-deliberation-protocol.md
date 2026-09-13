# Max Research deliberation protocol

## 1. Bounded iteration

每个 iteration 是一个独立、可审计的纯记录，必须绑定 project、run、sequence、
冻结的 kind、输入/输出 canonical IDs 和状态。MR-0 冻结以下 kind：

1. `socratic_exploration`：生成问题、候选解释和需要验证的边界；
2. `targeted_retrieval`：在既定 source role 和策略范围内检索；
3. `acquisition_request`：提出有信息增益/可证伪目标的获取请求；
4. `adversarial_attack`：攻击 active leading hypothesis；
5. `habermasian_adjudication`：保存理由、证据和异议后的裁决；
6. `rehydration_review`：冷恢复并检查 summary drift；
7. `state_update`：以新版本/新关系更新 canonical graph；
8. `synthesis`：在已有 State 上形成候选综合；
9. `cold_review`：不依赖工作 summary 的最终检查。

MR-0 只定义输入输出契约，不定义如何调度或执行这些 iteration。

## 2. Discussion Session

Discussion Session 必须保存：

- 至少两个独立 role 的立场记录；
- role 之间的交叉质询与回答；
- 必要的 correction position；
- 至少一个 validity audit；
- adjudication 的 value、rationale、rival IDs 和 canonical evidence IDs；
- dissent 存在时的 minority report。

推荐的 role 分工是 `lead`、`rival`、`source_auditor`、`validity_auditor`、
`adjudicator`。role 是分析立场，不等同于系统权限，也不授权 Agent 批准。

## 3. Habermasian adjudication values

| value | 含义 | 额外要求 |
| --- | --- | --- |
| `reasoned_consensus` | 理由和证据支持的共识 | rival 不能被抹除 |
| `qualified_consensus` | 有明确限定条件的共识 | 限定条件进入 rationale |
| `reasoned_dissensus` | 理由充分的持续分歧 | 必须保存 minority report |
| `underdetermined` | 当前证据不足以裁决 | 不得投影为确定结论 |
| `rejected` | 目标主张被拒绝 | 保留拒绝理由和证据 |

没有 rival、canonical evidence 或 rationale 的 adjudication 不能通过 validator。

## 4. Attack 与 completion

存在 active leading hypothesis 时，Completion Gate 需要达到最小 attack 次数，
且 attack 结果进入 adjudication。只完成 Socratic exploration 或重复同一查询
不算 adversarial coverage。

Completion Gate 同时检查 rehydration、citation traceability、未决 Critical/Major、
cold review、预算、source policy、model identity 和 required strategy families。
任何一个 false 都是 fail closed。

## 5. Acquisition Request

Acquisition Request 是一个受控的“为什么还需要来源”声明，不是 downloader。它
必须说明：

`research_gap`、target IDs、`why_needed`、`expected_information_gain`、
`possible_falsification`、`desired_source_role`、preferred types/languages/date
range、exclusions、`max_candidates`。

若不能说明新信息如何可能削弱或证伪当前解释，则请求无效。MR-0 不执行请求，
MR-1 才能决定是否增加 provider、网络权限或持久化队列。

## 6. Speculation Space

Speculative Idea 与 formal Claim/Evidence 是两个命名空间。合法状态迁移为：

```text
speculative -> candidate -> supported | weakened | rejected
```

每次状态变化都应创建新版本；不允许 `speculative -> supported`，不允许用
summary 直接把 candidate 提升为 formal Claim，也不允许 speculative idea 成为
报告中心结论而没有 canonical evidence trace。

## 7. MR-0A role isolation and cold review

Every Discussion Session is bound to one `project_id`, `run_id`, Research State
hash, model identity and inference-profile hash. Each independent role receives
one `RolePacket` containing only its allowed canonical IDs. A packet must not
see another role's output; forbidden output IDs may not overlap the allowed
set. Packet bindings are checked against the session, so a copied position or
stale model context cannot be presented as an independent rival.

An adjudication requires distinct independent roles, real cross-examination,
canonical evidence and a rationale. `ValidityAudit` records all four explicit
dimensions: facts/evidence truth, normative validity, expression clarity and
role fidelity. A missing dimension or failed audit blocks adjudication. A
minority report has its own stable report ID, and adjudication must reference
the exact IDs of the reports actually present in the session.

`ColdReviewPacket` is a separate state-bound projection. It contains final
claim IDs, exact evidence IDs, recomputable source-link records, report ID and
charter/state bindings. Recent summaries, working interpretation, search
history and role-discussion history are excluded rather than summarized into
the packet. A cold review cannot be satisfied by a caller-supplied boolean or
by fabricated source links.

These are contract invariants only. MR-0A does not create role workers, model
adapters, scheduling, persistence or approval workflow execution.
## MR-0B Typed Deliberation and Cold Review

Completion attacks use typed `AttackRecord` values. Each record binds project,
run, Charter, Research State, iteration, target stable/version IDs, objection
and counterevidence IDs, outcome, rationale, and a deterministic attack ID.
Every referenced ID must resolve inside the supplied Research State.

`ValidityAudit.passed` is exactly the conjunction of all mandatory dimensions.
Discussion validation can receive the Research State and then verifies target,
role packets, challenged claims, evidence, rivals, and minority reports against
that state rather than accepting format-correct orphan IDs.

`ColdReviewPacket` proves only canonical input isolation. It uses an exact
allowlist and a complete exclusion set for working summaries, recent
summaries, working interpretation, search history, search-history narrative,
and role discussion history. `ColdReviewResult` is a separate typed result
bound to packet ID/hash, report, state, reviewer model, inference profile,
audits, blocking findings, and evaluation time. Completion requires both a
valid packet and a passed, recomputable result.
