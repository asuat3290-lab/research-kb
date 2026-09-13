# MCP v1 tool contract

本项目使用官方 MCP Python SDK。Research MCP 必须且只能注册以下 12 个工具：

| # | 工具 | 作用 |
|---:|---|---|
| 1 | search_corpus | 项目范围内的受限词法检索 |
| 2 | get_passage | 按稳定 passage ID 读取原文片段和有限邻居 |
| 3 | get_document_metadata | 读取项目内来源元数据 |
| 4 | get_research_context | 恢复项目研究上下文 |
| 5 | submit_hypothesis | 保存 draft/candidate 假设 |
| 6 | submit_objection | 保存 draft/candidate 反驳 |
| 7 | save_research_note | 保存 draft 研究笔记 |
| 8 | verify_quote_or_claim | 核验 exact_quote 来源一致性并签发短期 token |
| 9 | submit_verified_evidence | 原子消费 token，创建 candidate evidence |
| 10 | get_search_history | 读取当前项目和会话的检索历史 |
| 11 | submit_research_report | 保存 candidate/draft 结构化报告 |
| 12 | request_user_approval | 创建 pending 人工审批请求 |

除上述名称外，不得注册任何工具。不得注册 status、数据库统计、Admin CLI、ingest、metadata update、approval decide、backup、reindex、任意 SQL、文件路径、文件读取、Shell、脚本、actor/role/admin 或项目授权修改工具。MCP 层不导入 AdminService 或审批决定路径。

## 身份和会话

MCP 服务器固定使用：

~~~text
actor_kind = agent
role       = researcher
~~~

actor_id、session_id、framework、model 由服务器配置或连接上下文注入，不能作为工具参数。stdio 模式下一个服务器进程保持稳定 session_id；客户端不能通过工具参数或环境变量提升为 admin。服务层仍会重新校验 active project、对象 ID、状态和配额。

## 统一 envelope

成功：

~~~json
{
  "ok": true,
  "protocol": "research-kb/v1",
  "schema_version": 5,
  "data": {},
  "warnings": [],
  "trace_id": "opaque-id"
}
~~~

失败：

~~~json
{
  "ok": false,
  "protocol": "research-kb/v1",
  "schema_version": 5,
  "error": {
    "code": "STABLE_CODE",
    "message": "sanitized message"
  },
  "warnings": [],
  "trace_id": "opaque-id"
}
~~~

稳定错误码：

| 错误码 | 典型场景 |
|---|---|
| INVALID_ARGUMENT | 字符串、列表、枚举或数值不合法 |
| NOT_FOUND | 项目内不存在目标 |
| OUT_OF_SCOPE | inactive project、跨项目 ID 或项目外 token |
| FORBIDDEN | 换 actor、管理员操作或策略禁止 |
| QUOTA_EXCEEDED | 会话检索/写入配额超限 |
| UNSUPPORTED_MODE | semantic、hybrid 或非 exact_quote 模式 |
| TOKEN_EXPIRED | token 已过期 |
| TOKEN_CONSUMED | token 已重放 |
| CONFLICT | 来源版本改变、并发消费或状态冲突 |
| INTERNAL | 未预期内部异常 |

错误和成功 envelope 都不得泄露 traceback、SQL、数据库绝对路径、corpus 路径、其他项目 ID、管理员配置、环境变量、原始 token 或敏感日志内容。原始 verification token 只在当前 verify_quote_or_claim 成功响应中返回给当前调用者；不进入日志、审计或其他响应。

## 通用限制

所有输入在 MCP schema 和服务层双重校验。当前默认上限：

- project/document/passage/item/evidence ID：256 字符；
- query：配置的 max_query_chars，默认 1000；
- top_k：1–20；
- context：0–3；
- 搜索过滤列表：source_types/languages/reliability_levels 各 20，document_ids 100；
- history limit：1–100；
- hypothesis/objection passage IDs：最多 50；
- report claims：1–50；
- 单个报告 evidence ID 列表：最多 50；
- 每个工具输出受 max_return_chars 限制；截断返回 RETURN_TRUNCATED warning 和仍然有效的 JSON。

## 工具输入与行为

### search_corpus

输入：

~~~json
{
  "project_id": "string",
  "query": "string",
  "search_mode": "auto|lexical|semantic|hybrid",
  "match_strategy": "all|any|auto",
  "source_types": ["string"],
  "languages": ["string"],
  "document_ids": ["string"],
  "reliability_levels": ["string"],
  "date_from": "string",
  "date_to": "string",
  "top_k": 10,
  "diversify_results": true,
  "include_possible_counterevidence": false
}
~~~

auto 在本版本固定转 lexical。semantic/hybrid 返回 UNSUPPORTED_MODE，不伪装成语义检索。结果只包含稳定 ID、显式元数据、原文 excerpt、受限 score 和 citation eligibility，不返回全文或路径。

### get_passage / get_document_metadata / get_research_context

- get_passage：project_id、passage_id、context=0..3；返回原文 passage 和有限邻居，不返回文件路径。
- get_document_metadata：project_id、document_id；返回来源身份、显式元数据、可靠性/核验状态和 passage 数量。
- get_research_context：project_id、detail=brief|full；只返回当前项目的研究条目和 pending approvals。

### submit_hypothesis

输入包括 project_id、title、claim、epistemic_status、supporting_passage_ids、counter_passage_ids、alternative_explanations、open_questions、confidence=low|medium|high、status=draft|candidate 和可选 supersedes_item_id。Agent 不能创建 accepted 状态；所有链接重新检查项目归属。

### submit_objection

输入包括 project_id、target_item_id、objection_type、text、passage_ids 和 status=draft|candidate。target item 与 passage 必须属于同一 active project。

### save_research_note

输入为 project_id、title、body，以及向后兼容的可选字段：

- `note_purpose=research_note|checkpoint`，默认 `research_note`；
- `supersedes_item_id`，默认 `null`，只用于 checkpoint successor。

旧三参数调用仍保存为 draft research note，payload 不带 checkpoint schema，也不参与唯一 current 约束。`note_purpose=checkpoint` 时，服务端生成 `research-checkpoint/v1`、`checkpoint_version=1` 和 server-owned checkpoint metadata；客户端不能伪造 project、actor、session、created_at 或 schema。第一个 checkpoint 不带 successor；已有一个 current 时必须原子 supersede 它；多个 current 或错误 target 返回 `CONFLICT`。current 查询、target 校验和 successor 插入均在同一 `BEGIN IMMEDIATE` 写事务内完成。普通 research note 不受该唯一性约束。详见 `docs/checkpoint-lifecycle.md`。

### verify_quote_or_claim

输入为 project_id、passage_id、quote_text、verification_type。当前只支持 verification_type=exact_quote；其他字符串返回 UNSUPPORTED_MODE。成功只证明 quote 是指定来源版本 passage 的精确子串，并签发绑定 project、source_version、document_hash、passage、quote_hash 和 actor 的短期单次 token；不证明事实真值、来源权威性或人工接受。

### submit_verified_evidence

输入为 project_id、verification_token。token 消费必须在事务中原子完成，并检查 expiry、replay、actor、project、source_version、document_hash、passage 和 quote。成功创建 candidate evidence，人工接受是后续 Admin CLI 状态转换；token 不在成功/失败日志中出现。

### get_search_history

输入为 project_id、limit=1..100。只返回当前 project 和稳定 session_id 的搜索事件，不能读取其他项目会话。

### submit_research_report

输入为 project_id、question、summary、claims、strongest_objection、alternative_explanations、unresolved_questions、evidence_limits、next_steps、status=draft|candidate 和可选 supersedes_item_id。每个 claim 包含 text、epistemic_status 和 verified_evidence_ids；source_fact 必须有 verified evidence。不能借报告输入绕过证据状态或项目范围。

### request_user_approval

输入为 project_id、target_type=research_item|evidence、target_id、rationale。只创建 pending request：

- research_item target 必须是当前项目 draft/candidate item；
- evidence target 必须是当前项目 candidate evidence；
- target 必须实际存在；
- MCP 不提供批准或拒绝操作，也不会将 pending 自动改为 accepted/rejected。

## 传输和日志

- stdio stdout 只能用于官方 MCP 协议；日志仅写 stderr。
- 模块 import 不输出内容。
- 正常启动、关闭和客户端取消由官方 SDK 管理。
- 内部异常转为 INTERNAL，并用 opaque trace_id 关联本地脱敏日志。
- 日志不写完整来源文本、原始 token、绝对路径、SQL、环境变量或 traceback。

## 非目标

本契约不包含本地模型、默认联网、向量检索、旧项目迁移、personal_kb 迁移或客户端全局配置修改。Phase 0 report manifest base completed; Phase 3 completed; Phase 3.5 not started。

## Phase 2 correction round: startup and protocol boundary

The MCP entry point performs a read-only readiness check before opening stdio. The configured database file must already exist, all migration versions must be present through the current schema version, and the required tables, triggers, and FTS table must be queryable. MCP startup never creates directories or a database, applies migrations, creates the default project, or rebuilds an index. A missing or stale database exits with a sanitized instruction to run the Admin CLI. Migration and reindex remain Admin CLI operations only.

Each stdio MCP process receives a cryptographically unpredictable actor_id and session_id. Both values remain stable for that process and are not accepted as tool arguments. Verification tokens are actor-bound by the service; a normal verification and consumption flow must use the same MCP process/session. A different process is rejected with FORBIDDEN, even if it possesses the token text.

Output sanitization is recursive. In addition to sensitive field names, every string value is checked for Windows drive paths, UNC paths, Windows device paths, POSIX absolute paths, and file:// URIs. Such values become `[redacted-local-path]`. Ordinary http:// and https:// URLs remain allowed. This applies inside nested dictionaries and lists regardless of the field name.

The registered tool functions return the research-kb envelope for application results and failures. FastMCP 1.27.1 validates tool arguments before invoking a function; the adapter catches that SDK validation failure and returns the same sanitized INVALID_ARGUMENT envelope. Non-tool MCP protocol failures, if produced by the SDK itself, remain protocol-level errors and must not expose traceback, SQL, paths, tokens, environment values, or internal model details.


## Phase 3 boundary notes

The MCP contract remains exactly twelve tools. Backup, restore, token cleanup, reindex, migration, and approval decisions are Admin CLI-only operations.

The current schema includes `003_phase3.sql`, which binds new verification tokens to both the server actor and issued MCP session. Tokens created before this migration cannot be safely resumed and are terminally marked during migration. Research item transitions are enforced as draft -> candidate -> under_review -> accepted/rejected; evidence transitions are candidate -> accepted/rejected.

MCP errors for cross-project, archived-project, malformed, injected, or unknown-argument requests remain sanitized stable envelopes. The Admin CLI is a local high-privilege boundary and may intentionally report local paths to its human administrator; those paths are not returned by MCP.

## Phase 3.25 citation and discovery additions

`get_document_metadata` and `get_passage` remain backward compatible: legacy fields are retained and the response additionally includes:

- `citation_record`: a whitelist-based bibliographic profile. It contains the supported fields for the document type plus `document_id`, `content_hash`, and `source_version`. Missing bibliographic fields are `unknown`. It never derives authority or bibliographic facts from a filename or local path.
- `citation_locator`: `page`, `location`, `document_id`, `passage_id`, and `source_version`. A document-level locator uses `passage_id: "unknown"`; a passage locator carries the source passage page/location.

Search hits also include a bounded `citation_locator`. For prose, use the stable form `Author, year, page/location, passage_id`. A report must end with a complete source table and an `evidence_id -> passage_id -> document_id -> citation_record` table. Do not cite the pilot runbook, Agent instructions, or unrelated local files.

`submit_research_report` retains all existing arguments and accepts three optional structured fields:

- `research_leads`: zero for legacy reports, or 3-6 discovery leads. Each lead contains `idea`, `source_bridges`, `supporting_passage_ids`, `why_not_literature_summary`, `possible_counterevidence`, `missing_evidence`, `next_search`, `epistemic_status`, and `confidence`.
- `source_table`: explicit source records for the end-of-report bibliography.
- `evidence_citation_map`: explicit rows linking each evidence ID to its passage ID, document ID, citation record, and citation locator.

The service revalidates all passage, document, and evidence IDs against the active project. Candidate leads are hypotheses or inferences, not accepted evidence. Only `request_user_approval` creates a pending approval request; the MCP surface cannot decide it.

Use `evidence mode` for source-consistency work: retrieve metadata and passages, separate source facts from interpretation, verify exact quotes, and submit only candidate evidence. Use `discovery mode` for cross-source reasoning: build a concept matrix, compare normative premises, identify conflicts and boundary conditions, state missing source types, reframe the question, and compare competing explanations. Discovery leads must remain explicitly labeled as inference, hypothesis, or open question.

## Server-owned report citations and successor approvals

The `citation_record` and `citation_locator` fields supplied inside `submit_research_report` are not trusted. For every `source_table` row, the service resolves the submitted `document_id` inside the active project and rebuilds the citation record from the current document metadata. For every `evidence_citation_map` row, it resolves `evidence_id`, `passage_id`, and `document_id` together and rebuilds both the citation record and locator from the database passage/document rows. Forged authors, years, DOI values, pages, or source versions are never persisted or returned. Local paths are not part of the generated records.

An Admin approval request for a research item that already has a successor (`supersedes_item_id`) cannot be approved. It may still be explicitly rejected by the user.


## Phase 3.3 cross-round continuity

`get_research_context(project_id, detail="brief|full")` remains backward compatible. Its large-context behavior is intentionally bounded:

- Without `item_id`, it returns a lightweight, project-scoped item index. Each record includes `item_id`, `kind`, `status`, `supersedes_item_id`, `has_successor`, `is_current`, `version_id`, `updated_at`, and `available_sections`. The response also includes `offset`, `limit`, `total_items`, `has_more`, and an opaque `next_cursor` when another page exists. It does not aggregate every report or note body.
- With `item_id`, the service resolves the latest version belonging to the active project. A small payload may remain in the backward-compatible `payload` field. A large payload reports `payload_complete=false`, its character size, and `available_sections`.
- With `item_id` and `section`, the response contains one bounded `section` object: `name`, `content_type` (`text` or `json`), `content`, `offset`, `next_offset`, and `total_chars`. Concatenate successive `content` values using `next_offset`; JSON sections become valid JSON after concatenation. `chunk_size` is bounded by the configured return limit and cannot make the envelope exceed `max_return_chars`.
- `cursor` is valid only for index pagination and is project-bound. A malformed cursor returns `INVALID_ARGUMENT`; a cursor used with another project fails closed. An item, section, or cursor is revalidated against the active project on every call. Records mark successor state so a caller can choose the current version rather than an obsolete superseded item.

`search_corpus` remains deterministic SQLite FTS5 lexical retrieval. `match_strategy` is `all`, `any`, or `auto`: `all` requires every normalized term, `any` accepts at least one term, and `auto` tries `all` first and only falls back to `any` when the first query returns zero rows. The response states the actual `match_strategy` and `query_relaxed`; the persisted search event records the requested strategy, actual strategy, and relaxation flag. This is not semantic or hybrid retrieval.

Search history is intentionally session-local and is not cross-round memory. Persistent research items and notes are the cross-round state. At the end of each round, save a concise checkpoint note containing the question, read item IDs, key findings, query strategy, newly created item IDs, unresolved questions, and the next first step. At the beginning of the next round, first list the lightweight index, locate the current (not superseded) report/checkpoint, read the checkpoint by `item_id`, then read only the report sections needed for the next question.


## Phase 3.3.1 source relationship recovery

The `get_research_context` item index now includes server-derived `source_link_count` and `source_link_relations` for every latest item version. When that exact version has append-only `evidence_links`, `available_sections` additionally contains the synthetic `source_links` section.

`section="source_links"` is not read from the client payload. It is rebuilt from the selected `version_id` and returns JSON records containing:

```json
{
  "version_id": "<latest-version-id>",
  "relation": "supports|counters|context",
  "passage_id": "<passage-id>",
  "verified_evidence_id": null,
  "document_id": "<document-id>",
  "citation_locator": {
    "page": "unknown",
    "location": {"page": 1},
    "document_id": "<document-id>",
    "passage_id": "<passage-id>",
    "source_version": "<source-version>"
  }
}
```

For a verified-evidence link, `verified_evidence_id` is populated and `passage_id` is resolved from the immutable evidence row. No local file path is returned. The service queries only the latest `version_id`; links belonging to an older version are not mixed into the response. A payload field named `source_links` is ignored for this purpose and is not returned as an authoritative payload field.

The synthetic section uses the same `offset`/`chunk_size`/`next_offset` protocol as other sections. At `max_return_chars=4000`, a bounded chunk is returned without an unnecessary `RETURN_TRUNCATED` warning. If a defensive outer fit is ever required, the requested item/section container is preserved and `next_offset` advances over any shortened current chunk.

## Phase 3.3.2 contextual source roles

Contextual source roles do not add a thirteenth MCP tool, migration, or global document-ranking field. The current twelve-tool surface is sufficient: save a Source Role Map as a UTF-8 JSON research note, then recover it with `get_research_context(item_id=..., section=body, offset=..., chunk_size=...)`. The existing bounded section protocol must be used when `max_return_chars=4000`.

Keep three layers separate:

1. **Document integrity** is stable for a document/source version: extraction or OCR quality, content hash, source version, duplicate handling, `reliability_status`, and `verification_status`.
2. **Research role** is contextual and revisable: current object, source-side primary, target-side primary, core research object, secondary interpretation, historical background, competing-idea source, counterevidence, discovery-only, or excluded.
3. **Evidential function** is claim-level and contextual: `supports`, `counters`, `contextualizes`, `competing_explanation`, `identifies_transmission`, or `discovery_only`.

Reliability and verification describe source/version integrity and verification state. They do not express importance for the current question. Do not derive a permanent rank from author fame or a fixed topic label, and do not store dynamic roles in global document metadata.

A role-map assignment must contain `research_question`, `subtask`, `document_id`, a service-recoverable `citation_identity`, `role_type`, `evidential_function`, `rationale`, `can_support`, `cannot_support`, `directness`, `confidence`, `provisional`, `supporting_passage_ids`, and `competing_or_alternative_sources`. The same document may receive different roles for different questions, subtasks, or claims.

Role changes are append-only in the note/checkpoint representation. Preserve `previous_role`, `new_role`, `reason_for_change`, and `affected_subtask_or_claim`; never silently overwrite a prior assignment. The role map is an analysis record, not a source of truth for author, title, page, DOI, document ID, project membership, or passage relations. Citations and `source_links` remain server-generated and project-scoped.

Before synthesis or a hypothesis, the Agent should recover the current checkpoint and Source Role Map, state the current question and subtasks, then search and retrieve passages. Re-evaluate roles when the question, subtask, claim, or search results change. Conceptual similarity is not evidence of influence: consider source/target direction, time, explicit citation, contact, shared background, and competing sources. Low relevance is not low data quality; a high-quality version is not by itself proof of a claim.

The final report should disclose Research Scope, Source Role Map, Claim–Evidence–Role Matrix, Role Changes, and Limitations. Candidate hypotheses and candidate evidence remain subject to human approval. No MCP operation may accept or reject them automatically.

## Phase 0 report manifest

`004_phase0.sql` adds the append-only `report_manifest` table. It does not add or remove MCP tools; the research surface remains exactly twelve tools.

Every report created through `submit_research_report` writes one manifest row in the same transaction as the report version. The manifest is bound to `report_version_id` and `protocol_project_id`, and stores the stable revision IDs for the report's claims, verified evidence, and supporting passages, plus empty lists for verification events, approval events, source snapshots, project exports, and cross-project links. Later phases will append only the event and export IDs after the corresponding phase is completed; a manifest row never updates or deletes an earlier record.

MCP readiness now requires the `report_manifest` table and its three append-only/target-existence triggers. `get_research_context` records for report items include the read-only `report_manifest_id` and `report_revision_id` fields. Direct `UPDATE` or `DELETE` on `report_manifest` is rejected by the database.

## Phase 5 writing policy and delivery metadata

`005_writing_policy.sql` is additive and backward compatible. It appends seven nullable columns to `report_manifest`: `deliverable_layer`, `artifact_profile`, `writing_policy_id`, `writing_policy_version`, `writing_policy_snapshot_json`, `compression_review_status`, and `writing_audit_summary_json`. Existing manifest rows keep their meaning and their new fields are NULL. The migration can be re-run safely and the tool surface remains exactly twelve tools.

`submit_research_report` retains every existing argument and accepts optional Phase 5 fields:

- `deliverable_layer`: `A` (formal academic paper), `B` (method appendix), or `C` (system/technical report).
- `artifact_profile`: `academic_paper`, `method_appendix`, `technical_report`, or `research_memo`.
- `writing_policy_id` and `writing_policy_version`: the policy identity used by the caller.
- `writing_policy_snapshot`: the fully resolved policy snapshot that was applied before submission.
- `writing_policy_overrides`: per-submission overrides merged after system default, artifact profile, and project configuration.
- `compression_review_status`: `not_required`, `pending`, `passed`, or `returned`.
- `writing_audit_summary`: compact counts with `errors`, `warnings`, `review_items`, and `approval_blockers`.

Legacy calls that omit all of these fields remain valid and write NULL for every new column. When any policy field is present, the service reads the project `config_json`, resolves the policy with system default, artifact profile, project configuration, and submission overrides, validates the result, and stores the final snapshot in the manifest. The manifest stores only the compact audit summary; the full JSON/Markdown audit report remains a file or artifact outside the manifest. `get_report_manifest` returns the new fields, parsing JSON columns to `null` for legacy rows.

The bundled writing policy version is 1.2.0. The local `writing_audit` CLI is the
only surface that runs policy rules and public parity; `submit_research_report`
never reruns the writing audit and never writes public exports.

## Checkpoint successor boundary

`submit_hypothesis` and `submit_research_report` retain their existing
optional `supersedes_item_id` behavior for their own non-checkpoint item
families. They cannot supersede a standard checkpoint. The service enforces
this distinction in the shared item write path, so the MCP error is the same
sanitized `CONFLICT` envelope regardless of which research-item tool attempted
the bypass. `save_research_note` with `note_purpose="research_note"` cannot
carry a successor target; only the server-generated
`note_purpose="checkpoint"` path can create a checkpoint successor.
