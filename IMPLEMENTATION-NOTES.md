# research-kb — historical implementation notes

> Phase labels and environment-specific results below describe their original
> milestones, not current product readiness. Start with [README.md](README.md).

research-kb 是面向 Codex、OpenCode、GPT 及其他外部 Agent 的轻量本地研究知识库。它不运行本地研究模型；本机只保存原始材料、显式来源元数据、检索片段、研究状态、证据、审批记录和审计历史。

> Current status: Phase 0 report manifest base completed; Phase 3 passed; Phase 3.5 and Phase 4 have not started.

## SG-1B2 canonical Skill and adapter governance

The single semantic authority is
skills/source-based-research/SKILL.md. Deploy that file byte-for-byte to
the runtime workspace at
workspace/.agents/skills/source-based-research/SKILL.md; keep the runtime
project ID in controlled project configuration rather than in the canonical
Skill.

Cross-agent templates are under adapters/codex/, adapters/luna/,
adapters/qoder/, and adapters/opencode/. They only load the canonical
Skill, verify the research-kb MCP exact-12 contract, require an explicit
<PROJECT_ID>, and hand off. They are templates, not automatic installations.

Use docs/skill-authority-and-adapters.md and
docs/system-manifest.example.toml to deploy and review the authority
relationship. doctor --deep checks declared canonical/runtime hashes and
explicit adapter files. Each declared adapter has a raw-byte `content_sha256`;
a match is INFO and any existing-file drift is P1, even if the adapter remains
semantically thin. Optional absence is P2. It never scans global Agent Skill
directories, installs adapters, or accepts a new hash without human review.

SG-1B2B may register an explicitly installed Codex adapter in the runtime
manifest. The rendered Skill and `agents/openai.yaml` are each locked by
SHA-256 and must remain byte-identical to their installed counterparts. Deep
doctor checks only those four declared files, never scans the global Skill
root, and reports drift as P1. Installation and rollback remain manual;
Luna, Qoder, and OpenCode adapters are not installed by this phase.

## 已有能力

- SQLite + FTS5：项目、文档、片段、研究条目、版本、证据、审批、会话、搜索历史和审计日志。
- 按版本排序、事务化、幂等迁移；001_initial.sql 保持不变，当前 schema is 5。
- 来源一致性核验、candidate evidence 和人工 accepted/rejected evidence 分离。
- verification token 绑定 project、source version、document hash、passage、quote hash 和 actor，单次原子消费。
- active-project 校验、项目隔离、悬空 approval target 防护和来源元数据修改审计。
- 无模型的确定性中英混合检索：2/3 字中文、长中文短语、中英混合、英文连字符、原文 excerpt、项目隔离和可重建索引。
- Admin CLI：init、status、project、ingest、metadata、approval、backup、reindex。
- System Governance 1.0：版本化 system manifest 与只读 `doctor` 控制面诊断；不执行迁移、导入、reindex 或修复。
- 官方 MCP Python SDK 适配器：只注册 12 个研究工具；不注册 Admin CLI、SQL、文件、Shell 或审批决定工具。
- thesis_review：独立可选的论文审阅与受控修改工作流（Review/Revision 分离）；纯校验器，不改 SQLite/MCP/Claim-Link-Event；见 docs/thesis-review-policy.md。
- TXT、Markdown、HTML、DOCX、EPUB 提取；PDF 为可选依赖。

## MCP 研究面

工具集合必须正好是：

~~~
search_corpus
get_passage
get_document_metadata
get_research_context
submit_hypothesis
submit_objection
save_research_note
verify_quote_or_claim
submit_verified_evidence
get_search_history
submit_research_report
request_user_approval
~~~

MCP 中 actor_kind=agent、role=researcher 固定；actor/session/framework/model 由服务器配置或连接上下文注入，工具参数不接受这些可信身份字段。stdio stdout 只承载 MCP 协议，脱敏日志写 stderr。

search_mode=auto 在当前版本等价 lexical；semantic 和 hybrid 明确返回 UNSUPPORTED_MODE。verify_quote_or_claim 当前只支持 exact_quote，核验的是来源版本中的精确片段一致性，不声称事实真值。request_user_approval 只创建 pending request，不执行批准。

完整字段和错误契约见 docs/tool-contract.md。

## 安装

核心运行时只使用 Python 3.11+ 标准库。MCP 是可选 extra，但安装 extra 后 research-kb-mcp 入口必须使用真实官方 SDK：

~~~bash
python -m pip install -e .
python -m pip install -e ".[mcp]"
# Optional PDF extraction support
python -m pip install -e ".[pdf]"
~~~

本次验收环境：

~~~
Python 3.13.1
mcp 1.27.1
~~~

缺少 MCP extra 时，入口会明确提示安装 research-kb[mcp]，不会静默退化成假服务器。

## 初始化与 Admin CLI

Bash：

~~~bash
cd <PROJECT_ROOT>
python -m research_kb.cli --config <CONFIG_PATH> init
python -m research_kb.cli --config <CONFIG_PATH> status
python -m research_kb.cli --config <CONFIG_PATH> project list
python -m research_kb.cli --config <CONFIG_PATH> doctor --json
python -m research_kb.cli --config <CONFIG_PATH> doctor --manifest <SYSTEM_MANIFEST_TOML> --json
python -m research_kb.cli --config <CONFIG_PATH> doctor --manifest <SYSTEM_MANIFEST_TOML> --deep --json
~~~

PowerShell：

~~~powershell
Set-Location "<PROJECT_ROOT>"
python -m research_kb.cli --config "<CONFIG_PATH>" init
python -m research_kb.cli --config "<CONFIG_PATH>" status
python -m research_kb.cli --config "<CONFIG_PATH>" project list
python -m research_kb.cli --config "<CONFIG_PATH>" doctor --json
~~~

`doctor` 的退出码固定为 `0=healthy`、`1=warning`、`2=failed 或输入无效`；`--strict` 会将 warning 提升为退出码 2。系统 manifest 示例见 `docs/system-manifest.example.toml`，治理边界见 `docs/system-governance.md`。

doctor 默认在结构化对象层脱敏本机路径（`<local-path>`、`<unc-path>`、`<file-uri>`），保留相对路径的 `/` 形式和普通 HTTP(S) URL；`--show-paths` 才显示本机路径。默认 MCP 结果 `mcp_tool_contract_declared` 只表示声明契约，`--deep` 才读取 FastMCP 实际注册集合。deep Skill inventory 固定限制为深度 8、目录 1024、每目录条目 5120、文件 4096 和约 1 秒；external 或越界根拒绝扫描，达到限制返回 `skill_inventory_scan_limited`。

Manifest 导入必须显式声明来源元数据；缺失字段只会保存为 unknown 或 unverified，不会根据文件名推断权威性：

~~~bash
python -m research_kb.cli --config <CONFIG_PATH> ingest \
  --project default --manifest corpus/manifest.json --dry-run
python -m research_kb.cli --config <CONFIG_PATH> ingest \
  --project default --manifest corpus/manifest.json
~~~

正式研究 Agent 的工作目录应与数据库和 corpus 目录分离。Agent 只通过稳定 ID 和受限 excerpt 访问研究面。

## stdio 启动

跨平台统一使用同一个 Python 入口：

~~~bash
cd <PROJECT_ROOT>
python -m research_kb.mcp_server --config <CONFIG_PATH>
~~~

或：

~~~powershell
Set-Location "<PROJECT_ROOT>"
python -m research_kb.mcp_server --config "<CONFIG_PATH>"
~~~

### Codex 示例配置（不自动写入）

以下是配置示意，不是本项目会自动修改的文件：

~~~toml
[mcp_servers.research-kb]
command = "<PYTHON_EXECUTABLE>"
args = ["-m", "research_kb.mcp_server", "--config", "<CONFIG_PATH>"]
cwd = "<PROJECT_ROOT>"
~~~

### OpenCode 示例配置（不自动写入）

~~~json
{
  "mcp": {
    "research-kb": {
      "type": "local",
      "command": [
        "<PYTHON_EXECUTABLE>",
        "-m",
        "research_kb.mcp_server",
        "--config",
        "<CONFIG_PATH>"
      ],
      "cwd": "<PROJECT_ROOT>",
      "enabled": true
    }
  }
}
~~~

配置字段以客户端版本的 schema 为准；示例只表达命令、参数和工作目录，不应复制到全局配置后不做审查。

Windows JSON 路径中的反斜杠必须转义，例如 "C:\\path\\to\\config.toml"；也可以使用 "C:/path/to/config.toml"。POSIX 使用普通 / 路径，例如 "/path/to/config.toml"。不要把真实路径、管理员凭据或环境变量内容放入工具参数。

## 测试

跨平台测试临时目录使用 Python tempfile 机制；在受限环境可设置 RESEARCH_KB_TEST_TMP 指向临时目录。

~~~bash
python -m unittest discover -s tests -v
~~~

Phase 2 验收覆盖：

- 12 工具枚举严格相等、输入 schema 结构和身份字段排除；
- 统一成功/失败 envelope、稳定错误码、输出长度和脱敏日志；
- semantic/hybrid fail closed；
- 跨项目 document/passage/item/evidence ID；
- token 过期、重放、换 actor、换项目、source conflict；
- request approval 仅保持 pending；
- stdout 无调试内容、模块导入无输出、stdio 启动/关闭；
- 真实官方 MCP client 完成搜索、passage、hypothesis、objection、exact quote、candidate evidence、report 和 approval request；
- Phase 0/1 回归。

本次结果：11 个测试文件，73 个测试通过（1 skipped）；阶段 0 修复后含 EPUB 契约、PDF 探针超时和 report manifest 测试。

## 明确不包含

- 本地 LLM、后台自动研究、默认联网或自动审批；
- 任意 SQL、Shell、脚本执行、任意文件路径或任意文件读取工具；
- 第一版向量检索；semantic/hybrid 保持 fail closed；
- MCP 层的 AdminService、approval decide、ingest、metadata update、backup、reindex；
- 对旧项目代码、旧数据库、旧向量索引或 personal_kb 的运行时依赖；
- 自动修改 Codex、OpenCode 或用户全局配置。

## 结构

~~~text
research-kb/
├─ docs/
│  ├─ architecture-and-implementation-plan.md
│  ├─ tool-contract.md
│  └─ manifest-format.md
├─ tests/
│  ├─ test_framework_smoke.py
│  ├─ test_phase1.py
│  ├─ test_phase2_mcp.py
│  ├─ test_phase325_feedback.py
│  ├─ test_phase331_source_links.py
│  ├─ test_phase332_source_roles.py
│  ├─ test_phase33_continuity.py
│  ├─ test_phase34a_catalog.py
│  ├─ test_phase34a1_catalog_quality.py
│  ├─ test_phase3_security.py
│  └─ test_phase0_manifest.py
└─ src/research_kb/
   ├─ admin.py
   ├─ cli.py
   ├─ config.py
   ├─ db.py
   ├─ ingest.py
   ├─ mcp_server.py
   ├─ policy.py
   ├─ search.py
   ├─ service.py
   └─ migrations/
      ├─ 001_initial.sql
      ├─ 002_phase1.sql
      ├─ 003_phase3.sql
      └─ 004_phase0.sql
~~~

## 后续阶段

Phase 3 completed。后续候选工作包括更系统的并发/运维加固、恢复演练和发布自动化；这些不属于本次交付。

## Phase 2 correction round

MCP startup is read-only: the database must be initialized and current before the process starts. MCP does not create directories, apply migrations, create projects, or rebuild FTS. Run the Admin CLI `init`, `migrate`, or `reindex` commands before starting MCP when readiness fails.

Every stdio process has a unique actor/session pair. Verification and token consumption must remain in one client session; a second MCP process is rejected. Metadata output recursively redacts local paths, UNC/device paths, and `file://` values while allowing normal HTTP(S) URLs. FastMCP schema validation failures are returned as a sanitized `INVALID_ARGUMENT` research-kb envelope.


## Phase 3 security and recovery

Phase 3 adds a versioned `003_phase3.sql` migration for strict research-item/evidence state transitions and verification-token session binding. The original `001_initial.sql` and `002_phase1.sql` remain unchanged.

Admin-only operations now include atomic online backup, separate-path restore validation, transactional reindex, and terminal cleanup of expired tokens. MCP still exposes exactly twelve research tools and never exposes these administrative operations.

See `docs/threat-model.md`, `docs/security-deployment.md`, and `docs/backup-and-recovery.md` for deployment assumptions, privacy boundaries, recovery drills, Windows/POSIX path notes, and known limitations. Semantic/hybrid retrieval and remote MCP remain unsupported.

## Governed Codex local MCP

The runtime manifest can declare a single Codex MCP installation under
`[mcp_authority]`. It governs only the named `research-kb-pilot` server table,
not the full Codex configuration and not unrelated servers such as `node_repl`.
Doctor checks the explicit config file, stdio command, ordered arguments, cwd,
timeouts, enabled state, and the exact twelve-tool allowlist without scanning
the global Codex directory.

Run the static and deep checks with:

~~~bash
python -m research_kb.cli --config <runtime-config> doctor --manifest <system-manifest> --deep --json
~~~

Deep mode starts the declared local stdio command and verifies an official MCP
client initialize plus `list_tools()` result. Missing or drifting configuration
is P1. The installation is manual: preserve the old config under the controlled
backup directory, verify its SHA-256, replace it atomically, and retain the
backup for rollback. Doctor never installs, rewrites, or accepts a new config
automatically.


## Phase 3.4A full material catalog

The human-admin `catalog scan` command builds a read-only, resumable catalog and an actual (not padded) candidate set from explicit root aliases. It separates ready, metadata-review, privacy, generated/code, PDF-probe, size-only, possible-duplicate, and exact-duplicate states. It never performs formal ingest, OCR, network lookup, or MCP registration. See `docs/catalog.md` for Bash and PowerShell examples.


## Phase 0 report manifest base

`004_phase0.sql` adds the append-only `report_manifest` table without changing the MCP surface. `submit_research_report` writes one manifest row in the same transaction as the report version; the manifest records stable claim, verified-evidence, and supporting-passage revision IDs, with empty event/export lists reserved for later phases.

Catalog readiness is now a five-level ladder: `ingest_ready`, `search_ready`, `citation_ready`, `evidence_ready`, and `report_ready`. Only the first two current-level fields (`ingest_ready` and `citation_ready`) can be true after a dry-run scan; the remaining levels are false until their phase is implemented. Direct updates or deletes on `report_manifest` are rejected by database triggers, and MCP startup requires the new table and triggers.
## Max Research phases

MR-0/MR-0A/MR-0B define the pure, deterministic Max Research contract. MR-1
adds an independent SQLite control plane and Admin CLI for persistence,
approval authority, event verification, leases/fencing, budgets, checkpoints,
and iteration history. It keeps the researcher-facing MCP surface at exactly
12 tools and does not implement a runner, model integration, scheduler,
network access, source acquisition worker, or real Max Run.

MR-1A closes the persistence boundary: the independent control schema is at
version 2 (`002_run_scoped_history.sql`), while core schema 5 and migrations
001-005 remain separate and unchanged. Canonical objects and relations are
run-scoped, all graph changes are atomic lease-fenced change sets, and source
references are verified and hashed by the server. Iteration outcomes, exact
snapshots, typed attack/adjudication/rehydration artifacts, and authoritative
usage receipts back completion and budget reconstruction; payload-only claims,
stale fencing tokens, and conflicting idempotency retries fail closed.

Only the explicit Max Admin API/CLI may create or mutate the control database.
Import, MCP startup, readiness checks, and read-only commands never initialize
it. MR-1A is complete without a runner, model adapter, scheduler, network,
acquisition worker, or real Max Run; it stops pending approval for MR-2.

MR-2A adds the provider-neutral bounded runner kernel in independent control
schema version 3 (`003_bounded_runner.sql`). It supports one immutable model
profile, explicit admin-to-runner handoff, deterministic one-iteration
planning, append-only call/attempt/result/recovery records, lease fencing,
authoritative fake usage, and crash-safe recovery. Adapter calls occur outside
SQLite transactions. The first `unknown` dispatch acknowledgement is never
rewritten; a later provider query or safe idempotent retry records the
resolution separately.

MR-2A.1 closes the runner authority chain in independent control schema
version 4 (`004_mr2a1_runner_closure.sql`). Production runner services have
no fixture defaults; fixture simulation requires an explicit fixture marker
and `max simulate-next --fixture`. Intent persistence is metadata-only,
invocation claims are append-only and fence-bound, adjudication persists
separate lead/rival calls, authoritative iteration outcomes drive the
deterministic cycle, and public verification includes the runner chain.
Rehydration is server-side canonical reconstruction, and supporting evidence
does not become counterevidence without an exact `counters` relation.

MR-2A still exposes no thirteenth MCP tool and does not implement a real model
provider, network, scheduler, daemon, acquisition worker, completion command,
or real Max Run. MR-2A.1 also stops pending approval for MR-2B; neither phase
starts a real Max Run.

MR-2A.2 is the current bounded-runner closure in independent control schema
version 5 (`005_mr2a2_deliberation_usage.sql`). An adjudication iteration is
one auditable outcome made from five same-model/profile calls: two isolated
canonical positions, rival cross-examination, lead response, and an
adjudicator. Each logical call has an immutable intent/result/usage/artifact
binding. Verified usage is charged once per call even when a proposal is
rejected; failed calls without a verified receipt release unused reservation,
while a known-call receipt dispute pauses with reservation retained.

Fixture control databases are creation-time-only and cannot be retrofitted.
Public `verify` recomputes call topology, receipt authority, ledger totals,
iteration charges, artifact provenance, conflict escalation, and reservation
closure. MR-2A.2 does not add a thirteenth MCP tool, real provider, model
integration, scheduler, network, acquisition worker, completion command, or
real Max Run. It stops pending human approval for MR-2B.

MR-2A.2R also closes nested deliberation validation and terminal recovery:
provider contract errors become controlled redacted aborts, five-call usage
and iteration charges remain auditable exactly once, and `verify` rejects
terminal-ready orphan groups without a live invocation claim. No migration or
provider/network capability is added.

MR-2B0R2 adds only the independent Max Research provider boundary and bounded
foreground scheduler. The Max control database is schema 8; the core
research database remains schema 5 and Max migrations 001-005 are frozen.
Provider profiles are strict, versioned, credential-reference-only objects;
the only dispatchable transport is injected in-memory hermetic transport.
There is no API-key lookup, network call, provider SDK, or real model in this
phase.

ProviderCallRecord, server-priced ProviderUsageAttestation, the existing
UsageReceipt, and the budget ledger form one auditable usage chain. A human
admin must explicitly issue a run-bound, one-time LiveExecutionGrant with
caps and expiry. The scheduler is a finite foreground service: one tick owns
at most one existing runner call, durable session/tick/current records bind
state hashes and fencing tokens, and expired-lease handoff reuses the grant
without allowing stale workers to write.

MR-2B0R2 requires explicit request limits for input, output, cache-read, and
reasoning tokens. It enforces aggregate input/cache and output/reasoning grant
caps, reserves an immutable physical dispatch attempt before each send, and
replays settled results without sending again. Legacy character-to-token
estimates are diagnostic-only and fail closed before execution.

The research MCP surface remains exact-12. MR-2B0 does not include a daemon,
acquisition worker, real provider/network execution, MR-3, MR-4, or a real Max
Run; it stops pending human approval.

MR-2B1A was the pre-live offline/control-plane phase. It uses independent Max
control schema 10 (`010_mr2b1a_live_dispatch_permit.sql`); schema 8 and 9 are
historical phases, while core schema 5 and Max migrations 001-010 remain
byte-for-byte frozen. Migration 007 is
007_mr2b0r_authority_budget_closure.sql; migration 010 is
010_mr2b1a_live_dispatch_permit.sql. The
administrator-only `LiveNetworkAuthorization` is bound to the exact run,
project, charter, provider/profile/model, endpoint and network policy,
pricing/budget, caps, expiry, and lease fence; its consumption is append-only
and one-time. A server-owned `LiveDispatchPermit` additionally binds that
consumption to one claim, one physical attempt, one request/intent and
idempotency hash, and the current worker fence. Only credential-reference and
endpoint/policy hashes are durable. The default live transport factory remains
disabled, and read-only preflight never does DNS, reads a credential, consumes
authority, or opens a socket.

MR-2B1A tests the injected HTTPS boundary for exact endpoint policy,
DNS rebinding/SSRF, redirects, caller headers/payloads, expiry, replay,
cross-binding rejection, crash recovery, and stale fencing. The controlled
`provider-live-smoke` command only prepares a fixed redacted request and
refuses `--execute` in this phase. Neither MR-2B1 nor MR-2B1A verifies a real
provider, reads an API key, connects to a network, incurs cost, or starts a
Max Run. A first real HTTPS call is a separate approval phase with explicit
endpoint, model, token/cost caps, credential source, and rollback plan.

MR-4A is the current offline accepted implementation boundary. The
independent Max control database is schema 14 through
`013_mr4a_long_run_authorization.sql` and
`014_mr4a_source_egress.sql`; core schema 5 and core migrations 001-005
remain unchanged. MR-2B2 and MR-3 remain the preceding accepted phases.
MR-2B2 adds an ordered, immutable pool of per-call live-network authorities
and one durable human approval for exactly the next canonical-state-bound
iteration. MR-3 adds a restartable foreground worker with bounded heartbeats
and pause/drain/stop commands, plus a separately authorized acquisition
worker whose staging output is independently hash-validated into a dry-run
projection. It never ingests automatically.

MR-4A adds one StartApproval-backed long-run window, one-time server-minted
state-bound iteration permits, explicit append-only successors, and a
canonical source-egress gateway boundary. Its 48-iteration synthetic fixture
keeps network/DNS/credential/cost at zero, rejects semantic/hybrid retrieval,
and never persists source text, prompts, PDFs, paths, or citation overrides.
Acceptance is still offline: no real provider, DeepSeek/API key, credential,
network call, charge, acquisition download, OCR, ingest, unattended worker,
or real Max Run is claimed. The exact-12 MCP surface is unchanged. MR-4B is
only a manual-approval canary plan in `docs/max-research-live-canary-plan.md`.
