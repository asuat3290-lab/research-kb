# System Governance 1.0

本文件定义 SG-1A 的控制面边界。它描述 research-kb 的运行方式，不保存论文正文、引文、证据、审批决定或项目研究结论。

## 组件边界

- **engine/package**：源码包、运行版本和兼容性规则。
- **runtime**：由配置加载的本机运行实例，包括数据库连接、corpus 根目录和 workspace 根目录。
- **corpus**：受管理的原始材料和 canonical 抽取文本。系统 manifest 只记录路径和边界，不复制材料。
- **catalog**：目录化扫描产生的摘要、状态和候选清单。catalog 不是 ingestion，也不是第二份数据库。
- **workspace**：项目成果、checkpoint、草稿、交付件和管理员运行记录所在的工作区。
- **Skill**：agent 行为约束和工作流说明。SG-1A 只记录声明的路径、版本和内容哈希，不重构正在使用的 Skill。

## System Manifest

## SG-1B2 Canonical Skill and adapter authority

The repository file skills/source-based-research/SKILL.md is the single
semantic authority for the research workflow. A runtime deployment at
workspace/.agents/skills/source-based-research/SKILL.md must be
byte-identical to it. The System Manifest records both SHA-256 values and the
declared adapter templates; it is the only Skill hash authority.

The files under adapters/ are thin, platform-neutral templates. They locate
and load the complete canonical or runtime Skill, check the research-kb MCP
server and its exact twelve tools, require an explicit project ID, and hand
control to the canonical Skill. They do not repeat checkpoint, source-role,
evidence, or citation rules. Every declared adapter has a required raw-byte
`content_sha256` in the System Manifest. A matching hash is reported as
`adapter_template_hash_ok` (INFO); an existing adapter hash drift is P1 even
if the thin-adapter checks still pass. Optional absence is P2, required
absence is P1, and unsafe paths or copied canonical rules remain P1.

doctor --deep checks only files explicitly declared by the manifest. For each
adapter it safely resolves the single file, checks its boundary and reparse
status, reads UTF-8, hashes the original bytes, compares the manifest, and
then runs the thin-adapter checks. It does not scan global Agent Skill
directories, install adapters, copy content, or repair drift. Global Agent
Skills remain outside this round's authority boundary. See
docs/skill-authority-and-adapters.md for the manual review and release
procedure.

An optional `skill_authority.installations` table governs an explicitly
installed adapter without merging it into the repository template. It records
the rendered and installed Skill/metadata paths, boundaries, and four hashes
of authority: one Skill hash and one metadata hash, each checked against the
rendered and installed file. The rendered files must stay inside the runtime
root; the installed paths may use `${USERPROFILE}` and are checked as single
files only. Missing environment variables, unsafe/reparse paths, missing
required files, UTF-8 errors, hash drift, byte mismatch, or contract failure
are P1. Healthy findings are `installed_adapter_skill_hash_ok`,
`installed_adapter_metadata_hash_ok`, `installed_adapter_bytes_ok`, and
`installed_adapter_contract_ok`. Doctor never installs, overwrites, rolls
back, or accepts a new hash.

The Codex global replacement is a manually approved operation. The old Skill
and `agents/openai.yaml` are backed up together under a directory named by the
old Skill hash. Rollback means restoring both files from that backup, checking
both old hashes, restoring the matching manifest declaration, and rerunning
deep doctor. Backups are retained.

`docs/system-manifest.example.toml` 是版本化、机器可读的控制面示例。manifest 至少声明 engine/package、schema、protocol、config、database、corpus、workspace、catalog、backup、skills、MCP 工具集合、可选项目注册表、Skill 记录、catalog 生命周期和能力开关。

相对路径相对于运行实例的 config 目录解析；本机部署可用环境变量占位符替代绝对路径。manifest 不得包含 token、密码、引文正文或研究内容。解析器对未知字段、错误类型和不支持的 manifest format version 显式失败。`mcp.server_name` 只接受 `research-kb`，`checkpoint_policy` 只接受 `one-current`。catalog 摘要文件只由 `[catalog].summary_files` 声明；`components.catalog` 只描述路径和 boundary。

manifest 不是研究数据库，不参与迁移，不创建项目，不导入资料，也不保存研究状态。

## Skill 锁定与漂移

System Manifest 是运行实例唯一的 Skill 哈希权威来源。登记项只允许指向受控 workspace 内实际存在的单个 `SKILL.md`，每项记录 name、相对路径和 SHA-256；不创建第二份 skill-lock 文件。`doctor --deep` 只对 manifest 声明的、位于 runtime root 内的 Skill 根目录执行 bounded inventory，不扫描全局 Skill。

Skill 修改流程是人工控制的：

1. 修改前保留旧 manifest；
2. 修改 Skill 后运行 doctor，预期出现 `skill_hash_drift`；
3. 人工审阅 Skill 修改；
4. 审阅通过后重新计算 SHA-256；
5. 人工更新 manifest；
6. 再次运行 doctor 确认 hash 恢复；
7. Agent 不得自行接受新的 Skill 哈希。

## doctor 只读入口

```text
python -m research_kb.cli --config <config.toml> doctor --json
python -m research_kb.cli --config <config.toml> doctor --manifest <manifest.toml> --json
```

doctor 只打开已有数据库的 SQLite immutable/read-only 连接。它不会调用 migration、创建目录或数据库、创建 default project、reindex、更新 FTS、写 audit、读取论文正文或扫描全部资料；发现非空 WAL 时会 fail closed。默认输出中的本地路径在结构化对象层脱敏为 `<local-path>`、`<unc-path>` 或 `<file-uri>`，相对路径规范化为 `/`，普通 HTTP(S) URL 保留；管理员需要诊断路径时可显式使用 `--show-paths`。manifest 文件自身路径不进入报告。

严重性和退出码固定为：

- `P0`：完整性、schema、protocol 或 MCP readiness 不可用；总状态 `failed`，退出码 `2`。
- `P1`：可能导致 agent 错用、项目映射歧义或多个 current checkpoint；总状态 `warning`，普通模式退出码 `1`。
- `P2`：治理债务，例如旧审批、Skill 漂移、目录摘要缺失或备份信息不足；总状态 `warning`，普通模式退出码 `1`。
- `INFO`：正常检查结果；没有 P0/P1/P2 时总状态 `healthy`，退出码 `0`。

`--strict` 将 warning 的退出码提升为 `2`，但不会把历史治理问题自动修复。默认 doctor 只读取已有 catalog 摘要，并把 MCP 结果标记为 `mcp_tool_contract_declared`；这表示代码声明的契约，不等于已经枚举真实注册。`--deep` 才读取 FastMCP 的实际 `list_tools()` 集合，并比较严格的十二个名称。

`--deep` 的 Skill inventory 固定限制为最大深度 `8`、最大访问目录 `1024`、每目录最大条目 `5120`、最大文件 `4096` 和约 `1` 秒 best-effort 时间预算。只允许扫描 boundary 为 `runtime_root` 且解析后位于 runtime root 内的根；external、越界、symlink、junction 或其他 reparse point 会被拒绝或跳过。达到限制会返回 `skill_inventory_scan_limited`，不会伪装成完整扫描。MCP extra 不可用时返回 P2 `mcp_live_check_unavailable`，不会抛出 traceback；真实集合不匹配是 P0。

## Codex 本地 MCP 安装治理

SG-1B2C 的 `[mcp_authority]` 只治理明确声明的 Codex
`mcp_servers.research-kb-pilot` 子表，不保存或锁定整个
`C:\Users\...\.codex\config.toml` 的哈希。`node_repl`、模型设置、插件设置和其他无关 MCP server 不属于该 authority。

声明至少固定：外部 config 文件 boundary、server name、`stdio` transport、
command、args 顺序、cwd、enabled/required、startup/tool timeout，以及严格
12 个 `enabled_tools`。doctor 只解析一个明确文件，不递归扫描全局目录。

配置缺失、TOML 无效、目标子表缺失、command/args/cwd/状态/timeout 漂移、
HTTP transport、URL、认证字段、`disabled_tools`、危险 env、工具缺失/重复/多出，
均为 P1。`--deep` 运行真实 stdio MCP client 的 initialize/list_tools；失败、
stderr 非空或工具集合不符均明确报告，不输出配置正文、凭据或研究内容。

安装前必须把旧 Codex config 逐字节备份到受控目录，记录旧 SHA-256，使用安全替换，
再验证 TOML、目标子表和官方 client。失败时同时恢复完整旧文件。doctor 不自动修复、
覆盖或接受新的 MCP 配置。

## 项目注册关系

数据库 `projects.project_id` 是运行时项目 ID。manifest 的可选 registry 为每个项目记录：

- `project_id`；
- 相对于 workspace 根目录的 workspace 位置；
- 相对于已配置 corpus root 的逻辑 corpus scope；
- checkpoint policy（SG-1A 只支持 `one-current`）。

workspace mapping 必须是相对于 workspace root 的安全相对路径，不得包含绝对路径、`..`、UNC、设备路径或 `file://`；缺失只报告，不创建目录。corpus scope 也必须是相对于已配置 corpus root 的安全逻辑子路径；越界、无法映射或同时映射到多个 corpus root 时报告 P1，不猜测、不读取 scope 内文献正文，也不把 scope 当作第二份 ingest manifest。doctor 只报告 database project 与 registry 的 orphan/mismatch，以及这些 mapping 问题。archived project 只被报告为 archived，不会被激活。registry 不创建、归档或删除项目。

## Checkpoint、successor、approval 生命周期

checkpoint 作为项目 note 最新版本中带有 `research-checkpoint/v1` 标记的治理记录识别。current checkpoint 是没有 successor、且未被 archived/rejected 的记录。archived 项目返回 `checkpoint_not_required_archived`；没有 research item 的 active 空项目返回 `checkpoint_not_required_empty`。active 且有研究活动时，恰好一个标准 current checkpoint 为 INFO，多于一个为 P1；没有标准 checkpoint 但有旧 note/交接记录为 P2 `checkpoint_legacy_unrecognized`；完全没有 checkpoint/note 为 P2 `checkpoint_zero_current`。details 同时给出 project status、research item count、standard checkpoint count 和 legacy candidate count。doctor 只读取最新版本的 schema 标记、计数和必要状态，不输出 note 正文，不自动转换或写 successor。

SG-1B1 为 `save_research_note` 增加可选 `note_purpose` 与 `supersedes_item_id`，旧客户端保持兼容。标准 checkpoint 的 schema、版本和 metadata 由服务端生成；普通 note 不带 schema，也不受唯一 current 约束。第一个 checkpoint 不带 successor；已有一个 current 时必须在同一 `BEGIN IMMEDIATE` 写事务中 supersede 它；多 current 或无效 target fail closed。旧 checkpoint adoption 由未来人工阶段处理，不能原地覆盖 legacy note。完整协议见 `docs/checkpoint-lifecycle.md`。

已接受条目不可覆盖；后续修改通过 successor 指向旧条目。agent 只能提交 candidate 或 approval request；审批由人工管理员决定。doctor 只检测 pending approval 的重复或超过 freshness window 的情况，不批准、拒绝、删除或改写审批。

## Catalog 生命周期

建议生命周期为：

`cataloged → reviewed → ready → ingested → indexed → available → retired`

catalog 摘要中的就绪、review 和 duplicate-risk 计数只用于诊断阶段与风险。它们不等于正式 ingest，不会触发导入、OCR、索引或 MCP 注册。

## 三类来源语义必须分离

- **document integrity**：内容哈希、来源版本、原始字节和不可变身份是否一致。
- **research role**：来源在项目中的角色，例如背景、理论、反例或比较材料。
- **evidential function**：某个 passage 或 verified evidence 支持、反驳或限定哪条主张。

metadata 的可靠性、来源角色和证据功能不能互相推导，也不能由文件名推断权威性。

## 后续 Skill 分层建议

未来可将治理职责分层为：

- `research-kb-system`：系统 manifest、doctor、兼容矩阵和运行边界；
- `source-based-research`：检索、核验、checkpoint 和证据工作流；
- `source-acquisition`：资料获取、staging 和来源元数据；
- `academic-writing`：论证、引用和交付文本；
- 项目级 `AGENTS.md`：项目局部边界和交接规则。

SG-1A 不删除、移动或重写当前 Skill；实际重构留到 SG-1B。

## SG-1B2 后续清单

以下事项只登记，不在 SG-1B1 实施：

1. stale approval 处理机制；
2. project registry 是否需要正式数据库实体；
3. Source Role Map 是否需要升级为正式实体；
4. Skill 模板生成与版本同步；
5. PDF 探测子进程隔离和 wall-clock timeout；
6. EPUB `author/authors` 兼容问题；
7. Catalog 生命周期正式落地；
8. release/package/schema/protocol 兼容矩阵。
