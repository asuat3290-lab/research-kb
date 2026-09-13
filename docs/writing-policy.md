# research-kb 写作政策

本文件是面向人的写作政策规范。机器执行的权威配置是
`src/research_kb/writing_policy.json`，两者必须保持同一版本；测试会检查本文件中的
`policy_id` 与 `policy_version` 和 JSON 是否一致。

```yaml
policy_id: default-writing-policy
policy_version: 1.2.0
schema_version: "1"
```

## 一、三层交付结构

研究成果按交付层拆分，避免把研究过程、审计状态和写作规则写进正式论文：

| 层 | 默认 profile | 内容 | 系统内容 |
| --- | --- | --- | --- |
| A | `academic_paper` | 摘要、导论、研究史、正文、比较性结语、结论、脚注、参考文献 | 原则上禁止 |
| B | `method_appendix` | 定义句与功能句、证据等级、桥梁强度、五项检验、证据投射表、命题变更、未决问题、研究史核验记录 | 允许研究方法信息 |
| C | `technical_report` | exact-quote 结果、REVIEW 状态、PENDING_PAGE、审批请求、Claim/Link/Event、锚点映射、审计错误与警告、版本迁移、扩写与压缩日志 | 允许完整系统信息 |

一次研究可以提交一个交付包，包含 A、B、C 三份文件和一个 `manifest.json`。三份文件
分别按各自 profile 审计，不因为同属一个交付包而混用规则。

## 二、配置继承顺序

政策合并顺序固定为：

```text
系统默认政策 -> 成果类型 profile -> 项目配置 -> 单次 report_manifest 配置
```

- `locked.fields` 是系统底线，任何层级都不能覆盖：
  `policy_id`、`policy_version`、`deliverable_layer`。
- `overridable_fields` 允许项目或单次提交覆盖：`budget`、
  `extra_forbidden_terms`、`allowed_sections`、`compression_review_options`。
- 数组字段默认追加：`extra_forbidden_terms`、`allowed_sections`；
  `compression_review_options` 为替换。
- 最终解析后的政策快照写入 `report_manifest`，旧报告在任何时候都可按提交时政策复现。

项目配置放在 `projects.config_json.writing_policy`；单次提交通过
`submit_research_report` 的 `writing_policy_overrides` 传入。

## 三、profile

支持四种 profile：

| profile | deliverable_layer | 软预算（字符） | 旁注要求 |
| --- | --- | --- | --- |
| `academic_paper` | A | 40000–55000 | 受管草稿要求 `argument_gain` |
| `method_appendix` | B | 0–60000 | 否 |
| `technical_report` | C | 不限 | 否 |
| `research_memo` | 无固定层 | 不限 | 否 |

软预算是预警而不是硬验收。超出预算时必须说明新增篇幅增加了哪一种论证增量。

## 四、规则类型与四级结果

审计器按 profile 运行规则，输出统一四级结构：

```json
{
  "errors": [],
  "warnings": [],
  "review_items": [],
  "approval_blockers": []
}
```

规则类型：

- `forbidden_term`：禁用词，按 profile、allowlist 和忽略区执行；
- `regex`：正则规则，按 profile、allowlist 和忽略区执行；
- `budget`：软篇幅预算；
- `section_numbering`：补丁式编号或同一章节内编号倒序；
- `required_section`：该 profile 要求的必备部分；
- `required_section_content`：必备部分非空或条目数量不足；
- `footnote_integrity`：脚注引用与定义完整性；
- `bibliography`：参考文献条目数量；
- `bibliography_completeness`：参考文献按类型检查作者、题名、出版社/期刊/容器与年份（默认 review item）；
- `citation_surface`：研究者表述表面匹配（默认关闭）；
- `argument_gain`：受管草稿的论证单元后台标注覆盖；
- `compression_duplicate` 与 `compression_limit_echo`：压缩审查专用；

忽略区包括代码块、行内代码、HTML 注释、front matter；A 层系统信息规则同时扫描脚注定义与参考文献（`system_leakage_scope: all_visible_text`），代码块与后台注释仍忽略。
`approval_blockers` 主要对 A 层有效；B/C 层默认不产生该桶。

## 五、A 层禁用内容

正式论文正文禁止出现：

```text
v6.3
本轮
用户要求
字符目标
exact-quote
verified_evidence_id
OCR-normalized
Claim
Link
Event
maps_to
锚点
REVIEW
APPROVED
PENDING_PAGE
审批阻断
审计脚本
系统状态
research-core
Admin CLI
```

同时禁止汇报审批、等待人工批准、流程状态、扩写、压缩或字数过程。这些内容属于 B 层
方法附录或 C 层技术报告。

## 六、argument_gain 后台标注

每个重要论证单元只要求五项：局部命题、关键证据、解释步骤、竞争解释、阶段结论。
新增段落必须通过论证增量测试。

`argument_gain` 允许六类增量：

```text
new_evidence
new_inference
concept_distinction
rival_interpretation
revision
unresolved_mechanism
```

旁注不进入公开正文。受管草稿写在 Markdown 注释中：

```markdown
<!-- writing:
section_id: ch5-time-abstraction
argument_gain:
  - new_inference
  - concept_distinction
-->
```

外部导入草稿可用 sidecar JSON 补充，例如：

```json
{
  "ch5-time-abstraction": {
    "argument_gain": ["new_inference", "concept_distinction"]
  }
}
```

导出 A 层正式论文时自动移除旁注。

public 导出只允许删除 writing 旁注和规范化空行；导出前执行 parity 校验
（H1-H3 标题集合及顺序、摘要非空、脚注引用与定义集合、表格数量、直接引语数量、
参考文献条目数），parity 失败时不写 public 文件。

## 七、压缩审查

`compression_review` 状态固定为：

```text
not_required
pending
passed
returned
```

压缩审查检查八项：同一命题三处重复、同一组引文重复解释、同一限制反复展开、方法内容
侵入正文、补丁式编号、研究史重复介绍、结论包含项目状态、论证单元缺少 `argument_gain`。
压缩审查只删除不增加论证信息的内容，不做摘要化。

## 八、提交契约

`submit_research_report` 不隐式重跑写作审计。审计先运行，提交时验证提交条件并登记
审计摘要：

```json
{
  "deliverable_layer": "A",
  "artifact_profile": "academic_paper",
  "writing_policy_version": "1.2.0",
  "compression_review_status": "passed",
  "writing_audit_summary": {
    "errors": 0,
    "warnings": 0,
    "review_items": 0,
    "approval_blockers": 0
  }
}
```

完整审计报告保存为文件或 artifact，`writing_audit_summary` 只保存四个非负整数计数。

Delivery package manifest v2 在旧字段之外增加 `manifest_version`、`created_at`、`package_state`、
`artifact_audit`、`research_approval`、`final_approval`、
`supporting_artifacts` 和 `policy_snapshot_sha256`。旧 manifest 仍可读取，校验结果
标记 `legacy` 与 `migration_recommended`；`upgrade_manifest` 生成 v2 副本而不原地覆盖。

## 审计可复现性

每次审计都会把最终解析后的政策快照写入结果，并输出一个规范化的
`policy_fingerprint`（对去除 `_meta` 后的快照做确定性 SHA-256）。提交审计报告时，
`policy_fingerprint` 与快照一起保存，之后可以用相同的快照重新运行审计并核对指纹。

审计 CLI 支持四种与解析相关的输入：

- `--policy JSON`：指定完整政策文件；
- `--project-config JSON`：指定项目配置中的 `writing_policy`；
- `--policy-overrides JSON`：指定单次 `report_manifest` 覆盖；
- `--policy-snapshot JSON`：直接复用已经解析并验证过的政策快照，
  与 `--policy-overrides` 互斥，且快照 profile 与 `--profile` 必须一致。

## 交付包哈希绑定

一次研究可以提交一个交付包：A、B、C 三份文件和 `manifest.json`。每份文件与对应的
审计 JSON 都必须有 SHA-256，manifest 还保存包级 `package_sha256`（对按文件名排序的
工件哈希摘要计算），用于发现缺文件、换文件或哈希漂移。

校验器按层约束 profile：A→`academic_paper`，B→`method_appendix`，C→`technical_report`。
它还会核对审计 JSON 的 profile、policy_version、policy_fingerprint、`source_path`
文件名和四级计数摘要，但不会在提交时重新执行写作审计。审计先运行，提交只验证
哈希、政策版本和阻断状态。

命令行示例：

```text
python -m research_kb.delivery_package path/to/manifest.json
```

## legacy 回归

v6.2、v6.3 的历史审计输出被保存为 golden fixtures
（`tests/fixtures/writing/legacy-v62.json`、`legacy-v63.json`），只比较规则 ID、
严重级别、数量和关键对象语义，不要求时间戳、绝对路径或 JSON 字段顺序逐字一致。
任何 profile、规则或审计结构的变更都必须先通过这两份 fixtures 的回归测试。
