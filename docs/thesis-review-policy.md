# thesis-review-policy 1.0.0

状态：独立可选能力。`policy_version: 1.0.0`，`schema_version: 1`。
本机制**不修改** SQLite、12 个 MCP 工具、Claim/Link/Event 正式 Schema、主状态机、
`submit_research_report`、`writing_policy.*` 与 `delivery_package.py`。

## 一、目的与边界

`thesis_review` 的对象不是“从零研究一个问题”，而是：

> 给定一篇已经存在的论文，把论文自身的论点、证据、推理和章节关系变成可审计对象，
> 发现真实问题；在人工确认后，再进行范围受控的修改，并检查修改是否引入新的矛盾。

本机制回答五类问题：论证结构、证据、概念一致性、跨章节一致性、竞争解释与审稿人攻击。

## 二、第一约束：Review 与 Revision 分离

### Phase A：Review（默认只读）

- 允许：解析论文、建立论点树、登记 claim、建立 supports/depends_on/opposes/limits 关系、
  核查引用、找矛盾、找证据缺口、提出修改建议。
- 禁止：直接重写论文正文。

### Phase B：Controlled Revision（必须人工批准后）

- 每个修改任务必须是一个 revision item，至少包含：
  `id / severity / location / problem_type / problem_description / evidence /
  recommended_change / allowed_scope / must_preserve / forbidden_changes /
  dependencies / related_claims / human_status`。
- `human_status` 生命周期：`proposed → approved / rejected → completed`。
- Agent 只能在批准范围内修改；不因一个问题顺手重写整章；不引入未经研究的新理论；
  不扩大作者原有论点；不偷偷改变作者立场；新增事实性材料必须进入证据流程。

### 特别禁止

> 为了“让文章更好看”，把 research-risk、Claim、C1/H1 等后台术语写进正式论文。
> 这些只能存在于 review/audit 层。

## 三、建议工作流（阶段）

```text
INGEST
  ↓
ARGUMENT_MAP
  ↓
EVIDENCE_AUDIT
  ↓
SEMANTIC_REVIEW
  ↓
ADVERSARIAL_REVIEW
  ↓
REVISION_PLAN
  ↓
HUMAN_APPROVAL
  ↓
CONTROLLED_REVISION
  ↓
POST_REVISION_AUDIT
```

不引入新的复杂状态机。阶段通过 review/00-review-summary.json 的 `stage` 字段与
每轮 KB checkpoint note 跟踪。

## 四、ARGUMENT_MAP 的抽取纪律

- 不是每句话都登记 claim。
- 优先登记：总论点、章节中心论点、关键定义、关键中间推论、对竞争解释的回应、
  后续章节反复依赖的命题。
- 目标是形成可读的论证地图，而不是把全文碎成几千个原子 claim。

## 五、证据审计纪律

- 每个重要 claim 至少区分：claim → supporting evidence → evidence role →
  claim actually supported → overclaim?
- 引文真实性：来源已入 research-kb 时优先 exact_quote；未入库来源标注证据等级。
- 引文功能：区分“原文确实说了 A”与“原文证明了作者由 A 推出的 B”。
  很多论文真正的问题不是引文错误，而是引文被赋予超过其证明能力的功能。
- 禁止用摘要级材料承担强主张；D 级材料不承担核心判断。

## 六、竞争解释纪律

- 对中心论点生成最强 rival（不制造稻草人），每中心命题最多 2–4 个主要 rival。
- 裁决三分：排除 / 削弱 / 开放（unresolved）。
- rival prediction 失败不能自动等于 primary supported；单反例失败不宣布整个 rival 证伪。
- 不要求每次论文审阅重跑完整 research-risk 项目；thesis_review 比开放研究工作流轻。

## 七、Review 输出

`review/` 目录（模板见 docs/templates/thesis-review/）：

```text
review/
├── 00-review-summary.md / .json     # Critical/Major/Moderate/Minor，人可读
├── 01-argument-map.md / .json       # 论点树
├── 02-evidence-audit.md
├── 03-concept-drift.md
├── 04-cross-chapter-conflicts.md
├── 05-adversarial-review.md
├── 06-overclaims.md
├── 07-literature-gaps.md
├── 08-revision-priorities.md        # 人可读优先级
├── 08-revision-items.json           # 机器可审计的 revision item 注册表
├── revision-audit.md                # Post-Revision 审计
└── versions.sha256                  # 论文版本哈希（可选）
```

- 00-review-summary 必须是给人看的，不充满系统术语；明确哪些问题不改会影响中心结论，
  哪些只是表达质量问题。
- review markdown 是**可读的事实来源**；需要审批/审计的 revision item、重要
  hypothesis/objection、每轮 checkpoint 才登记 KB（note/hypothesis/objection +
  request_user_approval）。

## 八、Post-Revision Audit

修改完成以后不要只比较 diff，重新检查：

1. 修改的问题是否真的解决；
2. 原有证据是否仍然匹配；
3. 有没有引入新的概念漂移；
4. 有没有造成跨章节矛盾；
5. 摘要/导论/结论是否需要同步。

最后生成 `revision-audit.md`，记录：已解决 / 部分解决 / 未解决 / 新发现问题。

## 九、存储要求

- `thesis_review` 不复制研究库中的原始文献。
- 论文正文版本：`thesis-v1.md`、`thesis-v2.md`……保留历史，不覆盖旧稿；
  可选 `versions.sha256` sidecar 记录哈希。
- review markdown、revision records 均为小型文本，完整保留。

## 十、启用方式

项目通过 `projects.config_json.thesis_review` 显式启用（默认关闭）：

```json
{
  "thesis_review": {
    "enabled": true,
    "paper_id": "lukacs-contemporary-v2",
    "thesis_path": "04-output/lukacs-contemporary-paper-v4.1.md",
    "review_dir": "thesis-review",
    "stages": ["ingest", "argument_map", "evidence_audit", "semantic_review", "adversarial_review", "revision_plan"]
  }
}
```

- Review 阶段：`python -m research_kb.thesis_review init <review_dir> --paper <thesis>`
  与 `validate <review_dir>`；也可用 `research-kb thesis-review init|validate`。
- 修订批准（v1 集成说明）：现有 approval 只接受 candidate 状态，而 `save_research_note` 只产出 draft。
  v1 的映射是：revision item 以 `submit_hypothesis`（status=candidate）登记，标题前缀 `thesis_review: revision <id> (proposed)`，
  claim 内嵌 problem/recommended_change/allowed_scope/must_preserve/forbidden；`human_status` 以 `08-revision-items.json` 为准；
  然后 `request_user_approval(target_type="research_item")` → Admin CLI `approval decide`。
  不新增 note 的 candidate 写入路径，也不新增 revision kind（保持核心不变）。

## 十一、第一轮验收标准

停在 REVISION_PLAN，人工检查：①发现的是不是真问题；②伪问题比例；③漏检明显问题；
④是否尊重作者理论意图；⑤能否区分“证据不足”与“我不同意作者”。
通过后再开放 Phase B（Controlled Revision）。