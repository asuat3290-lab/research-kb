# research-risk-policy 1.1.0

状态：系统级能力。`policy_version: 1.1.0`，`schema_version: 1.1`。

## 一、目的与边界

本机制用于回答三类不同的问题：

1. 交付系统是否可靠（由既有交付管道负责）；
2. 研究设计是否允许失败（本机制负责）；
3. 某个具体连续性判断是否经得起竞争解释（由项目级审计负责）。

1.1 把风险审计从形式字段检查升级为具有时间一致性的研究风险审计：

- 设计、结果、裁决分离为三个文件；
- 结果与裁决通过 `design_sha256` 绑定不可变设计；
- 材料角色区分 `discovery` 与 `design_evidence`；
- 观测记录区分锁定前已知与锁定后新结果；
- 正区分性证据必须同时满足锁定后观测、锁定时结果未知、支持主假设预测、与主要竞争假设有方向差异四项条件。

本机制是独立的可选系统能力，不修改 SQLite、12 个 MCP 工具、
Claim/Link/Event 正式 Schema、主状态机、`submit_research_report`、
`writing_policy.*` 与 `delivery_package.py`。

新增文件：

```text
src/research_kb/research_risk.schema.json   # Schema 1.1
src/research_kb/research_risk.py            # 独立审计器
docs/research-risk-policy.md                # 面向人的政策文档
tests/test_research_risk.py                 # 单元测试
tests/fixtures/research_risk/*.json         # 匿名 fixtures
tests/fixtures/research_risk/tri_file/*.json # 三文件 fixtures
```

## 二、启用方式与级别

风险机制默认关闭。项目通过设计文件显式启用：

```json
{
  "schema_version": "1.1",
  "enabled": true,
  "policy_level": "genealogical",
  "design_version": 1,
  "design_status": "locked"
}
```

允许级别：

| 级别 | 含义 | 系统强制项 |
| --- | --- | --- |
| `none` | 翻译、书目、引文核验等 | 无 |
| `interpretive` | 单篇细读、概念解释 | 风险承担命题、至少 1 个竞争解释、明确失败条件 |
| `comparative` | 跨文本/作者比较 | 上一级 + 区分性预测、负面对照 |
| `genealogical` | 思想连续、概念谱系 | 上一级 + 多个竞争假设、共同来源假设、历时连接证据、留出或验证材料、撤回分支 |
| `causal` | 因果机制解释 | 上一级相关部分 + 机制链、替代机制、机制失败条件、反事实或区分性证据 |

`enabled=false` 或 `policy_level=none` 时，审计不产生任何 findings，
不阻断普通项目。`research_risk_policy: {enabled, level}` 包装块与顶层
字段等价，代码先读包装块。

## 三、三文件模型

新项目使用三个文件：

```text
research-risk-design.json         # 研究设计，含 H、标准、预测、材料、分支
research-risk-results.json        # 假设状态、正区分性证据、观测
research-risk-adjudication.json   # 裁决版本与逐假设裁决
```

`results` 与 `adjudication` 都保存设计文件的不可变哈希：

```json
{
  "schema_version": "1.1",
  "design_version": 1,
  "design_sha256": "..."
}
```

CLI 运行时校验：

```text
hash(current design) == design_sha256 referenced by results/adjudication
```

不一致时报告 `LOCKED_DESIGN_HASH_MISMATCH`。设计发生合法修改时，必须
递增 `design_version` 并重新锁定；旧结果仍绑定旧哈希。单文件入口已标记
为 deprecated，仅用于读取既有项目；新项目不得把结果和裁决写回设计文件。

规范哈希按以下方式计算：

```text
SHA-256(UTF-8(json.dumps(design, sort_keys=True, ensure_ascii=False)))
```

计算前将 `\r\n` 与 `\r` 统一为 `\n`，保证跨平台可复现。

## 四、材料角色

`materials[].evidence_role` 枚举：

- `discovery`：用于发现问题、生成候选方向的材料；
- `design_evidence`：已经进入正式研究设计，用于定义假设、标准、预测或
  证伪条件的材料，必须声明 `design_impacted=true`；
- `holdout`：锁定后保留、未参与设计形成的材料；
- `negative_control`：用于负面对照的材料；
- `validation`：锁定后验证材料；
- `background`：背景材料。

材料一旦影响正式设计，应从 `discovery` 升级为 `design_evidence`。
`design_impacted=true` 但角色不是 `design_evidence`，或
`design_evidence` 未声明 `design_impacted=true`，都报告
`EVIDENCE_ROLE_STALE`。

## 五、观测与正区分性证据

`observations[]` 记录单个观测结果：

```json
{
  "id": "O1",
  "evidence_class": "source_texts",
  "outcome": "...",
  "known_before_lock": false,
  "observed_at": "2026-08-07T12:00:00+08:00",
  "observation_scope": "..."
}
```

`known_before_lock` 判断该具体观测结果在锁定前是否已经进入研究设计，
不是判断材料文件是否早就在本地存在。

完成的验证必须包含锁定后观测。已完成的验证若把锁定前已知观测当作
证据，报告 `VALIDATION_EVIDENCE_CONTAMINATED`。锁定后要求验证但已完成
验证中没有 `known_before_lock=false` 的观测，报告
`POST_LOCK_VALIDATION_MISSING`。

正区分性证据必须满足四项条件：

```text
positive_discriminating_evidence requires:
1. observed_after_lock = true
2. outcome_unknown_at_lock = true
3. supports_primary_prediction = true
4. discriminates_against >= 1 major rival
```

主假设状态为 `supported` 或 `partially_supported` 但没有任何正区分性
证据时，报告 `PRIMARY_SUPPORTED_BY_RIVAL_FAILURE_ONLY`。

## 六、裁决契约

`hypothesis_statuses` 与 `verdicts` 使用同一状态枚举：

```text
supported / partially_supported / not_falsified /
unresolved / weakened / falsified / unadjudicated
```

裁决版本保存在 `adjudication.json`。结果与裁决不得写回设计文件；
设计文件中出现结果或裁决键时报告 `DESIGN_RESULT_MIXED`。

锁定的设计至少保留一个 `status_at_lock="genuinely_open"` 的证伪条件；
否则报告 `NO_OPEN_FALSIFICATION_CONDITION`。

## 七、审计规则目录

输出沿用四级桶：`errors / warnings / review_items / approval_blockers`。

| rule_id | 适用级别 | 桶 | 触发条件 |
| --- | --- | --- | --- |
| `SCHEMA_INVALID` | 全部 | errors | 结构不合法 |
| `RISK_BEARING_MISSING` | interpretive+ | errors + blockers | 无风险承担命题 |
| `FAILURE_EFFECT_MISSING` | interpretive+ | errors | 失败效果为空 |
| `PRIMARY_HYPOTHESIS_MISSING` | interpretive+ | errors | 无主假设 |
| `RIVAL_HYPOTHESIS_MISSING` | interpretive+ | errors + blockers | 无竞争假设 |
| `FALSIFICATION_CONDITIONS_MISSING` | interpretive+ | errors | 无证伪条件 |
| `HYPOTHESIS_PREDICTIONS_MISSING` | interpretive+ | warnings | 假设无预测 |
| `RIVAL_HYPOTHESIS_NOT_DISCRIMINATING` | comparative+ | warnings | 两假设预测完全相同或过相似 |
| `OUTCOME_BRANCHES_MISSING` | interpretive+ | errors + blockers | 结果分支为空 |
| `ALL_OUTCOMES_PRESERVE_PRIMARY_HYPOTHESIS` | interpretive+ | errors + blockers | 所有结果都保留主解释 |
| `NEGATIVE_CONTROL_MISSING` | comparative+ | errors（锁定后加 blockers） | 必需负面对照缺失 |
| `NEGATIVE_CONTROL_NOT_COMPLETED` | comparative+ | warnings（锁定后加 blockers） | actual_result 为空 |
| `NEGATIVE_CONTROL_NOT_COMPARABLE` | comparative+ | warnings | 未声明同一标准 |
| `NEGATIVE_CONTROL_PASSES_PRIMARY_CRITERIA` | comparative+ | errors | 对照也满足主标准 |
| `MATERIALS_MISSING` | genealogical+ | errors | 无材料登记 |
| `VALIDATION_OR_HOLDOUT_MISSING` | genealogical+ | errors + blockers | 无留出或验证材料 |
| `HOLDOUT_CONTAMINATED` | genealogical+ | errors + blockers | holdout 在锁定前已被使用 |
| `SHARED_SOURCE_RIVAL_MISSING` | genealogical | errors | 无共同来源竞争假设 |
| `DIACHRONIC_EVIDENCE_MISSING` | genealogical | errors | 无历时连接证据 |
| `MECHANISM_CHAIN_MISSING` | causal | errors | 无机制链 |
| `ALTERNATIVE_MECHANISM_MISSING` | causal | errors | 无替代机制 |
| `MECHANISM_FAILURE_CONDITIONS_MISSING` | causal | errors | 无机制失败条件 |
| `COUNTERFACTUAL_EVIDENCE_MISSING` | causal | warnings | 无反事实证据 |
| `DESIGN_DRIFT_UNDISCLOSED` | 全部 | errors + blockers | 版本变化无历史记录 |
| `POST_HOC_CRITERIA_RELAXATION` | 全部 | warnings | 见证据后放宽标准但未完整记录 |
| `LOCKED_AT_MISSING` | 全部 | errors | locked 但无 locked_at |
| `ADVERSARIAL_REVIEW_INCOMPLETE` | genealogical+ | blockers | 锁定后独立反证审查未完成 |
| `VALIDATION_INCOMPLETE` | genealogical+ | blockers | 锁定后验证未完成 |
| `CONTRIBUTION_TYPE_MISMATCH` | 全部 | errors | 贡献类型与证据结构不匹配 |
| `BRIDGE_STRENGTH_AGGREGATED` | 可选 | warnings | 桥梁只给单一 high 而无维度拆分 |
| `CRITERIA_EXCLUSION_MISSING` | comparative+ | review_items | 判定标准缺排除测试 |
| `RIVAL_SIMPLICITY_REVIEW` | comparative+ | review_items | 竞争解释缺简约性说明 |
| `DESIGN_CHANGE_REVIEW` | 全部 | review_items | 设计修改缺旧设计结果说明 |

1.1 新增规则：

| rule_id | 触发条件 |
| --- | --- |
| `NO_OPEN_FALSIFICATION_CONDITION` | 锁定设计没有 `genuinely_open` 证伪条件 |
| `PRIMARY_SUPPORTED_BY_RIVAL_FAILURE_ONLY` | supported/partially_supported 无正区分性证据 |
| `POST_LOCK_VALIDATION_MISSING` | 已完成的验证没有锁定后观测 |
| `VALIDATION_EVIDENCE_CONTAMINATED` | 已完成的验证使用锁定前已知观测 |
| `CHRONOLOGY_USED_AS_CONNECTION_EVIDENCE` | 仅年代顺序被当作谱系/因果贡献证据 |
| `CONTRIBUTION_EXCEEDS_BRIDGE_STATUS` | 谱系/因果贡献超过桥梁维度的已证状态 |
| `NEGATIVE_CONTROL_OVERGENERALIZED` | 负面对照未声明所测试的假设 |
| `DESIGN_RESULT_MIXED` | 结果或裁决数据写回设计文件 |
| `EVIDENCE_ROLE_STALE` | 材料角色与 `design_impacted` 不一致 |
| `LOCKED_DESIGN_HASH_MISMATCH` | results/adjudication 哈希与当前设计不一致 |

## 八、CLI

```text
python -m research_kb.research_risk research-risk-design.json \
  --results research-risk-results.json \
  --adjudication research-risk-adjudication.json \
  --manifest research-risk-audit.json \
  --markdown research-risk-audit.md \
  --strict
```

JSON 输出包含：`schema_version`、`policy_version`、`policy_level`、
`design_status`、`design_version`、`design_sha256`、
`design_hash_status`、四级 findings、`input_sha256`、`source_path`、
`summary`。`--strict` 在存在 errors 或 approval_blockers 时以状态 1 退出。

## 九、通用 fixtures

根目录 fixtures 覆盖结构规则；`tri_file/` 覆盖三文件、哈希绑定、观测与
裁决契约。新规则对应的匿名测试项目包括：

```text
valid-genealogical.json                有效风险设计，0 findings
pseudo-rival.json                      伪竞争假设
never-fail.json                        永不失败设计
holdout-contaminated.json              holdout 污染
design-drift.json                      未记录设计漂移
negative-control-fails.json            负面对照失败
risk-bearing-missing.json              风险承担缺失
contribution-mismatch.json             贡献类型错配
bridge-aggregated.json                 桥梁强度聚合
disabled.json                          关闭政策
no-open-falsification.json             锁定后无开放证伪条件
chronology-only.json                   年代顺序冒充连接证据
contribution-exceeds-bridge.json       贡献超过桥梁状态
control-overgeneralized.json           负面对照未声明测试假设
design-result-mixed.json               结果写回设计文件
evidence-role-stale.json               材料角色过期
tri_file/valid                         三文件有效设计
tri_file/post-lock-missing             验证完成但无锁定后观测
tri_file/validation-contaminated       验证使用锁定前观测
tri_file/rival-failure-only            无正区分性证据的有限支持
tri_file/hash-mismatch                 设计哈希不一致
```
