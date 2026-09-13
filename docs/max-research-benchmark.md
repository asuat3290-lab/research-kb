# Max Research v1 MR-0 benchmark 与验收矩阵

本 benchmark 是确定性契约测试设计，不是模型质量 benchmark。所有 fixture 都
是内存对象；不访问真实 pilot 数据库、WAL/SHM、corpus、catalog、网络或模型。

## 1. 规范化与身份

| case | 预期 |
| --- | --- |
| mapping 插入顺序不同 | charter hash 相同 |
| question/scope/model/budget/source policy/quality gate 任一改变 | hash 改变 |
| 非 NFC 字符与 NFC 等价表示 | hash 按 NFC 规范化 |
| 非法 kind/project/opaque ID | fail closed |
| 同一 stable/version 重复或 version gap | fail closed |
| relation 两端 project 不同 | fail closed |

## 2. 启动与状态机

| case | 预期 |
| --- | --- |
| 缺少 approval | AWAITING_START_APPROVAL 不能进入 APPROVED/RUNNING |
| run/project/charter/model/budget/source-policy 任一不匹配 | approval 失效 |
| 过期或已消费 approval | fail closed，不能重放 |
| terminal state 再转换 | fail closed |
| model identity、budget 或 source policy 变化 | 旧 approval 失效 |

## 3. Canonical graph、checkpoint 与 rebuild

fixture 会覆盖：

- Claim → Evidence Link → Evidence → Passage → Document Version 完整链；
- summary-only claim、orphan claim 和没有 Document Version 的 Evidence；
- checkpoint 嵌入无 ID 的 formal Claim/Evidence；
- state 从 objects/versions/relations 重建后 hash 稳定；
- 100 轮 summary rehydration 不改变 canonical graph；
- checkpoint one-current、单 successor、无环；
- cold review packet 拒绝 working summary 或历史推理替代 canonical input。

## 4. Deliberation、收敛与投影

fixture 会覆盖：

- active leading hypothesis 没有足够 attack 时 Completion Gate 失败；
- 缺 rival、canonical evidence 或 minority preservation 时 adjudication 失败；
- 同一 family/query/targets/filters 重复不增加 strategy saturation；
- required strategy family 未覆盖时 Completion Gate 失败；
- acquisition 缺 gap、information gain 或 falsification 时失败；
- speculative idea 不能直接成为 supported Claim/report conclusion；
- report claim 无法追溯到 canonical evidence 时失败；
- valid report projection 只能来自当前 Research State。

## 5. 回归与交付验收

MR-0 交付前应执行：

1. `compileall`；
2. `tests/test_max_research_contracts.py`；
3. 完整 unittest；
4. 官方 MCP client exact-12 检查；
5. wheel/sdist 构建和内容检查；
6. 干净 venv 离线安装与 `pip check`；
7. UTF-8/BOM、连续半角问号、replacement character、常见 mojibake 扫描；
8. 真实 pilot 默认 doctor 与 manifest/deep doctor 只读检查；
9. 真实 pilot database/WAL/SHM、schema/migration、corpus/catalog/workspace、
   Skill/manifest 前后签名核对。

若受限沙箱不能创建 Windows MCP stdio 管道，必须报告 `sandbox-limited`，并
同时提供默认 doctor、进程内 live registry 和沙箱外官方 MCP client 证据；不能
把受限环境伪装成 deep doctor 成功。

MR-0 完成后停止。Migration、runner、scheduler、provider adapter、网络获取、
真实 Max Run 和数据库写入全部留给人工批准后的 MR-1。

## 6. MR-0A invariant regression matrix

The independent repair round covers the following failures and their required
fail-closed outcomes:

| invariant | regression outcome |
| --- | --- |
| object version identity | distinct semantic objects have distinct version IDs; forged IDs fail |
| acquisition/speculation identity | same-project requests and ideas use complete semantic IDs |
| explicit approval | missing decision, actor, authority or approval ID fails |
| approval consumption | one consume on start; resume never re-consumes |
| run completion | invalid state transitions and boolean-only completion fail |
| relation binding | endpoint versions and relation ID must agree |
| evidence trace | direct evidence bypass, stale relation and unverified final evidence fail |
| report projection | source links must equal the exact canonical projection |
| checkpoint frontier | working frontier is exact; embedded formal payload fails |
| lineage/rehydration | branches, deletion, same-version drift and extra objects fail |
| speculation | v1 cannot jump directly to supported |
| deliberation | packet contamination, missing audit dimensions and fake minority IDs fail |
| cold review | working-context contamination and fake links fail |
| saturation/completion | duplicate strategy and caller booleans do not count |

The staged suite contains 21 tests, including a synthetic 100-round drift
loop. It is run against the isolated package before any synchronization to the
existing project. Build, offline installation, `pip check`, UTF-8/BOM scan,
exact-12 MCP registry checks and read-only pilot signature checks remain part of
the handoff. A Windows MCP stdio creation error in the restricted execution
environment is reported as `sandbox-limited`; it is never downgraded inside the
doctor or MCP implementation.
## MR-0B Adversarial Contract Benchmark

The MR-0B benchmark includes independent regression cases for fabricated
completion results, stale state, nested binding mismatches, placeholder and
orphan attacks, packet-only cold review, blocking findings, inconsistent
validity audits, state-external discussion IDs, missing ledgers, all four
saturation dimensions, typed formal evidence, evidence eligibility, provisional
claim projection, exact per-evidence source-link paths, immutable approval
consumption, complete cold-review exclusions, and deterministic evaluator
replay.

The completion evaluator is a pure function. Repeating the same typed input
produces byte-identical gate/result projections. Changing an epistemic field
changes the input hash, gate hash, and result ID. The benchmark also retains
the MR-0A 100-round rehydration drift loop and ID/version/relation/speculation
regressions.
