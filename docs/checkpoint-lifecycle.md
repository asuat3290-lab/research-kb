# Checkpoint lifecycle

本文件定义 SG-1B1 的 checkpoint 运行协议。checkpoint 是项目研究状态的恢复点，不是另一份研究数据库，也不是对 legacy note 的自动迁移。

## Research note 与 checkpoint

`save_research_note` 保留原有三参数调用：`project_id`、`title`、`body`。未提供新参数时，或显式使用 `note_purpose="research_note"` 时，服务端保存普通 draft note：

- payload 不带 `research-checkpoint/v1` schema；
- 不参与唯一 current checkpoint 规则；
- 不自动成为 checkpoint；
- `supersedes_item_id` 只对 `note_purpose="checkpoint"` 有效，普通 note 传入该字段会被拒绝。

checkpoint 使用同一个 MCP 工具的可选参数：

```text
note_purpose="checkpoint"
supersedes_item_id=null | "<current-item-id>"
```

服务端生成的 payload 至少包含：

```json
{
  "schema": "research-checkpoint/v1",
  "checkpoint_version": 1,
  "title": "<validated title>",
  "body": "<validated body>",
  "checkpoint_metadata": {
    "project_id": "<server-owned>",
    "created_by": "<server-owned>",
    "session_id": "<server-owned>",
    "created_at": "<server-owned>"
  }
}
```

客户端不能通过 body 覆盖顶层 schema、版本或 metadata。project、actor、session 和时间由服务端从已验证的请求上下文生成；token 不进入 payload、audit 参数或日志。source links 仍只由服务端从 append-only evidence links 生成。

## Current、superseded、archived、rejected

- **current**：最新 payload 带有 `research-checkpoint/v1`，item 未被 `archived` 或 `rejected`，并且不存在任何 successor。
- **superseded**：另一个 item 的 `supersedes_item_id` 指向它。旧 item 保留，不覆盖、不删除。
- **archived**：治理上不再活动；archived item 不能作为 checkpoint successor target。
- **rejected**：被拒绝的 item 不能作为 checkpoint successor target。

一个 active 项目最多允许一个 standard current checkpoint。第一个 checkpoint 的 `supersedes_item_id` 必须为空；已有一个 current 时，新 checkpoint 必须指向它；多个 current、缺失 target、跨项目 target、普通 note target、非 note target、已被 successor 指向的 target，以及 rejected/archived target 都 fail closed。创建 checkpoint 的 current 查询、target 校验和 successor 插入在同一个 `BEGIN IMMEDIATE` 写事务中完成，因此并发 supersede 同一 current 时最多一个请求成功。普通 research note 不受这个唯一性约束。

`get_research_context` 通过稳定 `item_id` 和 bounded section read 恢复 checkpoint。新会话应先读取项目的 lightweight index，再读取未被 successor 指向的 current checkpoint；大 body 必须按 `offset`/`next_offset` 分段恢复。

## Legacy checkpoint

本轮不转换真实 pilot 中的 legacy checkpoint。doctor 只读取最新版本的 schema 标记和必要状态，并继续报告没有 standard current 但存在旧 note/交接记录的项目为 `checkpoint_legacy_unrecognized` P2。archived 项目和没有任何 research item 的 active 空项目不要求 current checkpoint。

未来人工 adoption 必须：

1. 先读取并确认旧 checkpoint 的内容和所属项目；
2. 明确记录 adoption 决策及其人工批准边界；
3. 使用标准 payload 创建新的 checkpoint successor（若存在 standard current，则指向该 current）；
4. 保留旧 note，不原地覆盖、不删除、不伪装为已迁移；
5. 再由 doctor 验证唯一 current。

本轮 pilot 中的两个 legacy P2 保留，等待后续人工 adoption 阶段。

## Successor invariant correction

The shared item creation path is the enforcement point for checkpoint
successors. If a supersedes target is a standard checkpoint, the new item
must be a server-generated standard checkpoint. Hypotheses, reports,
objections, ordinary research notes, and any other non-checkpoint item are
rejected before an item, version, evidence link, or audit row is written.

Checkpoint current detection, target classification, successor conflict
checking, and insertion remain in one `BEGIN IMMEDIATE` transaction. A
historical non-standard successor of a standard checkpoint is not repaired or
reconnected automatically. Doctor reports it as the P1 finding
`checkpoint_cross_kind_successor` with governance identifiers and statuses
only. Such a database is fail-closed for a new checkpoint root until manual
governance resolves the history.
