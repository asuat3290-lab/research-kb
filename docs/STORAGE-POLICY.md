# research-kb 存储策略（STORAGE-POLICY）

版本：1.0（2026-08-07）。本策略由存储优化项目确立，约束所有项目工作区与语料管理。

## 1. 核心原则

- **文献数量决定主存储**：项目数量只应增加结构化文本（claims/links/events/报告），不应复制原始文献。
- **原始文献唯一存放**：所有原始文件（PDF/扫描件）与 canonical extracted text 只保存在 `corpus/`（corpus_roots），项目工作区一律不得复制正文副本。
- **项目引用**：项目对文献的引用必须走 `project_sources`（document_id）或 `source_ref` 清单（文件路径+SHA），不复制文件。
- **审计性不牺牲**：Tier 1/2 数据长期保留；只有 Tier 3 数据可主动清理。

## 2. 存储分层

| Tier | 内容 | 处置 |
|---|---|---|
| Tier 1 永久保留 | 原始文献（corpus）、canonical extracted text、SQLite（documents/passages/claims/links/events/verified_evidence/audit）、approved report、审批记录 | 不删除、不压缩 |
| Tier 2 历史保留 | 旧 draft、旧 audit、旧 manifest、search history、项目历史版本目录 | 半年/一年打包 `.tar.zst` 归档，保留审计性 |
| Tier 3 随时可删 | 临时检索结果、debug logs、缓存、中间导出、OCR 派生产物、可重新生成的 build artifacts、`__pycache__` | 可 30 天清理或立即清理 |

## 3. 禁止事项

- 禁止把 corpus 中的文件复制到项目工作区（含"方便离线阅读"的理由）。
- 禁止在项目目录保存 PDF 的 OCR 派生副本；OCR 产物如需保留，必须可重新生成并标注来源。
- 禁止把同一抽取文本同时保存在 corpus 与项目目录。

## 4. 防复制检查

使用只读检查命令（不修改任何文件）：

```powershell
python -m research_kb.cli --config <config.toml> storage-check --scan <项目目录>
```

输出会报告：与 corpus 完全重复的文件（项目复制）、扫描目录内部重复组、可回收字节数。若输出 `corpus_duplicate_files > 0`，说明项目工作区存在 canonical 副本，应删除项目副本并改用引用。

## 5. 新项目初始化检查清单

1. 项目目录只创建结构化文件（notes/drafts/reports），不放置文献文件。
2. 文献引用使用 `source_ref.md`（路径+SHA）或 `project_sources`。
3. 项目创建后运行一次 `storage-check --scan <项目目录>`，应返回 0 个 corpus 重复。
4. 下载新文献统一先入 corpus（或 corpus 索引的 staging），再 ingest；不放入项目目录。

## 6. 清理规则

- Tier 3 目录（`.cache/`、`tmp/`、`staging/`、`__pycache__`、OCR 派生产物）可随时删除，删除前记录清单。
- 删除 Tier 1/2 数据需人工确认并留痕（清单+SHA）。
- 每次清理后更新 storage audit 报告。