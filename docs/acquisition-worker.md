# 文献获取 Worker

`research-kb-acquisition` 是一个可选的**外部**文献获取 Worker。它只负责把候选文献抓取到 staging 目录并生成 manifest，不写入权威数据库，也不新增 MCP 工具。

## 定位与边界

- 只使用公开合法的开放获取来源：Unpaywall、OpenAlex、SEP 等公开页面。
- 不绕过付费墙，不访问需要权限的下载链接；解析不到开放获取版本的文献进入 `manual-queue.jsonl`，由人工下载后走正常 ingest 流程。
- Worker 输出到 `--output` 下的一次性 run 目录，属于 staging 产物；正式入库仍由 Admin CLI 的 manifest ingest 完成。
- 不修改 `mcp_server.py`。MCP 工具面保持 12 个工具不变。

## 工作流

1. 从 SEP 条目（或用户提供的其它 SEP slug/URL）抓取条目页面，解析标题、出版信息、参考文献和 related entries。
2. 对每条参考文献提取 DOI、年份、标题候选和 URL。
3. 有 DOI 时先查 Unpaywall（需要 `--email`），失败或非开放获取时回退到 OpenAlex DOI 查询，再回退到 Crossref DOI 查询。
4. 无 DOI 或 DOI 查不到时，用 OpenAlex `title.search` / 全文检索做标题匹配，低于 0.55 token 覆盖率视为未命中；标题未命中时再回退到 Crossref 书目检索。
5. 用 OpenAlex 按 `publication_date` 倒序搜索 `--concept` 对应的最新文献，补充 SEP 之外的新近成果；OpenAlex 不可用时回退到 Crossref 按出版时间倒序检索。
6. 用户也可以直接传 `--doi`，让某篇已知文献走完整的解析、下载和人工队列流程。
7. 对解析到开放获取 PDF 的文献下载到 `files/{item_id}.pdf`，校验 `%PDF-` 魔数、大小上限和 SHA-256；若目标站点 SSL 证书校验失败，会仅对该次下载用宽松证书校验重试一次。
8. 没有开放获取版本或下载失败的文献写入 `manual-queue.jsonl`，附带建议 URL 和原因。

## 使用

安装项目后（`pip install -e .`）直接使用命令：

```powershell
research-kb-acquisition `
  --output D:\research-kb-pilot\workspace\staging `
  --sep-entry lukacs `
  --concept "Lukacs totality" `
  --email you@example.com `
  --recent-max 10 `
  --max-downloads 25
```

也可以通过模块运行：

```powershell
python -m research_kb.acquisition --output .\staging --sep-entry lukacs
```

只按 DOI 下载一篇文献：

```powershell
research-kb-acquisition `
  --output D:\research-kb-pilot\workspace\staging `
  --doi 10.48550/arXiv.2305.02104 `
  --email you@example.com
```

主要参数：

- `--sep-entry`：SEP slug 或完整条目 URL，可重复指定。
- `--doi`：直接解析并下载的 DOI，可重复指定；没有开放获取版本时进入人工队列。
- `--concept`：OpenAlex 最新文献检索主题，可选。
- `--email`：联系邮箱，启用 Unpaywall 和 OpenAlex polite pool。
- `--recent-max`：最新文献检索条数，默认 10。
- `--max-downloads`：单次运行最多下载 PDF 数，默认 25。
- `--max-items`：单次运行最多解析的 SEP 参考文献条数，默认不限制；大条目可以先限流试跑。
- `--max-bytes`：单个 PDF 大小上限，默认 128 MiB。
- `--timeout`：单请求超时秒数，默认 30。
- `--api-delay`：每次 OpenAlex/Unpaywall 请求前的等待秒数，默认 0.25，用于降低被限流的概率。

OpenAlex 返回 429 或 5xx 时，Worker 会按 `Retry-After`（或指数退避）重试最多 3 次；连续 3 条仍被限流时停止解析，剩余条目直接进入 `manual-queue.jsonl`，保证一次运行有明确的结束点。没有 `--email` 时无法使用 Unpaywall 和 OpenAlex polite pool，条目也会进入人工队列。

## 输出

每次运行在 `--output` 下创建 `acquisition-{timestamp}-{id}/`：

- `manifest.json`：schema_version、worker 版本、参数、输入内容哈希、输出文件哈希、起止时间、汇总和 notes。
- `sep-entries.jsonl`：SEP 条目解析结果（含参考文献和 related entries）。
- `bibliography.jsonl`：去重后的参考文献记录。
- `candidates.jsonl`：每条候选的解析结果、下载状态和错误信息。
- `manual-queue.jsonl`：需要人工下载的文献及建议 URL。
- `report.md`：人类可读的下载清单和人工队列。
- `files/*.pdf`：下载成功的开放获取 PDF。

manifest 的 `summary` 记录 `sep_entries`、`bibliography_items`、`recent_works`、`downloaded`、`manual_queue` 和 `skipped_download_limit`，便于接入后续筛选和 ingest。

## 人工队列示例

```json
{
  "key": "title:considerations on western marxism",
  "item_id": "item_0001",
  "title": "Considerations on Western Marxism",
  "authors": ["Perry Anderson"],
  "year": 1976,
  "doi": null,
  "reason": "no open access location",
  "suggested_urls": [
    {"kind": "sep_entry", "url": "https://plato.stanford.edu/entries/lukacs/"}
  ],
  "source": {
    "kind": "sep_bibliography",
    "entry_slug": "lukacs",
    "entry_title": "Georg Lukacs"
  }
}
```

人工下载完成后，将 PDF 放入 corpus，再按 `docs/manifest-format.md` 用 Admin CLI ingest。
