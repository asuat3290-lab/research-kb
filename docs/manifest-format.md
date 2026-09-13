# Manifest 格式

Admin CLI 的 `ingest` 只接受显式 JSON manifest。每个 `path` 必须是配置 corpus root 内的普通文件；相对路径按 corpus root 解析，多个 root 同时命中会被拒绝。

```json
{
  "files": [
    {
      "path": "papers/example.md",
      "title": "Explicit title",
      "creator": "Explicit creator",
      "source_type": "article",
      "language": "zh-en",
      "source_date": "2026-01-01",
      "source_version": "v1",
      "source_name": "Explicit source name",
      "reliability_status": "unverified",
      "metadata": {
        "collection": "example"
      }
    }
  ]
}
```

字段含义：

- `title`、`creator`、`source_type`、`language`、`source_date`、`source_version`、`source_name` 和 `reliability_status` 都是来源元数据，不从文件名推断。
- 缺失文本字段保存为 `unknown`；缺失 `reliability_status` 保存为 `unverified`。
- `metadata` 必须是 JSON object，作为描述性元数据保存。
- `path` 不能逃逸 corpus root，不能通过 symlink 或 junction 绕过目录边界。

先 dry-run：

```bash
python -m research_kb.cli --config config.toml ingest \
  --project default --manifest corpus/manifest.json --dry-run
```

执行导入：

```powershell
$env:PYTHONPATH = (Resolve-Path "src").Path
python -m research_kb.cli --config config.toml ingest `
  --project default --manifest corpus/manifest.json
```

损坏文件、无法提取文本的空文件、路径越界和不支持的扩展名都会返回明确错误；重复内容按 document content hash 幂等去重。
## Explicit bibliographic profile (Phase 3.25)

`metadata` may contain a `bibliographic_profile` object. The profile is an explicit record from the imported source, not an inference from the filename, path, DOI, or container type. Missing values are stored as `unknown`.

For `journal_article`, supported fields are `authors`, `title`, `container_title`, `year`, `volume`, `issue`, `page_range`, `doi`, and `publisher`. For `book`, supported fields are `authors`, `editors`, `translators`, `title`, `edition`, `place`, `publisher`, `year`, and `isbn`. Every profile also exposes `document_id`, `content_hash`, and `source_version` from the immutable document identity.

Example:

```json
{
  "files": [
    {
      "path": "papers/example.pdf",
      "title": "Explicit title",
      "creator": "Explicit creator",
      "source_type": "journal_article",
      "language": "en",
      "source_date": "2025",
      "source_version": "publisher-pdf",
      "source_name": "Explicit journal",
      "reliability_status": "unverified",
      "metadata": {
        "bibliographic_profile": {
          "type": "journal_article",
          "authors": ["Explicit Author"],
          "title": "Explicit title",
          "container_title": "Explicit journal",
          "year": 2025,
          "volume": "12",
          "issue": "2",
          "page_range": "10-25",
          "doi": "unknown",
          "publisher": "unknown"
        }
      }
    }
  ]
}
```

Use `unknown` when the PDF does not state a field. An administrator may complete or correct this profile with `metadata update`; the old value, new value, reason, actor, and timestamp are audited. MCP returns the profile as `citation_record` and a passage-specific `citation_locator`, without returning the original file path.

## Report manifest (Phase 0)

`submit_research_report` writes an append-only `report_manifest` row in the same transaction as the report version. The manifest is a database record, not a client-supplied file. It stores:

- `report_manifest_id` and `report_version_id`: stable IDs for the manifest and the report version it describes;
- `protocol_project_id`: the active project the report belongs to;
- `claim_revision_ids_json`, `evidence_revision_ids_json`, `passage_revision_ids_json`: deduplicated stable IDs from the submitted report;
- `verification_event_ids_json`, `approval_event_ids_json`, `source_snapshot_ids_json`, `project_export_ids_json`, `cross_project_link_ids_json`: empty lists reserved for later phases;
- `constraint_revision_id` and `research_project_id`: nullable placeholders for later constraints/research-project binding;
- `created_by` and `created_at`: manifest author and timestamp.

The manifest cannot be updated or deleted by any current path; direct `UPDATE` or `DELETE` raises a database integrity error. A manifest row can only exist when its `report_version_id` resolves to a `research_items` row with `kind='report'` in the same `protocol_project_id`.

<a id="manifest-delivery-package-v2"></a>
## Delivery package manifest v2

The delivery package manifest now accepts a v2 shape in addition to the original
legacy keys. This section is the normative anchor for schema field
`delivery_package.manifest.v2`; anchors below are stable and are not derived from
Markdown heading slugs.

- `manifest_version`: `"2.0"` for v2; missing or older values are read as legacy.
- `package_state`: `REVIEW`, `PENDING`, `APPROVED`, or `ARCHIVED`.
- <a id="manifest-v2-field-created_at"></a>`created_at`: ISO-8601 timestamp
  with timezone, required for v2 manifests.
- <a id="manifest-v2-field-artifact_audit"></a>`artifact_audit`: compact
  four-bucket audit counts (`errors`, `warnings`, `review_items`,
  `approval_blockers`). It is preferred over the legacy `writing_policy_audit`,
  which remains a supported fallback, and over `writing_audit_summary`.
- `research_approval`: `review_items` and `approval_blockers` counts.
- `final_approval`: human approval state, default `pending`.
- `supporting_artifacts`: audit JSON records with `file`, `type`, and `sha256`.
- `policy_snapshot_sha256`: must equal the A-layer audit `policy_fingerprint`.

Legacy manifests remain valid. Validation returns `legacy: true` and
`migration_recommended: true`; `upgrade_manifest()` produces a v2 copy without
mutating the original.

## Normative anchors

Schema fields and implementation code reference stable HTML anchors rather than rendered heading slugs. Every anchor below is unique within this document and must not be reused. Renaming or renumbering a heading does not change its anchor.

| Anchor | Normative section | Referenced by |
| --- | --- | --- |
| `manifest-delivery-package-v2` | Delivery package manifest v2 | `delivery_package.MANIFEST_SPEC_ANCHORS`, manifest schema validation |
| `manifest-v2-field-created_at` | Delivery package manifest v2 | `delivery_package.MANIFEST_SPEC_ANCHORS`, manifest schema validation |
| `manifest-v2-field-artifact_audit` | Delivery package manifest v2 | `delivery_package.MANIFEST_SPEC_ANCHORS`, manifest schema validation |

Document tests verify that anchors registered in `MANIFEST_SPEC_ANCHORS` exist here, that anchors are not duplicated, and that code and tests only reference registered anchors.
