# Backup and recovery

Phase 3 provides Admin CLI backup, separate-path restore, expired-token cleanup, and transactional lexical index rebuild. These operations are not exposed by MCP.

## Online backup

Run after initialization:

```bash
python -m research_kb.cli --config <CONFIG_PATH> backup --output <BACKUP_PATH>
```

```powershell
python -m research_kb.cli --config "<CONFIG_PATH>" backup --output "<BACKUP_PATH>"
```

The implementation uses SQLite's online backup API while the live database is in WAL mode. It writes to a temporary file in the destination directory, checks `quick_check` and `foreign_keys=1`, and atomically replaces the requested backup path only after validation.

Do not place a backup over the live database. Keep backups on storage with access controls appropriate to the corpus.

## Restore to a separate path

Restore is deliberately non-destructive and requires a new output path:

```bash
python -m research_kb.cli --config <CONFIG_PATH> restore \
  --input <BACKUP_PATH> --output <RESTORED_DATABASE_PATH>
```

```powershell
python -m research_kb.cli --config "<CONFIG_PATH>" restore `
  --input "<BACKUP_PATH>" --output "<RESTORED_DATABASE_PATH>"
```

Restore validates source and target `quick_check`, `foreign_keys=1`, current schema version, and core table counts before atomically publishing the separate output file. It does not overwrite the configured live database or apply migrations.

After restore, point a temporary configuration at the restored database and verify:

- `PRAGMA quick_check` is `ok`;
- `PRAGMA foreign_keys` is `1`;
- schema version equals the packaged migration version;
- documents, passages, research items, evidence, audit, and FTS counts match;
- lexical Chinese/English search works;
- accepted item/evidence statuses remain unchanged.

## Reindex

```bash
python -m research_kb.cli --config <CONFIG_PATH> reindex
```

Reindex deletes and rebuilds only the derived `passages_search_fts` table inside one transaction. Passage rows and source identity are immutable. If the process fails before commit, SQLite rolls the derived-table changes back. Run it only through Admin CLI; MCP readiness never rebuilds the index.

## Expired verification tokens

Expired unconsumed tokens are not physically deleted because the token table is append-only. The Admin CLI terminally marks them consumed, preserving a non-reusable audit-safe record:

```bash
python -m research_kb.cli --config <CONFIG_PATH> token cleanup
```

After cleanup, a replay is terminally classified as consumed. Before cleanup, an expired token is classified as expired. Raw token text is never stored; only a hash and binding metadata are stored.

## Recovery drill

Use a temporary database and corpus-independent configuration. Never test restore by overwriting a production database. Record the backup path, restore path, quick check, schema, table counts, FTS count, search results, and accepted status counts.
