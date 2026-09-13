# Full material catalog

Phase 3.4A creates a read-only inventory and a dry-run candidate set. It does not perform formal ingest, assign permanent research importance, or create Source Role Map roles.

## Command

The catalog scan is a human-admin CLI operation. Supply aliases explicitly; aliases and relative paths are the only paths written to publishable catalog files.

Bash:

```bash
research-kb catalog scan \
  --root learning_materials=<ROOT_ONE> \
  --root learning_materials_20=<ROOT_TWO> \
  --output <CATALOG_ROOT> \
  --candidate-limit 450
```

PowerShell:

```powershell
research-kb catalog scan `
  --root learning_materials=<ROOT_ONE> `
  --root learning_materials_20=<ROOT_TWO> `
  --output <CATALOG_ROOT> `
  --candidate-limit 450
```

`<ROOT_ONE>`, `<ROOT_TWO>`, and `<CATALOG_ROOT>` are user-supplied local paths. The generated `root-map.local.json` holds their local mapping and must not be published.

## Outputs

- `catalog.jsonl`: one record per current or previously removed file; no full text and no absolute source path.
- `scan-state.json`: atomic scan state, interruption/recovery status, and aggregate errors.
- `summary.json`: root, extension, file-kind, technical-status, duplicate, privacy, candidate, timing, and recovery aggregates.
- `duplicate-groups.jsonl`: independent size-only comparison buckets, quick-fingerprint possible duplicates, and full-SHA exact duplicates. A size bucket never changes technical status or candidate status.
- `technical-review.jsonl`: bounded probe results, duplicate state, metadata provenance, and reasons, never excerpts.
- `privacy-review.jsonl`: files requiring human privacy review, including personal-material and discovery-collection classifications.
- `first-batch-candidates.jsonl`: backward-compatible bounded candidate set; `candidate_kind` distinguishes `ready` from `review`.
- `first-batch-ready.jsonl`: only candidates satisfying the strict ready policy; no padding is performed.
- `first-batch-review.jsonl`: candidates requiring technical or human review.
- `first-batch-metadata-review.jsonl`: the subset with missing or unverified bibliographic metadata.
- `first-batch-manifest.dry-run.json`: an explicit manifest checked through existing ingest dry-run; it is not an import approval and includes a separate `ready_files` view.
- `storage-forecast.json`: separate first-batch and full-native-corpus forecasts with fixed schema bytes, marginal imported bytes, WAL/backup ranges, stratified coverage, confidence, and explicit PDF OCR unknown ranges.
- `CATALOG-RUNBOOK.md`: local review and recovery notes.

Temporary dry-run databases and sample databases are kept below the catalog output's `temp` directory or removed after measurement. They are not the formal research database and are never the pilot database.

## Interpretation rules

Technical readiness is not research importance. Missing bibliographic values remain `unknown`, `unverified`, or `needs_metadata_review`; filenames and paths are not authoritative metadata. Duplicate and derivative flags do not delete files and do not automatically merge evidence. Dynamic roles remain in a question-specific Source Role Map.

The packaged `catalog_policy.json` is the default classification policy and can be replaced with `--policy <POLICY_JSON>`. Its terms are configuration, not personal-directory assumptions. Private, unpublished, coursework, study-archive, code-repository, README, log, cache, generated-output, and OCR-page-fragment matches are review/exclusion signals. A DOCX core creator, operating-system username, or PDF file creator is never promoted to an author. A filename may produce `inferred_title`, but it remains unverified.

PDF states are `confirmed_text_layer`, `confirmed_needs_ocr`, `probe_pending`, `corrupt`, or `encrypted`. `probe_pending` is unknown and is not counted as zero OCR pages or as ready. The bounded pypdf probe samples first/middle/last pages without retaining source text.

Forecasts use deterministic strata by extension, top-level directory, and size bucket. Fixed schema bytes are measured once, marginal data bytes are measured separately, and WAL/backup reservations are explicit. Pending PDF page ranges remain unknown ranges. Candidate counts report the actual result; the scanner never pads to a target.

The scanner does not follow symlinks, junctions, or reparse points. It streams quick fingerprints and complete SHA-256 hashing, uses bounded probes, skips unstable files, and publishes final JSONL through atomic replacement. It performs no OCR, network lookup, local-model inference, or formal ingest.

## Five-level readiness

Each catalog record carries a `readiness` object with five boolean levels:

- `ingest_ready`: the file is present, extractable, and not a private, generated, code, repository, or OCR-fragment match;
- `search_ready`: reserved for the future formal-ingest/search phase;
- `citation_ready`: `ingest_ready` and the explicit bibliographic metadata are sufficient for a server-generated citation record;
- `evidence_ready`: reserved for the future verification/evidence phase;
- `report_ready`: reserved for the future report phase.

After a dry-run scan, only `ingest_ready` and `citation_ready` can be true. The reserved levels remain `false` until their phase is implemented, so a future phase must flip its own level explicitly rather than inheriting an earlier stage. `readiness_counts` in `summary.json` and `ingest_ready_count` / `citation_ready_count` mirror the ladder.
