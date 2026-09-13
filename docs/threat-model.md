# Threat model

## Protected assets

research-kb protects original corpus material and extracted passages; the SQLite database, WAL files, and FTS indexes; verification tokens and their source bindings; accepted research items; verified evidence and evidence status history; source metadata and metadata correction history; append-only audit logs; and administrator capabilities including migration, ingest, approval decisions, backup, restore, token cleanup, and reindex.

A successful source quote check proves source-version consistency only. It does not prove that a claim is true or that a source is authoritative.

## Trust boundaries

The Agent is untrusted. Tool arguments, text, IDs, prompts, and requests can be adversarial. Agent-controlled text is data, never a system instruction.

Source documents are untrusted data. HTML, Markdown, JSON, and document text cannot grant permissions, change actor identity, invoke Admin CLI operations, or alter the MCP tool surface.

The research MCP surface is a restricted, project-scoped boundary. It exposes exactly twelve researcher tools and does not expose SQL, files, shell, status, ingest, metadata update, approval decision, backup, restore, token cleanup, or reindex.

Admin CLI is a separate high-privilege boundary. It requires a local admin Actor and is the only interface for migrations, source ingest, metadata correction, approval decisions, backup, restore, expired-token cleanup, and index rebuild.

SQLite foreign keys, immutable tables, append-only triggers, token binding triggers, and status transition triggers are the last integrity boundary if application code fails. They do not replace operating-system permissions.

If an Agent and the database use the same OS account and that account has arbitrary Shell access, this project cannot claim absolute isolation. An attacker with arbitrary local code execution can read or modify the database and corpus outside the application policy.

## Deployment levels

### Ordinary personal use

Use an independent Agent workspace, a separate database/corpus directory, and the local stdio MCP process. Do not place the Agent working tree inside the corpus or database directory.

### Strong isolation

Run the database, corpus, Admin CLI, and MCP process under a dedicated service account. Use OS file ACLs, a separate workspace, least privilege, encrypted storage where appropriate, and restricted process access. Keep administrative actions outside the Agent account.

### Explicitly unsupported

Direct public-internet exposure, multi-user SaaS tenancy, remote unauthenticated MCP, and absolute isolation from an Agent that already has arbitrary Shell access under the same OS account are not supported claims.

## Main threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Cross-project ID probing | Active-project checks, project joins, sanitized errors, no target existence in MCP responses | A user authorized to name another active project can query that project by design |
| Token replay or concurrent consumption | Project/source/hash/quote/actor/session binding and transactional compare-and-consume | Token text returned to the current caller remains sensitive |
| Admin escalation through MCP | Fixed agent/researcher identity; no AdminService import or admin parameters | Same-OS-account arbitrary Shell defeats application boundaries |
| Path traversal and links | Canonical containment, symlink/junction rejection, Windows device/ADS/reserved-name checks | Filesystem races and OS-level privileges remain deployment concerns |
| Prompt injection in sources | Source material is never executed as instruction | An external model provider may see excerpts returned to its Agent |
| Database corruption | WAL, quick_check, foreign_keys, atomic migrations, transactional reindex, verified backup/restore | Physical disk failure requires independent storage backups |
| Sensitive logs | Sanitized envelopes, stderr-only diagnostics, no raw token/source/path/SQL | Admin CLI output is intended for a local administrator and can contain paths |

## Privacy boundary

Local source material is not automatically uploaded by research-kb. However, a model provider or Agent framework may receive excerpts returned by MCP. Users must understand and accept that provider-side privacy boundary before sending research results to an external model.

Hard integrity constraints improve traceability; they do not guarantee that a research conclusion is correct.
