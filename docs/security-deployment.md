# Security deployment

## Recommended layout

Keep these locations separate:

```text
<AGENT_WORKSPACE>/
<CONFIG_PATH>
<DATABASE_DIRECTORY>/
<CORPUS_DIRECTORY>/
<BACKUP_DIRECTORY>/
```

The research Agent should work in `<AGENT_WORKSPACE>`, not in the database or corpus directory. Configure paths using relative paths or platform-native absolute paths. Do not hard-code drive letters in application code.

## Local stdio boundary

Start the same Python module on Windows, macOS, and Linux:

```bash
python -m research_kb.mcp_server --config <CONFIG_PATH>
```

```powershell
python -m research_kb.mcp_server --config "<CONFIG_PATH>"
```

MCP stdout is reserved for protocol messages. Diagnostics go to stderr. The process performs read-only readiness checks and exits if the Admin CLI has not initialized and migrated the database.

## Strong isolation

For stronger separation, use a dedicated OS account; grant the Agent access only to the intended research surface; keep Admin CLI credentials and corpus administration outside the Agent account; apply OS ACLs to database, WAL, SHM, corpus, and backup directories; restrict process debugging and arbitrary child-process creation; encrypt storage and backups; and monitor failed Admin CLI operations and backup/restore results.

## Unsupported deployments

Do not expose this local stdio process directly to the public internet. Remote unauthenticated MCP, multi-user SaaS tenancy, and same-account arbitrary Shell access are outside the security claim.

## Privacy and model providers

Local material is not automatically uploaded by this package. The Agent framework or model provider may nevertheless receive MCP excerpts. Users must evaluate provider retention, training, logging, and regional processing policies before using external models with sensitive corpus material.

## Platform notes

Windows JSON strings may use escaped backslashes (`C:\\path\\config.toml`) or forward slashes (`C:/path/config.toml`). POSIX examples use `/path/to/config.toml`. Platform-specific symlink, junction, device-path, permission, and case-sensitivity checks are conditional tests; a non-Windows run does not claim to validate Windows behavior.

The package does not implement semantic/hybrid retrieval, remote MCP, automatic network access, or a local model.
