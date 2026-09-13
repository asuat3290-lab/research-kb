# Codex CLI worker integration: partial implementation

Status: OFFLINE_CODEC_TESTED; NOT_RUNNER_CONNECTED; LIVE_PROBE_INCONCLUSIVE.

The user authorized gpt-5.6-luna through the current Codex account, not OpenCode
or an independently billed API. That permission does not make CLI-reported
usage a provider billing attestation or authorize changing source permissions.

## Implemented

`max_research.runner.codex_cli_codec.decode_codex_turn` decodes a bounded UTF-8
JSONL stream for exactly one successful tool-free turn. It requires a successful
process exit, one final agent message, valid token usage, and closed item
lifecycles. It rejects tool events, CLI errors/reconnects, incomplete streams,
duplicate JSON keys, invalid token counters, repeated finals and trailing turns.

The result is immutable host-reported data. Cost and provider call ID remain
unknown. A host thread ID is not a provider request ID. Reasoning token usage is
optional and remains unknown when absent. The decoder does not validate the
research proposal itself; the existing proposal contract remains authoritative.

This is a decoder, not a process sandbox: rejecting a tool event after the fact
does not prevent that tool from having run. It must not be presented as source
egress enforcement, dispatch authority, or a production usage authority.

Offline verification: 16 unittest cases pass using synthetic CLI event streams.
The 17 existing portability foundation tests also pass in the authorized test
environment. Their first sandbox run failed while creating temporary SQLite
databases with Windows permission errors, not at functional assertions. The two
new Python files compile. The full project suite was not run.
No existing runner entry point, migration, MCP tool, runtime, or global
configuration was changed. This is not a new accepted release.

## Actual connection probe

One diagnostic CLI process was launched with the explicitly authorized model,
ephemeral mode, read-only sandbox and user-config isolation. The prompt contained
no research content and requested only a connection acknowledgement without
tools. The process emitted thread.started and turn.started, then timeout
reconnection events (including 2/5 and 3/5). It was interrupted and returned
exit code 1. No final answer or usage arrived.

This proves neither model availability nor successful research execution.
Physical backend attempt counts, external usage and billing are unknown; they
must not be reported as zero or as one physical call. A later process inventory
check was denied, so descendant-process termination was not independently
verified. No second diagnostic process was launched.

## Remaining production prerequisites

1. Establish a successful minimal account-backed CLI response before claiming
   model connectivity. Diagnose the observed timeout without reading or logging
   account secrets. Explicitly reconcile internal CLI retry behavior with the
   physical-call budget; never advertise provider idempotency/result-query
   capabilities that the CLI does not supply.
2. Implement bounded process I/O, timeout and descendant cleanup, plus enforceable
   tool/context isolation. Prompt instructions alone are insufficient.
3. Provide a server-owned request/result/usage binding with durable recovery.
   Subscription tokens cannot silently be converted to micro-USD or settled as
   zero. Unknown dispatch must retain the appropriate uncertainty and accounting.
4. Connect research data through the governed source-access path. The current
   gateway explicitly rejects source bodies. Renaming source-text fields or
   bypassing the gateway is not an implementation of source authorization.
5. Wire a backend-bound production runner entry point and demonstrate two actual
   iterations with canonical recovery and a candidate research result. Offline
   fixtures and this decoder's tests are not substitutes for that demonstration.

Official event-format reference:
https://learn.chatgpt.com/docs/non-interactive-mode

Do not install or rebind a runtime solely to ship this partial codec.
