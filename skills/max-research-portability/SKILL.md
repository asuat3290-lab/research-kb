# Max Research portability

Use this Skill when a Max Research run must be discovered, resumed, or moved
between supported agent hosts.

## Rules

1. Discover the project and Run through the governed Max control plane. Keep
   the Run ID, checkpoint ID, state hash, source-policy hash, budget hash, and
   binding IDs; do not infer them from a prompt or a host process.
2. Call the unified administrator JSON CLI for host/backend discovery. Agents
   never read or write SQLite directly.
3. Select a host profile and an execution backend profile independently. A
   host name never chooses a provider or model. OpenCode Go is an ordinary
   OpenAI-compatible backend, not a default.
4. Require an explicit `RunExecutionBinding`. Missing, revoked, disabled,
   cross-project, or hash-inconsistent bindings fail closed.
5. Pause at every human approval point. A backend handoff requires a
   server-owned Preview, an exact approval phrase, and a state/checkpoint hash
   that is still current. Never silently fall back to another backend.
6. On resume, rehydrate canonical state and evidence by server-owned IDs and
   hashes. A summary, transcript, or agent-produced prose is not canonical
   evidence.
7. Treat normalized agent output as proposals and bounded cognitive results.
   It cannot mark anything verified, accepted, approved, completed, or final.
8. Keep credential values, prompts, source text, raw responses, fencing tokens,
   and personal paths out of normal output and adapter code.

## Control surface

The supported commands include `host-list`, `host-describe`,
`host-installation-register`, `host-installation-status`, `backend-list`,
`backend-describe`, `portability-status`, `portability-quiescent`,
`bind-backend`, `preview-backend-handoff`, `approve-backend-handoff`,
`rehydration-packet-status`, `rehydration-packet-read`,
`acknowledge-rehydration`, `normalized-result-record`, and
`verify-portability`. The interface returns stable redacted JSON. It is an
administrator control surface; it is not an additional MCP tool.

## Lifecycle

`discover → attest installation → bind → checkpoint → pause → preview handoff
→ human approval → packet acknowledge → rehydrate → resume → normalize result
→ canonical review`.

If a host or backend is unavailable, wait for an explicit human decision or
pause the Run. Do not create a new project, copy a database, or substitute a
provider to make progress.

## Convergence requirements

For every handoff, the server persists an immutable, complete quiescence
snapshot at Preview and approval consumption. It must include all runner,
reservation, acquisition, scheduler, authorization, JIT, permit, lease,
provider-dispatch, provider-history, and network activity categories. The Run
must be paused and checkpoint/state-bound; unknown or active activity is a
hard failure.

Recovery is manifest-based. Read the packet through the bounded pagination
surface, verify every typed item and the server-computed manifest root, then
acknowledge with the target host installation, authenticated session,
observed checkpoint/state hashes, current handoff/binding, and complete
manifest proof. Blind acknowledgement is never valid for a real installation;
the two-argument fixture form is confined to the marked fixture store. Resume
requires that target-bound ACK.

Production result attribution comes from the durable runner graph. Do not
send caller-supplied iteration, invocation, intent, or attribution values.
Historical results remain attached to their original input checkpoint after
later checkpoints are added. Host portability requires a server-owned
installation attestation; a declarative host description alone is not an
executable installation.
