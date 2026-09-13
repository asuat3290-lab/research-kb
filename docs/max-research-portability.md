# Max Research agent portability

This document defines the portable control boundary for Max Research. A host
is an execution surface (Codex, Luna, Qoder, Hermes, or a generic CLI agent);
it is not a provider, model, or transport. A backend is an explicit,
server-owned execution profile. OpenCode Go / DeepSeek V4 Flash is registered
as an ordinary `openai_compatible_http` backend and is never selected merely
because of an agent name or process.

The administrator-only JSON interface is:

- `research-kb max host-list|host-describe`
- `research-kb max host-installation-register|host-installation-status`
- `research-kb max backend-list|backend-describe`
- `research-kb max portability-status`
- `research-kb max portability-quiescent`
- `research-kb max profile-disable|profile-revoke`
- `research-kb max bind-backend`
- `research-kb max preview-backend-handoff`
- `research-kb max approve-backend-handoff`
- `research-kb max rehydration-packet-status|rehydration-packet-read`
- `research-kb max acknowledge-rehydration`
- `research-kb max normalized-result-record`
- `research-kb max verify-portability`

Profile registration is explicit and content-addressed. Runs require an
explicit host/backend binding. Changing a binding requires a server-created
handoff preview and an exact human approval phrase. A missing, disabled,
revoked, cross-project, or hash-inconsistent binding fails closed; there is no
first-backend fallback or implicit default.

Agents do not open or write SQLite. Thin host adapters locate this Skill,
verify its hash, discover the unified CLI, declare the host kind, and invoke
the JSON interface. They do not contain project identifiers, personal paths,
API keys, provider selection, or a second persistence protocol.

Backend responses are normalized into bounded cognitive artifacts, proposed
canonical objects/relations, questions and objections, usage receipts, and a
backend status. They cannot assert that an object is verified, accepted,
approved, completed, or final. Canonical evidence remains in the governed
Max control plane and must be rehydrated by ID/hash after a host handoff;
human-readable summaries are not canonical recovery material.

Migrations 029 and 030 add the append-only profile, binding, handoff,
rehydration, installation-attestation, and invocation-attributed result
records while keeping core schema 5 and MCP exact-12 unchanged. Migration
030 does not rewrite the old result table or old handoff history. It adds a
bounded result table, sequential handoff lineage, a server-owned recovery
packet, profile lifecycle events, and attested installation records. The
local-agent backend is disabled by default. Live transport, credential
resolution, and provider usage remain governed by the existing server-owned
controls.

The packaged `CodexPortabilityAdapter`, `LunaPortabilityAdapter`,
`QoderPortabilityAdapter`, and `HermesPortabilityAdapter` are thin protocol
facades. They can discover a declarative host, submit an installation
attestation, read and acknowledge a recovery packet, and submit a bounded
result through an injected administrator-CLI callable. They never open SQLite,
select a backend from a host name, or imply that a declarative host has an
executable installation. Executable portability requires an attested
installation and an explicit Run binding.

## MR-PORTABILITY-0R2 convergence rules

Migration 031 adds append-only quiescence snapshots, typed rehydration
manifest items, target-bound acknowledgements, server-owned invocation and
result bindings, and installation attestations. It keeps core schema 5,
MCP exact-12, and migrations 001–030 byte-identical.

Before a handoff Preview and again when its approval is consumed, the control
plane records the complete activity inventory for the Run. The inventory
covers runner claims and groups, reservations, acquisition and scheduler
activity, long-run and authorization state, JIT/permits/leases, provider
history and dispatch, and network activity. A Run must be paused and its
checkpoint must still match its state; any active or unknown activity fails
closed. The snapshot payload and activity digest are immutable and verified
from their canonical JSON.

Recovery packets expose a bounded, paginated manifest of typed server IDs and
hashes. A production host must acknowledge the exact current handoff with an
attested installation, authenticated target session, observed checkpoint and
state hashes, and a complete manifest root/count. A two-field blind ACK is
accepted only for the explicitly marked fixture control store. Resume requires
the target-bound ACK and current handoff/binding projection.

Normalized production results are attributed from the durable runner graph;
callers cannot provide iteration, invocation, intent, or attribution hashes.
Historical results remain bound to their input checkpoint when later
checkpoints are created. Fixture compatibility is explicit and cannot escape
fixture-marked control stores. Non-fixture host bindings require a
server-recorded `admin_declared` or trusted verifier installation attestation.
