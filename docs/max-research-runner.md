# Max Research MR-2A Bounded Runner

MR-2A implements the provider-neutral bounded runner kernel. It is an
administrative control-plane capability, not a research worker. The shipped
implementation uses one immutable `RunnerProfile`, one model identity, a
bounded fake adapter, and a deterministic fixture gateway. It does not ship a
provider SDK, network client, scheduler, daemon, acquisition worker, or real
Max Run.

## MR-2B2/MR-3 execution boundary

`LiveRunnerExecutor` advances at most one iteration after consuming one exact
human `LiveIterationApproval`. The provider adapter receives an ordered pool
of server-issued physical-call authorities; every logical call is durably
assigned before transport construction. The approval, grant, bundle,
profile, canonical input state, expected iteration, runner identity and fence
must all agree.

`LongRunningWorker` may invoke an already-governed step repeatedly, but only
within explicit tick and wall-clock bounds. Commands, heartbeats, checkpoints,
iteration history and canonical state—not recent summaries—form restart
authority. It stops on admin command, policy boundary, pause/recovery,
conflict, budget, or completion-candidate status. No background daemon is
installed.

### MR-2B0 provider boundary and foreground scheduling

MR-2B0R2 adds independent control schema 8 migrations
`006_mr2b0_provider_scheduler.sql`, `007_mr2b0r_authority_budget_closure.sql`, and
`008_mr2b0r2_physical_dispatch_budget.sql`; core schema 5 and Max migrations 001-005
are unchanged. A strict ProviderProfile stores no secret and exposes only a
CredentialRef. The only dispatch path is injected HermeticTransport; the
live transport sentinel is disabled and no network, environment key, or real
model is called.

The provider call record, server-priced usage attestation, existing usage
receipt, and budget ledger form one immutable authority chain. A human admin
must explicitly issue a run-bound, one-time LiveExecutionGrant with caps and
expiry, and its consumption is one-time. The foreground scheduler calls at
most one existing `run_next` per tick, persists session/tick/current state and
stop reasons, and reuses the existing lease/fencing and invocation claims for
restart/handoff. It has no daemon, hidden loop, acquisition worker, MR-2B1,
MR-3, or real Max Run.

## Durable call boundary

`run-next` advances at most one iteration. The sequence is persisted as

```text
plan -> begin iteration -> reserve budget -> intent -> dispatch attempt
     -> adapter call (outside SQLite transaction)
     -> dispatch acknowledgement -> authoritative result/usage
     -> canonical change set -> iteration outcome
```

Plans, intents, dispatch acknowledgements, dispatch attempts, results,
recovery decisions, links, and attempt outcomes are immutable and bind the
run, project, iteration, input state hash, model identity, inference profile,
and server-owned actor. The original dispatch acknowledgement is never
rewritten: an `unknown` observation remains an `unknown` historical fact, even
when a later provider query or idempotent retry yields an authoritative result.

All formal payloads use the MR-0B canonical serializer and hashes are
recomputed from stored values. Event records remain in the independent Max
event chain. No model response may contain secrets, source text, absolute
paths, client citation metadata, or a final/verified/approved/completed
assertion. Unknown proposal fields fail closed.

## Handoff, lease, and fencing

An administrator registers the immutable profile and explicitly hands a Run
from the admin control plane to one runner actor. `run-next` requires that
handoff, a non-admin runner identity, and the current server lease. Lease
acquisition, renewal, expiry takeover, and profile binding use the existing
monotonic fencing token. A stale worker cannot append an attempt, result,
change set, usage entry, outcome, or event.

The model call is never made while a SQLite transaction is open. A persisted
`dispatching` attempt before the call distinguishes a process crash before
dispatch from an external call with an unknown outcome. If the provider has
neither a safe idempotency primitive nor a result query, the Run is paused and
requires an explicit administrator decision; the runner does not guess or
retry.

## Deterministic planning and rehydration

The planner is pure and deterministic: the same run, state hash, history,
profile, and budget snapshot produce the same plan hash and logical call ID.
Role packets are isolated. Rehydration context is reconstructed from
canonical object/version/relation IDs and source references and explicitly
excludes working summaries, recent summaries, narrative search history, and
role discussion history. A summary cannot replace the canonical graph.

## Completion and CLI boundary

MR-2A never persists a CompletionResult and provides no `max complete`
command. Completion remains an MR-0B gate driven by later authoritative
history. The available CLI additions are `register-profile`, `handoff`,
`run-next`, `runner-status`, and `ambiguous-decision`; status output is
redacted and read-only. Existing researcher-facing MCP remains exactly 12
tools.

All tests use temporary control databases, fake clocks/identities, and the
deterministic fake adapter. No test starts a real model, opens the network, or
writes the pilot database.

## MR-2A.2 five-call deliberation

Schema 5 adds an immutable call-spec/result-binding layer and closes the
adjudication group as five same-model/profile calls:

```text
lead_position -> rival_position -> rival_cross_examination
              -> lead_cross_examination_response -> adjudicator
```

Only the first two calls see the canonical packet alone. Later calls consume
named, normalized public artifacts and their hashes. Empty, unknown, replayed,
or cross-contaminated artifacts abort or pause the group; no service fallback
creates a position, question, answer, audit, rationale, or adjudication.

Every billable result, including a failed provider result with verified usage,
is bound to exactly one `UsageReceipt` and one ledger usage entry. Receipt
verification binds logical call, intent/request, provider call, Run,
iteration, model/profile, amount and hashes. Proposal rejection does not erase
usage. An invalid known-call receipt is a usage dispute: the Run pauses and
the reservation remains controlled until an administrator resolves it. The
service-owned iteration charge is appended once per terminal iteration.

`verify` recomputes result-call bindings, usage reverse mappings, artifact
provenance, conflict escalation, group completeness, iteration charges and
reservation closure. Fixture mode is a creation-time marker and cannot be
retrofit onto an existing control database. MR-2A.2 still has no real model,
provider, scheduler, network, acquisition worker, completion command, or real
Max Run.

### MR-2A.2R nested validation and terminal recovery

Provider-owned position, cross-examination, correction, validity-audit,
adjudication, and minority-report mappings are parsed behind one runner trust
boundary. Missing, empty, whitespace-only, wrong-type, and unknown nested
fields become a redacted controlled abort; `ContractValidationError` never
escapes as a runner business result. A rejected adjudication preserves the
five authoritative per-call usage facts, closes the iteration and group,
records one semantic conflict, and releases all remaining reservations.

The public verifier distinguishes a genuine in-flight open group by its live,
fencing-consistent lease and invocation claim. A terminal-ready open group
without that claim is an orphan and fails verification. Recovery after a
validation, conflict, iteration-finish, or group-finalize interruption reuses
immutable result, usage, conflict, and iteration identities; it cannot repeat
charges or leave an open terminal group. MR-2A.2R adds no migration and still
does not include a provider, network, scheduler, acquisition worker, or real
Max Run.
