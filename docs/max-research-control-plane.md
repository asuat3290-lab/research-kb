# Max Research MR-1 Control Plane

The control plane is exposed through the Python service/admin API and the
backward-compatible `research-kb max` Admin CLI. It does not add a thirteenth
research MCP tool; the researcher-facing MCP surface remains exact-12.

## Authority and transitions

`propose` creates an `AWAITING_START_APPROVAL` run and never creates an
approval. `approve` requires the exact stored Charter hash, an actor and a
reason. A server-owned `StartApproval` and its one-time `ApprovalConsumption`
are inserted together with the `AWAITING_START_APPROVAL -> APPROVED`
transition in one `BEGIN IMMEDIATE` transaction. Model or runner identities
cannot self-approve.

`start` is the only control command that enters `RUNNING` from `APPROVED`.
It acquires the first lease but does not call a model or start an iteration.
`pause`, `resume`, and `cancel` reuse the MR-0B state machine. Every
state-version write stores the exact MR-0B `RunTransitionResult` in an
append-only ledger, and every transition/approval action emits an immutable
event.

Canonical writes are not available as an unbound repository shortcut. The
service requires `run_id`, an open iteration, the current state hash, and the
current fencing token. `apply_change_set` validates all typed objects,
relations, endpoint versions, project/source references, and explicit adoption
of existing versions before atomically committing the graph and its state
successor. Verified source references are resolved server-side; client
citation metadata and client-supplied reference hashes are never authoritative.

## Events, leases, and budgets

Each run has an independent event sequence and SHA-256 chain. Every event
contains a server-owned actor/session and UTC timestamp. Event payloads are
redacted control summaries and cannot contain secrets, source text, or paths.

There is at most one active lease per run. Acquire, renew, release, and
expired takeover use a monotonically increasing fencing token. The token is
required for checkpoint, iteration, budget, state, and canonical writes; a
stale owner cannot write after takeover.

The budget ledger is append-only and reconstructable. Reserve, commit,
release/refund, and authoritative usage entries have idempotency keys. Usage
requires a typed receipt from a trusted or test-authoritative authority; a
free-form client provenance mapping cannot authorize usage. Idempotency keys
are request-bound and conflicting reuse fails closed.
The available balance is derived from the ledger and Charter limits.

## Canonical state and completion history

Canonical identity rows, immutable versions, and immutable relations bind exact
endpoint versions and project IDs. Working summaries and checkpoints contain
IDs and bounded working state; they do not replace canonical objects.

Iteration records persist input/output state hashes, snapshots, strategy
coverage, attack/adjudication/rehydration references, and budget deltas.
Completion persistence re-runs the MR-0B evaluator and additionally requires
historical evidence of the required attack, adjudication, rehydration, and
consecutive stable rounds. A single client completion payload cannot create a
completed run. A paused run releases its lease; resume reacquires a fresh
server-issued fencing token after recovery, so the former owner cannot write
with a stale token.

`status`, `events`, and `verify` are read-only and redact absolute paths,
source text, tokens, and secrets. A missing control database is an explicit
read-only failure; only `max init` may create it.

## MR-2A bounded runner boundary

MR-2A adds only the provider-neutral bounded runner kernel through the Python
service/admin API and backward-compatible Admin CLI. It uses one immutable
model identity and RunnerProfile, an explicit administrator-to-runner
handoff, the existing lease/fencing service, deterministic plans, append-only
model-call records, and crash-safe recovery. Adapter calls occur outside
SQLite transactions. Ambiguous external dispatch pauses the Run and requires
an administrator decision.

The runner does not create a CompletionResult, expose `max complete`, start a
scheduler, access the network, download sources, or start a real Max Run. The
MCP surface remains the exact existing 12 tools. MR-2A stops here pending
approval for MR-2B.

## MR-2A.1 authority closure

MR-2A.1 keeps the exact-12 MCP surface unchanged and closes the bounded-runner
authority chain in Max control schema 4. A production `MaxRunnerService` is
dependency-incomplete by default and fails closed with
`ADAPTER_NOT_CONFIGURED`, `GATEWAY_NOT_CONFIGURED`, or
`USAGE_AUTHORITY_NOT_CONFIGURED`. The shipped fake adapter/gateway/authority
are test fixtures only; they require a server-created fixture marker and the
explicit `simulate-next --fixture` command.

An invocation claim is a server-owned, append-only mutex bound to the current
lease fence, actor, session, and expiry. A paused or cancelled run may finish
releasing the original claim after its lease has been released; a stale owner
still cannot perform a new write. Call groups and immutable bindings make
multi-role adjudication auditable: lead and rival calls receive separate
packets, intent IDs, result IDs, usage receipts, and idempotency keys, while
the model identity remains singular and frozen.

The control store persists metadata-only intents and typed durable results.
Ephemeral gateway context is never a persistence channel. Iteration outcomes
are the authoritative history used by the deterministic cycle and completion
preconditions. Rehydration is a server-side canonical rebuild before model
dispatch; drift pauses the run. Only exact `counters` relations contribute to
counterevidence. Ambiguous recovery decisions are an administrator-only,
one-time consumption ledger; `accept` requires an already stored authoritative
provider result, while `retry` reuses the exact original intent key.

`verify` now verifies the event chain and the runner chain together, including
orphan detection for plans, intents, groups, claims, recovery consumptions,
typed cognitive artifacts, and links. MR-2A.1 still has no provider SDK,
network access, scheduler, acquisition worker, or real Max Run, and stops
pending human approval for MR-2B.

## MR-2A.2 multi-call deliberation and billing

Max control schema 5 adds only independent append-only authority tables. The
research MCP surface remains exact-12. An adjudication group is one
server-owned outcome composed of five same-model/profile calls:

```text
lead_position -> rival_position -> rival_cross_examination
              -> lead_cross_examination_response -> adjudicator
```

Positions are isolated canonical-packet calls. Cross-examination, response,
and adjudication receive normalized public artifacts through explicit upstream
call IDs; the service never invents a position, question, answer, audit, or
adjudication when a call is absent or invalid. ValidityAudit dimensions and
reasoned-dissensus minority reports are parsed from the adjudicator's typed
output and bound to that result.

Usage is per logical call, not per accepted proposal. A frozen profile call
budget creates the reservation upper bound. The server authority verifies the
exact receipt context and provider identity before appending one usage entry;
the immutable usage binding maps result, receipt, and ledger entry. Failed
provider results with verified usage are charged; failed results without a
receipt release unused reservation. Invalid known-call receipts pause the Run
with a retained reservation as a usage dispute. `verify` recomputes these
facts and rejects missing, duplicate, orphaned, replayed, or money-mismatched
chains.

Fixture mode is a creation-time marker only. `max init --fixture` refuses any
pre-existing path, including an empty or non-fixture control database, and
the 005 migration never retrofits the marker. Intent manifests contain only
bounded metadata, stable IDs, hashes, provider/gateway identity and public
artifact references; they do not contain prompts, source text, raw responses,
secrets or absolute paths.

## MR-2B0 provider boundary and foreground scheduler

The independent Max control schema is now version 8 through the fixed
`006_mr2b0_provider_scheduler.sql`, `007_mr2b0r_authority_budget_closure.sql`, and
`008_mr2b0r2_physical_dispatch_budget.sql` migrations. Core schema 5 and
core migrations 001-005 remain separate and unchanged. The new tables contain
only provider configuration hashes, server IDs, usage attestations, grants,
physical dispatch-attempt history, lease-bound scheduler sessions/ticks, and
redacted state pointers; they never store corpus text or a provider response
body.

ProviderProfile is strict and versioned. It stores only a CredentialRef and
requires a credential-free HTTPS origin with no local/private endpoint,
redirect/proxy/TLS relaxation, streaming, tool calling, or provider-side
fetch. The only dispatchable MR-2B0 transport is injected in-memory
HermeticTransport. DisabledLiveTransport fails closed, so no API key lookup or
network call is possible.

ProviderCallRecord -> ProviderUsageAttestation -> the existing authoritative
UsageReceipt/ledger chain is the usage boundary. Pricing is server-owned and
recomputed from normalized usage. A human-admin LiveExecutionGrant binds the
run, charter, model, profile, network policy, pricing, budget, caps, reason,
and expiry; its append-only consumption is one-time and is never created by
propose, approve, or start.

The provider authority profile must carry explicit `max_input_tokens`,
`max_output_tokens`, `max_cache_read_tokens`, and `max_reasoning_tokens`.
Input and cache-read are one aggregate grant dimension; output and reasoning
are the other. A physical attempt is reserved before `send()`, counted by
`max_provider_calls`, and kept as `unknown` when dispatch outcome is unknown.
Only an explicit recovery decision can allocate a subsequent attempt, while
a settled attempt is replayed from durable result facts without sending.

The foreground scheduler executes at most one existing run_next per tick and
has no daemon or hidden loop. Durable session/tick/current-pointer records,
lease fencing, stop reasons, and event-chain verification support bounded
restart and expired-lease handoff. It stops on policy, grant, pause/cancel,
recovery, usage, drift, conflict, no-progress, and completion-candidate
boundaries. MR-2B0R2 adds no thirteenth MCP tool and does not implement MR-2B1,
MR-3, a real provider, network access, acquisition worker, or real Max Run.

## MR-2B1A live-network authority and physical-send permit (offline only; schema 10)

Schema 9 is an independent control-plane migration. Schema 10, through
`010_mr2b1a_live_dispatch_permit.sql`, is a second independent migration. It
adds policy snapshots,
hash-only live authorizations, one-time consumption rows, current projections,
per-authorization access events, and live-attempt audit records. Each event
chain has contiguous sequence numbers and SHA-256 links; update/delete
triggers reject historical mutation. Schema 8 and 9 are historical phases. The
existing schema 5 research database and Max migrations 001-010 are not touched.
Migration 007 is `007_mr2b0r_authority_budget_closure.sql`.

`LiveNetworkAuthorization` is issued only by an administrator and binds the
exact run, project, charter, provider profile, model, endpoint policy, network
policy, pricing, budget, caps, validity window, and authority actor. A
consumer must also prove the already-consumed StartApproval and execution
grant plus the current lease/fencing token. The unique append-only consumption
record makes replay and concurrent consumption fail closed. Verification and
backup/restore recompute these bindings and the event chain.

Before any credential or DNS activity, the server atomically reserves the
provider claim and physical attempt, reserves budget, consumes the live
authorization, and creates one `LiveDispatchPermit` in `BEGIN IMMEDIATE`.
The permit binds authorization/consumption, run/project, grant/profile/
model/pricing/budget, claim/attempt, request/wire/intent/logical-call and
idempotency hashes, endpoint/network policy, and worker lease/fencing. The
transport accepts only this server-owned permit and revalidates the current
fence immediately before DNS. A settled durable result is replayed before
new authorization consumption; a send-started crash becomes `unknown` and
cannot be retried automatically. Revoke/expire are administrator-only,
append-only transitions.

Only a credential-reference hash is durable. The default resolver and live
transport are disabled; read-only preflight is static and reports zero DNS,
credential, and network activity. The injected HTTPS boundary rejects
credential-bearing endpoints, local/private DNS candidates, rebinding,
redirects, caller authorization headers, and forbidden payload material. No
real provider, API key, network connection, charge, or Max Run is part of
MR-2B1A. The production-shaped resolver/DNS/HTTPS assembly is not invoked by
the CLI or readiness path. `provider-live-smoke` prepares only a fixed,
redacted offline request and refuses `--execute`; no real provider, API key,
network connection, charge, or Max Run is part of MR-2B1A.

## MR-2B2 and MR-3 closure (schemas 11-12)

Schema 11 adds immutable ordered live-authorization bundles and an
append-only human authority for exactly one next iteration. A consumption is
bound to the current canonical state, expected sequence, provider/runner
profiles, runner session and fence. It cannot become authority for another
iteration. Bundle assignment supplies one previously unconsumed physical-call
authorization to each logical call in order.

Schema 12 adds restartable foreground-worker commands and heartbeats plus the
acquisition request/grant/claim/validation/stage authority chain. Worker and
acquisition projections are mutable caches whose hashes and append-only
histories are recomputed by `verify_database` and `verify_run`. Independent
staging validation produces only a dry-run ingest projection; acceptance does
not write the core research database.

The schemas persist no provider body, credential, source text, or absolute
path. Offline acceptance does not establish that a real provider or a useful
source-grounded Max Run has executed.
