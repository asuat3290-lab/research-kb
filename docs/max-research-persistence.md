# Max Research MR-1 Persistence

MR-1 uses an independent SQLite control database. It is not the core
research database and it does not add core migration 006. The control schema
starts at version 1 and is applied only by the explicit `research-kb max init`
administrative command. MR-1A advances this independent schema to version 2
with the fixed `002_run_scoped_history.sql` migration; MR-2A advances it to
version 3 with the fixed `003_bounded_runner.sql` migration; MR-2A.1 advances
it to version 4 with the fixed `004_mr2a1_runner_closure.sql` migration; MR-2A.2 advances it to version 5 with the fixed `005_mr2a2_deliberation_usage.sql` migration; core migrations 001-005
and the original Max migration 001 remain unchanged.

The control store contains Max Run metadata, append-only approvals and
consumptions, immutable RunTransitionResult records, event hash chains,
canonical object identities, immutable versions and relations,
run-scoped object/relation memberships and atomic canonical change sets,
Research State snapshots, checkpoint lineage, iteration history, leases, and
the budget ledger. It stores stable references to core source objects, not PDF
bytes, full passages, source text, API keys, or copied citation metadata.

Every canonical mutation is submitted as one server-validated change set bound
to a run, an open iteration, the current Research State hash, and the current
lease fencing token. The complete object/version/relation graph, membership,
state successor, checkpoint successor, transition result, and event are either
committed together or rolled back together. A run can read only its own
membership; same-project runs do not share canonical state implicitly.

Core references must include an explicit project boundary and stable server
IDs. A supplied resolver must verify project ownership and source-version
existence before a reference is accepted. Client-authored author, page, DOI,
or locator fields are not authoritative and cannot replace the resolver.

All formal JSON is canonical MR-0 serialization. Hashes are recomputed from
the stored normalized values. Historical approvals, consumption records,
events, canonical versions, relations, checkpoints, iterations, and budget
entries are append-only; database triggers reject update/delete attempts.

Iteration outcomes and typed artifact links are authoritative completion
history. They persist input/output state hashes, exact snapshots, strategy
coverage, attack/adjudication/rehydration references, and budget links. The
completion gate rebuilds its input from these records, so a single payload
cannot claim stable rounds or required history. Authoritative usage requires a
typed `UsageReceipt` verified by a registered `UsageAuthority`; budget
idempotency keys are bound to the complete request hash, so a conflicting retry
is rejected rather than replayed.

The current control store can be backed up or restored as a standalone file
through the explicit Python Admin API. Backup/restore verification recomputes
the event chain, transition-result ledger, canonical graph, Research State,
checkpoint lineage, approval consumption, and budget balance without opening
or modifying the pilot research database.

MR-1 does not include a runner, model adapter, scheduler, network access,
source acquisition worker, or a real Max Run.

## Schemas 11-12: MR-2B2 and MR-3

Migration 011 persists ordered live-authorization bundles, immutable bundle
members/assignments/events, one-iteration human approvals, and their
single-use consumptions. Migration 012 persists foreground-worker commands,
command consumptions, fenced heartbeats/current projection, and the complete
acquisition request/grant/claim/validation/stage event chain. Core schema 5
remains a separate database.

All authority, history, and receipt tables reject update/delete. The few
`*_current` tables are projections: their canonical JSON/hashes, cardinality,
and event tips are recomputed during database and run verification. The
acquisition receipts contain hashes, counts, risk flags and validator
identity, not downloaded source bodies or absolute staging paths. Acceptance
of a dry-run projection is not an ingest transaction.

## MR-2A runner persistence

MR-2A adds immutable runner profiles, explicit admin-to-runner handoffs,
deterministic plans, model call intents, dispatch attempts and
acknowledgements, authoritative results, recovery decisions, links, and
attempt outcomes. The begin iteration row remains immutable; its appended
iteration outcome is the authoritative finish record. An unknown dispatch is
never rewritten by recovery.

`run-next` performs at most one bounded iteration and makes the adapter call
outside SQLite. A crash-safe recovery decision reuses an un-dispatched intent,
queries or retries only through a declared safe provider primitive, and pauses
for admin decision when the outcome is ambiguous. No CompletionResult is
persisted by the runner.

## MR-2A.1 runner authority closure

The independent control schema is now version 4 through the fixed
`004_mr2a1_runner_closure.sql` migration. Migrations 001-003 are immutable;
schema-3 stores containing runner history are refused for automatic backfill
because a full request/response envelope cannot be safely reduced to a
metadata-only manifest.

Production runner construction has no fake adapter, gateway, or usage
authority default. Missing dependencies fail with stable codes. Fixture
execution requires both an explicit `max init --fixture` marker and an
explicit `max simulate-next --fixture` command. The marker is server-owned and
does not make the production `run-next` path a fixture path.

Durable intent rows contain only IDs, hashes, role/phase, canonical frontier
IDs, and frozen plan metadata. Ephemeral gateway context and model request
bodies are rebuilt after recovery and are rejected if they contain source
text, prompts, secrets, paths, or client citation metadata. Durable results
contain typed proposal and usage-receipt fields, not a raw response wrapper.

Each invocation has an append-only claim/release ledger tied to actor/session,
lease fence, and a bounded TTL. `BEGIN IMMEDIATE` serializes same-run
`run-next` claims. Call groups persist every isolated role call; adjudication
uses separate lead and rival intents, attempts, results, usage receipts, and
idempotency keys under the same frozen model identity.

The planner reads authoritative `max_iteration_outcomes`, not a caller's
payload. The deterministic cycle records exploration, acquisition review,
adjudication, attack, and subsequent acquisition review; interval and trigger
rehydration is performed by the repository before a model call. Rehydration
outputs and typed cognitive artifacts are server-normalized and validated;
supporting evidence is not copied into counterevidence snapshots. Public
verification includes invocation claims, call groups, intent manifests,
recovery consumption, cognitive artifacts, and runner links.

## MR-2A.2 deliberation and usage closure

The independent Max schema is version 5 through the fixed
`005_mr2a2_deliberation_usage.sql` migration. It does not modify core
migrations or the earlier Max migrations. An adjudication iteration has five
logical calls under one frozen model/profile: `lead_position`,
`rival_position`, `rival_cross_examination`,
`lead_cross_examination_response`, and `adjudicator`. The first two receive
only the canonical packet. Later calls receive only the named, normalized
public artifacts from predecessors. Missing, empty, unknown, replayed, or
cross-contaminated artifacts fail closed.

Every logical call has an immutable call spec, intent manifest, attempt and
dispatch acknowledgement, authoritative result-call binding, usage receipt
binding, idempotency key, and recovery record. A successful or billable failed
provider result is charged exactly once after exact receipt verification,
regardless of proposal acceptance. Unused reservation remainder is released;
an invalid receipt after a known provider call becomes a usage dispute, pauses
the Run, and retains the reservation for administrator resolution. The service
adds exactly one iteration-count charge per terminal iteration.

`UsageReceipt` binds logical call, intent, request, provider call, Run,
iteration, model/profile, amount, authority and receipt hashes. Public
verification recomputes the result-call graph, receipt reverse mapping, usage
totals, iteration charge, artifact provenance, group completeness and
reservation closure. The database also persists typed append-only
  `EpistemicConflictRecord` rows; repeated semantic conflicts escalate through
  rejection, rehydration-required, and pause resolutions.

## MR-2A.2R recovery correction

The nested deliberation payload is untrusted at every level. The runner
converts contract parse/semantic failures into a controlled
`INVALID_ADJUDICATION` path before canonical normalization. The failure keeps
the five provider result/receipt/usage bindings auditable, charges the
service-owned iteration exactly once, records the conflict ladder, and closes
the call group. No DiscussionSession or canonical change is written for the
invalid payload.

`verify` requires an open group to have a live invocation claim and matching
lease/fencing state. A released worker cannot make a terminal-ready orphan look
in flight. Crash recovery is idempotent around validation, conflict append,
iteration finish, and group finalization, and reuses the stored iteration
outcome and conflict identities.

## MR-2B0 independent provider and scheduler store

MR-2B0R2 advances only the independent Max control schema to version 8 with
the packaged `006_mr2b0_provider_scheduler.sql`,
`007_mr2b0r_authority_budget_closure.sql`, and
`008_mr2b0r2_physical_dispatch_budget.sql` migrations; core schema 5 and
Max migrations 001-005 are frozen. Provider profile/pricing snapshots,
immutable run bindings, one-time execution grants, provider calls, usage
attestations, physical dispatch attempts, scheduler sessions/ticks, and the
current pointer are stored as control metadata. No source body, PDF, passage,
prompt, secret, or model response body is copied.

The profile hash covers normalized provider configuration, model identity,
endpoint policy, capability restrictions, and the pricing hash. CredentialRef
is only a reference. MR-2B0 accepts only injected hermetic transport, and its
disabled live transport fails closed. The wire codec is strict about duplicate
JSON, unknown/sensitive fields, sizes, depths, model/profile binding, and the
five-call adjudication visibility partition.

Usage is server-priced and follows the immutable chain
`ProviderCallRecord -> ProviderUsageAttestation -> UsageReceipt -> ledger`.
The admin-only LiveExecutionGrant binds run/charter/model/profile/network/
pricing/budget/caps/reason/expiry; its consumption is one-time and does not
occur during propose, approve, or start.

MR-2B0R2 requires explicit profile request limits for input, output,
cache-read, and reasoning tokens. Grant caps are aggregate caps:
`input_tokens + cache_read_tokens` and `output_tokens + reasoning_tokens` are
checked before dispatch and again against the authoritative receipt. Every
physical `transport.send` gets an immutable, pre-send dispatch-attempt slot;
recovery/retry allocates another durable slot and cannot bypass
`max_provider_calls`. A settled claim replays its durable result without a
new send. Legacy character-to-token estimates are diagnostic-only and are
rejected by execution preflight.

The scheduler is a foreground, finite service. Each tick owns at most one
existing `BoundedRunner.run_next`; the durable session/tick/current records
bind state hashes and lease fences. Expired-lease handoff creates a new
session record but reuses the consumed grant. MR-2B0 has no daemon, real
provider, network, acquisition worker, MR-2B1, MR-3, or real Max Run.

## MR-2B1A pre-live execution persistence (historical; Max schema 10)

MR-2B1A advances only the independent Max control database to schema 10 through
`010_mr2b1a_live_dispatch_permit.sql`; schema 8 and 9 are historical phases,
core schema 5 and Max migrations 001-010 remain separate and frozen. Migration
007 is `007_mr2b0r_authority_budget_closure.sql`. Schema 009 persists hash-only
`LiveNetworkAuthorization` records, one-time consumption, a per-authorization
access-event chain, and redacted attempt audit. Schema 010 adds immutable
server-owned `LiveDispatchPermit` rows, a current projection, and a per-permit
event chain. Neither migration persists a key, token, header, URL credential,
source body, prompt, response body, or absolute path.

Issuance is administrator-only and binds the run/project/charter, registered
profile/model, endpoint and network policy, pricing/budget hashes, caps,
expiry, and authority actor. Consumption additionally requires the consumed
StartApproval, consumed execution grant, and current lease/fencing token. It
is a single `BEGIN IMMEDIATE` operation protected by an immutable unique
record. Read-only status and preflight never consume authority, resolve a
credential, perform DNS, or open a connection.

The default live factory is disabled. The HTTPS implementation is injected
only for offline boundary tests and validates exact HTTPS origin/path,
all-candidate DNS safety, credential isolation, request restrictions, and
redirect refusal. MR-2B1A additionally proves the atomic claim/attempt/
budget/authorization/permit order, durable replay, crash classification,
stale-fence rejection, and revoke/consume races. It proves the pre-live
control boundary only; it does not verify a real provider or start a real Max
Run.
