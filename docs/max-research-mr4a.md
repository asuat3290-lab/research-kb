# MR-4A Offline Long-Run Authorization and Canonical Source Egress

MR-4A closes the offline control plane for a bounded, restartable Max Research
long run. It advances the independent Max control database to schema 14 with
013_mr4a_long_run_authorization.sql and 014_mr4a_source_egress.sql. Core
research schema 5 and core migrations 001-005 are unchanged. The exact-12
research MCP surface is unchanged; no MCP tool 13 is added.

## Long-run authority

One consumed StartApproval may authorize one append-only long-run window. The
server binds that window to the Run, project, charter, initial canonical
state/checkpoint/version, provider/profile/model/pricing/budget hashes, source
policy and source-egress policy, endpoint-origin/path policy hashes, network
policy, credential-reference hash, runner/worker identity, lease fence,
not-before/expiry, and an explicit complete cap vector.

The cap vector covers iterations, ticks, wall-clock seconds, provider calls,
input/output/cache/reasoning tokens, cost units, consecutive failures,
no-progress iterations, acquisition requests, source packets/documents/
passages/characters/tokens, rehydration frequency, attack frequency,
adjudication frequency, round types, and strategy families. A worker can
cross a provider boundary only after the server mints a one-time
LongRunIterationPermit for the exact current state hash, checkpoint, version,
next iteration/tick, source-egress policy, worker session, and fence. The
permit is consumed once before any provider boundary. Existing
LiveIterationApproval is mutually exclusive for the same iteration.

Pause, drain, stop, revoke, expiry, exhaustion, failure, no-progress,
completion-candidate, acquisition-pending, and state/rehydration drift all
fail closed before the next provider I/O. A successor is append-only, carries
prior usage and requires a new human reason and exact confirmation. There is
no automatic renewal, cap reset, or implicit budget expansion.

## Canonical source egress

SourceEgressPolicy, SourcePacketRequest, CanonicalSourcePacket, SourceHandle,
SourcePacketReceipt, SourcePacketConsumption, and SourceEgressEvent provide
the server-owned evidence boundary. The only gateway is a controlled local
research-kb read-only interface bound to the active project and Run. Policies
explicitly allow purposes, projects, documents/passages, roles, evidential
functions, reliability/verification statuses, excerpt/context/document/
passage/token caps, and full-document prohibition.

The Max control database stores only hashes, IDs, counts, bounded locator
metadata, policy bindings, receipts, truncation, rejection and event-chain
facts. It does not store passage text, quotes, PDFs, prompts, credentials,
raw paths, file URIs, SQL, or client citation metadata. Source text is a
transient gateway result. It is sent to a provider-shaped boundary only as
quoted source data, explicitly separated from system/developer/role
instructions. Unverified material is discovery/candidate-only. Model output
may return server source handles only; the server reconstructs the final
Claim -> Evidence Link -> Evidence -> Passage -> Document Version chain.

Retrieval intent is structured and lexical-only in MR-4A. Semantic and hybrid
retrieval are rejected at the boundary until a separately approved design
exists. Project/run scope and bounded top_k are server-checked.

## Offline verification

The MR-4A adversarial fixture runs 48 synthetic iterations across exploration,
Socratic, source retrieval, evidence comparison, adjudication, Habermasian,
attack, and rehydration rounds. It exercises permit single-winner behavior,
revoke-before-next-I/O, renewal with carried usage, source injection
separation, citation/path/raw-text rejection, cross-scope rejection, and
lexical-only retrieval. It records zero network calls, zero DNS lookups, zero
credential reads, and zero cost. No provider, DeepSeek/API key, real Max Run,
source acquisition, OCR, ingest, or production unattended research is
claimed.

The human-admin CLI exposes read-only preview/status/preflight/verification
and explicit authorize/control/renew/policy actions. provider-live-smoke
--execute remains fail-closed. The next real-network phase is not part of
MR-4A; see max-research-live-canary-plan.md for a plan-only approval gate.
