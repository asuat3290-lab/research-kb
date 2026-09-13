# Max Research MR-2B0 provider boundary

MR-2B0 defines a provider execution boundary without enabling a real
provider. The existing research MCP surface remains exact-12. Provider
metadata lives in the independent Max control database (schema 8); the core
research database and its schema 5 migrations are unchanged.

## Profile and credential boundary

`ProviderProfile` is a strict, versioned, canonical object. Its hash covers
the normalized provider configuration, model identity, endpoint policy,
capabilities, inference defaults, timeouts, retry limits, request limits,
rate policy, network-policy hash, and pricing snapshot. Server-owned approval
actor/time are audit metadata and do not change the profile configuration hash.

The profile stores only a `CredentialRef`. It never stores a key, token,
header, cookie, `.env` value, or secret-bearing URL. MR-2B0 accepts only
credential-free HTTPS origins, explicit non-local/non-private hosts, a fixed
path policy, and no redirect, proxy, TLS-off, provider-side file/URL fetch,
streaming, or tool-calling capability.

## Hermetic transport

The only dispatchable transport in this phase is the injected in-memory
`HermeticTransport` (or its explicit injected subclass). It records request
metadata and deterministic counters but never opens a socket or resolves a
credential. `DisabledLiveTransport` is an explicit fail-closed sentinel.
There is no provider SDK, network implementation, environment-key lookup, or
real model call in MR-2B0.

The OpenAI-compatible codec is provider-neutral and strict: it emits one
server-owned typed JSON request and accepts exactly one complete JSON response.
Duplicate keys, NaN/infinite values, unknown fields, invalid depth/size,
wrong model/profile bindings, forbidden source/path/credential material, and
wrong phase visibility fail closed. The five adjudication calls use the
following visibility partition:

```text
lead_position -> rival_position -> rival_cross_examination
              -> lead_cross_examination_response -> adjudicator
```

The two positions see only the canonical packet. Each later call receives
only named, normalized public artifacts from its declared predecessors. Raw
prompt text, source bodies, absolute paths, chain-of-thought, and secrets are
not durable provider records.

## Usage authority

Every accepted hermetic call has the server-owned chain:

```text
ProviderCallRecord
  -> ProviderUsageAttestation (server pricing snapshot)
  -> existing UsageReceipt / authoritative budget ledger entry
```

The provider response cannot choose its monetary cost. Decimal pricing is
recomputed from normalized token units; ambiguous or disputed usage pauses
the controlled run and does not silently become free. Call, attestation,
receipt, and ledger identities are idempotent and hash-bound.

MR-2B0R2 closes the physical and aggregate budget boundary. Execution
profiles must explicitly declare all four token caps: input, output,
cache-read, and reasoning. Grant input usage is checked as
`input + cache_read`, and grant output usage as `output + reasoning`. Before
each physical `send()` the control store appends a reserved dispatch attempt
and increments the physical-call count. Unknown attempts retain their
reservation; a later admin-authorized retry appends a new attempt, while a
settled idempotency key returns its stored result without another send. A
character-count estimate is never execution authority.

## Explicit grant

`LiveExecutionGrant` is created only by an explicit human administrator. It
binds run, project, charter, model, provider profile, network policy,
pricing, budget, caps, reason, authority, and expiry. Consumption is an
append-only one-time record in a `BEGIN IMMEDIATE` transaction. Propose,
approve, and start do not create or consume a grant automatically.

The admin API/CLI exposes provider validation, profile registration/binding,
grant issuance/status, and verification. Output is redacted; provider
origins, credential names, tokens, source text, and absolute paths are not
printed.

MR-2B0 stops at this boundary. It does not implement a real model adapter,
network access, source acquisition, scheduler daemon, MR-2B1, MR-3, or a
real Max Run.

## MR-2B2 bounded live pool

Schema 11 connects the pre-live permit boundary to the bounded runner through
an immutable ordered authorization bundle. One human `LiveIterationApproval`
authorizes exactly the next canonical-state-bound iteration, while each
physical model call still needs its own network authorization and permit.
The production-shaped factory cannot be replaced except by an injected
fixture in a fixture-marked temporary control database.

Acceptance used injected DNS, credential and HTTPS components. No production
credential or network was used. Provider input continues to reject corpus
text, passage text, citations and local paths; source-grounded egress remains
a later separately reviewed boundary.
