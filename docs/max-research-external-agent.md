# Max Research external-Agent work protocol

## Architecture boundary

An external Agent is an already-running host participant.  It is not a
provider, a billing authority, a scheduler, or a process that the Max control
plane starts.  A Codex Desktop/Luna session, Hermes, Qoder, OpenCode, or
another integration can use the same protocol when it has an authenticated
connection to the governed control surface.  The host identity, claimed model
name, backend, provider, and transport remain separate fields.

This protocol therefore has a different execution shape from the provider
runner:

```
authenticated Agent -> bounded work packet -> governed research gateway
                     -> candidate result -> server validation and persistence
```

No external-Agent operation reads credentials, contacts a provider, performs
DNS, or infers a dollar cost.  Closing a Desktop session does not create a
scheduler or guarantee unattended continuation.

## Protocol v1

The control-plane discovery operation is:

```text
research-kb max external-agent-discover
```

It returns protocol `research-kb/external-agent/v1`, required fields, bounded
limits, and the distinction between server-injected authentication and
self-reported Agent/model metadata.  The implementation is exposed as the
`ExternalAgentService` API and a read-only CLI discovery command.  It does not
add to the existing researcher MCP exact-12 tool set.

The independent MCP transport is started as:

```text
research-kb-max-mcp --database <server-selected-max-db> \
  --actor-id <trusted-connection-actor> \
  --allowed-project <explicit-project-id>
```

Its tools are `max_discover`, `max_open_session`, `max_close_session`,
`max_get_work_packet`, `max_claim_work`, `max_recover_work`,
`max_release_work`, `max_submit_candidate`, `max_get_submission_status`, and
`max_verify`.  The database path, connection actor, and allowed project set
are process-start configuration; none can be overridden by a tool argument.
The transport never exposes the admin-only `issue_work_packet` or
`issue_next_round` operations to workers.  Those remain under the
human/server control plane.

The server-owned operations are:

- `open_session` / `close_session`: establish a project-scoped authenticated
  connection.  The server records the authenticated actor and keeps the
  claimed Agent/model name as untrusted metadata.
- `issue_work_packet`: an admin-only operation that binds a Run, iteration,
  state version/hash, question, role, allowed operations, result contract,
  expiry, and server-resolved source references.
- `claim_work`, `get_work_packet`, `recover_work`, and `release_work`: acquire
  at most one active claim, use a bounded fencing generation, and permit a
  different authenticated Agent in the same project to resume after release
  or expiry.
- `submit_candidate`: accepts only a strict candidate payload.  Claims,
  evidence links, objections, unresolved questions, and next steps remain
  candidate-only; the Agent cannot mark anything verified, accepted, or
  completed.  The server checks the packet, project, claim, state version/hash,
  allowed source identities, size, and idempotency key.
- `issue_next_round`: creates an append-only successor packet linked to the
  prior candidate result and reuses server-owned source and result-contract
  bindings.
- `verify`: checks JSON/hash bindings, event chains, current projections,
  claim generations, project-scoped references, candidate status, SQLite
  integrity, and foreign keys.

The transport is a local stdio boundary.  Its configured Actor proves only
that the server used the trusted process-start configuration; it does not
independently prove that the claimed model name is really Luna, Hermes, Qoder,
or any other model.  A production host must therefore launch it with an
authenticated connection binding and an explicit project allow-list.  The
optional `--research-config` attaches the existing research gateway as the
server-owned source resolver; it returns only stable document/passage
identities to Max control.

## Source and result discipline

Work packets contain source identities and bounded metadata, not copied source
正文.  The source resolver is server-owned and must validate each reference
for the packet project.  The Agent reads passage, metadata, and canonical
objects through the existing governed research interface.  A source reference
is not evidence of truth merely because its identifier is valid.

The result contract separates `unknown` and `self_reported` usage.  Neither
status is a provider receipt, and self-reported token counts are not a cost
ledger.  The control store intentionally does not accept API keys, prompts,
full source text, raw provider responses, or client-supplied approval/status
fields.

## Recovery semantics

Every session, packet, claim, claim transition, candidate result, and run
event is recorded with server-owned hashes.  Historical records are
append-only; current tables are projections.  A replay with the same packet
and idempotency key returns the same candidate result, while a conflicting
replay is rejected.  A stale state version, cross-project session, wrong
claim owner, forged identity, or expired packet/claim fails closed.

Recovery must begin by reading the canonical packet, permitted source
identities, and the current state.  A previous Agent summary is not a
canonical checkpoint.  The protocol distinguishes a packet completion from an
iteration completion, research readiness, and human acceptance; this surface
does not auto-accept research.

## Current implementation and enablement plan

The source implementation is an unreleased schema-32 candidate in the
development tree.  It does not change the installed governed runtime, global
Codex configuration, Pilot database, historical Canary databases, source
corpus, catalog, or Skill.  The existing provider-driven runner remains a
separate path.

Before enabling it in a Desktop integration, an administrator should:

1. review the schema-32 migration, release metadata, and protocol discovery
   document;
2. install the candidate into a new isolated runtime and run its migration,
   exact-12, doctor, and regression gates;
3. register an authenticated adapter that only translates the protocol calls;
4. bind that adapter to an explicit project and source policy;
5. run a disposable two-round validation with candidate-only results and
   inspect the event, claim, state, and recovery verifiers;
6. approve any runtime/config change separately before changing the Desktop
   MCP stanza.

This plan is not evidence that a real Codex Desktop, Luna, Hermes, Qoder, or
OpenCode connection has already been validated.  The repository tests use a
controlled source resolver and temporary control database; they are offline
protocol tests, not real Desktop-Agent research or provider execution.
