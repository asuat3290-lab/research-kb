# MR-4B1C Execution Window Renewal

Migration 026 upgrades the Max control schema from 25 to 26. It preserves
schema-25 Execution Preview history append-only and adds a server-owned
current projection plus a hash-chained lineage event table.

An unexpired Execution Preview is idempotent. An expired Preview may produce
one successor only when its Human Approval remains valid and unconsumed and no
JIT, lease, claim, permit, grant, network, credential, Provider, or send-boundary
activity has occurred. A successor records its generation, the superseded
Preview ID/hash, and `renewal_reason=expired_before_execution`.

Old Preview and Authorization rows are never updated, deleted, revived, or
re-authorized. The current projection is the only mutable projection. Each
generation can have at most one Authorization, and concurrent renewal callers
must converge on the same current successor.

Migration 026 is fail-closed on a non-matching schema-25 Preview table
fingerprint. The controlled rebuild runs in one transaction, validates the
foreign-key graph and historical row digests before commit, and is required to
pass rollback injection at table creation, copy, rename, index/trigger
rebuild, and current-projection backfill boundaries. Real governed databases
must be migrated only after a separate human installation/rebind approval.

## MR-4B1C-NP0: durable Live Network Policy

MR-4B1C-NP0 closes the production network-policy lookup gap without touching
the governed V20 database. The existing server-owned, content-addressed
policy registry remains the source of truth. A new schema-027 binding table
records the immutable project/run/profile/release/endpoint/policy relationship,
and Preview, JIT, and verifier paths fail closed unless that binding and its
canonical payload are present and consistent.

The dev17 candidate keeps core schema 5 and MCP exact-12, raises Max control
schema to 27, and leaves migrations 001--026 unchanged. Installation, runtime
rebind, and any real V20 migration require a separate human approval; this
closure phase is offline and produces only a candidate release.
