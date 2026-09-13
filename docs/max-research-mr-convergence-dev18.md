# MR-CONVERGENCE-DEV18

This release provides a compact, server-owned Max Research canary surface for
the final validation path. It is intentionally separate from the historical
multi-step live-canary commands.

## User-facing flow

1. Complete the normal preparation chain through a durable Preparation Preview
   and DNS request.
2. Create one immutable capsule Preview:

   `research-kb max canary-preflight --database <control-db> --preview-id <preparation-preview-id>`

   The command performs no DNS, credential read, transport operation, or
   Provider call. It returns a server-owned capsule hash and the phrase
   `EXECUTE MAX CANARY <capsule-hash>`.
3. After an operator has reviewed that phrase, execute it once:

   `research-kb max canary-execute --database <control-db> --capsule-hash <capsule-hash> --confirmation "EXECUTE MAX CANARY <capsule-hash>"`

The execute command owns the internal DNS preflight, approval chain, JIT
lease/claim, permits, budget reservation, and Provider transport. These are
append-only control-plane facts; callers cannot supply policy, source text,
prompt, endpoint, model, token caps, or cost caps.

## Safety boundary

The capsule is content-addressed and immutable. Its payload contains only
bounded identifiers, hashes, policy fields, caps, timestamps, and state. It
does not persist prompts, source text, credential values, response bodies, or
resolved addresses. A second consume, a replayed phrase, expired state,
binding drift, or a concurrent claim fails closed.

Production transport is enabled only through the package-owned transport
factory. Hermetic tests inject DNS, credential, and HTTPS seams into the same
production-shaped adapter; they never open a socket or read a real secret.
The production command has no fixture transport selector.

## Release identity

Dev18 adds Max migration 028, keeps core schema 5, and keeps the MCP surface
at exactly twelve tools. The release manifest and wheelhouse are checked by
the offline installer before the runtime is activated.

