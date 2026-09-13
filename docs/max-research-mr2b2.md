# MR-2B2 One-Iteration Live Execution Closure

MR-2B2 advances the independent Max control database to schema 11 through
`011_mr2b2_live_authorization_bundle.sql`. Core research schema 5 and the
researcher-facing exact-12 MCP surface are unchanged.

## Human authority and bounded execution

A live iteration requires all of the following server-verified records:

1. a consumed Max StartApproval;
2. a consumed run/profile LiveExecutionGrant with finite call, token, cost,
   iteration, and wall-clock caps;
3. an ordered LiveAuthorizationBundle containing one unconsumed
   LiveNetworkAuthorization for every possible physical provider call;
4. the current runner handoff, lease, and fencing token; and
5. one unexpired `LiveIterationApproval` issued by a human administrator for
   the exact next sequence number and current canonical state hash.

The approval is consumed once by the bound runner. Its consumption binds the
iteration input state and expected sequence before the runner can construct a
transport or perform DNS, credential, or socket work. Recovery may reuse the
same consumption only at the exact pre-iteration or matching in-flight
boundary. A later iteration, different runner, stale fence, changed state,
different bundle, or different provider profile fails closed.

The bundle assigns authorities in a fixed ordinal order. Each logical call
receives exactly one durable assignment before physical dispatch. Bundle
membership, assignment, current projection, and event history are verified;
historical rows are append-only. Deliberation may therefore consume several
physical-call authorizations while remaining one human-approved bounded
iteration.

## Production and acceptance boundary

The production entry point is `LiveRunnerExecutor`. It accepts the exact
package `LiveProviderTransportFactory`; injected subclasses are accepted only
by explicitly fixture-marked temporary control databases. The implementation
has been exercised end to end with injected DNS, credentials, and HTTPS, with
one dispatch and one charge, but no real network, credential, provider, or
fee was used during acceptance.

`live_execution_confirmation_hash` is only a preview/confirmation digest. It
is not authority and cannot replace the durable human approval.

MR-2B2 deliberately does not export corpus text, passage text, citations, or
local paths to a provider. The existing provider codec rejects those fields.
A useful real source-grounded Max run therefore still requires a separately
approved source-egress/gateway design and live canary. This stage does not
claim that such a run has occurred.

