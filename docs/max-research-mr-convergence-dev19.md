# Max Research convergence dev19

`0.1.1.dev19` keeps Max control schema 28 and migrations 001–028 unchanged.
It closes the production Capsule bridge introduced by the dev18 convergence
surface.

## Transport authority

The production path constructs a package-owned one-shot transport factory.  The
factory shares the already completed bounded DNS resolver with the HTTPS
transport, so transport creation cannot silently perform a second lookup.
The adapter and native executor accept only the exact package-owned production
types.  A user-defined subclass or a `convergence_owned` marker is not an
authority.  Fixture transport seams remain restricted to explicitly marked
fixture control databases; the production CLI exposes no transport, connector,
credential-resolver, or request injection option.

## Durable closure

After a successful or authoritative provider result, the service closes the
runner result, usage receipt, iteration, call group, JIT authority, handoff,
lease, and invocation claim through their existing server-owned persistence
APIs.  A known pre-send failure closes dispatch capabilities and releases the
unused reservation without inventing a provider call or rolling back consumed
DNS/source/network facts.  An unknown-after-send result remains a durable
reconciliation state and is never retried.

## Charter budget

`max propose` invokes the formal budget normalizer before opening the control
database or creating a Run.  Charter budget units are distinct from provider
and runner caps and from human/effective approval ceilings.  Unsupported
fields fail closed with zero control-plane writes.

All production-facing payloads remain bounded and hash-bound.  The convergence
preflight creates a server-owned Capsule Preview only; execution still
requires the exact server-generated confirmation phrase and a separate human
execution boundary.
