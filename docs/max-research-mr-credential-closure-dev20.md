# Max Research credential closure dev20

`0.1.1.dev20` keeps core schema 5, Max schema 28, and migrations 001–028
unchanged.  It closes the production pre-send credential-resolution boundary
without changing the historical control databases or the research corpus.

## Server-owned host resolution

The convergence production factory creates a
`BoundHostEnvironmentCredentialResolver` only after the server has validated
the registered provider profile, dispatch permit, and network policy.  The
resolver is bound to the canonical credential-reference hash and accepts only
an exact `environment` reference.

Resolution is non-enumerating: the exact process-environment name is checked
first.  On Windows, a missing process value may fall back to the exact value in
the current user's `Environment` key.  Only `REG_SZ` values are accepted;
machine scope, expansion, helper processes, and environment enumeration are
not used.  Values are bounded, non-empty strings and are never included in
errors or audit records.

The audit separates `credential_resolution_attempts` from
`credential_reads_succeeded`.  A failed lookup therefore cannot be reported as
a successful credential read.  Audit source categories are limited to
`process_environment` and `windows_user_environment`.

## Test and live boundaries

The legacy environment resolver remains disabled by default.  Hermetic tests
may provide package-owned fake resolver and connector seams; the production
convergence path does not expose arbitrary resolver injection.  Preview,
doctor, MCP readiness, build, and release checks do not resolve host
credentials.  A missing or invalid host value fails closed before the HTTP
send boundary.

The dev20 candidate must be installed and rebound only after the offline
release, clean-install, exact-12, and doctor gates pass.  No real canary or
external network action is part of this closure.
