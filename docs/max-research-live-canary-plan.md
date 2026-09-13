# MR-4B Live Canary Plan (Plan Only)

This document is a release-gated plan, not an execution record. MR-4B is not
authorized by MR-4A. No DNS resolution, credential lookup, HTTPS request,
provider call, source acquisition, OCR, ingest, long worker, or real Max Run
may be performed from this plan.

## Manual approval checklist

Before any canary, a human administrator must inspect and explicitly confirm
each item below. A preview hash is not authority; the signed/recorded human
confirmation must bind the exact values.

- project ID and Run ID; charter hash and current canonical state/checkpoint
  hash/version;
- endpoint origin, exact path policy, HTTPS-only transport, no redirects,
  DNS/SSRF/private-address policy, timeout and retry limits;
- provider name, provider profile hash, exact model identity and model version;
- credential source reference (reference only, never the secret), credential
  owner, retention/rotation responsibility and incident contact;
- source-egress policy hash, gateway origin/path, project/document/passage
  allowlist, denylist, source roles, purposes, reliability and verification
  policy, full-document prohibition and redaction policy;
- iteration/tick/wall-clock/provider-call/input/output/cache/reasoning/
  source/character/token/cost/failure/no-progress/acquisition caps;
- canary timeout, maximum retries (normally zero or one), no redirect, kill
  switch, pause/drain/stop/revoke procedure and rollback target;
- incident escalation, evidence preservation, redaction requirements, data
  retention and deletion owner;
- success criteria, failure criteria, exact typed confirmation phrase, and
  hashes for the final preview, provider profile, source policy, endpoint
  policy and cap vector.

The approval record must state that the operator has reviewed the exact
endpoint origin/path, model, credential reference, project, allowlist, policy
hashes, caps, timeout/retry/no-redirect rules, kill/rollback/incident plan,
redaction/retention, success/failure criteria, and confirmation phrase.

## First canary shape

The first canary is deliberately smaller than a research run:

1. one already-ingested, allowlisted project and one approved Run;
2. one or two passages returned through the controlled local gateway;
3. one provider call only, with the lowest practical input/output and cost
   caps, no retries unless separately approved;
4. no acquisition, downloading, OCR, staging, authoritative ingest,
   background worker, unattended loop, or automatic renewal;
5. one operator watching the kill switch and inspecting the server-rebuilt
   source handles/citation chain before any follow-up decision.

The canary may proceed only after a fresh read-only preflight confirms all
hashes and current state. Any drift, unknown response, timeout, redirect,
credential failure, source-version mismatch, citation mismatch, cost
uncertainty, or redaction violation pauses and records the incident; it does
not retry automatically. A successful canary does not authorize MR-4B
long-run operation or MR-5.
