# Max Research MR-2B0 bounded scheduler

The MR-2B0 scheduler is an explicit foreground service over one Max Run. It
is not a daemon, background task, hidden loop, or model orchestration worker.
Its independent durable state is stored in the Max control database schema 8
and never in the core research database.

## One bounded tick

One `tick` owns at most one existing `BoundedRunner.run_next` invocation. A
finite `run_bounded` call repeats only the caller-supplied bounded number of
ticks. The durable records are:

- immutable scheduler policy;
- append-only scheduler session and tick records;
- one mutable current pointer containing the state hash, tick number, next
  action, stop status, and stop reason.

The current pointer, runner result hash, fencing token, and event hash chain
are verified together. A tick is recorded only after the runner result has
passed the existing provider/profile, invocation, lease, usage, iteration,
and canonical-state boundaries.

Provider dispatch authority is checked before the tick can send: all four
profile token caps must be explicit, aggregate cache/reasoning totals must fit
the grant, and a physical attempt slot must be durable before `send()`. The
slot count is the `max_provider_calls` authority; settled replay does not send
again and unknown recovery cannot consume a slot implicitly.

## Lease and restart

The scheduler reuses the existing single-run lease and monotonic fencing
token. An expired worker lease can be taken over only through the explicit
admin handoff path. A new worker creates a durable scheduler-session handoff
that reuses the already-consumed grant; it cannot consume the grant again.
The previous owner cannot write a tick, checkpoint, iteration, event, or
budget entry with a stale token.

Concurrent owner attempts are serialized by SQLite `BEGIN IMMEDIATE` and the
runner invocation claim. The test fixture exercises 20 competing workers;
at most one writes the authoritative tick for that race.

## Stop rules

The service stops and persists a reason when it reaches tick/iteration,
wall-clock, consecutive-failure, no-progress, grant-expiry, pause/cancel,
usage-dispute, ambiguous-recovery, rehydration-drift, acquisition-review,
human-approval, epistemic-conflict, or completion-candidate boundaries. A
policy cannot exceed the explicit grant caps. Completion is still evaluated
only by the existing history-based gate; MR-2B0 has no `max complete` command.

## Hermetic acceptance

The only accepted transport is injected in-memory hermetic transport. The
MR-2B0 fixture runs 48 finite ticks through exploration, acquisition review,
adjudication, attack, and four rehydration boundaries with network and
credential-read counters equal to zero. This is a control-plane fixture, not
a research run and not evidence from a real provider.

CLI support is explicit and redacted:

```text
research-kb max provider-validate
research-kb max provider-register
research-kb max provider-bind
research-kb max grant-live
research-kb max grant-status
research-kb max scheduler-tick
research-kb max scheduler-run-bounded
research-kb max scheduler-status
research-kb max scheduler-verify
```

MR-2B0 does not add a thirteenth research MCP tool and does not include a
scheduler daemon, network access, provider SDK, acquisition worker, MR-2B1,
MR-3, or MR-4.

## MR-3 extension (schema 12)

MR-3 layers a restartable foreground worker over the bounded runner. It adds
finite tick/wall-clock process bounds, fenced append-only heartbeats, and one
pending admin command per run (`pause`, `drain`, or `stop`). It remains an
explicit process and does not install a daemon.

Acquisition is a separate authority chain: typed request, human decision,
bounded worker grant, single claim, independent offline staging validation,
dry-run projection, and optional human acceptance. The validator rejects
links/reparse points, path escape, hash or size drift, unsupported formats,
archive expansion and active-content risk; it does not download, OCR, or
ingest. See `max-research-mr3.md`.
