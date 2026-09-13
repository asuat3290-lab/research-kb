# MR-3 Restartable Orchestration and Acquisition Isolation

MR-3 advances the independent Max control database to schema 12 through
`012_mr3_orchestration_acquisition.sql`. It adds a restartable foreground
worker and a controlled acquisition staging workflow. It does not add a
daemon, background service, thirteenth MCP tool, automatic ingest, OCR, or
network downloader.

## Foreground worker

`LongRunningWorker` is an explicitly invoked, bounded process loop. Every run
has finite tick and wall-clock limits. Durable state consists of:

- append-only administrator commands (`pause`, `drain`, or `stop`) and their
  single-consumer records;
- append-only, monotonically sequenced heartbeats bound to the current run
  state hash and lease fence; and
- one reconstructible current projection.

Only one unconsumed command may exist for a run, preventing contradictory
administrative instructions. Repeating the same command is idempotent. A
stale worker cannot consume a command or append a heartbeat. Lease takeover
uses the existing monotonic fencing protocol. The return value retains only a
bounded redacted tail; canonical state remains in SQLite, not in a growing
summary chain.

An operating-system supervisor may restart the foreground process, but the
repository does not install or start one. Restart reads durable canonical
state, iteration history, commands, and the current checkpoint rather than a
recent model summary.

## Acquisition separation

An agent may propose a typed `AcquisitionRequest`, but cannot approve it. A
human administrator must approve the request and issue one bounded worker
grant. The bound acquisition worker may consume that grant and claim the
request once. It cannot validate or accept its own output.

The worker writes only to an explicitly selected staging directory outside
the research database. Independent administrator validation then:

- rejects absolute/escaping paths, symlinks, junctions, and reparse points;
- verifies declared byte counts and SHA-256 values;
- checks format magic and bounded ZIP structure;
- quarantines PDF active-content/encryption signals;
- flags within-batch and pre-existing content duplicates;
- enforces candidate and total-byte caps; and
- generates a server-owned dry-run ingest projection.

The resulting validation and stage receipts are immutable and hash-bound.
Human `accept` records only acceptance of that dry-run projection. It never
calls core ingest and never changes the corpus. Authoritative ingest remains
a separate Admin CLI action and approval boundary.

## Verification and limits

`verify_database` and `verify_run` include worker commands, command
consumptions, heartbeat continuity, current projections, acquisition
authority cardinality, grants, claims, validation/stage receipts, and the
acquisition event chain. The command-line additions expose only redacted
control-plane administration and read-only verification.

MR-3 acceptance is offline. No real provider, API key, network call,
acquisition download, model charge, or real Max Run is asserted. Long-running
production research additionally needs a separately approved source gateway,
live canary, and operating procedure.

