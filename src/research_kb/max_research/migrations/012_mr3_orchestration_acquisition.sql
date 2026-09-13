-- MR-3: restartable long-running worker control and acquisition handoff.
--
-- The worker remains an explicit foreground process.  These tables persist
-- commands, heartbeats and external acquisition handoffs so an OS supervisor
-- may restart it without reconstructing authority from recent summaries.

CREATE TABLE IF NOT EXISTS max_worker_commands(
    command_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    command TEXT NOT NULL CHECK(command IN ('pause','drain','stop')),
    reason_hash TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    command_json TEXT NOT NULL,
    command_hash TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(length(reason_hash)=64),
    CHECK(length(command_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_worker_command_consumptions(
    consumption_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE REFERENCES max_worker_commands(command_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE,
    CHECK(length(consumption_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_worker_heartbeats(
    heartbeat_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    worker_state TEXT NOT NULL CHECK(worker_state IN ('starting','running','draining','paused','stopped','failed')),
    tick_count INTEGER NOT NULL CHECK(tick_count >= 0),
    state_hash TEXT,
    heartbeat_json TEXT NOT NULL,
    heartbeat_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, sequence_no),
    CHECK(state_hash IS NULL OR length(state_hash)=64),
    CHECK(length(heartbeat_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_worker_current(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    state TEXT NOT NULL CHECK(state IN ('starting','running','draining','paused','stopped','failed')),
    tick_count INTEGER NOT NULL CHECK(tick_count >= 0),
    last_heartbeat_id TEXT REFERENCES max_worker_heartbeats(heartbeat_id) ON DELETE RESTRICT,
    stop_reason TEXT,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(length(current_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_acquisition_requests(
    request_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL,
    request_json TEXT NOT NULL,
    request_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(length(source_policy_hash)=64),
    CHECK(length(request_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_acquisition_current(
    request_id TEXT PRIMARY KEY REFERENCES max_acquisition_requests(request_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('proposed','approved','claimed','staged','accepted','rejected','cancelled')),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(length(current_hash)=64)
);

-- Acquisition workers are intentionally governed independently from the
-- research runner lease.  A human admin issues one bounded, one-use grant for
-- exactly one approved acquisition request and one worker session.
CREATE TABLE IF NOT EXISTS max_acquisition_worker_grants(
    worker_grant_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_requests(request_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    max_candidates INTEGER NOT NULL CHECK(max_candidates > 0),
    max_bytes INTEGER NOT NULL CHECK(max_bytes > 0),
    reason_hash TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    grant_json TEXT NOT NULL,
    grant_hash TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(length(source_policy_hash)=64),
    CHECK(length(reason_hash)=64),
    CHECK(length(grant_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_acquisition_worker_grant_consumptions(
    consumption_id TEXT PRIMARY KEY,
    worker_grant_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_worker_grants(worker_grant_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_requests(request_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE,
    CHECK(length(consumption_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_acquisition_claims(
    claim_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_requests(request_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    worker_grant_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_worker_grants(worker_grant_id) ON DELETE RESTRICT,
    grant_consumption_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_worker_grant_consumptions(consumption_id) ON DELETE RESTRICT,
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    claimed_at TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    claim_hash TEXT NOT NULL UNIQUE,
    CHECK(length(claim_hash)=64)
);

-- A worker cannot attest that its own output is safe.  A separate validator
-- (or the human admin) reads the explicit staging directory and writes this
-- server-owned, hash-bound receipt.  The receipt contains no source text or
-- absolute path.
CREATE TABLE IF NOT EXISTS max_acquisition_validation_receipts(
    validation_receipt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_requests(request_id) ON DELETE RESTRICT,
    claim_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_claims(claim_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    worker_grant_id TEXT NOT NULL REFERENCES max_acquisition_worker_grants(worker_grant_id) ON DELETE RESTRICT,
    staging_manifest_hash TEXT NOT NULL,
    output_set_hash TEXT NOT NULL,
    validation_hash TEXT NOT NULL,
    dry_run_manifest_hash TEXT NOT NULL,
    validator_version_hash TEXT NOT NULL,
    candidate_count INTEGER NOT NULL CHECK(candidate_count >= 0),
    eligible_count INTEGER NOT NULL CHECK(eligible_count >= 0),
    duplicate_count INTEGER NOT NULL CHECK(duplicate_count >= 0),
    manual_review_count INTEGER NOT NULL CHECK(manual_review_count >= 0),
    total_bytes INTEGER NOT NULL CHECK(total_bytes >= 0),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(length(staging_manifest_hash)=64),
    CHECK(length(output_set_hash)=64),
    CHECK(length(validation_hash)=64),
    CHECK(length(dry_run_manifest_hash)=64),
    CHECK(length(validator_version_hash)=64),
    CHECK(length(receipt_hash)=64),
    CHECK(eligible_count + duplicate_count + manual_review_count <= candidate_count * 2)
);

CREATE TABLE IF NOT EXISTS max_acquisition_stage_receipts(
    receipt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_requests(request_id) ON DELETE RESTRICT,
    claim_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_claims(claim_id) ON DELETE RESTRICT,
    validation_receipt_id TEXT NOT NULL UNIQUE REFERENCES max_acquisition_validation_receipts(validation_receipt_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    staging_manifest_hash TEXT NOT NULL,
    validation_hash TEXT NOT NULL,
    dry_run_manifest_hash TEXT NOT NULL,
    candidate_count INTEGER NOT NULL CHECK(candidate_count >= 0),
    total_bytes INTEGER NOT NULL CHECK(total_bytes >= 0),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(length(staging_manifest_hash)=64),
    CHECK(length(validation_hash)=64),
    CHECK(length(dry_run_manifest_hash)=64),
    CHECK(length(receipt_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_acquisition_events(
    acquisition_event_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES max_acquisition_requests(request_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(request_id, sequence_no),
    CHECK(length(payload_hash)=64),
    CHECK(length(event_hash)=64)
);

CREATE INDEX IF NOT EXISTS max_worker_commands_run_idx ON max_worker_commands(run_id, issued_at);
CREATE INDEX IF NOT EXISTS max_worker_heartbeats_run_idx ON max_worker_heartbeats(run_id, sequence_no);
CREATE INDEX IF NOT EXISTS max_acquisition_requests_run_idx ON max_acquisition_requests(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_acquisition_worker_grants_run_idx ON max_acquisition_worker_grants(run_id, issued_at);
CREATE INDEX IF NOT EXISTS max_acquisition_validation_receipts_run_idx ON max_acquisition_validation_receipts(run_id, created_at);

CREATE TRIGGER IF NOT EXISTS max_worker_commands_no_update BEFORE UPDATE ON max_worker_commands BEGIN SELECT RAISE(ABORT, 'Max worker commands are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_worker_commands_no_delete BEFORE DELETE ON max_worker_commands BEGIN SELECT RAISE(ABORT, 'Max worker commands are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_worker_command_consumptions_no_update BEFORE UPDATE ON max_worker_command_consumptions BEGIN SELECT RAISE(ABORT, 'Max worker command consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_worker_command_consumptions_no_delete BEFORE DELETE ON max_worker_command_consumptions BEGIN SELECT RAISE(ABORT, 'Max worker command consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_worker_heartbeats_no_update BEFORE UPDATE ON max_worker_heartbeats BEGIN SELECT RAISE(ABORT, 'Max worker heartbeats are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_worker_heartbeats_no_delete BEFORE DELETE ON max_worker_heartbeats BEGIN SELECT RAISE(ABORT, 'Max worker heartbeats are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_requests_no_update BEFORE UPDATE ON max_acquisition_requests BEGIN SELECT RAISE(ABORT, 'Max acquisition requests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_requests_no_delete BEFORE DELETE ON max_acquisition_requests BEGIN SELECT RAISE(ABORT, 'Max acquisition requests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_worker_grants_no_update BEFORE UPDATE ON max_acquisition_worker_grants BEGIN SELECT RAISE(ABORT, 'Max acquisition worker grants are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_worker_grants_no_delete BEFORE DELETE ON max_acquisition_worker_grants BEGIN SELECT RAISE(ABORT, 'Max acquisition worker grants are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_worker_grant_consumptions_no_update BEFORE UPDATE ON max_acquisition_worker_grant_consumptions BEGIN SELECT RAISE(ABORT, 'Max acquisition worker grant consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_worker_grant_consumptions_no_delete BEFORE DELETE ON max_acquisition_worker_grant_consumptions BEGIN SELECT RAISE(ABORT, 'Max acquisition worker grant consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_claims_no_update BEFORE UPDATE ON max_acquisition_claims BEGIN SELECT RAISE(ABORT, 'Max acquisition claims are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_claims_no_delete BEFORE DELETE ON max_acquisition_claims BEGIN SELECT RAISE(ABORT, 'Max acquisition claims are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_validation_receipts_no_update BEFORE UPDATE ON max_acquisition_validation_receipts BEGIN SELECT RAISE(ABORT, 'Max acquisition validation receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_validation_receipts_no_delete BEFORE DELETE ON max_acquisition_validation_receipts BEGIN SELECT RAISE(ABORT, 'Max acquisition validation receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_stage_receipts_no_update BEFORE UPDATE ON max_acquisition_stage_receipts BEGIN SELECT RAISE(ABORT, 'Max acquisition receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_stage_receipts_no_delete BEFORE DELETE ON max_acquisition_stage_receipts BEGIN SELECT RAISE(ABORT, 'Max acquisition receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_events_no_update BEFORE UPDATE ON max_acquisition_events BEGIN SELECT RAISE(ABORT, 'Max acquisition events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_acquisition_events_no_delete BEFORE DELETE ON max_acquisition_events BEGIN SELECT RAISE(ABORT, 'Max acquisition events are append-only'); END;
