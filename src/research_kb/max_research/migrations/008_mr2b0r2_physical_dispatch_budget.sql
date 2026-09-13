-- MR-2B0R2: physical dispatch attempts and aggregate provider budget closure.
-- Migrations 001-007 are frozen and are never rewritten by this migration.

CREATE TABLE IF NOT EXISTS max_provider_dispatch_attempts(
    attempt_id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES max_provider_call_claims(claim_id) ON DELETE RESTRICT,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    grant_consumption_id TEXT NOT NULL REFERENCES max_live_execution_grant_consumptions(consumption_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    logical_call_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL,
    physical_attempt_no INTEGER NOT NULL CHECK(physical_attempt_no >= 1),
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    owner_id TEXT NOT NULL,
    owner_session TEXT NOT NULL,
    reserved_input_tokens INTEGER NOT NULL CHECK(reserved_input_tokens >= 0),
    reserved_output_tokens INTEGER NOT NULL CHECK(reserved_output_tokens >= 0),
    reserved_cache_read_tokens INTEGER NOT NULL CHECK(reserved_cache_read_tokens >= 0),
    reserved_reasoning_tokens INTEGER NOT NULL CHECK(reserved_reasoning_tokens >= 0),
    reserved_cost_units INTEGER NOT NULL CHECK(reserved_cost_units >= 0),
    attempt_json TEXT NOT NULL,
    attempt_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(claim_id, physical_attempt_no),
    UNIQUE(grant_id, physical_attempt_no)
);

CREATE TABLE IF NOT EXISTS max_provider_dispatch_attempt_current(
    attempt_id TEXT PRIMARY KEY REFERENCES max_provider_dispatch_attempts(attempt_id) ON DELETE RESTRICT,
    claim_id TEXT NOT NULL REFERENCES max_provider_call_claims(claim_id) ON DELETE RESTRICT,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('reserved','dispatching','succeeded','failed','unknown','cancelled','disputed','settled')),
    provider_call_id TEXT,
    call_record_id TEXT,
    attestation_id TEXT,
    actual_input_tokens INTEGER NOT NULL CHECK(actual_input_tokens >= 0),
    actual_output_tokens INTEGER NOT NULL CHECK(actual_output_tokens >= 0),
    actual_cache_read_tokens INTEGER NOT NULL CHECK(actual_cache_read_tokens >= 0),
    actual_reasoning_tokens INTEGER NOT NULL CHECK(actual_reasoning_tokens >= 0),
    actual_cost_units INTEGER NOT NULL CHECK(actual_cost_units >= 0),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_provider_dispatch_attempt_events(
    attempt_event_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES max_provider_dispatch_attempts(attempt_id) ON DELETE RESTRICT,
    claim_id TEXT NOT NULL REFERENCES max_provider_call_claims(claim_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL CHECK(event_type IN ('reserved','dispatching','succeeded','failed','unknown','cancelled','disputed','settled')),
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(attempt_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_provider_call_attempt_bindings(
    call_record_id TEXT PRIMARY KEY REFERENCES max_provider_call_records(call_record_id) ON DELETE RESTRICT,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES max_provider_dispatch_attempts(attempt_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_provider_call_results(
    call_record_id TEXT PRIMARY KEY REFERENCES max_provider_call_records(call_record_id) ON DELETE RESTRICT,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES max_provider_dispatch_attempts(attempt_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    proposal_json TEXT NOT NULL,
    proposal_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_provider_dispatch_attempts_run_idx
    ON max_provider_dispatch_attempts(run_id, grant_id, physical_attempt_no);
CREATE INDEX IF NOT EXISTS max_provider_dispatch_attempt_events_run_idx
    ON max_provider_dispatch_attempt_events(run_id, attempt_id, sequence_no);

CREATE TRIGGER IF NOT EXISTS max_provider_dispatch_attempts_no_update
BEFORE UPDATE ON max_provider_dispatch_attempts BEGIN
    SELECT RAISE(ABORT, 'Provider dispatch attempts are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_dispatch_attempts_no_delete
BEFORE DELETE ON max_provider_dispatch_attempts BEGIN
    SELECT RAISE(ABORT, 'Provider dispatch attempts are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_dispatch_attempt_events_no_update
BEFORE UPDATE ON max_provider_dispatch_attempt_events BEGIN
    SELECT RAISE(ABORT, 'Provider dispatch attempt events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_dispatch_attempt_events_no_delete
BEFORE DELETE ON max_provider_dispatch_attempt_events BEGIN
    SELECT RAISE(ABORT, 'Provider dispatch attempt events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_call_attempt_bindings_no_update
BEFORE UPDATE ON max_provider_call_attempt_bindings BEGIN
    SELECT RAISE(ABORT, 'Provider call attempt bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_call_attempt_bindings_no_delete
BEFORE DELETE ON max_provider_call_attempt_bindings BEGIN
    SELECT RAISE(ABORT, 'Provider call attempt bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_call_results_no_update
BEFORE UPDATE ON max_provider_call_results BEGIN
    SELECT RAISE(ABORT, 'Provider call results are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_call_results_no_delete
BEFORE DELETE ON max_provider_call_results BEGIN
    SELECT RAISE(ABORT, 'Provider call results are append-only');
END;
