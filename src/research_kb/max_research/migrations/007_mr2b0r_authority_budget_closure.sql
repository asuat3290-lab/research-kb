-- MR-2B0R: durable provider-call authority, reservations, and recovery facts.
-- Migrations 001-006 are published bytes and remain unchanged.

CREATE TABLE IF NOT EXISTS max_provider_grant_usage_current(
    grant_id TEXT PRIMARY KEY REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    dispatch_count INTEGER NOT NULL CHECK(dispatch_count >= 0),
    reserved_input_tokens INTEGER NOT NULL CHECK(reserved_input_tokens >= 0),
    reserved_output_tokens INTEGER NOT NULL CHECK(reserved_output_tokens >= 0),
    reserved_cache_read_tokens INTEGER NOT NULL CHECK(reserved_cache_read_tokens >= 0),
    reserved_reasoning_tokens INTEGER NOT NULL CHECK(reserved_reasoning_tokens >= 0),
    reserved_cost_units INTEGER NOT NULL CHECK(reserved_cost_units >= 0),
    settled_input_tokens INTEGER NOT NULL CHECK(settled_input_tokens >= 0),
    settled_output_tokens INTEGER NOT NULL CHECK(settled_output_tokens >= 0),
    settled_cache_read_tokens INTEGER NOT NULL CHECK(settled_cache_read_tokens >= 0),
    settled_reasoning_tokens INTEGER NOT NULL CHECK(settled_reasoning_tokens >= 0),
    settled_cost_units INTEGER NOT NULL CHECK(settled_cost_units >= 0),
    released_cost_units INTEGER NOT NULL CHECK(released_cost_units >= 0),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, grant_id)
);

CREATE TABLE IF NOT EXISTS max_provider_call_claims(
    claim_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    grant_consumption_id TEXT NOT NULL REFERENCES max_live_execution_grant_consumptions(consumption_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    logical_call_id TEXT NOT NULL REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    intent_id TEXT NOT NULL REFERENCES max_model_call_intents(intent_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    intent_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL,
    attempt_no INTEGER NOT NULL CHECK(attempt_no >= 1),
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    owner_id TEXT NOT NULL,
    owner_session TEXT NOT NULL,
    reserved_input_tokens INTEGER NOT NULL CHECK(reserved_input_tokens >= 0),
    reserved_output_tokens INTEGER NOT NULL CHECK(reserved_output_tokens >= 0),
    reserved_cache_read_tokens INTEGER NOT NULL CHECK(reserved_cache_read_tokens >= 0),
    reserved_reasoning_tokens INTEGER NOT NULL CHECK(reserved_reasoning_tokens >= 0),
    reserved_cost_units INTEGER NOT NULL CHECK(reserved_cost_units >= 0),
    claim_json TEXT NOT NULL,
    claim_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, idempotency_key),
    UNIQUE(grant_id, logical_call_id, attempt_no)
);

CREATE TABLE IF NOT EXISTS max_provider_call_claim_events(
    claim_event_id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES max_provider_call_claims(claim_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL CHECK(event_type IN ('claimed','dispatching','dispatched','failed','unknown','attested','settled','disputed','released')),
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(claim_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_provider_call_claim_current(
    claim_id TEXT PRIMARY KEY REFERENCES max_provider_call_claims(claim_id) ON DELETE RESTRICT,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('claimed','dispatching','dispatched','failed','unknown','attested','settled','disputed','released')),
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

CREATE INDEX IF NOT EXISTS max_provider_call_claims_run_idx
    ON max_provider_call_claims(run_id, grant_id, created_at);
CREATE INDEX IF NOT EXISTS max_provider_call_claim_events_run_idx
    ON max_provider_call_claim_events(run_id, claim_id, sequence_no);

INSERT INTO max_provider_grant_usage_current(
    grant_id, run_id, project_id, dispatch_count,
    reserved_input_tokens, reserved_output_tokens, reserved_cache_read_tokens,
    reserved_reasoning_tokens, reserved_cost_units,
    settled_input_tokens, settled_output_tokens, settled_cache_read_tokens,
    settled_reasoning_tokens, settled_cost_units, released_cost_units,
    current_json, current_hash, updated_at
)
SELECT grant_id, run_id, project_id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       '{"dispatch_count":0,"released_cost_units":0,"reserved_cache_read_tokens":0,"reserved_cost_units":0,"reserved_input_tokens":0,"reserved_output_tokens":0,"reserved_reasoning_tokens":0,"settled_cache_read_tokens":0,"settled_cost_units":0,"settled_input_tokens":0,"settled_output_tokens":0,"settled_reasoning_tokens":0}',
       '8da84c4faf796abcde0b51bddde1a5f235f2f071e6a8aaae9eb60173a5313aa0',
       granted_at
  FROM max_live_execution_grants
 WHERE grant_id NOT IN (SELECT grant_id FROM max_provider_grant_usage_current);

CREATE TRIGGER IF NOT EXISTS max_provider_call_claims_no_update
BEFORE UPDATE ON max_provider_call_claims BEGIN
    SELECT RAISE(ABORT, 'Provider call claims are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_call_claims_no_delete
BEFORE DELETE ON max_provider_call_claims BEGIN
    SELECT RAISE(ABORT, 'Provider call claims are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_call_claim_events_no_update
BEFORE UPDATE ON max_provider_call_claim_events BEGIN
    SELECT RAISE(ABORT, 'Provider call claim events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_provider_call_claim_events_no_delete
BEFORE DELETE ON max_provider_call_claim_events BEGIN
    SELECT RAISE(ABORT, 'Provider call claim events are append-only');
END;
