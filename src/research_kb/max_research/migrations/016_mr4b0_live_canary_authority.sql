-- MR-4B0: plan-only live canary authority.
-- Hashes, IDs and bounded metadata only; no secret, source body or prompt.

CREATE TABLE IF NOT EXISTS max_live_canary_previews(
    preview_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    charter_hash TEXT NOT NULL CHECK(length(charter_hash)=64),
    current_state_hash TEXT NOT NULL CHECK(length(current_state_hash)=64),
    current_checkpoint_id TEXT,
    current_state_version INTEGER NOT NULL CHECK(current_state_version > 0),
    engine_package TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    core_schema_version INTEGER NOT NULL CHECK(core_schema_version > 0),
    control_schema_version INTEGER NOT NULL CHECK(control_schema_version > 0),
    candidate_wheel_sha256 TEXT NOT NULL CHECK(length(candidate_wheel_sha256)=64),
    source_manifest_sha256 TEXT NOT NULL CHECK(length(source_manifest_sha256)=64),
    source_tree_sha256 TEXT NOT NULL CHECK(length(source_tree_sha256)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    model_version TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    endpoint_path_policy_hash TEXT NOT NULL CHECK(length(endpoint_path_policy_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    credential_ref_hash TEXT NOT NULL CHECK(length(credential_ref_hash)=64),
    source_egress_policy_hash TEXT NOT NULL CHECK(length(source_egress_policy_hash)=64),
    source_allowlist_json TEXT NOT NULL,
    source_policy_json TEXT NOT NULL,
    runner_profile_hash TEXT NOT NULL CHECK(length(runner_profile_hash)=64),
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    cap_vector_json TEXT NOT NULL,
    cap_vector_hash TEXT NOT NULL CHECK(length(cap_vector_hash)=64),
    transport_policy_json TEXT NOT NULL,
    kill_rollback_incident_policy_json TEXT NOT NULL,
    preview_json TEXT NOT NULL,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    confirmation_phrase TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, preview_hash)
);

CREATE TABLE IF NOT EXISTS max_live_canary_approvals(
    approval_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    confirmation_phrase TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approval_json TEXT NOT NULL,
    approval_hash TEXT NOT NULL CHECK(length(approval_hash)=64),
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_approval_current(
    approval_id TEXT PRIMARY KEY REFERENCES max_live_canary_approvals(approval_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('active','revoked','expired','consumed')),
    consumption_id TEXT,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_approval_consumptions(
    consumption_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_approvals(approval_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    consumer_id TEXT NOT NULL,
    consumer_kind TEXT NOT NULL,
    consumer_session TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL CHECK(length(consumption_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_canary_execution_permits(
    permit_id TEXT PRIMARY KEY,
    consumption_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_approval_consumptions(consumption_id) ON DELETE RESTRICT,
    approval_id TEXT NOT NULL REFERENCES max_live_canary_approvals(approval_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    claim_id TEXT NOT NULL UNIQUE,
    reservation_json TEXT NOT NULL,
    reservation_hash TEXT NOT NULL CHECK(length(reservation_hash)=64),
    permit_json TEXT NOT NULL,
    permit_hash TEXT NOT NULL CHECK(length(permit_hash)=64),
    current_state_hash TEXT NOT NULL CHECK(length(current_state_hash)=64),
    current_checkpoint_id TEXT,
    current_state_version INTEGER NOT NULL CHECK(current_state_version > 0),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    endpoint_path_policy_hash TEXT NOT NULL CHECK(length(endpoint_path_policy_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    credential_ref_hash TEXT NOT NULL CHECK(length(credential_ref_hash)=64),
    source_egress_policy_hash TEXT NOT NULL CHECK(length(source_egress_policy_hash)=64),
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    idempotency_key_hash TEXT NOT NULL CHECK(length(idempotency_key_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_execution_permit_current(
    permit_id TEXT PRIMARY KEY REFERENCES max_live_canary_execution_permits(permit_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('ready','send_started','succeeded','failed','unknown','aborted','revoked')),
    outcome_id TEXT,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_outcomes(
    outcome_id TEXT PRIMARY KEY,
    permit_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_execution_permits(permit_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','failed','unknown','aborted')),
    provider_call_id TEXT,
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    response_hash TEXT,
    usage_json TEXT NOT NULL,
    cost_units INTEGER NOT NULL CHECK(cost_units >= 0),
    outcome_json TEXT NOT NULL,
    outcome_hash TEXT NOT NULL CHECK(length(outcome_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_events(
    event_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    approval_id TEXT,
    permit_id TEXT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(preview_id, sequence_no)
);

CREATE TRIGGER IF NOT EXISTS max_live_canary_previews_no_update BEFORE UPDATE ON max_live_canary_previews BEGIN SELECT RAISE(ABORT, 'live canary previews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_previews_no_delete BEFORE DELETE ON max_live_canary_previews BEGIN SELECT RAISE(ABORT, 'live canary previews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_approvals_no_update BEFORE UPDATE ON max_live_canary_approvals BEGIN SELECT RAISE(ABORT, 'live canary approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_approvals_no_delete BEFORE DELETE ON max_live_canary_approvals BEGIN SELECT RAISE(ABORT, 'live canary approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_approval_consumptions_no_update BEFORE UPDATE ON max_live_canary_approval_consumptions BEGIN SELECT RAISE(ABORT, 'live canary approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_approval_consumptions_no_delete BEFORE DELETE ON max_live_canary_approval_consumptions BEGIN SELECT RAISE(ABORT, 'live canary approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_execution_permits_no_update BEFORE UPDATE ON max_live_canary_execution_permits BEGIN SELECT RAISE(ABORT, 'live canary execution permits are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_execution_permits_no_delete BEFORE DELETE ON max_live_canary_execution_permits BEGIN SELECT RAISE(ABORT, 'live canary execution permits are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_outcomes_no_update BEFORE UPDATE ON max_live_canary_outcomes BEGIN SELECT RAISE(ABORT, 'live canary outcomes are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_outcomes_no_delete BEFORE DELETE ON max_live_canary_outcomes BEGIN SELECT RAISE(ABORT, 'live canary outcomes are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_events_no_update BEFORE UPDATE ON max_live_canary_events BEGIN SELECT RAISE(ABORT, 'live canary events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_events_no_delete BEFORE DELETE ON max_live_canary_events BEGIN SELECT RAISE(ABORT, 'live canary events are append-only'); END;
