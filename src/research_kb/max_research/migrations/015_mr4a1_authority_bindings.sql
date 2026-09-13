-- MR-4A.1: immutable bindings between the long-run window, the physical
-- provider authority, canonical runner outcomes, source receipts and usage.
-- These tables contain hashes, IDs and bounded metadata only.  They do not
-- store provider credentials, source bodies, prompts or model responses.

CREATE TABLE IF NOT EXISTS max_long_run_execution_bindings(
    execution_binding_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL UNIQUE REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    grant_consumption_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    provider_profile_hash TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL,
    budget_hash TEXT NOT NULL,
    runner_profile_hash TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    authority_json TEXT NOT NULL,
    authority_hash TEXT NOT NULL CHECK(length(authority_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_long_run_iteration_execution_bindings(
    iteration_execution_binding_id TEXT PRIMARY KEY,
    execution_binding_id TEXT NOT NULL REFERENCES max_long_run_execution_bindings(execution_binding_id) ON DELETE RESTRICT,
    window_id TEXT NOT NULL REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    permit_id TEXT NOT NULL REFERENCES max_long_run_iteration_permits(permit_id) ON DELETE RESTRICT,
    permit_consumption_id TEXT NOT NULL REFERENCES max_long_run_permit_consumptions(consumption_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    call_group_id TEXT,
    invocation_claim_id TEXT,
    input_state_hash TEXT NOT NULL CHECK(length(input_state_hash)=64),
    input_checkpoint_id TEXT,
    input_state_version INTEGER NOT NULL,
    round_type TEXT NOT NULL,
    cognitive_kind TEXT NOT NULL,
    plan_hash TEXT NOT NULL CHECK(length(plan_hash)=64),
    logical_call_ids_json TEXT NOT NULL,
    physical_attempt_ids_json TEXT NOT NULL,
    provider_call_ids_json TEXT NOT NULL,
    usage_receipt_ids_json TEXT NOT NULL,
    canonical_outcome_id TEXT,
    output_state_hash TEXT NOT NULL CHECK(length(output_state_hash)=64),
    output_checkpoint_id TEXT,
    output_state_version INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('settled','failed','paused')),
    lease_fencing_token INTEGER NOT NULL CHECK(lease_fencing_token > 0),
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL CHECK(length(binding_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(window_id, permit_id),
    UNIQUE(window_id, iteration_id)
);

CREATE TABLE IF NOT EXISTS max_long_run_iteration_source_sets(
    source_set_id TEXT PRIMARY KEY,
    iteration_execution_binding_id TEXT NOT NULL REFERENCES max_long_run_iteration_execution_bindings(iteration_execution_binding_id) ON DELETE RESTRICT,
    window_id TEXT NOT NULL REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    permit_id TEXT NOT NULL REFERENCES max_long_run_iteration_permits(permit_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL,
    logical_call_id TEXT NOT NULL,
    provider_call_ids_json TEXT NOT NULL,
    receipt_ids_json TEXT NOT NULL,
    consumption_ids_json TEXT NOT NULL,
    source_receipt_set_hash TEXT NOT NULL CHECK(length(source_receipt_set_hash)=64),
    packet_count INTEGER NOT NULL CHECK(packet_count >= 0),
    document_count INTEGER NOT NULL CHECK(document_count >= 0),
    passage_count INTEGER NOT NULL CHECK(passage_count >= 0),
    source_characters INTEGER NOT NULL CHECK(source_characters >= 0),
    source_tokens INTEGER NOT NULL CHECK(source_tokens >= 0),
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL CHECK(length(binding_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(iteration_execution_binding_id, logical_call_id)
);

CREATE TABLE IF NOT EXISTS max_long_run_iteration_usage_receipts(
    usage_binding_id TEXT PRIMARY KEY,
    iteration_execution_binding_id TEXT NOT NULL REFERENCES max_long_run_iteration_execution_bindings(iteration_execution_binding_id) ON DELETE RESTRICT,
    window_id TEXT NOT NULL REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    permit_id TEXT NOT NULL REFERENCES max_long_run_iteration_permits(permit_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL,
    logical_call_id TEXT NOT NULL,
    provider_call_id TEXT NOT NULL,
    call_record_id TEXT NOT NULL,
    attestation_id TEXT NOT NULL,
    usage_receipt_id TEXT NOT NULL,
    usage_json TEXT NOT NULL,
    usage_hash TEXT NOT NULL CHECK(length(usage_hash)=64),
    cost_units INTEGER NOT NULL CHECK(cost_units >= 0),
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL CHECK(length(binding_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(iteration_execution_binding_id, provider_call_id)
);

CREATE TABLE IF NOT EXISTS max_long_run_renewal_approvals(
    approval_id TEXT PRIMARY KEY,
    previous_window_id TEXT NOT NULL REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    successor_window_id TEXT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    previous_caps_hash TEXT NOT NULL CHECK(length(previous_caps_hash)=64),
    successor_caps_hash TEXT NOT NULL CHECK(length(successor_caps_hash)=64),
    changed_fields_json TEXT NOT NULL,
    reason_hash TEXT NOT NULL CHECK(length(reason_hash)=64),
    confirmation_hash TEXT NOT NULL CHECK(length(confirmation_hash)=64),
    approval_json TEXT NOT NULL,
    approval_hash TEXT NOT NULL CHECK(length(approval_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS max_long_run_execution_bindings_no_update BEFORE UPDATE ON max_long_run_execution_bindings BEGIN SELECT RAISE(ABORT, 'Max long-run execution bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_execution_bindings_no_delete BEFORE DELETE ON max_long_run_execution_bindings BEGIN SELECT RAISE(ABORT, 'Max long-run execution bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_iteration_execution_bindings_no_update BEFORE UPDATE ON max_long_run_iteration_execution_bindings BEGIN SELECT RAISE(ABORT, 'Max long-run iteration bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_iteration_execution_bindings_no_delete BEFORE DELETE ON max_long_run_iteration_execution_bindings BEGIN SELECT RAISE(ABORT, 'Max long-run iteration bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_iteration_source_sets_no_update BEFORE UPDATE ON max_long_run_iteration_source_sets BEGIN SELECT RAISE(ABORT, 'Max long-run source sets are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_iteration_source_sets_no_delete BEFORE DELETE ON max_long_run_iteration_source_sets BEGIN SELECT RAISE(ABORT, 'Max long-run source sets are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_iteration_usage_receipts_no_update BEFORE UPDATE ON max_long_run_iteration_usage_receipts BEGIN SELECT RAISE(ABORT, 'Max long-run usage bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_iteration_usage_receipts_no_delete BEFORE DELETE ON max_long_run_iteration_usage_receipts BEGIN SELECT RAISE(ABORT, 'Max long-run usage bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_renewal_approvals_no_update BEFORE UPDATE ON max_long_run_renewal_approvals BEGIN SELECT RAISE(ABORT, 'Max long-run renewal approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_renewal_approvals_no_delete BEFORE DELETE ON max_long_run_renewal_approvals BEGIN SELECT RAISE(ABORT, 'Max long-run renewal approvals are append-only'); END;
