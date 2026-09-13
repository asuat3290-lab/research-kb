-- MR-2A.2 closes the deliberation and usage authority chain.
-- Max migrations are independent from the core research database.  This
-- migration is append-only and never retrofits a production database into a
-- fixture database.

CREATE TABLE IF NOT EXISTS max_runner_call_specs(
    spec_id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES max_runner_call_groups(group_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    call_index INTEGER NOT NULL CHECK(call_index >= 0),
    call_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    role TEXT NOT NULL,
    upstream_call_ids_json TEXT NOT NULL,
    input_mode TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    spec_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(group_id, call_index),
    UNIQUE(group_id, call_id)
);

CREATE TABLE IF NOT EXISTS max_runner_usage_bindings(
    binding_id TEXT PRIMARY KEY,
    result_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_results(result_id) ON DELETE RESTRICT,
    logical_call_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    intent_id TEXT NOT NULL REFERENCES max_model_call_intents(intent_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    group_id TEXT REFERENCES max_runner_call_groups(group_id) ON DELETE RESTRICT,
    intent_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    provider_call_id TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    inference_profile_hash TEXT NOT NULL,
    receipt_id TEXT NOT NULL UNIQUE REFERENCES max_usage_receipts(receipt_id) ON DELETE RESTRICT,
    receipt_hash TEXT NOT NULL,
    usage_entry_id TEXT NOT NULL UNIQUE REFERENCES max_budget_ledger(entry_id) ON DELETE RESTRICT,
    amount_json TEXT NOT NULL,
    amount_hash TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status='settled'),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_result_call_bindings(
    binding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    group_id TEXT REFERENCES max_runner_call_groups(group_id) ON DELETE RESTRICT,
    logical_call_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    result_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_results(result_id) ON DELETE RESTRICT,
    call_index INTEGER,
    role TEXT NOT NULL,
    phase TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_artifact_bindings(
    binding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    group_id TEXT REFERENCES max_runner_call_groups(group_id) ON DELETE RESTRICT,
    logical_call_id TEXT NOT NULL REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    result_id TEXT NOT NULL REFERENCES max_model_call_results(result_id) ON DELETE RESTRICT,
    artifact_type TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(iteration_id, artifact_type, artifact_id),
    UNIQUE(logical_call_id, artifact_type, artifact_id)
);

CREATE TABLE IF NOT EXISTS max_epistemic_conflicts(
    conflict_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    logical_call_id TEXT NOT NULL REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    intent_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    proposal_hash TEXT NOT NULL,
    validator_hash TEXT NOT NULL,
    canonical_state_hash TEXT NOT NULL,
    canonical_version_hashes_json TEXT NOT NULL,
    issue_codes_json TEXT NOT NULL,
    conflict_type TEXT NOT NULL,
    canonical_basis_json TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    repeat_count INTEGER NOT NULL CHECK(repeat_count >= 1),
    resolution TEXT NOT NULL CHECK(resolution IN ('rejected','rehydration_required','paused','resolved')),
    conflict_json TEXT NOT NULL,
    conflict_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, fingerprint, repeat_count)
);

CREATE INDEX IF NOT EXISTS max_runner_usage_bindings_run_idx
    ON max_runner_usage_bindings(run_id, iteration_id, logical_call_id);
CREATE INDEX IF NOT EXISTS max_runner_result_call_bindings_run_idx
    ON max_runner_result_call_bindings(run_id, iteration_id, call_index);
CREATE INDEX IF NOT EXISTS max_epistemic_conflicts_fingerprint_idx
    ON max_epistemic_conflicts(run_id, fingerprint, repeat_count);

CREATE TRIGGER IF NOT EXISTS max_runner_call_specs_no_update
BEFORE UPDATE ON max_runner_call_specs BEGIN
    SELECT RAISE(ABORT, 'Runner call specs are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_runner_call_specs_no_delete
BEFORE DELETE ON max_runner_call_specs BEGIN
    SELECT RAISE(ABORT, 'Runner call specs are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_runner_usage_binding_no_update
BEFORE UPDATE ON max_runner_usage_bindings BEGIN
    SELECT RAISE(ABORT, 'Runner usage bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_runner_usage_binding_no_delete
BEFORE DELETE ON max_runner_usage_bindings BEGIN
    SELECT RAISE(ABORT, 'Runner usage bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_runner_result_call_binding_no_update
BEFORE UPDATE ON max_runner_result_call_bindings BEGIN
    SELECT RAISE(ABORT, 'Runner result call bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_runner_result_call_binding_no_delete
BEFORE DELETE ON max_runner_result_call_bindings BEGIN
    SELECT RAISE(ABORT, 'Runner result call bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_runner_artifact_binding_no_update
BEFORE UPDATE ON max_runner_artifact_bindings BEGIN
    SELECT RAISE(ABORT, 'Runner artifact bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_runner_artifact_binding_no_delete
BEFORE DELETE ON max_runner_artifact_bindings BEGIN
    SELECT RAISE(ABORT, 'Runner artifact bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_epistemic_conflicts_no_update
BEFORE UPDATE ON max_epistemic_conflicts BEGIN
    SELECT RAISE(ABORT, 'Epistemic conflict records are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_epistemic_conflicts_no_delete
BEFORE DELETE ON max_epistemic_conflicts BEGIN
    SELECT RAISE(ABORT, 'Epistemic conflict records are append-only');
END;
