CREATE TABLE IF NOT EXISTS max_runs(
    run_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL,
    charter_json TEXT NOT NULL,
    charter_hash TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    source_policy_json TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL,
    budget_policy_json TEXT NOT NULL,
    budget_hash TEXT NOT NULL,
    current_state_hash TEXT,
    current_checkpoint_id TEXT,
    state_version INTEGER NOT NULL CHECK(state_version >= 1),
    iteration_index INTEGER NOT NULL DEFAULT 0 CHECK(iteration_index >= 0),
    completion_result_id TEXT,
    completion_state_hash TEXT,
    completion_result_json TEXT,
    completion_result_hash TEXT,
    run_state_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_run_transition_results(
    transition_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    prior_state_version INTEGER NOT NULL CHECK(prior_state_version >= 1),
    resulting_state_version INTEGER NOT NULL CHECK(resulting_state_version = prior_state_version + 1),
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    transition_json TEXT NOT NULL,
    transition_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    session_id TEXT NOT NULL,
    UNIQUE(run_id, resulting_state_version)
);

CREATE TABLE IF NOT EXISTS max_start_approvals(
    approval_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    charter_hash TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    budget_json TEXT NOT NULL,
    budget_hash TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL,
    reason TEXT NOT NULL,
    approval_json TEXT NOT NULL,
    approval_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_approval_consumptions(
    consumption_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES max_start_approvals(approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    charter_hash TEXT NOT NULL,
    prior_state_version INTEGER NOT NULL,
    resulting_state_version INTEGER NOT NULL,
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_events(
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    session_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_canonical_object_versions(
    version_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    stable_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    supersedes_version_id TEXT,
    object_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    source_reference_json TEXT NOT NULL,
    source_reference_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(project_id, stable_id, version)
);

CREATE TABLE IF NOT EXISTS max_canonical_objects(
    project_id TEXT NOT NULL,
    stable_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    PRIMARY KEY(project_id, stable_id)
);

CREATE TABLE IF NOT EXISTS max_canonical_relations(
    relation_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_version_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_version_id TEXT NOT NULL,
    relation_kind TEXT NOT NULL,
    relation_json TEXT NOT NULL,
    metadata_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_research_states(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    state_json TEXT NOT NULL,
    canonical_frontier_json TEXT NOT NULL,
    working_state_json TEXT NOT NULL,
    rehydration_input_hash TEXT,
    rehydration_output_hash TEXT,
    drift_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_checkpoints(
    checkpoint_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    checkpoint_version INTEGER NOT NULL CHECK(checkpoint_version >= 1),
    lineage_version INTEGER NOT NULL CHECK(lineage_version >= 1),
    supersedes_item_id TEXT,
    state_hash TEXT NOT NULL,
    checkpoint_json TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, lineage_version)
);

CREATE TABLE IF NOT EXISTS max_checkpoint_current(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    checkpoint_id TEXT NOT NULL UNIQUE REFERENCES max_checkpoints(checkpoint_id) ON DELETE RESTRICT,
    set_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_iterations(
    iteration_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    round_type TEXT NOT NULL,
    status TEXT NOT NULL,
    input_state_hash TEXT NOT NULL,
    output_state_hash TEXT,
    iteration_json TEXT NOT NULL,
    claim_snapshots_json TEXT NOT NULL,
    evidence_snapshots_json TEXT NOT NULL,
    counterevidence_snapshots_json TEXT NOT NULL,
    strategy_ledger_json TEXT NOT NULL,
    record_refs_json TEXT NOT NULL,
    budget_delta_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_leases(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    owner_id TEXT,
    session_id TEXT,
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK(fencing_token >= 0),
    expires_at TEXT,
    acquired_at TEXT,
    renewed_at TEXT,
    released_at TEXT
);

CREATE TABLE IF NOT EXISTS max_budget_ledger(
    entry_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    amount_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    reservation_id TEXT,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, sequence_no),
    UNIQUE(run_id, idempotency_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS max_checkpoint_version_unique
    ON max_checkpoints(run_id, lineage_version);
CREATE INDEX IF NOT EXISTS max_events_run_sequence
    ON max_events(run_id, sequence_no);
CREATE INDEX IF NOT EXISTS max_transition_results_run_version
    ON max_run_transition_results(run_id, resulting_state_version);
CREATE INDEX IF NOT EXISTS max_objects_project_identity
    ON max_canonical_object_versions(project_id, stable_id, version);
CREATE INDEX IF NOT EXISTS max_iterations_run_sequence
    ON max_iterations(run_id, sequence_no);
CREATE INDEX IF NOT EXISTS max_budget_run_sequence
    ON max_budget_ledger(run_id, sequence_no);

CREATE TRIGGER IF NOT EXISTS max_start_approvals_no_update
BEFORE UPDATE ON max_start_approvals
BEGIN SELECT RAISE(ABORT, 'Max start approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_transition_results_no_update
BEFORE UPDATE ON max_run_transition_results
BEGIN SELECT RAISE(ABORT, 'Max transition results are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_transition_results_no_delete
BEFORE DELETE ON max_run_transition_results
BEGIN SELECT RAISE(ABORT, 'Max transition results are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_start_approvals_no_delete
BEFORE DELETE ON max_start_approvals
BEGIN SELECT RAISE(ABORT, 'Max start approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_approval_consumptions_no_update
BEFORE UPDATE ON max_approval_consumptions
BEGIN SELECT RAISE(ABORT, 'Max approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_approval_consumptions_no_delete
BEFORE DELETE ON max_approval_consumptions
BEGIN SELECT RAISE(ABORT, 'Max approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_events_no_update
BEFORE UPDATE ON max_events
BEGIN SELECT RAISE(ABORT, 'Max events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_events_no_delete
BEFORE DELETE ON max_events
BEGIN SELECT RAISE(ABORT, 'Max events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_objects_no_update
BEFORE UPDATE ON max_canonical_object_versions
BEGIN SELECT RAISE(ABORT, 'Max canonical object versions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_objects_no_delete
BEFORE DELETE ON max_canonical_object_versions
BEGIN SELECT RAISE(ABORT, 'Max canonical object versions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_object_identities_no_update
BEFORE UPDATE ON max_canonical_objects
BEGIN SELECT RAISE(ABORT, 'Max canonical object identities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_object_identities_no_delete
BEFORE DELETE ON max_canonical_objects
BEGIN SELECT RAISE(ABORT, 'Max canonical object identities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_relations_no_update
BEFORE UPDATE ON max_canonical_relations
BEGIN SELECT RAISE(ABORT, 'Max canonical relations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_relations_no_delete
BEFORE DELETE ON max_canonical_relations
BEGIN SELECT RAISE(ABORT, 'Max canonical relations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_checkpoints_no_update
BEFORE UPDATE ON max_checkpoints
BEGIN SELECT RAISE(ABORT, 'Max checkpoints are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_checkpoints_no_delete
BEFORE DELETE ON max_checkpoints
BEGIN SELECT RAISE(ABORT, 'Max checkpoints are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_iterations_no_update
BEFORE UPDATE ON max_iterations
BEGIN SELECT RAISE(ABORT, 'Max iterations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_iterations_no_delete
BEFORE DELETE ON max_iterations
BEGIN SELECT RAISE(ABORT, 'Max iterations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_budget_no_update
BEFORE UPDATE ON max_budget_ledger
BEGIN SELECT RAISE(ABORT, 'Max budget ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_budget_no_delete
BEFORE DELETE ON max_budget_ledger
BEGIN SELECT RAISE(ABORT, 'Max budget ledger is append-only'); END;
