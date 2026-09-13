-- MR-1A: run-scoped canonical membership, typed iteration history, and usage receipts.
-- Max migration 001 is intentionally immutable; this file is the only schema-2 delta.

ALTER TABLE max_budget_ledger ADD COLUMN request_hash TEXT;
ALTER TABLE max_budget_ledger ADD COLUMN iteration_id TEXT;

CREATE TABLE max_run_object_memberships(
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    version_id TEXT NOT NULL REFERENCES max_canonical_object_versions(version_id) ON DELETE RESTRICT,
    adopted_by_change_set_id TEXT,
    adopted_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    membership_hash TEXT NOT NULL,
    PRIMARY KEY(run_id, version_id),
    UNIQUE(run_id, project_id, version_id)
);

CREATE TABLE max_run_relation_memberships(
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    relation_id TEXT NOT NULL REFERENCES max_canonical_relations(relation_id) ON DELETE RESTRICT,
    adopted_by_change_set_id TEXT,
    adopted_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    membership_hash TEXT NOT NULL,
    PRIMARY KEY(run_id, relation_id),
    UNIQUE(run_id, project_id, relation_id)
);

CREATE TABLE max_canonical_change_sets(
    change_set_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL,
    input_state_hash TEXT NOT NULL,
    expected_output_state_hash TEXT NOT NULL,
    change_set_json TEXT NOT NULL,
    change_set_hash TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, change_set_hash)
);

CREATE TABLE max_iteration_outcomes(
    outcome_id TEXT PRIMARY KEY,
    iteration_id TEXT NOT NULL UNIQUE REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('completed','aborted')),
    input_state_hash TEXT NOT NULL,
    output_state_hash TEXT,
    outcome_json TEXT NOT NULL,
    outcome_hash TEXT NOT NULL,
    claim_snapshots_json TEXT NOT NULL,
    evidence_snapshots_json TEXT NOT NULL,
    counterevidence_snapshots_json TEXT NOT NULL,
    strategy_ledger_json TEXT NOT NULL,
    record_refs_json TEXT NOT NULL,
    budget_delta_json TEXT NOT NULL,
    artifact_summary_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE max_iteration_artifact_links(
    link_id TEXT PRIMARY KEY,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    artifact_type TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_json TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(iteration_id, artifact_type, artifact_id)
);

CREATE TABLE max_iteration_budget_links(
    link_id TEXT PRIMARY KEY,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    entry_id TEXT NOT NULL REFERENCES max_budget_ledger(entry_id) ON DELETE RESTRICT,
    amount_json TEXT NOT NULL,
    amount_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(iteration_id, entry_id)
);

CREATE TABLE max_iteration_current(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL UNIQUE REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    set_at TEXT NOT NULL
);

CREATE TABLE max_usage_receipts(
    receipt_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    model_identity TEXT NOT NULL,
    amount_json TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    verifier_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, receipt_id)
);

CREATE INDEX max_run_object_memberships_run ON max_run_object_memberships(run_id, project_id, version_id);
CREATE INDEX max_run_relation_memberships_run ON max_run_relation_memberships(run_id, project_id, relation_id);
CREATE INDEX max_change_sets_run ON max_canonical_change_sets(run_id, created_at);
CREATE INDEX max_iteration_outcomes_run ON max_iteration_outcomes(run_id, iteration_id);
CREATE INDEX max_iteration_artifacts_run ON max_iteration_artifact_links(run_id, iteration_id, artifact_type);
CREATE INDEX max_iteration_budget_run ON max_iteration_budget_links(run_id, iteration_id);
CREATE INDEX max_usage_receipts_run ON max_usage_receipts(run_id, iteration_id);

CREATE TRIGGER max_run_object_memberships_no_update
BEFORE UPDATE ON max_run_object_memberships
BEGIN SELECT RAISE(ABORT, 'Max run object memberships are append-only'); END;
CREATE TRIGGER max_run_object_memberships_no_delete
BEFORE DELETE ON max_run_object_memberships
BEGIN SELECT RAISE(ABORT, 'Max run object memberships are append-only'); END;
CREATE TRIGGER max_run_relation_memberships_no_update
BEFORE UPDATE ON max_run_relation_memberships
BEGIN SELECT RAISE(ABORT, 'Max run relation memberships are append-only'); END;
CREATE TRIGGER max_run_relation_memberships_no_delete
BEFORE DELETE ON max_run_relation_memberships
BEGIN SELECT RAISE(ABORT, 'Max run relation memberships are append-only'); END;
CREATE TRIGGER max_canonical_change_sets_no_update
BEFORE UPDATE ON max_canonical_change_sets
BEGIN SELECT RAISE(ABORT, 'Max canonical change sets are append-only'); END;
CREATE TRIGGER max_canonical_change_sets_no_delete
BEFORE DELETE ON max_canonical_change_sets
BEGIN SELECT RAISE(ABORT, 'Max canonical change sets are append-only'); END;
CREATE TRIGGER max_iteration_outcomes_no_update
BEFORE UPDATE ON max_iteration_outcomes
BEGIN SELECT RAISE(ABORT, 'Max iteration outcomes are append-only'); END;
CREATE TRIGGER max_iteration_outcomes_no_delete
BEFORE DELETE ON max_iteration_outcomes
BEGIN SELECT RAISE(ABORT, 'Max iteration outcomes are append-only'); END;
CREATE TRIGGER max_iteration_artifacts_no_update
BEFORE UPDATE ON max_iteration_artifact_links
BEGIN SELECT RAISE(ABORT, 'Max iteration artifact links are append-only'); END;
CREATE TRIGGER max_iteration_artifacts_no_delete
BEFORE DELETE ON max_iteration_artifact_links
BEGIN SELECT RAISE(ABORT, 'Max iteration artifact links are append-only'); END;
CREATE TRIGGER max_iteration_budget_no_update
BEFORE UPDATE ON max_iteration_budget_links
BEGIN SELECT RAISE(ABORT, 'Max iteration budget links are append-only'); END;
CREATE TRIGGER max_iteration_budget_no_delete
BEFORE DELETE ON max_iteration_budget_links
BEGIN SELECT RAISE(ABORT, 'Max iteration budget links are append-only'); END;
CREATE TRIGGER max_usage_receipts_no_update
BEFORE UPDATE ON max_usage_receipts
BEGIN SELECT RAISE(ABORT, 'Max usage receipts are append-only'); END;
CREATE TRIGGER max_usage_receipts_no_delete
BEFORE DELETE ON max_usage_receipts
BEGIN SELECT RAISE(ABORT, 'Max usage receipts are append-only'); END;
