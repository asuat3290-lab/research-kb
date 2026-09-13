-- MR-2A.1 runner authority and cognitive-round closure.
-- This migration is independent from the core research database and from
-- Max migrations 001-003.  Historical rows remain immutable; mutable
-- pointers are kept in explicitly named current/claim tables.

CREATE TABLE IF NOT EXISTS max_runner_invocation_claims(
    claim_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id),
    actor_id TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    attempt_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','released','expired','busy')),
    claim_json TEXT NOT NULL,
    claim_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    released_at TEXT,
    UNIQUE(run_id, attempt_id)
);
CREATE INDEX IF NOT EXISTS max_runner_invocation_expiry
    ON max_runner_invocation_claims(run_id, status, expires_at);

CREATE TABLE IF NOT EXISTS max_runner_call_groups(
    group_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id),
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id),
    plan_id TEXT NOT NULL REFERENCES max_runner_plans(plan_id),
    phase TEXT NOT NULL,
    call_count INTEGER NOT NULL CHECK(call_count >= 1),
    group_json TEXT NOT NULL,
    group_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, iteration_id, plan_id)
);

CREATE TABLE IF NOT EXISTS max_runner_call_group_current(
    group_id TEXT PRIMARY KEY REFERENCES max_runner_call_groups(group_id),
    run_id TEXT NOT NULL REFERENCES max_runs(run_id),
    current_index INTEGER NOT NULL CHECK(current_index >= 0),
    status TEXT NOT NULL CHECK(status IN ('open','completed','aborted','paused')),
    current_logical_call_id TEXT,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_call_bindings(
    binding_id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES max_runner_call_groups(group_id),
    run_id TEXT NOT NULL REFERENCES max_runs(run_id),
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id),
    logical_call_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_intents(logical_call_id),
    call_index INTEGER NOT NULL CHECK(call_index >= 0),
    role TEXT NOT NULL,
    phase TEXT NOT NULL,
    packet_hash TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    result_id TEXT,
    status TEXT NOT NULL CHECK(status IN ('planned','dispatched','succeeded','failed','ambiguous','aborted')),
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(group_id, call_index)
);
CREATE INDEX IF NOT EXISTS max_runner_call_bindings_group_order
    ON max_runner_call_bindings(group_id, call_index);

CREATE TABLE IF NOT EXISTS max_runner_intent_manifests(
    intent_id TEXT PRIMARY KEY REFERENCES max_model_call_intents(intent_id),
    logical_call_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_intents(logical_call_id),
    run_id TEXT NOT NULL REFERENCES max_runs(run_id),
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id),
    plan_id TEXT NOT NULL REFERENCES max_runner_plans(plan_id),
    manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_recovery_consumptions(
    consumption_id TEXT PRIMARY KEY,
    recovery_id TEXT NOT NULL UNIQUE REFERENCES max_runner_recovery_decisions(recovery_id),
    run_id TEXT NOT NULL REFERENCES max_runs(run_id),
    logical_call_id TEXT NOT NULL REFERENCES max_model_call_intents(logical_call_id),
    intent_hash TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('retry','abort','accept')),
    admin_actor_id TEXT NOT NULL,
    admin_session TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    fencing_token INTEGER,
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    UNIQUE(run_id, logical_call_id)
);

CREATE TABLE IF NOT EXISTS max_runner_cognitive_artifacts(
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id),
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id),
    group_id TEXT REFERENCES max_runner_call_groups(group_id),
    artifact_type TEXT NOT NULL,
    phase TEXT NOT NULL,
    role TEXT,
    artifact_json TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    accepted INTEGER NOT NULL CHECK(accepted IN (0,1)),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS max_runner_cognitive_artifacts_iteration
    ON max_runner_cognitive_artifacts(run_id, iteration_id, phase, artifact_type);

CREATE TABLE IF NOT EXISTS max_fixture_control_markers(
    marker_id TEXT PRIMARY KEY,
    marker_kind TEXT NOT NULL CHECK(marker_kind='fixture-control-db'),
    fixture_identity TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    marker_json TEXT NOT NULL,
    marker_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS max_runner_invocation_no_update BEFORE UPDATE ON max_runner_invocation_claims BEGIN SELECT RAISE(ABORT, 'Max runner invocation claims are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_invocation_no_delete BEFORE DELETE ON max_runner_invocation_claims BEGIN SELECT RAISE(ABORT, 'Max runner invocation claims are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_group_no_update BEFORE UPDATE ON max_runner_call_groups BEGIN SELECT RAISE(ABORT, 'Max runner call groups are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_group_no_delete BEFORE DELETE ON max_runner_call_groups BEGIN SELECT RAISE(ABORT, 'Max runner call groups are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_binding_no_update BEFORE UPDATE ON max_runner_call_bindings BEGIN SELECT RAISE(ABORT, 'Max runner call bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_binding_no_delete BEFORE DELETE ON max_runner_call_bindings BEGIN SELECT RAISE(ABORT, 'Max runner call bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_manifest_no_update BEFORE UPDATE ON max_runner_intent_manifests BEGIN SELECT RAISE(ABORT, 'Max runner intent manifests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_manifest_no_delete BEFORE DELETE ON max_runner_intent_manifests BEGIN SELECT RAISE(ABORT, 'Max runner intent manifests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_consumption_no_update BEFORE UPDATE ON max_runner_recovery_consumptions BEGIN SELECT RAISE(ABORT, 'Max recovery consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_consumption_no_delete BEFORE DELETE ON max_runner_recovery_consumptions BEGIN SELECT RAISE(ABORT, 'Max recovery consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_artifact_no_update BEFORE UPDATE ON max_runner_cognitive_artifacts BEGIN SELECT RAISE(ABORT, 'Max runner cognitive artifacts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_artifact_no_delete BEFORE DELETE ON max_runner_cognitive_artifacts BEGIN SELECT RAISE(ABORT, 'Max runner cognitive artifacts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_fixture_marker_no_update BEFORE UPDATE ON max_fixture_control_markers BEGIN SELECT RAISE(ABORT, 'Fixture control markers are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_fixture_marker_no_delete BEFORE DELETE ON max_fixture_control_markers BEGIN SELECT RAISE(ABORT, 'Fixture control markers are append-only'); END;
