-- MR-2A: immutable bounded-runner plans, model call intents/results, and recovery.
-- Migrations 001 and 002 are published bytes and remain unchanged.

ALTER TABLE max_leases ADD COLUMN runner_profile_hash TEXT;

CREATE TABLE IF NOT EXISTS max_runner_profiles(
    profile_hash TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    inference_profile_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_handoffs(
    handoff_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_runner_profiles(profile_hash) ON DELETE RESTRICT,
    admin_actor_id TEXT NOT NULL,
    admin_actor_kind TEXT NOT NULL,
    admin_session TEXT NOT NULL,
    runner_actor_id TEXT NOT NULL,
    runner_actor_kind TEXT NOT NULL,
    runner_session TEXT NOT NULL,
    prior_fencing_token INTEGER NOT NULL CHECK(prior_fencing_token >= 0),
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    handoff_json TEXT NOT NULL,
    handoff_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, fencing_token)
);

CREATE TABLE IF NOT EXISTS max_runner_plans(
    plan_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    -- The deterministic plan is persisted before begin_iteration.  The
    -- runner verifies the later iteration binding in service code.
    iteration_id TEXT NOT NULL,
    input_state_hash TEXT NOT NULL,
    round_type TEXT NOT NULL,
    cognitive_kind TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_runner_profiles(profile_hash) ON DELETE RESTRICT,
    plan_json TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, sequence_no),
    UNIQUE(run_id, plan_hash)
);

CREATE TABLE IF NOT EXISTS max_runner_plan_current(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    plan_id TEXT NOT NULL UNIQUE REFERENCES max_runner_plans(plan_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL UNIQUE REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    active_logical_call_id TEXT,
    set_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_model_call_intents(
    intent_id TEXT PRIMARY KEY,
    logical_call_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    plan_id TEXT NOT NULL REFERENCES max_runner_plans(plan_id) ON DELETE RESTRICT,
    input_state_hash TEXT NOT NULL,
    role_packet_id TEXT NOT NULL,
    round_type TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    inference_profile_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    intent_json TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS max_model_dispatch_acks(
    ack_id TEXT PRIMARY KEY,
    logical_call_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    dispatch_status TEXT NOT NULL CHECK(dispatch_status IN ('dispatched','unknown','not_dispatched')),
    dispatch_known INTEGER NOT NULL CHECK(dispatch_known IN (0,1)),
    provider_call_id TEXT,
    ack_json TEXT NOT NULL,
    ack_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_model_call_attempts(
    attempt_id TEXT PRIMARY KEY,
    logical_call_id TEXT NOT NULL REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    attempt_no INTEGER NOT NULL CHECK(attempt_no >= 1),
    stage TEXT NOT NULL CHECK(stage IN ('dispatching','dispatched','unknown','failed')),
    attempt_json TEXT NOT NULL,
    attempt_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(logical_call_id, attempt_no)
);

CREATE TABLE IF NOT EXISTS max_model_call_results(
    result_id TEXT PRIMARY KEY,
    logical_call_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    intent_id TEXT NOT NULL REFERENCES max_model_call_intents(intent_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    intent_hash TEXT NOT NULL,
    result_status TEXT NOT NULL CHECK(result_status IN ('succeeded','failed')),
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    usage_json TEXT NOT NULL,
    usage_hash TEXT NOT NULL,
    authoritative INTEGER NOT NULL CHECK(authoritative = 1),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_recovery_decisions(
    recovery_id TEXT PRIMARY KEY,
    logical_call_id TEXT NOT NULL REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    disposition TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    decision_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_attempt_outcomes(
    outcome_id TEXT PRIMARY KEY,
    logical_call_id TEXT NOT NULL UNIQUE REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK(status IN ('completed','aborted','paused')),
    change_set_id TEXT,
    iteration_outcome_id TEXT,
    usage_entry_id TEXT,
    outcome_json TEXT NOT NULL,
    outcome_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_links(
    link_id TEXT PRIMARY KEY,
    logical_call_id TEXT NOT NULL REFERENCES max_model_call_intents(logical_call_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    link_type TEXT NOT NULL CHECK(link_type IN ('change_set','artifact','budget_entry','iteration_outcome','checkpoint')),
    target_id TEXT NOT NULL,
    target_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(logical_call_id, link_type, target_id)
);

CREATE INDEX IF NOT EXISTS max_runner_handoffs_run ON max_runner_handoffs(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_runner_plans_run ON max_runner_plans(run_id, sequence_no);
CREATE INDEX IF NOT EXISTS max_model_intents_run ON max_model_call_intents(run_id, iteration_id);
CREATE INDEX IF NOT EXISTS max_model_results_run ON max_model_call_results(run_id, iteration_id);
CREATE INDEX IF NOT EXISTS max_model_attempts_run ON max_model_call_attempts(run_id, logical_call_id, attempt_no);
CREATE INDEX IF NOT EXISTS max_runner_recovery_run ON max_runner_recovery_decisions(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_runner_outcomes_run ON max_runner_attempt_outcomes(run_id, iteration_id);
CREATE INDEX IF NOT EXISTS max_runner_links_run ON max_runner_links(run_id, logical_call_id);

CREATE TRIGGER max_runner_profiles_no_update
BEFORE UPDATE ON max_runner_profiles
BEGIN SELECT RAISE(ABORT, 'Max runner profiles are append-only'); END;
CREATE TRIGGER max_runner_profiles_no_delete
BEFORE DELETE ON max_runner_profiles
BEGIN SELECT RAISE(ABORT, 'Max runner profiles are append-only'); END;
CREATE TRIGGER max_runner_handoffs_no_update
BEFORE UPDATE ON max_runner_handoffs
BEGIN SELECT RAISE(ABORT, 'Max runner handoffs are append-only'); END;
CREATE TRIGGER max_runner_handoffs_no_delete
BEFORE DELETE ON max_runner_handoffs
BEGIN SELECT RAISE(ABORT, 'Max runner handoffs are append-only'); END;
CREATE TRIGGER max_runner_plans_no_update
BEFORE UPDATE ON max_runner_plans
BEGIN SELECT RAISE(ABORT, 'Max runner plans are append-only'); END;
CREATE TRIGGER max_runner_plans_no_delete
BEFORE DELETE ON max_runner_plans
BEGIN SELECT RAISE(ABORT, 'Max runner plans are append-only'); END;
CREATE TRIGGER max_model_call_intents_no_update
BEFORE UPDATE ON max_model_call_intents
BEGIN SELECT RAISE(ABORT, 'Max model call intents are append-only'); END;
CREATE TRIGGER max_model_call_intents_no_delete
BEFORE DELETE ON max_model_call_intents
BEGIN SELECT RAISE(ABORT, 'Max model call intents are append-only'); END;
CREATE TRIGGER max_model_dispatch_acks_no_update
BEFORE UPDATE ON max_model_dispatch_acks
BEGIN SELECT RAISE(ABORT, 'Max dispatch acknowledgements are append-only'); END;
CREATE TRIGGER max_model_dispatch_acks_no_delete
BEFORE DELETE ON max_model_dispatch_acks
BEGIN SELECT RAISE(ABORT, 'Max dispatch acknowledgements are append-only'); END;
CREATE TRIGGER max_model_call_attempts_no_update
BEFORE UPDATE ON max_model_call_attempts
BEGIN SELECT RAISE(ABORT, 'Max model call attempts are append-only'); END;
CREATE TRIGGER max_model_call_attempts_no_delete
BEFORE DELETE ON max_model_call_attempts
BEGIN SELECT RAISE(ABORT, 'Max model call attempts are append-only'); END;
CREATE TRIGGER max_model_call_results_no_update
BEFORE UPDATE ON max_model_call_results
BEGIN SELECT RAISE(ABORT, 'Max model call results are append-only'); END;
CREATE TRIGGER max_model_call_results_no_delete
BEFORE DELETE ON max_model_call_results
BEGIN SELECT RAISE(ABORT, 'Max model call results are append-only'); END;
CREATE TRIGGER max_runner_recovery_no_update
BEFORE UPDATE ON max_runner_recovery_decisions
BEGIN SELECT RAISE(ABORT, 'Max runner recovery decisions are append-only'); END;
CREATE TRIGGER max_runner_recovery_no_delete
BEFORE DELETE ON max_runner_recovery_decisions
BEGIN SELECT RAISE(ABORT, 'Max runner recovery decisions are append-only'); END;
CREATE TRIGGER max_runner_outcomes_no_update
BEFORE UPDATE ON max_runner_attempt_outcomes
BEGIN SELECT RAISE(ABORT, 'Max runner attempt outcomes are append-only'); END;
CREATE TRIGGER max_runner_outcomes_no_delete
BEFORE DELETE ON max_runner_attempt_outcomes
BEGIN SELECT RAISE(ABORT, 'Max runner attempt outcomes are append-only'); END;
CREATE TRIGGER max_runner_links_no_update
BEFORE UPDATE ON max_runner_links
BEGIN SELECT RAISE(ABORT, 'Max runner links are append-only'); END;
CREATE TRIGGER max_runner_links_no_delete
BEFORE DELETE ON max_runner_links
BEGIN SELECT RAISE(ABORT, 'Max runner links are append-only'); END;
