-- MR-4B1B-v4R: terminal closure for a known pre-send canary failure.
-- The grant itself and its consumption remain immutable.  This separate
-- append-only record makes a consumed grant explicitly non-dispatchable even
-- when the failure happened before a provider dispatch permit existed.

CREATE TABLE IF NOT EXISTS max_live_execution_grant_closures(
    closure_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL UNIQUE REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    grant_consumption_id TEXT REFERENCES max_live_execution_grant_consumptions(consumption_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    terminal_state TEXT NOT NULL CHECK(terminal_state = 'terminal-unused/pre-send-aborted'),
    failure_stage TEXT NOT NULL,
    error_code TEXT NOT NULL,
    usage_json TEXT NOT NULL,
    reservation_json TEXT NOT NULL,
    cost_units INTEGER NOT NULL CHECK(cost_units = 0),
    closure_json TEXT NOT NULL,
    closure_hash TEXT NOT NULL UNIQUE CHECK(length(closure_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_live_execution_grant_closures_run_idx
    ON max_live_execution_grant_closures(run_id, created_at, closure_id);

CREATE TRIGGER IF NOT EXISTS max_live_execution_grant_closures_no_update
BEFORE UPDATE ON max_live_execution_grant_closures
BEGIN SELECT RAISE(ABORT, 'live execution grant closures are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_execution_grant_closures_no_delete
BEFORE DELETE ON max_live_execution_grant_closures
BEGIN SELECT RAISE(ABORT, 'live execution grant closures are append-only'); END;
