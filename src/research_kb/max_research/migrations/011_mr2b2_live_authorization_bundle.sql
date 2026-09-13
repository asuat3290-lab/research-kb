-- MR-2B2: durable multi-call live authorization bundles.
--
-- A live network authorization remains single-use.  A bundle is an immutable,
-- ordered collection of those authorities and only assigns one authority to
-- one persisted logical call.  No endpoint, credential name, request body,
-- response body, source text, or secret is stored here.

CREATE TABLE IF NOT EXISTS max_live_authorization_bundles(
    bundle_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    budget_hash TEXT NOT NULL,
    member_count INTEGER NOT NULL CHECK(member_count > 0 AND member_count <= 256),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    bundle_json TEXT NOT NULL,
    bundle_hash TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(length(profile_hash)=64),
    CHECK(length(pricing_hash)=64),
    CHECK(length(budget_hash)=64),
    CHECK(length(bundle_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_authorization_bundle_members(
    member_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL REFERENCES max_live_authorization_bundles(bundle_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    authorization_id TEXT NOT NULL UNIQUE REFERENCES max_live_network_authorizations(authorization_id) ON DELETE RESTRICT,
    authorization_hash TEXT NOT NULL,
    member_json TEXT NOT NULL,
    member_hash TEXT NOT NULL UNIQUE,
    UNIQUE(bundle_id, ordinal),
    CHECK(length(authorization_hash)=64),
    CHECK(length(member_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_authorization_bundle_current(
    bundle_id TEXT PRIMARY KEY REFERENCES max_live_authorization_bundles(bundle_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','exhausted','revoked','expired')),
    next_ordinal INTEGER NOT NULL CHECK(next_ordinal >= 0),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(length(current_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_authorization_assignments(
    assignment_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL REFERENCES max_live_authorization_bundles(bundle_id) ON DELETE RESTRICT,
    member_id TEXT NOT NULL UNIQUE REFERENCES max_live_authorization_bundle_members(member_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    authorization_id TEXT NOT NULL UNIQUE REFERENCES max_live_network_authorizations(authorization_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL,
    logical_call_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL,
    assigned_at TEXT NOT NULL,
    assignment_json TEXT NOT NULL,
    assignment_hash TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(bundle_id, logical_call_id),
    UNIQUE(bundle_id, idempotency_key_hash),
    CHECK(length(intent_hash)=64),
    CHECK(length(idempotency_key_hash)=64),
    CHECK(length(assignment_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_authorization_bundle_events(
    bundle_event_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL REFERENCES max_live_authorization_bundles(bundle_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(bundle_id, sequence_no),
    UNIQUE(bundle_id, event_hash),
    CHECK(length(payload_hash)=64),
    CHECK(length(event_hash)=64)
);

-- One explicit human approval authorizes at most one next bounded live
-- iteration. The identity binds the current state, expected sequence,
-- runner handoff/fence and provider authority set. A durable consumption
-- permits recovery of that same sequence but never a later iteration.
CREATE TABLE IF NOT EXISTS max_live_iteration_approvals(
    live_iteration_approval_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    expected_sequence INTEGER NOT NULL CHECK(expected_sequence >= 1),
    current_state_hash TEXT NOT NULL,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    bundle_id TEXT NOT NULL REFERENCES max_live_authorization_bundles(bundle_id) ON DELETE RESTRICT,
    provider_profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    runner_profile_hash TEXT NOT NULL REFERENCES max_runner_profiles(profile_hash) ON DELETE RESTRICT,
    runner_id TEXT NOT NULL,
    runner_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    reason_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approval_json TEXT NOT NULL,
    approval_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(length(current_state_hash)=64),
    CHECK(length(provider_profile_hash)=64),
    CHECK(length(runner_profile_hash)=64),
    CHECK(length(reason_hash)=64),
    CHECK(length(approval_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_iteration_approval_consumptions(
    consumption_id TEXT PRIMARY KEY,
    live_iteration_approval_id TEXT NOT NULL UNIQUE REFERENCES max_live_iteration_approvals(live_iteration_approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    expected_sequence INTEGER NOT NULL CHECK(expected_sequence >= 1),
    runner_id TEXT NOT NULL,
    runner_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE,
    UNIQUE(run_id, expected_sequence),
    CHECK(length(consumption_hash)=64)
);

CREATE INDEX IF NOT EXISTS max_live_authorization_bundles_run_idx
    ON max_live_authorization_bundles(run_id, issued_at);
CREATE INDEX IF NOT EXISTS max_live_authorization_assignments_run_idx
    ON max_live_authorization_assignments(run_id, iteration_id, logical_call_id);
CREATE INDEX IF NOT EXISTS max_live_iteration_approvals_run_idx
    ON max_live_iteration_approvals(run_id, expected_sequence);

CREATE TRIGGER IF NOT EXISTS max_live_authorization_bundles_no_update
BEFORE UPDATE ON max_live_authorization_bundles BEGIN
    SELECT RAISE(ABORT, 'Max live authorization bundles are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_authorization_bundles_no_delete
BEFORE DELETE ON max_live_authorization_bundles BEGIN
    SELECT RAISE(ABORT, 'Max live authorization bundles are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_authorization_bundle_members_no_update
BEFORE UPDATE ON max_live_authorization_bundle_members BEGIN
    SELECT RAISE(ABORT, 'Max live authorization bundle members are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_authorization_bundle_members_no_delete
BEFORE DELETE ON max_live_authorization_bundle_members BEGIN
    SELECT RAISE(ABORT, 'Max live authorization bundle members are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_authorization_assignments_no_update
BEFORE UPDATE ON max_live_authorization_assignments BEGIN
    SELECT RAISE(ABORT, 'Max live authorization assignments are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_authorization_assignments_no_delete
BEFORE DELETE ON max_live_authorization_assignments BEGIN
    SELECT RAISE(ABORT, 'Max live authorization assignments are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_authorization_bundle_events_no_update
BEFORE UPDATE ON max_live_authorization_bundle_events BEGIN
    SELECT RAISE(ABORT, 'Max live authorization bundle events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_authorization_bundle_events_no_delete
BEFORE DELETE ON max_live_authorization_bundle_events BEGIN
    SELECT RAISE(ABORT, 'Max live authorization bundle events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_iteration_approvals_no_update
BEFORE UPDATE ON max_live_iteration_approvals BEGIN
    SELECT RAISE(ABORT, 'Max live iteration approvals are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_iteration_approvals_no_delete
BEFORE DELETE ON max_live_iteration_approvals BEGIN
    SELECT RAISE(ABORT, 'Max live iteration approvals are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_iteration_approval_consumptions_no_update
BEFORE UPDATE ON max_live_iteration_approval_consumptions BEGIN
    SELECT RAISE(ABORT, 'Max live iteration approval consumptions are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_iteration_approval_consumptions_no_delete
BEFORE DELETE ON max_live_iteration_approval_consumptions BEGIN
    SELECT RAISE(ABORT, 'Max live iteration approval consumptions are append-only');
END;
