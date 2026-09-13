-- MR-2B1: production-provider security boundary.
-- This migration is deliberately additive. It never stores an endpoint,
-- credential name, header, request body, response body or secret.

CREATE TABLE IF NOT EXISTS max_live_network_policies(
    network_policy_hash TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(length(network_policy_hash)=64),
    CHECK(network_policy_hash=policy_hash)
);

CREATE TABLE IF NOT EXISTS max_live_network_authorizations(
    authorization_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    charter_hash TEXT NOT NULL,
    profile_hash TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    endpoint_origin_hash TEXT NOT NULL,
    endpoint_path_policy_hash TEXT NOT NULL,
    network_policy_hash TEXT NOT NULL REFERENCES max_live_network_policies(network_policy_hash) ON DELETE RESTRICT,
    credential_ref_hash TEXT NOT NULL,
    pricing_hash TEXT NOT NULL,
    budget_hash TEXT NOT NULL,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    max_provider_calls INTEGER NOT NULL CHECK(max_provider_calls > 0),
    max_input_tokens INTEGER NOT NULL CHECK(max_input_tokens >= 0),
    max_output_tokens INTEGER NOT NULL CHECK(max_output_tokens >= 0),
    max_cache_read_tokens INTEGER NOT NULL CHECK(max_cache_read_tokens >= 0),
    max_reasoning_tokens INTEGER NOT NULL CHECK(max_reasoning_tokens >= 0),
    max_cost_units INTEGER NOT NULL CHECK(max_cost_units >= 0),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    reason_hash TEXT NOT NULL,
    execution_mode TEXT NOT NULL CHECK(execution_mode='live_https'),
    authorization_json TEXT NOT NULL,
    authorization_hash TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(authorization_hash),
    CHECK(length(endpoint_origin_hash)=64),
    CHECK(length(endpoint_path_policy_hash)=64),
    CHECK(length(credential_ref_hash)=64),
    CHECK(length(pricing_hash)=64),
    CHECK(length(budget_hash)=64),
    CHECK(length(reason_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_network_authorization_current(
    authorization_id TEXT PRIMARY KEY REFERENCES max_live_network_authorizations(authorization_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','consumed','expired','revoked')),
    consumption_id TEXT,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_network_authorization_consumptions(
    consumption_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL UNIQUE REFERENCES max_live_network_authorizations(authorization_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    profile_hash TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    endpoint_origin_hash TEXT NOT NULL,
    endpoint_path_policy_hash TEXT NOT NULL,
    credential_ref_hash TEXT NOT NULL,
    consumer_id TEXT NOT NULL,
    consumer_kind TEXT NOT NULL,
    consumer_session TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL,
    CHECK(length(endpoint_origin_hash)=64),
    CHECK(length(endpoint_path_policy_hash)=64),
    CHECK(length(credential_ref_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_network_access_events(
    access_event_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL REFERENCES max_live_network_authorizations(authorization_id) ON DELETE RESTRICT,
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
    UNIQUE(authorization_id, sequence_no),
    UNIQUE(authorization_id, event_hash)
);

CREATE TABLE IF NOT EXISTS max_live_network_attempt_records(
    live_attempt_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL REFERENCES max_live_network_authorizations(authorization_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    provider_attempt_id TEXT,
    claim_id TEXT,
    outcome TEXT NOT NULL CHECK(outcome IN ('not_dispatched','settled','unknown','disputed')),
    outcome_json TEXT NOT NULL,
    outcome_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(authorization_id, live_attempt_id)
);

CREATE TRIGGER IF NOT EXISTS max_live_network_policies_no_update
BEFORE UPDATE ON max_live_network_policies BEGIN
    SELECT RAISE(ABORT, 'Max live network policies are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_policies_no_delete
BEFORE DELETE ON max_live_network_policies BEGIN
    SELECT RAISE(ABORT, 'Max live network policies are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_authorizations_no_update
BEFORE UPDATE ON max_live_network_authorizations BEGIN
    SELECT RAISE(ABORT, 'Max live network authorizations are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_authorizations_no_delete
BEFORE DELETE ON max_live_network_authorizations BEGIN
    SELECT RAISE(ABORT, 'Max live network authorizations are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_consumptions_no_update
BEFORE UPDATE ON max_live_network_authorization_consumptions BEGIN
    SELECT RAISE(ABORT, 'Max live network authorization consumptions are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_consumptions_no_delete
BEFORE DELETE ON max_live_network_authorization_consumptions BEGIN
    SELECT RAISE(ABORT, 'Max live network authorization consumptions are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_access_events_no_update
BEFORE UPDATE ON max_live_network_access_events BEGIN
    SELECT RAISE(ABORT, 'Max live network access events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_access_events_no_delete
BEFORE DELETE ON max_live_network_access_events BEGIN
    SELECT RAISE(ABORT, 'Max live network access events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_attempt_records_no_update
BEFORE UPDATE ON max_live_network_attempt_records BEGIN
    SELECT RAISE(ABORT, 'Max live network attempt records are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_attempt_records_no_delete
BEFORE DELETE ON max_live_network_attempt_records BEGIN
    SELECT RAISE(ABORT, 'Max live network attempt records are append-only');
END;
