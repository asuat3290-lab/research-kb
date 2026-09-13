-- MR-2B1A: server-owned live dispatch permits.
-- This migration stores only binding hashes and bounded audit facts.  It never
-- stores request bodies, response bodies, endpoint text, credential values or
-- API keys.

CREATE TABLE IF NOT EXISTS max_live_dispatch_permits(
    permit_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL REFERENCES max_live_network_authorizations(authorization_id) ON DELETE RESTRICT,
    consumption_id TEXT NOT NULL UNIQUE REFERENCES max_live_network_authorization_consumptions(consumption_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    grant_consumption_id TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    budget_hash TEXT NOT NULL,
    claim_id TEXT NOT NULL REFERENCES max_provider_call_claims(claim_id) ON DELETE RESTRICT,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES max_provider_dispatch_attempts(attempt_id) ON DELETE RESTRICT,
    request_hash TEXT NOT NULL,
    wire_request_hash TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    logical_call_id TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL,
    endpoint_origin_hash TEXT NOT NULL,
    endpoint_path_policy_hash TEXT NOT NULL,
    network_policy_hash TEXT NOT NULL REFERENCES max_live_network_policies(network_policy_hash) ON DELETE RESTRICT,
    credential_ref_hash TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    permit_json TEXT NOT NULL,
    permit_hash TEXT NOT NULL UNIQUE,
    CHECK(length(request_hash)=64),
    CHECK(length(wire_request_hash)=64),
    CHECK(length(intent_hash)=64),
    CHECK(length(idempotency_key_hash)=64),
    CHECK(length(endpoint_origin_hash)=64),
    CHECK(length(endpoint_path_policy_hash)=64),
    CHECK(length(network_policy_hash)=64),
    CHECK(length(credential_ref_hash)=64),
    CHECK(length(pricing_hash)=64),
    CHECK(length(budget_hash)=64),
    CHECK(length(permit_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_dispatch_permit_current(
    permit_id TEXT PRIMARY KEY REFERENCES max_live_dispatch_permits(permit_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('ready','send_started','settled','failed','unknown','disputed','revoked','expired')),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_dispatch_permit_events(
    permit_event_id TEXT PRIMARY KEY,
    permit_id TEXT NOT NULL REFERENCES max_live_dispatch_permits(permit_id) ON DELETE RESTRICT,
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
    UNIQUE(permit_id, sequence_no),
    UNIQUE(permit_id, event_hash)
);

CREATE INDEX IF NOT EXISTS max_live_dispatch_permits_request_idx
    ON max_live_dispatch_permits(run_id, idempotency_key_hash);
CREATE INDEX IF NOT EXISTS max_live_dispatch_permits_auth_idx
    ON max_live_dispatch_permits(authorization_id);

CREATE TRIGGER IF NOT EXISTS max_live_dispatch_permits_no_update
BEFORE UPDATE ON max_live_dispatch_permits BEGIN
    SELECT RAISE(ABORT, 'Max live dispatch permits are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_dispatch_permits_no_delete
BEFORE DELETE ON max_live_dispatch_permits BEGIN
    SELECT RAISE(ABORT, 'Max live dispatch permits are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_dispatch_permit_events_no_update
BEFORE UPDATE ON max_live_dispatch_permit_events BEGIN
    SELECT RAISE(ABORT, 'Max live dispatch permit events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_dispatch_permit_events_no_delete
BEFORE DELETE ON max_live_dispatch_permit_events BEGIN
    SELECT RAISE(ABORT, 'Max live dispatch permit events are append-only');
END;
