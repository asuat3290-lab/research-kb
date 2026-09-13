-- MR-4B1A: server-owned one-shot canary authority snapshot.
-- This record is created from already durable provider, runner, lease,
-- claim, source-egress and artifact authorities.  It contains references,
-- hashes and bounded policy JSON only; no credential value, prompt or source
-- body is ever persisted here.

CREATE TABLE IF NOT EXISTS max_live_canary_authority_bindings(
    authority_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL UNIQUE,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    charter_hash TEXT NOT NULL CHECK(length(charter_hash)=64),
    current_state_hash TEXT NOT NULL CHECK(length(current_state_hash)=64),
    current_checkpoint_id TEXT,
    current_state_version INTEGER NOT NULL CHECK(current_state_version > 0),
    engine_package TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    core_schema_version INTEGER NOT NULL CHECK(core_schema_version > 0),
    control_schema_version INTEGER NOT NULL CHECK(control_schema_version > 0),
    candidate_wheel_sha256 TEXT NOT NULL CHECK(length(candidate_wheel_sha256)=64),
    source_manifest_sha256 TEXT NOT NULL CHECK(length(source_manifest_sha256)=64),
    source_tree_sha256 TEXT NOT NULL CHECK(length(source_tree_sha256)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    model_version TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    endpoint_path_policy_hash TEXT NOT NULL CHECK(length(endpoint_path_policy_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    credential_ref_hash TEXT NOT NULL CHECK(length(credential_ref_hash)=64),
    source_egress_policy_hash TEXT NOT NULL CHECK(length(source_egress_policy_hash)=64),
    source_allowlist_json TEXT NOT NULL,
    source_policy_json TEXT NOT NULL,
    network_policy_json TEXT NOT NULL,
    credential_ref_json TEXT NOT NULL,
    runner_profile_hash TEXT NOT NULL CHECK(length(runner_profile_hash)=64),
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    claim_id TEXT NOT NULL,
    cap_vector_json TEXT NOT NULL,
    cap_vector_hash TEXT NOT NULL CHECK(length(cap_vector_hash)=64),
    transport_policy_json TEXT NOT NULL,
    kill_rollback_incident_policy_json TEXT NOT NULL,
    authority_json TEXT NOT NULL,
    authority_hash TEXT NOT NULL CHECK(length(authority_hash)=64),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_live_canary_authority_bindings_run_idx
    ON max_live_canary_authority_bindings(run_id, created_at, authority_id);

CREATE TRIGGER IF NOT EXISTS max_live_canary_authority_bindings_no_update
BEFORE UPDATE ON max_live_canary_authority_bindings
BEGIN
    SELECT RAISE(ABORT, 'live canary authority bindings are append-only');
END;

CREATE TRIGGER IF NOT EXISTS max_live_canary_authority_bindings_no_delete
BEFORE DELETE ON max_live_canary_authority_bindings
BEGIN
    SELECT RAISE(ABORT, 'live canary authority bindings are append-only');
END;
