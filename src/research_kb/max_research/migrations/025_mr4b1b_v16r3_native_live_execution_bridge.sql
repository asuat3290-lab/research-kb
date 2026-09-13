-- MR-4B1B-v16R3: Native JIT -> production live-provider execution bridge.
--
-- Migration 025 is additive.  Migrations 001-024 are immutable release
-- inputs.  Every execution capability below is server-owned and append-only;
-- state changes are represented by a successor projection or hash-chained
-- event.  No secret, prompt, source text, response body, or raw address is
-- stored here.

CREATE TABLE IF NOT EXISTS max_live_canary_native_execution_previews(
    execution_preview_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_native_approvals_v2(approval_id) ON DELETE RESTRICT,
    approval_hash TEXT NOT NULL CHECK(length(approval_hash)=64),
    approval_preview_id TEXT NOT NULL REFERENCES max_live_canary_approval_previews(approval_preview_id) ON DELETE RESTRICT,
    approval_preview_hash TEXT NOT NULL CHECK(length(approval_preview_hash)=64),
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preparation_preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preparation_preview_hash TEXT NOT NULL CHECK(length(preparation_preview_hash)=64),
    handoff_id TEXT NOT NULL REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    handoff_hash TEXT NOT NULL CHECK(length(handoff_hash)=64),
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    dns_attempt_id TEXT NOT NULL REFERENCES max_live_canary_dns_attempts(attempt_id) ON DELETE RESTRICT,
    dns_receipt_id TEXT NOT NULL REFERENCES max_live_canary_dns_attempt_receipts(receipt_id) ON DELETE RESTRICT,
    dns_receipt_hash TEXT NOT NULL CHECK(length(dns_receipt_hash)=64),
    bounded_dns_result_hash TEXT NOT NULL CHECK(length(bounded_dns_result_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    source_tree_hash TEXT NOT NULL CHECK(length(source_tree_hash)=64),
    wheel_hash TEXT NOT NULL CHECK(length(wheel_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    current_state_hash TEXT NOT NULL CHECK(length(current_state_hash)=64),
    current_state_version INTEGER NOT NULL CHECK(current_state_version >= 0),
    human_cost_ceiling INTEGER NOT NULL CHECK(human_cost_ceiling >= 0),
    profile_worst_case_cost INTEGER NOT NULL CHECK(profile_worst_case_cost >= 0),
    effective_cost_cap INTEGER NOT NULL CHECK(effective_cost_cap >= 0),
    max_provider_calls INTEGER NOT NULL CHECK(max_provider_calls=1),
    max_input_tokens INTEGER NOT NULL CHECK(max_input_tokens >= 0),
    max_output_tokens INTEGER NOT NULL CHECK(max_output_tokens >= 0),
    max_cache_read_tokens INTEGER NOT NULL CHECK(max_cache_read_tokens >= 0),
    max_reasoning_tokens INTEGER NOT NULL CHECK(max_reasoning_tokens >= 0),
    state TEXT NOT NULL CHECK(state='AWAITING_EXPLICIT_EXECUTION_AUTHORIZATION'),
    execution_phrase_hash TEXT NOT NULL CHECK(length(execution_phrase_hash)=64),
    execution_preview_json TEXT NOT NULL,
    execution_preview_hash TEXT NOT NULL UNIQUE CHECK(length(execution_preview_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_execution_authorizations(
    execution_authorization_id TEXT PRIMARY KEY,
    execution_preview_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_native_execution_previews(execution_preview_id) ON DELETE RESTRICT,
    execution_preview_hash TEXT NOT NULL CHECK(length(execution_preview_hash)=64),
    approval_id TEXT NOT NULL REFERENCES max_live_canary_native_approvals_v2(approval_id) ON DELETE RESTRICT,
    approval_hash TEXT NOT NULL CHECK(length(approval_hash)=64),
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    current_state_hash TEXT NOT NULL CHECK(length(current_state_hash)=64),
    current_state_version INTEGER NOT NULL CHECK(current_state_version >= 0),
    max_provider_calls INTEGER NOT NULL CHECK(max_provider_calls=1),
    effective_cost_cap INTEGER NOT NULL CHECK(effective_cost_cap >= 0),
    authorization_json TEXT NOT NULL,
    authorization_hash TEXT NOT NULL UNIQUE CHECK(length(authorization_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_execution_authorization_consumptions(
    consumption_id TEXT PRIMARY KEY,
    execution_authorization_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_native_execution_authorizations(execution_authorization_id) ON DELETE RESTRICT,
    execution_preview_id TEXT NOT NULL REFERENCES max_live_canary_native_execution_previews(execution_preview_id) ON DELETE RESTRICT,
    approval_id TEXT NOT NULL REFERENCES max_live_canary_native_approvals_v2(approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    authorization_hash TEXT NOT NULL CHECK(length(authorization_hash)=64),
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE CHECK(length(consumption_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_source_permits(
    source_permit_id TEXT PRIMARY KEY,
    execution_authorization_id TEXT NOT NULL REFERENCES max_live_canary_native_execution_authorizations(execution_authorization_id) ON DELETE RESTRICT,
    execution_preview_id TEXT NOT NULL REFERENCES max_live_canary_native_execution_previews(execution_preview_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    passage_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    source_tree_hash TEXT NOT NULL CHECK(length(source_tree_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    expires_at TEXT NOT NULL,
    permit_json TEXT NOT NULL,
    permit_hash TEXT NOT NULL UNIQUE CHECK(length(permit_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_source_permit_current(
    source_permit_id TEXT PRIMARY KEY REFERENCES max_live_canary_native_source_permits(source_permit_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('issued','consumed','revoked','expired')),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_source_permit_events(
    source_permit_event_id TEXT PRIMARY KEY,
    source_permit_id TEXT NOT NULL REFERENCES max_live_canary_native_source_permits(source_permit_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(source_permit_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_live_jit_authorities(
    authority_id TEXT PRIMARY KEY,
    execution_authorization_id TEXT NOT NULL REFERENCES max_live_canary_native_execution_authorizations(execution_authorization_id) ON DELETE RESTRICT,
    execution_consumption_id TEXT NOT NULL REFERENCES max_live_canary_native_execution_authorization_consumptions(consumption_id) ON DELETE RESTRICT,
    approval_id TEXT NOT NULL REFERENCES max_live_canary_native_approvals_v2(approval_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    execution_preview_hash TEXT NOT NULL CHECK(length(execution_preview_hash)=64),
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    source_tree_hash TEXT NOT NULL CHECK(length(source_tree_hash)=64),
    wheel_hash TEXT NOT NULL CHECK(length(wheel_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    lease_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    grant_id TEXT NOT NULL,
    grant_consumption_id TEXT NOT NULL,
    network_authorization_id TEXT NOT NULL,
    dispatch_permit_id TEXT NOT NULL,
    source_permit_id TEXT NOT NULL REFERENCES max_live_canary_native_source_permits(source_permit_id) ON DELETE RESTRICT,
    authority_expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state='ready'),
    authority_json TEXT NOT NULL,
    authority_hash TEXT NOT NULL UNIQUE CHECK(length(authority_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(execution_authorization_id),
    UNIQUE(claim_id)
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_live_jit_events(
    event_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL REFERENCES max_live_canary_native_live_jit_authorities(authority_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    state TEXT NOT NULL CHECK(state IN ('ready','preflight_validated','credential_read_started','credential_resolved','transport_created','send_started','response_headers_received','response_body_received','authoritative_result_committed','authoritative_provider_rejection','known_pre_send_failure','unknown_after_send','closed')),
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(authority_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_live_canary_native_execution_previews_run_idx ON max_live_canary_native_execution_previews(run_id, created_at, execution_preview_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_execution_authorizations_run_idx ON max_live_canary_native_execution_authorizations(run_id, created_at, execution_authorization_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_execution_consumptions_run_idx ON max_live_canary_native_execution_authorization_consumptions(run_id, created_at, consumption_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_source_permits_run_idx ON max_live_canary_native_source_permits(run_id, created_at, source_permit_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_live_jit_authorities_run_idx ON max_live_canary_native_live_jit_authorities(run_id, created_at, authority_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_live_jit_events_run_idx ON max_live_canary_native_live_jit_events(run_id, authority_id, sequence_no);

CREATE TRIGGER IF NOT EXISTS max_live_canary_native_execution_previews_no_update BEFORE UPDATE ON max_live_canary_native_execution_previews BEGIN SELECT RAISE(ABORT, 'native execution previews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_execution_previews_no_delete BEFORE DELETE ON max_live_canary_native_execution_previews BEGIN SELECT RAISE(ABORT, 'native execution previews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_execution_authorizations_no_update BEFORE UPDATE ON max_live_canary_native_execution_authorizations BEGIN SELECT RAISE(ABORT, 'native execution authorizations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_execution_authorizations_no_delete BEFORE DELETE ON max_live_canary_native_execution_authorizations BEGIN SELECT RAISE(ABORT, 'native execution authorizations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_execution_consumptions_no_update BEFORE UPDATE ON max_live_canary_native_execution_authorization_consumptions BEGIN SELECT RAISE(ABORT, 'native execution authorization consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_execution_consumptions_no_delete BEFORE DELETE ON max_live_canary_native_execution_authorization_consumptions BEGIN SELECT RAISE(ABORT, 'native execution authorization consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_source_permits_no_update BEFORE UPDATE ON max_live_canary_native_source_permits BEGIN SELECT RAISE(ABORT, 'native source permits are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_source_permits_no_delete BEFORE DELETE ON max_live_canary_native_source_permits BEGIN SELECT RAISE(ABORT, 'native source permits are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_source_permit_events_no_update BEFORE UPDATE ON max_live_canary_native_source_permit_events BEGIN SELECT RAISE(ABORT, 'native source permit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_source_permit_events_no_delete BEFORE DELETE ON max_live_canary_native_source_permit_events BEGIN SELECT RAISE(ABORT, 'native source permit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_live_jit_authorities_no_update BEFORE UPDATE ON max_live_canary_native_live_jit_authorities BEGIN SELECT RAISE(ABORT, 'native live JIT authorities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_live_jit_authorities_no_delete BEFORE DELETE ON max_live_canary_native_live_jit_authorities BEGIN SELECT RAISE(ABORT, 'native live JIT authorities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_live_jit_events_no_update BEFORE UPDATE ON max_live_canary_native_live_jit_events BEGIN SELECT RAISE(ABORT, 'native live JIT events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_live_jit_events_no_delete BEFORE DELETE ON max_live_canary_native_live_jit_events BEGIN SELECT RAISE(ABORT, 'native live JIT events are append-only'); END;
