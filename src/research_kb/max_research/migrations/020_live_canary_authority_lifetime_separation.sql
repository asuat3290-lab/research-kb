-- MR-4B1B-v11R1: separate durable human-review preparation from JIT execution.
-- Preparation rows never contain a lease, invocation claim, fencing token,
-- endpoint, credential, prompt, message, source text, or raw request body.

CREATE TABLE IF NOT EXISTS max_live_canary_preparation_snapshots(
    snapshot_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    charter_hash TEXT NOT NULL CHECK(length(charter_hash)=64),
    research_state_hash TEXT NOT NULL CHECK(length(research_state_hash)=64),
    checkpoint_id TEXT,
    state_version INTEGER NOT NULL CHECK(state_version > 0),
    plan_id TEXT NOT NULL,
    plan_hash TEXT NOT NULL CHECK(length(plan_hash)=64),
    iteration_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    logical_call_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    wire_request_hash TEXT NOT NULL CHECK(length(wire_request_hash)=64),
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    source_egress_policy_hash TEXT NOT NULL CHECK(length(source_egress_policy_hash)=64),
    source_version TEXT NOT NULL,
    document_id TEXT NOT NULL,
    passage_id TEXT NOT NULL,
    document_content_hash TEXT NOT NULL CHECK(length(document_content_hash)=64),
    passage_content_hash TEXT NOT NULL CHECK(length(passage_content_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    caps_json TEXT NOT NULL,
    caps_hash TEXT NOT NULL CHECK(length(caps_hash)=64),
    engine_version TEXT NOT NULL,
    candidate_wheel_sha256 TEXT NOT NULL CHECK(length(candidate_wheel_sha256)=64),
    source_manifest_sha256 TEXT NOT NULL CHECK(length(source_manifest_sha256)=64),
    source_tree_sha256 TEXT NOT NULL CHECK(length(source_tree_sha256)=64),
    release_metadata_sha256 TEXT NOT NULL CHECK(length(release_metadata_sha256)=64),
    migration_release_manifest_sha256 TEXT NOT NULL CHECK(length(migration_release_manifest_sha256)=64),
    release_identity_json TEXT NOT NULL,
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    snapshot_json TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL UNIQUE CHECK(length(snapshot_hash)=64),
    created_at TEXT NOT NULL,
    review_expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS max_live_canary_preparation_snapshots_run_hash_idx
    ON max_live_canary_preparation_snapshots(run_id, snapshot_hash);
CREATE INDEX IF NOT EXISTS max_live_canary_preparation_snapshots_run_idx
    ON max_live_canary_preparation_snapshots(run_id, created_at, snapshot_id);

CREATE TABLE IF NOT EXISTS max_live_canary_preparation_snapshot_current(
    snapshot_id TEXT PRIMARY KEY REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL UNIQUE REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK(status IN ('active','invalidated','superseded','consumed')),
    reason_code TEXT,
    current_event_sequence INTEGER NOT NULL CHECK(current_event_sequence > 0),
    current_event_hash TEXT NOT NULL CHECK(length(current_event_hash)=64),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_preparation_snapshot_events(
    event_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    event_type TEXT NOT NULL CHECK(event_type IN ('created','invalidated','superseded','consumed')),
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(snapshot_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_live_canary_preparation_snapshot_events_run_idx
    ON max_live_canary_preparation_snapshot_events(run_id, snapshot_id, sequence_no);

CREATE TABLE IF NOT EXISTS max_live_canary_preparation_previews(
    preview_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    source_egress_policy_hash TEXT NOT NULL CHECK(length(source_egress_policy_hash)=64),
    source_version TEXT NOT NULL,
    document_id TEXT NOT NULL,
    passage_id TEXT NOT NULL,
    document_content_hash TEXT NOT NULL CHECK(length(document_content_hash)=64),
    passage_content_hash TEXT NOT NULL CHECK(length(passage_content_hash)=64),
    caps_json TEXT NOT NULL,
    caps_hash TEXT NOT NULL CHECK(length(caps_hash)=64),
    engine_version TEXT NOT NULL,
    candidate_wheel_sha256 TEXT NOT NULL CHECK(length(candidate_wheel_sha256)=64),
    source_manifest_sha256 TEXT NOT NULL CHECK(length(source_manifest_sha256)=64),
    source_tree_sha256 TEXT NOT NULL CHECK(length(source_tree_sha256)=64),
    release_identity_json TEXT NOT NULL,
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    dns_policy_hash TEXT NOT NULL CHECK(length(dns_policy_hash)=64),
    kill_switch_hash TEXT NOT NULL CHECK(length(kill_switch_hash)=64),
    rollback_policy_hash TEXT NOT NULL CHECK(length(rollback_policy_hash)=64),
    incident_policy_hash TEXT NOT NULL CHECK(length(incident_policy_hash)=64),
    preview_json TEXT NOT NULL,
    preview_hash TEXT NOT NULL UNIQUE CHECK(length(preview_hash)=64),
    created_at TEXT NOT NULL,
    review_expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(snapshot_id, preview_hash)
);

CREATE TABLE IF NOT EXISTS max_live_canary_preparation_approvals(
    approval_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    source_egress_policy_hash TEXT NOT NULL CHECK(length(source_egress_policy_hash)=64),
    caps_hash TEXT NOT NULL CHECK(length(caps_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    approval_json TEXT NOT NULL,
    approval_hash TEXT NOT NULL UNIQUE CHECK(length(approval_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(preview_id, approval_hash)
);

CREATE TABLE IF NOT EXISTS max_live_canary_preparation_approval_consumptions(
    consumption_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_preparation_approvals(approval_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE CHECK(length(consumption_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_jit_execution_authorities(
    authority_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL REFERENCES max_live_canary_preparation_approvals(approval_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    lease_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    owner_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    authority_expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','pre_send_aborted','unknown_after_send','succeeded','failed','consumed')),
    authority_json TEXT NOT NULL,
    authority_hash TEXT NOT NULL UNIQUE CHECK(length(authority_hash)=64),
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(approval_id)
);

CREATE TABLE IF NOT EXISTS max_live_canary_preparation_dns_authorities(
    authority_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    max_getaddrinfo_calls INTEGER NOT NULL CHECK(max_getaddrinfo_calls=1),
    max_dns_candidates INTEGER NOT NULL CHECK(max_dns_candidates > 0 AND max_dns_candidates <= 16),
    credential_reads INTEGER NOT NULL CHECK(credential_reads=0),
    tcp_connections INTEGER NOT NULL CHECK(tcp_connections=0),
    tls_https_calls INTEGER NOT NULL CHECK(tls_https_calls=0),
    provider_calls INTEGER NOT NULL CHECK(provider_calls=0),
    cost_units INTEGER NOT NULL CHECK(cost_units=0),
    status TEXT NOT NULL CHECK(status='AWAITING_DNS_PREFLIGHT_AUTHORIZATION'),
    authority_json TEXT NOT NULL,
    authority_hash TEXT NOT NULL UNIQUE CHECK(length(authority_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_preparation_dns_requests(
    request_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_preparation_dns_authorities(authority_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    request_json TEXT NOT NULL,
    request_hash TEXT NOT NULL UNIQUE CHECK(length(request_hash)=64),
    status TEXT NOT NULL CHECK(status='AWAITING_DNS_PREFLIGHT_AUTHORIZATION'),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_snapshots_no_update
BEFORE UPDATE ON max_live_canary_preparation_snapshots
BEGIN SELECT RAISE(ABORT, 'preparation snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_snapshots_no_delete
BEFORE DELETE ON max_live_canary_preparation_snapshots
BEGIN SELECT RAISE(ABORT, 'preparation snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_snapshot_events_no_update
BEFORE UPDATE ON max_live_canary_preparation_snapshot_events
BEGIN SELECT RAISE(ABORT, 'preparation snapshot events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_snapshot_events_no_delete
BEFORE DELETE ON max_live_canary_preparation_snapshot_events
BEGIN SELECT RAISE(ABORT, 'preparation snapshot events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_previews_no_update
BEFORE UPDATE ON max_live_canary_preparation_previews
BEGIN SELECT RAISE(ABORT, 'preparation previews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_previews_no_delete
BEFORE DELETE ON max_live_canary_preparation_previews
BEGIN SELECT RAISE(ABORT, 'preparation previews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_approvals_no_update
BEFORE UPDATE ON max_live_canary_preparation_approvals
BEGIN SELECT RAISE(ABORT, 'preparation approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_approvals_no_delete
BEFORE DELETE ON max_live_canary_preparation_approvals
BEGIN SELECT RAISE(ABORT, 'preparation approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_approval_consumptions_no_update
BEFORE UPDATE ON max_live_canary_preparation_approval_consumptions
BEGIN SELECT RAISE(ABORT, 'preparation approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_approval_consumptions_no_delete
BEFORE DELETE ON max_live_canary_preparation_approval_consumptions
BEGIN SELECT RAISE(ABORT, 'preparation approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_jit_execution_authorities_no_update
BEFORE UPDATE ON max_live_canary_jit_execution_authorities
BEGIN SELECT RAISE(ABORT, 'JIT execution authorities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_jit_execution_authorities_no_delete
BEFORE DELETE ON max_live_canary_jit_execution_authorities
BEGIN SELECT RAISE(ABORT, 'JIT execution authorities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_dns_authorities_no_update
BEFORE UPDATE ON max_live_canary_preparation_dns_authorities
BEGIN SELECT RAISE(ABORT, 'preparation DNS authorities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_dns_authorities_no_delete
BEFORE DELETE ON max_live_canary_preparation_dns_authorities
BEGIN SELECT RAISE(ABORT, 'preparation DNS authorities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_dns_requests_no_update
BEFORE UPDATE ON max_live_canary_preparation_dns_requests
BEGIN SELECT RAISE(ABORT, 'preparation DNS requests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_preparation_dns_requests_no_delete
BEFORE DELETE ON max_live_canary_preparation_dns_requests
BEGIN SELECT RAISE(ABORT, 'preparation DNS requests are append-only'); END;
