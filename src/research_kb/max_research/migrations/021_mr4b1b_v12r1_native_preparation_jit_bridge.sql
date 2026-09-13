-- MR-4B1B-v12R1: native Preparation -> JIT -> Provider bridge.
--
-- These objects are deliberately separate from the schema-19 live-canary
-- authority tables and from the v11 preparation/JIT compatibility tables.
-- Every row is immutable.  State changes are represented by a hash-chained
-- successor event so a provider executor can never update an authority into
-- existence or replay an approval by editing a projection.

CREATE TABLE IF NOT EXISTS max_live_canary_native_dns_receipts(
    receipt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_preparation_dns_requests(request_id) ON DELETE RESTRICT,
    authority_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_authorities(authority_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    dns_authority_hash TEXT NOT NULL CHECK(length(dns_authority_hash)=64),
    endpoint_scheme TEXT NOT NULL CHECK(endpoint_scheme='https'),
    endpoint_hostname TEXT NOT NULL CHECK(endpoint_hostname='opencode.ai'),
    endpoint_port INTEGER NOT NULL CHECK(endpoint_port=443),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    source_tree_sha256 TEXT NOT NULL CHECK(length(source_tree_sha256)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    max_getaddrinfo_calls INTEGER NOT NULL CHECK(max_getaddrinfo_calls=1),
    getaddrinfo_attempts INTEGER NOT NULL CHECK(getaddrinfo_attempts=1),
    max_dns_candidates INTEGER NOT NULL CHECK(max_dns_candidates > 0 AND max_dns_candidates <= 16),
    candidate_count INTEGER NOT NULL CHECK(candidate_count >= 0),
    ipv4_count INTEGER NOT NULL CHECK(ipv4_count >= 0),
    ipv6_count INTEGER NOT NULL CHECK(ipv6_count >= 0),
    all_global INTEGER NOT NULL CHECK(all_global IN (0,1)),
    ssrf_safe INTEGER NOT NULL CHECK(ssrf_safe IN (0,1)),
    cap_satisfied INTEGER NOT NULL CHECK(cap_satisfied IN (0,1)),
    retry_count INTEGER NOT NULL CHECK(retry_count=0),
    credential_reads INTEGER NOT NULL CHECK(credential_reads=0),
    tcp_connections INTEGER NOT NULL CHECK(tcp_connections=0),
    tls_https_calls INTEGER NOT NULL CHECK(tls_https_calls=0),
    provider_calls INTEGER NOT NULL CHECK(provider_calls=0),
    cost_units INTEGER NOT NULL CHECK(cost_units=0),
    status TEXT NOT NULL CHECK(status IN ('passed','failed')),
    bounded_result_hash TEXT NOT NULL CHECK(length(bounded_result_hash)=64),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK(length(receipt_hash)=64),
    executed_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_approvals(
    approval_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    snapshot_state_hash TEXT NOT NULL CHECK(length(snapshot_state_hash)=64),
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    dns_receipt_id TEXT NOT NULL REFERENCES max_live_canary_native_dns_receipts(receipt_id) ON DELETE RESTRICT,
    dns_receipt_hash TEXT NOT NULL CHECK(length(dns_receipt_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    caps_hash TEXT NOT NULL CHECK(length(caps_hash)=64),
    confirmation_phrase_hash TEXT NOT NULL CHECK(length(confirmation_phrase_hash)=64),
    approval_json TEXT NOT NULL,
    approval_hash TEXT NOT NULL UNIQUE CHECK(length(approval_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(preview_id, approval_hash)
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_approval_consumptions(
    consumption_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_native_approvals(approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    approval_hash TEXT NOT NULL CHECK(length(approval_hash)=64),
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE CHECK(length(consumption_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_approval_revocations(
    revocation_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_native_approvals(approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    reason_hash TEXT NOT NULL CHECK(length(reason_hash)=64),
    revocation_json TEXT NOT NULL,
    revocation_hash TEXT NOT NULL UNIQUE CHECK(length(revocation_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_jit_authorities(
    authority_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL REFERENCES max_live_canary_native_approvals(approval_id) ON DELETE RESTRICT,
    consumption_id TEXT NOT NULL REFERENCES max_live_canary_native_approval_consumptions(consumption_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    dns_receipt_id TEXT NOT NULL REFERENCES max_live_canary_native_dns_receipts(receipt_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    owner_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    idempotency_key_hash TEXT NOT NULL CHECK(length(idempotency_key_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    grant_id TEXT,
    network_authorization_id TEXT,
    dispatch_permit_id TEXT,
    source_permit_id TEXT,
    authority_expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state='ready'),
    authority_json TEXT NOT NULL,
    authority_hash TEXT NOT NULL UNIQUE CHECK(length(authority_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(approval_id),
    UNIQUE(claim_id)
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_jit_events(
    event_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL REFERENCES max_live_canary_native_jit_authorities(authority_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    state TEXT NOT NULL CHECK(state IN ('ready','send_started','known_pre_send_failure','unknown_after_send','succeeded','failed_with_authoritative_response','closed')),
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

CREATE INDEX IF NOT EXISTS max_live_canary_native_dns_receipts_run_idx ON max_live_canary_native_dns_receipts(run_id, executed_at, receipt_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_approvals_run_idx ON max_live_canary_native_approvals(run_id, created_at, approval_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_approval_revocations_run_idx ON max_live_canary_native_approval_revocations(run_id, created_at, revocation_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_jit_authorities_run_idx ON max_live_canary_native_jit_authorities(run_id, created_at, authority_id);
CREATE INDEX IF NOT EXISTS max_live_canary_native_jit_events_run_idx ON max_live_canary_native_jit_events(run_id, authority_id, sequence_no);

CREATE TRIGGER IF NOT EXISTS max_live_canary_native_dns_receipts_no_update BEFORE UPDATE ON max_live_canary_native_dns_receipts BEGIN SELECT RAISE(ABORT, 'native DNS receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_dns_receipts_no_delete BEFORE DELETE ON max_live_canary_native_dns_receipts BEGIN SELECT RAISE(ABORT, 'native DNS receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approvals_no_update BEFORE UPDATE ON max_live_canary_native_approvals BEGIN SELECT RAISE(ABORT, 'native approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approvals_no_delete BEFORE DELETE ON max_live_canary_native_approvals BEGIN SELECT RAISE(ABORT, 'native approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approval_consumptions_no_update BEFORE UPDATE ON max_live_canary_native_approval_consumptions BEGIN SELECT RAISE(ABORT, 'native approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approval_consumptions_no_delete BEFORE DELETE ON max_live_canary_native_approval_consumptions BEGIN SELECT RAISE(ABORT, 'native approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approval_revocations_no_update BEFORE UPDATE ON max_live_canary_native_approval_revocations BEGIN SELECT RAISE(ABORT, 'native approval revocations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approval_revocations_no_delete BEFORE DELETE ON max_live_canary_native_approval_revocations BEGIN SELECT RAISE(ABORT, 'native approval revocations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_jit_authorities_no_update BEFORE UPDATE ON max_live_canary_native_jit_authorities BEGIN SELECT RAISE(ABORT, 'native JIT authorities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_jit_authorities_no_delete BEFORE DELETE ON max_live_canary_native_jit_authorities BEGIN SELECT RAISE(ABORT, 'native JIT authorities are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_jit_events_no_update BEFORE UPDATE ON max_live_canary_native_jit_events BEGIN SELECT RAISE(ABORT, 'native JIT events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_jit_events_no_delete BEFORE DELETE ON max_live_canary_native_jit_events BEGIN SELECT RAISE(ABORT, 'native JIT events are append-only'); END;
