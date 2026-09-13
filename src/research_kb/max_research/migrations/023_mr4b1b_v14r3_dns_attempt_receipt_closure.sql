-- MR-4B1B-v14R3: durable DNS attempt and receipt closure.
--
-- A resolver is an external side effect.  The attempt intent, the two
-- authority consumptions, and resolver_started are committed before the
-- resolver boundary.  The bounded receipt is appended in a second
-- transaction.  No table in this migration stores an address value.

CREATE TABLE IF NOT EXISTS max_live_canary_dns_attempts(
    attempt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_preparation_dns_requests(request_id) ON DELETE RESTRICT,
    authority_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_authorities(authority_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    handoff_id TEXT NOT NULL REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    handoff_hash TEXT NOT NULL CHECK(length(handoff_hash)=64),
    request_hash TEXT NOT NULL UNIQUE CHECK(length(request_hash)=64),
    authority_hash TEXT NOT NULL CHECK(length(authority_hash)=64),
    endpoint_scheme TEXT NOT NULL CHECK(endpoint_scheme='https'),
    endpoint_hostname TEXT NOT NULL CHECK(endpoint_hostname='opencode.ai'),
    endpoint_port INTEGER NOT NULL CHECK(endpoint_port=443),
    source_binding_hash TEXT NOT NULL CHECK(length(source_binding_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    confirmation_phrase_hash TEXT NOT NULL CHECK(length(confirmation_phrase_hash)=64),
    max_getaddrinfo_calls INTEGER NOT NULL CHECK(max_getaddrinfo_calls=1),
    max_dns_candidates INTEGER NOT NULL CHECK(max_dns_candidates > 0 AND max_dns_candidates <= 16),
    credential_reads INTEGER NOT NULL CHECK(credential_reads=0),
    tcp_connections INTEGER NOT NULL CHECK(tcp_connections=0),
    tls_https_calls INTEGER NOT NULL CHECK(tls_https_calls=0),
    provider_calls INTEGER NOT NULL CHECK(provider_calls=0),
    cost_units INTEGER NOT NULL CHECK(cost_units=0),
    state TEXT NOT NULL CHECK(state='resolver_started'),
    attempt_json TEXT NOT NULL,
    attempt_hash TEXT NOT NULL UNIQUE CHECK(length(attempt_hash)=64),
    started_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_dns_attempt_consumptions(
    consumption_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES max_live_canary_dns_attempts(attempt_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_requests(request_id) ON DELETE RESTRICT,
    authority_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_authorities(authority_id) ON DELETE RESTRICT,
    consumption_type TEXT NOT NULL CHECK(consumption_type IN ('authority','request')),
    binding_hash TEXT NOT NULL CHECK(length(binding_hash)=64),
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE CHECK(length(consumption_hash)=64),
    consumed_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(request_id, consumption_type),
    UNIQUE(attempt_id, consumption_type)
);

CREATE TABLE IF NOT EXISTS max_live_canary_dns_attempt_events(
    event_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES max_live_canary_dns_attempts(attempt_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_requests(request_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    state TEXT NOT NULL CHECK(state IN ('resolver_started','resolver_returned','receipt_committed','DNS_PREFLIGHT_PASSED','FAILED_WITH_BOUNDED_RESULT','KNOWN_PRE_RESOLVER_FAILURE','UNKNOWN_AFTER_RESOLVER_START')),
    failure_stage TEXT NOT NULL CHECK(failure_stage IN ('preflight_validation','attempt_claim','resolver_started','resolver_call','result_normalization','receipt_transaction','receipt_committed')),
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(attempt_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_live_canary_dns_attempt_current(
    attempt_id TEXT PRIMARY KEY REFERENCES max_live_canary_dns_attempts(attempt_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_preparation_dns_requests(request_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('resolver_started','resolver_returned','receipt_committed','DNS_PREFLIGHT_PASSED','FAILED_WITH_BOUNDED_RESULT','KNOWN_PRE_RESOLVER_FAILURE','UNKNOWN_AFTER_RESOLVER_START')),
    current_event_sequence INTEGER NOT NULL CHECK(current_event_sequence > 0),
    current_event_hash TEXT NOT NULL CHECK(length(current_event_hash)=64),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_dns_attempt_receipts(
    receipt_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_dns_attempts(attempt_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_preparation_dns_requests(request_id) ON DELETE RESTRICT,
    authority_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_authorities(authority_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    handoff_id TEXT NOT NULL REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    handoff_hash TEXT NOT NULL CHECK(length(handoff_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    authority_hash TEXT NOT NULL CHECK(length(authority_hash)=64),
    endpoint_scheme TEXT NOT NULL CHECK(endpoint_scheme='https'),
    endpoint_hostname TEXT NOT NULL CHECK(endpoint_hostname='opencode.ai'),
    endpoint_port INTEGER NOT NULL CHECK(endpoint_port=443),
    max_getaddrinfo_calls INTEGER NOT NULL CHECK(max_getaddrinfo_calls=1),
    getaddrinfo_attempts INTEGER NOT NULL CHECK(getaddrinfo_attempts=1),
    max_dns_candidates INTEGER NOT NULL CHECK(max_dns_candidates > 0 AND max_dns_candidates <= 16),
    candidate_count INTEGER NOT NULL CHECK(candidate_count >= 0 AND candidate_count <= 2000000000),
    ipv4_count INTEGER NOT NULL CHECK(ipv4_count >= 0 AND ipv4_count <= 2000000000),
    ipv6_count INTEGER NOT NULL CHECK(ipv6_count >= 0 AND ipv6_count <= 2000000000),
    all_global INTEGER NOT NULL CHECK(all_global IN (0,1)),
    ssrf_safe INTEGER NOT NULL CHECK(ssrf_safe IN (0,1)),
    cap_satisfied INTEGER NOT NULL CHECK(cap_satisfied IN (0,1)),
    retry_count INTEGER NOT NULL CHECK(retry_count=0),
    credential_reads INTEGER NOT NULL CHECK(credential_reads=0),
    tcp_connections INTEGER NOT NULL CHECK(tcp_connections=0),
    tls_https_calls INTEGER NOT NULL CHECK(tls_https_calls=0),
    provider_calls INTEGER NOT NULL CHECK(provider_calls=0),
    cost_units INTEGER NOT NULL CHECK(cost_units=0),
    status TEXT NOT NULL CHECK(status IN ('passed','failed','unknown')),
    error_code TEXT,
    failure_stage TEXT NOT NULL CHECK(failure_stage IN ('preflight_validation','attempt_claim','resolver_started','resolver_call','result_normalization','receipt_transaction','receipt_committed')),
    bounded_result_hash TEXT CHECK(bounded_result_hash IS NULL OR length(bounded_result_hash)=64),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK(length(receipt_hash)=64),
    executed_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_live_canary_dns_attempts_run_idx
    ON max_live_canary_dns_attempts(run_id, started_at, attempt_id);
CREATE INDEX IF NOT EXISTS max_live_canary_dns_attempt_consumptions_run_idx
    ON max_live_canary_dns_attempt_consumptions(attempt_id, consumed_at, consumption_type);
CREATE INDEX IF NOT EXISTS max_live_canary_dns_attempt_events_run_idx
    ON max_live_canary_dns_attempt_events(run_id, attempt_id, sequence_no);
CREATE INDEX IF NOT EXISTS max_live_canary_dns_attempt_receipts_run_idx
    ON max_live_canary_dns_attempt_receipts(run_id, executed_at, receipt_id);

CREATE TRIGGER IF NOT EXISTS max_live_canary_dns_attempts_no_update
BEFORE UPDATE ON max_live_canary_dns_attempts
BEGIN SELECT RAISE(ABORT, 'DNS attempts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_dns_attempts_no_delete
BEFORE DELETE ON max_live_canary_dns_attempts
BEGIN SELECT RAISE(ABORT, 'DNS attempts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_dns_attempt_consumptions_no_update
BEFORE UPDATE ON max_live_canary_dns_attempt_consumptions
BEGIN SELECT RAISE(ABORT, 'DNS attempt consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_dns_attempt_consumptions_no_delete
BEFORE DELETE ON max_live_canary_dns_attempt_consumptions
BEGIN SELECT RAISE(ABORT, 'DNS attempt consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_dns_attempt_events_no_update
BEFORE UPDATE ON max_live_canary_dns_attempt_events
BEGIN SELECT RAISE(ABORT, 'DNS attempt events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_dns_attempt_events_no_delete
BEFORE DELETE ON max_live_canary_dns_attempt_events
BEGIN SELECT RAISE(ABORT, 'DNS attempt events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_dns_attempt_receipts_no_update
BEFORE UPDATE ON max_live_canary_dns_attempt_receipts
BEGIN SELECT RAISE(ABORT, 'DNS attempt receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_dns_attempt_receipts_no_delete
BEFORE DELETE ON max_live_canary_dns_attempt_receipts
BEGIN SELECT RAISE(ABORT, 'DNS attempt receipts are append-only'); END;
