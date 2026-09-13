-- MR-CONVERGENCE-DEV18: one server-owned capsule for the compact canary flow.
--
-- The capsule is a bounded, content-addressed preview.  Its history,
-- consumption and event chain are append-only; only the small current
-- projection changes at execution time.  No prompt, source text, credential
-- value, response body or raw network address is stored here.

CREATE TABLE IF NOT EXISTS max_live_execution_capsule_previews(
    capsule_id TEXT PRIMARY KEY,
    capsule_hash TEXT NOT NULL UNIQUE CHECK(length(capsule_hash)=64),
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL UNIQUE REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    charter_hash TEXT NOT NULL CHECK(length(charter_hash)=64),
    current_state_hash TEXT NOT NULL CHECK(length(current_state_hash)=64),
    current_state_version INTEGER NOT NULL CHECK(current_state_version >= 0),
    plan_id TEXT NOT NULL,
    plan_hash TEXT NOT NULL CHECK(length(plan_hash)=64),
    iteration_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preparation_preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preparation_preview_hash TEXT NOT NULL CHECK(length(preparation_preview_hash)=64),
    handoff_id TEXT NOT NULL REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    handoff_hash TEXT NOT NULL CHECK(length(handoff_hash)=64),
    dns_authority_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_authorities(authority_id) ON DELETE RESTRICT,
    dns_request_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_requests(request_id) ON DELETE RESTRICT,
    dns_request_hash TEXT NOT NULL CHECK(length(dns_request_hash)=64),
    dns_policy_hash TEXT NOT NULL CHECK(length(dns_policy_hash)=64),
    max_getaddrinfo_calls INTEGER NOT NULL CHECK(max_getaddrinfo_calls=1),
    max_dns_candidates INTEGER NOT NULL CHECK(max_dns_candidates >= 1 AND max_dns_candidates <= 16),
    policy_binding_id TEXT NOT NULL REFERENCES max_live_network_policy_bindings(binding_id) ON DELETE RESTRICT,
    network_policy_hash TEXT NOT NULL REFERENCES max_live_network_policies(network_policy_hash) ON DELETE RESTRICT,
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    provider_profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    wheel_hash TEXT NOT NULL CHECK(length(wheel_hash)=64),
    source_tree_hash TEXT NOT NULL CHECK(length(source_tree_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    source_binding_hash TEXT NOT NULL CHECK(length(source_binding_hash)=64),
    source_document_id TEXT NOT NULL,
    source_passage_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    human_cost_ceiling INTEGER NOT NULL CHECK(human_cost_ceiling >= 0),
    profile_worst_case_cost INTEGER NOT NULL CHECK(profile_worst_case_cost >= 0),
    effective_cost_cap INTEGER NOT NULL CHECK(effective_cost_cap >= 0 AND effective_cost_cap <= 729),
    max_provider_calls INTEGER NOT NULL CHECK(max_provider_calls=1),
    max_input_tokens INTEGER NOT NULL CHECK(max_input_tokens >= 0),
    max_output_tokens INTEGER NOT NULL CHECK(max_output_tokens >= 0),
    max_cache_read_tokens INTEGER NOT NULL CHECK(max_cache_read_tokens >= 0),
    max_reasoning_tokens INTEGER NOT NULL CHECK(max_reasoning_tokens >= 0),
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state='AWAITING_EXECUTION'),
    confirmation_phrase_hash TEXT NOT NULL CHECK(length(confirmation_phrase_hash)=64),
    capsule_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_execution_capsule_current(
    capsule_id TEXT PRIMARY KEY REFERENCES max_live_execution_capsule_previews(capsule_id) ON DELETE RESTRICT,
    capsule_hash TEXT NOT NULL CHECK(length(capsule_hash)=64),
    state TEXT NOT NULL CHECK(state IN ('AWAITING_EXECUTION','EXECUTING','SUCCEEDED','KNOWN_PRE_SEND_FAILURE','KNOWN_PROVIDER_FAILURE','UNKNOWN_AFTER_SEND')),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    consumed_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_execution_capsule_consumptions(
    consumption_id TEXT PRIMARY KEY,
    capsule_id TEXT NOT NULL UNIQUE REFERENCES max_live_execution_capsule_previews(capsule_id) ON DELETE RESTRICT,
    capsule_hash TEXT NOT NULL CHECK(length(capsule_hash)=64),
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    consumed_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE CHECK(length(consumption_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_live_execution_capsule_events(
    event_id TEXT PRIMARY KEY,
    capsule_id TEXT NOT NULL REFERENCES max_live_execution_capsule_previews(capsule_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    event_type TEXT NOT NULL CHECK(event_type IN ('created','execution_started','terminal')),
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(capsule_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_live_execution_capsule_previews_run_idx
    ON max_live_execution_capsule_previews(run_id, created_at, capsule_id);
CREATE INDEX IF NOT EXISTS max_live_execution_capsule_current_state_idx
    ON max_live_execution_capsule_current(state, updated_at, capsule_id);
CREATE INDEX IF NOT EXISTS max_live_execution_capsule_events_run_idx
    ON max_live_execution_capsule_events(run_id, capsule_id, sequence_no);

CREATE TRIGGER IF NOT EXISTS max_live_execution_capsule_previews_no_update
BEFORE UPDATE ON max_live_execution_capsule_previews BEGIN
    SELECT RAISE(ABORT, 'execution capsule previews are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_execution_capsule_previews_no_delete
BEFORE DELETE ON max_live_execution_capsule_previews BEGIN
    SELECT RAISE(ABORT, 'execution capsule previews are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_execution_capsule_consumptions_no_update
BEFORE UPDATE ON max_live_execution_capsule_consumptions BEGIN
    SELECT RAISE(ABORT, 'execution capsule consumptions are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_execution_capsule_consumptions_no_delete
BEFORE DELETE ON max_live_execution_capsule_consumptions BEGIN
    SELECT RAISE(ABORT, 'execution capsule consumptions are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_execution_capsule_events_no_update
BEFORE UPDATE ON max_live_execution_capsule_events BEGIN
    SELECT RAISE(ABORT, 'execution capsule events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_execution_capsule_events_no_delete
BEFORE DELETE ON max_live_execution_capsule_events BEGIN
    SELECT RAISE(ABORT, 'execution capsule events are append-only');
END;
