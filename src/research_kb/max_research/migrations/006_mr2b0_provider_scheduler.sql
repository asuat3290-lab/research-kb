-- MR-2B0: provider profiles, usage attestations, live grants and bounded
-- foreground scheduler state.  Core schema and Max migrations 001-005 are
-- intentionally independent and unchanged.

CREATE TABLE IF NOT EXISTS max_provider_pricing_snapshots(
    pricing_hash TEXT PRIMARY KEY,
    pricing_id TEXT NOT NULL,
    pricing_version TEXT NOT NULL,
    pricing_json TEXT NOT NULL,
    currency TEXT NOT NULL,
    source_label TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(pricing_id, pricing_version)
);

CREATE TABLE IF NOT EXISTS max_provider_profiles(
    profile_hash TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    protocol TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    endpoint_origin TEXT NOT NULL,
    endpoint_path_policy TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    inference_defaults_json TEXT NOT NULL,
    timeout_policy_json TEXT NOT NULL,
    retry_policy_json TEXT NOT NULL,
    request_limits_json TEXT NOT NULL,
    rate_policy_json TEXT NOT NULL,
    credential_ref_json TEXT NOT NULL,
    network_policy_hash TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    profile_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(profile_id, profile_version)
);

CREATE TABLE IF NOT EXISTS max_run_provider_bindings(
    binding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    model_identity TEXT NOT NULL,
    network_policy_hash TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    charter_hash TEXT NOT NULL,
    budget_hash TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_execution_grants(
    grant_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    charter_hash TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    network_policy_hash TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    budget_hash TEXT NOT NULL,
    caps_json TEXT NOT NULL,
    grant_json TEXT NOT NULL,
    grant_hash TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    authority_kind TEXT NOT NULL,
    authority_session TEXT NOT NULL,
    UNIQUE(run_id, grant_hash)
);

CREATE TABLE IF NOT EXISTS max_live_execution_grant_consumptions(
    consumption_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL UNIQUE REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    grant_hash TEXT NOT NULL,
    consumer_id TEXT NOT NULL,
    consumer_kind TEXT NOT NULL,
    consumer_session TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_provider_call_records(
    call_record_id TEXT PRIMARY KEY,
    provider_call_id TEXT NOT NULL,
    logical_call_id TEXT,
    intent_id TEXT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    model_identity TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    transport_status TEXT NOT NULL,
    terminal_status TEXT NOT NULL,
    usage_json TEXT NOT NULL,
    usage_hash TEXT NOT NULL,
    response_manifest_json TEXT NOT NULL,
    response_manifest_hash TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    record_json TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(profile_hash, provider_call_id),
    UNIQUE(run_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS max_provider_usage_attestations(
    attestation_id TEXT PRIMARY KEY,
    call_record_id TEXT NOT NULL UNIQUE REFERENCES max_provider_call_records(call_record_id) ON DELETE RESTRICT,
    provider_call_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    usage_json TEXT NOT NULL,
    usage_hash TEXT NOT NULL,
    cost_units INTEGER NOT NULL CHECK(cost_units >= 0),
    authority_id TEXT NOT NULL,
    attestation_json TEXT NOT NULL,
    attestation_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_scheduler_policies(
    policy_hash TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_scheduler_sessions(
    session_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    grant_id TEXT NOT NULL REFERENCES max_live_execution_grants(grant_id) ON DELETE RESTRICT,
    grant_consumption_id TEXT NOT NULL REFERENCES max_live_execution_grant_consumptions(consumption_id) ON DELETE RESTRICT,
    policy_hash TEXT NOT NULL REFERENCES max_scheduler_policies(policy_hash) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL,
    owner_kind TEXT NOT NULL,
    owner_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    status TEXT NOT NULL CHECK(status IN ('active','paused','stopped','completed','cancelled')),
    tick_count INTEGER NOT NULL CHECK(tick_count >= 0),
    started_at TEXT NOT NULL,
    stopped_at TEXT,
    stop_reason TEXT,
    session_json TEXT NOT NULL,
    session_hash TEXT NOT NULL,
    UNIQUE(run_id, session_id)
);

CREATE TABLE IF NOT EXISTS max_scheduler_current(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    session_id TEXT NOT NULL UNIQUE REFERENCES max_scheduler_sessions(session_id) ON DELETE RESTRICT,
    tick_no INTEGER NOT NULL CHECK(tick_no >= 0),
    status TEXT NOT NULL CHECK(status IN ('active','paused','stopped','completed','cancelled')),
    updated_at TEXT NOT NULL,
    pointer_json TEXT NOT NULL,
    pointer_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_scheduler_ticks(
    tick_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES max_scheduler_sessions(session_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    tick_no INTEGER NOT NULL CHECK(tick_no >= 1),
    prior_state_hash TEXT NOT NULL,
    resulting_state_hash TEXT NOT NULL,
    runner_status TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0),
    budget_delta_json TEXT NOT NULL,
    next_action TEXT NOT NULL,
    stop_reason TEXT,
    fencing_token INTEGER NOT NULL CHECK(fencing_token >= 1),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(session_id, tick_no)
);

CREATE INDEX IF NOT EXISTS max_provider_profiles_id_idx ON max_provider_profiles(profile_id, profile_version);
CREATE INDEX IF NOT EXISTS max_provider_calls_run_idx ON max_provider_call_records(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_provider_attestations_run_idx ON max_provider_usage_attestations(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_grants_run_idx ON max_live_execution_grants(run_id, granted_at);
CREATE INDEX IF NOT EXISTS max_scheduler_ticks_run_idx ON max_scheduler_ticks(run_id, tick_no);

CREATE TRIGGER IF NOT EXISTS max_provider_pricing_no_update BEFORE UPDATE ON max_provider_pricing_snapshots BEGIN SELECT RAISE(ABORT, 'Provider pricing snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_provider_pricing_no_delete BEFORE DELETE ON max_provider_pricing_snapshots BEGIN SELECT RAISE(ABORT, 'Provider pricing snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_provider_profiles_no_update BEFORE UPDATE ON max_provider_profiles BEGIN SELECT RAISE(ABORT, 'Provider profiles are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_provider_profiles_no_delete BEFORE DELETE ON max_provider_profiles BEGIN SELECT RAISE(ABORT, 'Provider profiles are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_run_provider_bindings_no_update BEFORE UPDATE ON max_run_provider_bindings BEGIN SELECT RAISE(ABORT, 'Run provider bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_run_provider_bindings_no_delete BEFORE DELETE ON max_run_provider_bindings BEGIN SELECT RAISE(ABORT, 'Run provider bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_grants_no_update BEFORE UPDATE ON max_live_execution_grants BEGIN SELECT RAISE(ABORT, 'Live execution grants are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_grants_no_delete BEFORE DELETE ON max_live_execution_grants BEGIN SELECT RAISE(ABORT, 'Live execution grants are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_consumptions_no_update BEFORE UPDATE ON max_live_execution_grant_consumptions BEGIN SELECT RAISE(ABORT, 'Live execution grant consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_consumptions_no_delete BEFORE DELETE ON max_live_execution_grant_consumptions BEGIN SELECT RAISE(ABORT, 'Live execution grant consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_provider_calls_no_update BEFORE UPDATE ON max_provider_call_records BEGIN SELECT RAISE(ABORT, 'Provider call records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_provider_calls_no_delete BEFORE DELETE ON max_provider_call_records BEGIN SELECT RAISE(ABORT, 'Provider call records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_provider_attestations_no_update BEFORE UPDATE ON max_provider_usage_attestations BEGIN SELECT RAISE(ABORT, 'Provider usage attestations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_provider_attestations_no_delete BEFORE DELETE ON max_provider_usage_attestations BEGIN SELECT RAISE(ABORT, 'Provider usage attestations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_scheduler_policies_no_update BEFORE UPDATE ON max_scheduler_policies BEGIN SELECT RAISE(ABORT, 'Scheduler policies are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_scheduler_policies_no_delete BEFORE DELETE ON max_scheduler_policies BEGIN SELECT RAISE(ABORT, 'Scheduler policies are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_scheduler_sessions_no_update BEFORE UPDATE ON max_scheduler_sessions BEGIN SELECT RAISE(ABORT, 'Scheduler sessions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_scheduler_sessions_no_delete BEFORE DELETE ON max_scheduler_sessions BEGIN SELECT RAISE(ABORT, 'Scheduler sessions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_scheduler_ticks_no_update BEFORE UPDATE ON max_scheduler_ticks BEGIN SELECT RAISE(ABORT, 'Scheduler ticks are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_scheduler_ticks_no_delete BEFORE DELETE ON max_scheduler_ticks BEGIN SELECT RAISE(ABORT, 'Scheduler ticks are append-only'); END;
