-- MR-PORTABILITY-0: explicit Agent Host / Execution Backend portability.
--
-- Every history table in this migration is append-only.  The two *_current
-- tables are deliberately small projections: they may move forward, but a
-- historical profile, binding, approval, event, or normalized result can
-- never be rewritten or deleted.  No credential value is represented here.

CREATE TABLE IF NOT EXISTS max_agent_host_profiles(
    host_profile_id TEXT PRIMARY KEY,
    host_kind TEXT NOT NULL CHECK(host_kind IN ('codex','luna','qoder','hermes','generic_cli_agent')),
    host_version TEXT NOT NULL,
    control_surface TEXT NOT NULL,
    capability_manifest_hash TEXT NOT NULL CHECK(length(capability_manifest_hash)=64),
    canonical_skill_hash TEXT NOT NULL CHECK(length(canonical_skill_hash)=64),
    adapter_hash TEXT NOT NULL CHECK(length(adapter_hash)=64),
    allowed_operations_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','disabled','revoked')),
    created_at TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    profile_hash TEXT NOT NULL UNIQUE CHECK(length(profile_hash)=64),
    UNIQUE(host_kind, host_version, profile_hash)
);

CREATE TABLE IF NOT EXISTS max_execution_backend_profiles(
    backend_profile_id TEXT PRIMARY KEY,
    backend_kind TEXT NOT NULL CHECK(backend_kind IN ('openai_compatible_http','openai_responses_http','local_agent_cli','hermetic_fixture')),
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    invocation_contract_version TEXT NOT NULL,
    capability_manifest_json TEXT NOT NULL,
    capability_manifest_hash TEXT NOT NULL CHECK(length(capability_manifest_hash)=64),
    credential_strategy_json TEXT NOT NULL,
    usage_authority_strategy_json TEXT NOT NULL,
    idempotency_strategy_json TEXT NOT NULL,
    recovery_strategy_json TEXT NOT NULL,
    network_policy_requirement_json TEXT NOT NULL,
    source_egress_requirement_json TEXT NOT NULL,
    pricing_policy_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','disabled','revoked')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    profile_hash TEXT NOT NULL UNIQUE CHECK(length(profile_hash)=64),
    UNIQUE(backend_kind, provider_name, model_identity, profile_hash)
);

CREATE TABLE IF NOT EXISTS max_run_execution_bindings(
    binding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    host_profile_id TEXT NOT NULL REFERENCES max_agent_host_profiles(host_profile_id) ON DELETE RESTRICT,
    backend_profile_id TEXT NOT NULL REFERENCES max_execution_backend_profiles(backend_profile_id) ON DELETE RESTRICT,
    backend_profile_hash TEXT NOT NULL CHECK(length(backend_profile_hash)=64),
    capability_manifest_hash TEXT NOT NULL CHECK(length(capability_manifest_hash)=64),
    model_identity TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    binding_version INTEGER NOT NULL CHECK(binding_version >= 1),
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL UNIQUE CHECK(length(binding_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, binding_version)
);

CREATE TABLE IF NOT EXISTS max_run_execution_binding_current(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    binding_id TEXT NOT NULL UNIQUE REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    host_profile_id TEXT NOT NULL REFERENCES max_agent_host_profiles(host_profile_id) ON DELETE RESTRICT,
    backend_profile_id TEXT NOT NULL REFERENCES max_execution_backend_profiles(backend_profile_id) ON DELETE RESTRICT,
    backend_profile_hash TEXT NOT NULL CHECK(length(backend_profile_hash)=64),
    binding_version INTEGER NOT NULL CHECK(binding_version >= 1),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_backend_handoff_approvals(
    handoff_approval_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    old_binding_id TEXT REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    old_host_profile_id TEXT REFERENCES max_agent_host_profiles(host_profile_id) ON DELETE RESTRICT,
    old_backend_profile_id TEXT REFERENCES max_execution_backend_profiles(backend_profile_id) ON DELETE RESTRICT,
    old_backend_profile_hash TEXT CHECK(old_backend_profile_hash IS NULL OR length(old_backend_profile_hash)=64),
    new_host_profile_id TEXT NOT NULL REFERENCES max_agent_host_profiles(host_profile_id) ON DELETE RESTRICT,
    new_backend_profile_id TEXT NOT NULL REFERENCES max_execution_backend_profiles(backend_profile_id) ON DELETE RESTRICT,
    new_backend_profile_hash TEXT NOT NULL CHECK(length(new_backend_profile_hash)=64),
    current_research_state_hash TEXT NOT NULL CHECK(length(current_research_state_hash)=64),
    current_checkpoint_id TEXT,
    reason_hash TEXT NOT NULL CHECK(length(reason_hash)=64),
    confirmation_phrase_hash TEXT NOT NULL CHECK(length(confirmation_phrase_hash)=64),
    state TEXT NOT NULL CHECK(state='PENDING'),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    handoff_json TEXT NOT NULL,
    handoff_hash TEXT NOT NULL UNIQUE CHECK(length(handoff_hash)=64),
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_backend_handoff_current(
    run_id TEXT PRIMARY KEY REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    handoff_approval_id TEXT NOT NULL UNIQUE REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('PENDING','CONSUMED','REJECTED','EXPIRED')),
    binding_id TEXT REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_backend_handoff_events(
    event_id TEXT PRIMARY KEY,
    handoff_approval_id TEXT NOT NULL REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL CHECK(event_type IN ('created','approved','consumed','rejected','expired')),
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(handoff_approval_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_portability_events(
    event_id TEXT PRIMARY KEY,
    stream_key TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(stream_key, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_normalized_agent_results(
    result_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    binding_id TEXT NOT NULL REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL UNIQUE CHECK(length(result_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_run_execution_bindings_run_idx
    ON max_run_execution_bindings(run_id, binding_version, created_at, binding_id);
CREATE INDEX IF NOT EXISTS max_run_execution_bindings_backend_idx
    ON max_run_execution_bindings(backend_profile_id, run_id, binding_id);
CREATE INDEX IF NOT EXISTS max_backend_handoff_approvals_run_idx
    ON max_backend_handoff_approvals(run_id, created_at, handoff_approval_id);
CREATE INDEX IF NOT EXISTS max_backend_handoff_events_run_idx
    ON max_backend_handoff_events(run_id, created_at, handoff_approval_id);
CREATE INDEX IF NOT EXISTS max_portability_events_stream_idx
    ON max_portability_events(stream_key, sequence_no, created_at);
CREATE INDEX IF NOT EXISTS max_normalized_agent_results_run_idx
    ON max_normalized_agent_results(run_id, created_at, result_id);

CREATE TRIGGER IF NOT EXISTS max_agent_host_profiles_no_update
BEFORE UPDATE ON max_agent_host_profiles BEGIN
    SELECT RAISE(ABORT, 'Max Agent Host profiles are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_agent_host_profiles_no_delete
BEFORE DELETE ON max_agent_host_profiles BEGIN
    SELECT RAISE(ABORT, 'Max Agent Host profiles are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_execution_backend_profiles_no_update
BEFORE UPDATE ON max_execution_backend_profiles BEGIN
    SELECT RAISE(ABORT, 'Max Execution Backend profiles are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_execution_backend_profiles_no_delete
BEFORE DELETE ON max_execution_backend_profiles BEGIN
    SELECT RAISE(ABORT, 'Max Execution Backend profiles are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_run_execution_bindings_no_update
BEFORE UPDATE ON max_run_execution_bindings BEGIN
    SELECT RAISE(ABORT, 'Run Execution bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_run_execution_bindings_no_delete
BEFORE DELETE ON max_run_execution_bindings BEGIN
    SELECT RAISE(ABORT, 'Run Execution bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_backend_handoff_approvals_no_update
BEFORE UPDATE ON max_backend_handoff_approvals BEGIN
    SELECT RAISE(ABORT, 'Backend handoff approvals are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_backend_handoff_approvals_no_delete
BEFORE DELETE ON max_backend_handoff_approvals BEGIN
    SELECT RAISE(ABORT, 'Backend handoff approvals are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_backend_handoff_events_no_update
BEFORE UPDATE ON max_backend_handoff_events BEGIN
    SELECT RAISE(ABORT, 'Backend handoff events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_backend_handoff_events_no_delete
BEFORE DELETE ON max_backend_handoff_events BEGIN
    SELECT RAISE(ABORT, 'Backend handoff events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_portability_events_no_update
BEFORE UPDATE ON max_portability_events BEGIN
    SELECT RAISE(ABORT, 'Portability events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_portability_events_no_delete
BEFORE DELETE ON max_portability_events BEGIN
    SELECT RAISE(ABORT, 'Portability events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_normalized_agent_results_no_update
BEFORE UPDATE ON max_normalized_agent_results BEGIN
    SELECT RAISE(ABORT, 'Normalized Agent Results are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_normalized_agent_results_no_delete
BEFORE DELETE ON max_normalized_agent_results BEGIN
    SELECT RAISE(ABORT, 'Normalized Agent Results are append-only');
END;
