-- MR-4A1: bounded long-run authorization.  A single consumed StartApproval
-- creates one append-only window; every later provider boundary requires one
-- server-minted, one-time permit bound to the current state and lease fence.

CREATE TABLE IF NOT EXISTS max_long_run_windows(
    window_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    charter_hash TEXT NOT NULL,
    start_approval_id TEXT NOT NULL REFERENCES max_start_approvals(approval_id) ON DELETE RESTRICT,
    approval_consumption_id TEXT NOT NULL REFERENCES max_approval_consumptions(consumption_id) ON DELETE RESTRICT,
    initial_state_hash TEXT NOT NULL,
    initial_checkpoint_id TEXT REFERENCES max_checkpoints(checkpoint_id) ON DELETE RESTRICT,
    initial_state_version INTEGER NOT NULL CHECK(initial_state_version >= 1),
    provider_name TEXT NOT NULL,
    provider_profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL REFERENCES max_provider_pricing_snapshots(pricing_hash) ON DELETE RESTRICT,
    budget_hash TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL,
    source_egress_policy_hash TEXT NOT NULL,
    endpoint_origin_hash TEXT NOT NULL,
    endpoint_path_policy_hash TEXT NOT NULL,
    network_policy_hash TEXT NOT NULL,
    credential_ref_hash TEXT NOT NULL,
    runner_profile_hash TEXT NOT NULL REFERENCES max_runner_profiles(profile_hash) ON DELETE RESTRICT,
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    confirmation_hash TEXT NOT NULL UNIQUE,
    window_hash TEXT NOT NULL UNIQUE,
    previous_window_id TEXT REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    renewal_reason_hash TEXT,
    changed_fields_json TEXT NOT NULL,
    human_authority_json TEXT NOT NULL,
    max_iterations INTEGER NOT NULL CHECK(max_iterations > 0),
    max_ticks INTEGER NOT NULL CHECK(max_ticks > 0),
    max_wall_clock_seconds INTEGER NOT NULL CHECK(max_wall_clock_seconds > 0),
    max_provider_calls INTEGER NOT NULL CHECK(max_provider_calls > 0),
    max_input_tokens INTEGER NOT NULL CHECK(max_input_tokens > 0),
    max_output_tokens INTEGER NOT NULL CHECK(max_output_tokens > 0),
    max_cache_read_tokens INTEGER NOT NULL CHECK(max_cache_read_tokens >= 0),
    max_reasoning_tokens INTEGER NOT NULL CHECK(max_reasoning_tokens >= 0),
    max_cost_units INTEGER NOT NULL CHECK(max_cost_units >= 0),
    max_consecutive_failures INTEGER NOT NULL CHECK(max_consecutive_failures > 0),
    max_no_progress_iterations INTEGER NOT NULL CHECK(max_no_progress_iterations > 0),
    max_acquisition_requests INTEGER NOT NULL CHECK(max_acquisition_requests >= 0),
    max_source_packets INTEGER NOT NULL CHECK(max_source_packets > 0),
    max_source_documents INTEGER NOT NULL CHECK(max_source_documents > 0),
    max_source_passages INTEGER NOT NULL CHECK(max_source_passages > 0),
    max_source_characters INTEGER NOT NULL CHECK(max_source_characters > 0),
    max_source_tokens INTEGER NOT NULL CHECK(max_source_tokens > 0),
    rehydration_interval INTEGER NOT NULL CHECK(rehydration_interval > 0),
    attack_min_frequency INTEGER NOT NULL CHECK(attack_min_frequency > 0),
    adjudication_min_frequency INTEGER NOT NULL CHECK(adjudication_min_frequency > 0),
    round_types_json TEXT NOT NULL,
    strategy_families_json TEXT NOT NULL,
    caps_json TEXT NOT NULL,
    renewal_json TEXT NOT NULL,
    created_json TEXT NOT NULL,
    window_json TEXT NOT NULL,
    CHECK(length(charter_hash)=64), CHECK(length(initial_state_hash)=64),
    CHECK(length(provider_profile_hash)=64), CHECK(length(pricing_hash)=64),
    CHECK(length(source_policy_hash)=64), CHECK(length(source_egress_policy_hash)=64),
    CHECK(length(endpoint_origin_hash)=64), CHECK(length(endpoint_path_policy_hash)=64),
    CHECK(length(network_policy_hash)=64), CHECK(length(credential_ref_hash)=64),
    CHECK(length(runner_profile_hash)=64), CHECK(length(confirmation_hash)=64),
    CHECK(length(window_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_long_run_window_current(
    window_id TEXT PRIMARY KEY REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','paused','draining','stopped','revoked','expired','exhausted','completion_candidate','acquisition_pending','failed','superseded')),
    current_state_hash TEXT NOT NULL,
    current_checkpoint_id TEXT,
    current_state_version INTEGER NOT NULL CHECK(current_state_version >= 1),
    next_iteration INTEGER NOT NULL CHECK(next_iteration >= 1),
    next_tick INTEGER NOT NULL CHECK(next_tick >= 1),
    pending_permit_id TEXT,
    pending_consumption_id TEXT,
    used_json TEXT NOT NULL,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(length(current_state_hash)=64), CHECK(length(current_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_long_run_usage(
    usage_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_no INTEGER NOT NULL CHECK(iteration_no >= 1),
    tick_no INTEGER NOT NULL CHECK(tick_no >= 1),
    wall_clock_seconds INTEGER NOT NULL CHECK(wall_clock_seconds >= 0),
    round_type TEXT NOT NULL,
    provider_calls INTEGER NOT NULL CHECK(provider_calls >= 0),
    input_tokens INTEGER NOT NULL CHECK(input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK(output_tokens >= 0),
    cache_read_tokens INTEGER NOT NULL CHECK(cache_read_tokens >= 0),
    reasoning_tokens INTEGER NOT NULL CHECK(reasoning_tokens >= 0),
    cost_units INTEGER NOT NULL CHECK(cost_units >= 0),
    failure_count INTEGER NOT NULL CHECK(failure_count >= 0),
    consecutive_failures INTEGER NOT NULL CHECK(consecutive_failures >= 0),
    no_progress_count INTEGER NOT NULL CHECK(no_progress_count >= 0),
    acquisition_requests INTEGER NOT NULL CHECK(acquisition_requests >= 0),
    source_packets INTEGER NOT NULL CHECK(source_packets >= 0),
    source_documents INTEGER NOT NULL CHECK(source_documents >= 0),
    source_passages INTEGER NOT NULL CHECK(source_passages >= 0),
    source_characters INTEGER NOT NULL CHECK(source_characters >= 0),
    source_tokens INTEGER NOT NULL CHECK(source_tokens >= 0),
    output_state_hash TEXT NOT NULL,
    output_checkpoint_id TEXT,
    output_state_version INTEGER NOT NULL CHECK(output_state_version >= 1),
    usage_json TEXT NOT NULL,
    usage_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(window_id, iteration_no),
    CHECK(length(output_state_hash)=64), CHECK(length(usage_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_long_run_iteration_permits(
    permit_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_no INTEGER NOT NULL CHECK(iteration_no >= 1),
    tick_no INTEGER NOT NULL CHECK(tick_no >= 1),
    round_type TEXT NOT NULL,
    current_state_hash TEXT NOT NULL,
    current_checkpoint_id TEXT,
    current_state_version INTEGER NOT NULL CHECK(current_state_version >= 1),
    provider_profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    runner_profile_hash TEXT NOT NULL REFERENCES max_runner_profiles(profile_hash) ON DELETE RESTRICT,
    source_egress_policy_hash TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    expires_at TEXT NOT NULL,
    permit_json TEXT NOT NULL,
    permit_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, iteration_no),
    CHECK(length(current_state_hash)=64), CHECK(length(provider_profile_hash)=64),
    CHECK(length(runner_profile_hash)=64), CHECK(length(source_egress_policy_hash)=64),
    CHECK(length(permit_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_long_run_permit_consumptions(
    consumption_id TEXT PRIMARY KEY,
    permit_id TEXT NOT NULL UNIQUE REFERENCES max_long_run_iteration_permits(permit_id) ON DELETE RESTRICT,
    window_id TEXT NOT NULL REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    iteration_no INTEGER NOT NULL CHECK(iteration_no >= 1),
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE,
    CHECK(length(consumption_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_long_run_events(
    event_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(window_id, sequence_no),
    CHECK(length(payload_hash)=64), CHECK(length(event_hash)=64)
);

CREATE INDEX IF NOT EXISTS max_long_run_windows_run_idx ON max_long_run_windows(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_long_run_usage_run_idx ON max_long_run_usage(run_id, iteration_no);
CREATE INDEX IF NOT EXISTS max_long_run_permits_run_idx ON max_long_run_iteration_permits(run_id, iteration_no);
CREATE INDEX IF NOT EXISTS max_long_run_events_run_idx ON max_long_run_events(run_id, sequence_no);

CREATE TRIGGER IF NOT EXISTS max_long_run_windows_no_update BEFORE UPDATE ON max_long_run_windows BEGIN SELECT RAISE(ABORT, 'Max long-run windows are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_windows_no_delete BEFORE DELETE ON max_long_run_windows BEGIN SELECT RAISE(ABORT, 'Max long-run windows are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_usage_no_update BEFORE UPDATE ON max_long_run_usage BEGIN SELECT RAISE(ABORT, 'Max long-run usage is append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_usage_no_delete BEFORE DELETE ON max_long_run_usage BEGIN SELECT RAISE(ABORT, 'Max long-run usage is append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_iteration_permits_no_update BEFORE UPDATE ON max_long_run_iteration_permits BEGIN SELECT RAISE(ABORT, 'Max long-run permits are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_iteration_permits_no_delete BEFORE DELETE ON max_long_run_iteration_permits BEGIN SELECT RAISE(ABORT, 'Max long-run permits are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_permit_consumptions_no_update BEFORE UPDATE ON max_long_run_permit_consumptions BEGIN SELECT RAISE(ABORT, 'Max long-run permit consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_permit_consumptions_no_delete BEFORE DELETE ON max_long_run_permit_consumptions BEGIN SELECT RAISE(ABORT, 'Max long-run permit consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_events_no_update BEFORE UPDATE ON max_long_run_events BEGIN SELECT RAISE(ABORT, 'Max long-run events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_long_run_events_no_delete BEFORE DELETE ON max_long_run_events BEGIN SELECT RAISE(ABORT, 'Max long-run events are append-only'); END;
