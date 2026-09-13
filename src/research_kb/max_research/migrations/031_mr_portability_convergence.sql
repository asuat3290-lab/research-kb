-- MR-PORTABILITY-0R2: server-owned portability convergence.
-- Migration 030 remains byte-for-byte frozen.  These tables are additive;
-- they carry the proof material that was previously represented only by
-- caller-supplied identifiers or aggregate counts.

CREATE TABLE IF NOT EXISTS max_portability_quiescence_snapshots(
    snapshot_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    handoff_approval_id TEXT REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    phase TEXT NOT NULL CHECK(phase IN ('preview','approval_consume')),
    state_version INTEGER NOT NULL CHECK(state_version >= 1),
    state_hash TEXT NOT NULL CHECK(length(state_hash)=64),
    checkpoint_id TEXT,
    binding_id TEXT REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    activity_json TEXT NOT NULL,
    activity_hash TEXT NOT NULL CHECK(length(activity_hash)=64),
    snapshot_json TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL UNIQUE CHECK(length(snapshot_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_portability_quiescence_snapshots_run_idx
    ON max_portability_quiescence_snapshots(run_id, phase, created_at, snapshot_id);

CREATE TABLE IF NOT EXISTS max_rehydration_packet_manifest_items(
    manifest_item_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES max_rehydration_packets(packet_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    item_type TEXT NOT NULL,
    item_id TEXT NOT NULL,
    item_hash TEXT NOT NULL CHECK(length(item_hash)=64),
    item_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(packet_id, ordinal),
    UNIQUE(packet_id, item_type, item_id)
);

CREATE INDEX IF NOT EXISTS max_rehydration_packet_manifest_items_page_idx
    ON max_rehydration_packet_manifest_items(packet_id, ordinal, manifest_item_id);

CREATE TABLE IF NOT EXISTS max_rehydration_packet_target_acks(
    target_ack_id TEXT PRIMARY KEY,
    ack_id TEXT NOT NULL UNIQUE REFERENCES max_rehydration_packet_acks(ack_id) ON DELETE RESTRICT,
    packet_id TEXT NOT NULL UNIQUE REFERENCES max_rehydration_packets(packet_id) ON DELETE RESTRICT,
    handoff_approval_id TEXT NOT NULL REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    new_binding_id TEXT NOT NULL REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    target_host_profile_id TEXT NOT NULL REFERENCES max_agent_host_profiles(host_profile_id) ON DELETE RESTRICT,
    target_installation_id TEXT NOT NULL,
    target_installation_hash TEXT NOT NULL CHECK(length(target_installation_hash)=64),
    adapter_capability_hash TEXT NOT NULL CHECK(length(adapter_capability_hash)=64),
    target_session TEXT NOT NULL,
    observed_checkpoint_hash TEXT NOT NULL CHECK(length(observed_checkpoint_hash)=64),
    observed_state_hash TEXT NOT NULL CHECK(length(observed_state_hash)=64),
    rehydrated_state_hash TEXT NOT NULL CHECK(length(rehydrated_state_hash)=64),
    manifest_root TEXT NOT NULL CHECK(length(manifest_root)=64),
    manifest_count INTEGER NOT NULL CHECK(manifest_count >= 0),
    read_complete INTEGER NOT NULL CHECK(read_complete IN (0,1)),
    fixture_only INTEGER NOT NULL DEFAULT 0 CHECK(fixture_only IN (0,1)),
    ack_json TEXT NOT NULL,
    ack_hash TEXT NOT NULL UNIQUE CHECK(length(ack_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_rehydration_packet_target_acks_run_idx
    ON max_rehydration_packet_target_acks(run_id, packet_id, created_at);

CREATE TABLE IF NOT EXISTS max_portability_invocation_bindings(
    invocation_binding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    binding_id TEXT NOT NULL REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    iteration_id TEXT REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    group_id TEXT REFERENCES max_runner_call_groups(group_id) ON DELETE RESTRICT,
    intent_id TEXT REFERENCES max_model_call_intents(intent_id) ON DELETE RESTRICT,
    invocation_id TEXT NOT NULL,
    invocation_hash TEXT NOT NULL CHECK(length(invocation_hash)=64),
    intent_hash TEXT,
    manifest_hash TEXT,
    input_state_hash TEXT NOT NULL CHECK(length(input_state_hash)=64),
    checkpoint_id TEXT,
    state_version INTEGER NOT NULL CHECK(state_version >= 1),
    source_kind TEXT NOT NULL CHECK(source_kind IN ('server_runner','fixture_compat')),
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL UNIQUE CHECK(length(binding_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, binding_id, invocation_id)
);

CREATE INDEX IF NOT EXISTS max_portability_invocation_bindings_run_idx
    ON max_portability_invocation_bindings(run_id, binding_id, created_at, invocation_binding_id);

CREATE TABLE IF NOT EXISTS max_portability_result_bindings(
    result_id TEXT PRIMARY KEY REFERENCES max_normalized_agent_results_v2(result_id) ON DELETE RESTRICT,
    invocation_binding_id TEXT NOT NULL REFERENCES max_portability_invocation_bindings(invocation_binding_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    result_hash TEXT NOT NULL CHECK(length(result_hash)=64),
    attribution_hash TEXT NOT NULL CHECK(length(attribution_hash)=64),
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL UNIQUE CHECK(length(binding_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_portability_result_bindings_run_idx
    ON max_portability_result_bindings(run_id, invocation_binding_id, created_at);

CREATE TABLE IF NOT EXISTS max_host_installation_attestations(
    attestation_id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL UNIQUE REFERENCES max_host_installations(installation_id) ON DELETE RESTRICT,
    host_profile_id TEXT NOT NULL REFERENCES max_agent_host_profiles(host_profile_id) ON DELETE RESTRICT,
    attestation_kind TEXT NOT NULL CHECK(attestation_kind IN ('admin_declared','trusted_local_verifier')),
    verifier_authority TEXT NOT NULL,
    executable_proof INTEGER NOT NULL CHECK(executable_proof IN (0,1)),
    attestation_json TEXT NOT NULL,
    attestation_hash TEXT NOT NULL UNIQUE CHECK(length(attestation_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_host_installation_attestations_host_idx
    ON max_host_installation_attestations(host_profile_id, installation_id, created_at);

CREATE TRIGGER IF NOT EXISTS max_portability_quiescence_snapshots_no_update
BEFORE UPDATE ON max_portability_quiescence_snapshots BEGIN SELECT RAISE(ABORT, 'Portability quiescence snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_portability_quiescence_snapshots_no_delete
BEFORE DELETE ON max_portability_quiescence_snapshots BEGIN SELECT RAISE(ABORT, 'Portability quiescence snapshots are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packet_manifest_items_no_update
BEFORE UPDATE ON max_rehydration_packet_manifest_items BEGIN SELECT RAISE(ABORT, 'Rehydration manifest items are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packet_manifest_items_no_delete
BEFORE DELETE ON max_rehydration_packet_manifest_items BEGIN SELECT RAISE(ABORT, 'Rehydration manifest items are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packet_target_acks_no_update
BEFORE UPDATE ON max_rehydration_packet_target_acks BEGIN SELECT RAISE(ABORT, 'Rehydration target acknowledgements are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packet_target_acks_no_delete
BEFORE DELETE ON max_rehydration_packet_target_acks BEGIN SELECT RAISE(ABORT, 'Rehydration target acknowledgements are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_portability_invocation_bindings_no_update
BEFORE UPDATE ON max_portability_invocation_bindings BEGIN SELECT RAISE(ABORT, 'Portability invocation bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_portability_invocation_bindings_no_delete
BEFORE DELETE ON max_portability_invocation_bindings BEGIN SELECT RAISE(ABORT, 'Portability invocation bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_portability_result_bindings_no_update
BEFORE UPDATE ON max_portability_result_bindings BEGIN SELECT RAISE(ABORT, 'Portability result bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_portability_result_bindings_no_delete
BEFORE DELETE ON max_portability_result_bindings BEGIN SELECT RAISE(ABORT, 'Portability result bindings are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_host_installation_attestations_no_update
BEFORE UPDATE ON max_host_installation_attestations BEGIN SELECT RAISE(ABORT, 'Host installation attestations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_host_installation_attestations_no_delete
BEFORE DELETE ON max_host_installation_attestations BEGIN SELECT RAISE(ABORT, 'Host installation attestations are append-only'); END;
