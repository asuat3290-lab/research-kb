-- MR-PORTABILITY-0R: append-only portability correction.
-- Migration 029 remains byte-for-byte frozen.  These tables are additive so
-- historical portability rows never need to be rewritten or deleted.

CREATE TABLE IF NOT EXISTS max_normalized_agent_results_v2(
    result_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    binding_id TEXT NOT NULL REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    input_state_hash TEXT NOT NULL CHECK(length(input_state_hash)=64),
    checkpoint_id TEXT,
    input_research_state_hash TEXT NOT NULL CHECK(length(input_research_state_hash)=64),
    invocation_hash TEXT NOT NULL CHECK(length(invocation_hash)=64),
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL CHECK(length(result_hash)=64),
    attribution_hash TEXT NOT NULL CHECK(length(attribution_hash)=64),
    result_size_bytes INTEGER NOT NULL CHECK(result_size_bytes >= 0),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, binding_id, iteration_id, invocation_id, intent_id)
);

CREATE INDEX IF NOT EXISTS max_normalized_agent_results_v2_run_idx
    ON max_normalized_agent_results_v2(run_id, created_at, result_id);
CREATE INDEX IF NOT EXISTS max_normalized_agent_results_v2_invocation_idx
    ON max_normalized_agent_results_v2(invocation_hash, run_id, binding_id);

CREATE TABLE IF NOT EXISTS max_backend_handoff_lineage(
    handoff_approval_id TEXT PRIMARY KEY REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    supersedes_handoff_approval_id TEXT REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    supersedes_handoff_hash TEXT CHECK(supersedes_handoff_hash IS NULL OR length(supersedes_handoff_hash)=64),
    handoff_hash TEXT NOT NULL UNIQUE CHECK(length(handoff_hash)=64),
    state TEXT NOT NULL CHECK(state IN ('PENDING','CONSUMED','REJECTED','EXPIRED')),
    lineage_json TEXT NOT NULL,
    lineage_hash TEXT NOT NULL UNIQUE CHECK(length(lineage_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, generation)
);

CREATE INDEX IF NOT EXISTS max_backend_handoff_lineage_run_idx
    ON max_backend_handoff_lineage(run_id, generation, created_at);

CREATE TABLE IF NOT EXISTS max_rehydration_packets(
    packet_id TEXT PRIMARY KEY,
    handoff_approval_id TEXT NOT NULL REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    old_binding_id TEXT REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    new_binding_id TEXT NOT NULL REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    checkpoint_id TEXT,
    state_version INTEGER NOT NULL CHECK(state_version >= 1),
    state_hash TEXT NOT NULL CHECK(length(state_hash)=64),
    canonical_object_version_ids_json TEXT NOT NULL,
    canonical_relation_ids_json TEXT NOT NULL,
    claim_ids_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    objection_ids_json TEXT NOT NULL,
    hypothesis_ids_json TEXT NOT NULL,
    research_question_ids_json TEXT NOT NULL,
    source_role_ids_json TEXT NOT NULL,
    unresolved_frontier_ids_json TEXT NOT NULL,
    event_chain_tip_hash TEXT CHECK(event_chain_tip_hash IS NULL OR length(event_chain_tip_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    canonical_object_version INTEGER NOT NULL CHECK(canonical_object_version >= 1),
    packet_json TEXT NOT NULL,
    packet_hash TEXT NOT NULL UNIQUE CHECK(length(packet_hash)=64),
    state TEXT NOT NULL CHECK(state IN ('AWAITING_ACK','ACKNOWLEDGED','INVALID')),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_rehydration_packets_run_idx
    ON max_rehydration_packets(run_id, created_at, packet_id);

CREATE TABLE IF NOT EXISTS max_rehydration_packet_acks(
    ack_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL UNIQUE REFERENCES max_rehydration_packets(packet_id) ON DELETE RESTRICT,
    handoff_approval_id TEXT NOT NULL REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    new_binding_id TEXT NOT NULL REFERENCES max_run_execution_bindings(binding_id) ON DELETE RESTRICT,
    packet_hash TEXT NOT NULL CHECK(length(packet_hash)=64),
    ack_json TEXT NOT NULL,
    ack_hash TEXT NOT NULL UNIQUE CHECK(length(ack_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_rehydration_packet_events(
    event_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES max_rehydration_packets(packet_id) ON DELETE RESTRICT,
    handoff_approval_id TEXT NOT NULL REFERENCES max_backend_handoff_approvals(handoff_approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL CHECK(event_type IN ('created','acknowledged','invalidated')),
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(packet_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_rehydration_packet_events_run_idx
    ON max_rehydration_packet_events(run_id, packet_id, sequence_no);

CREATE TABLE IF NOT EXISTS max_portability_profile_status_events(
    status_event_id TEXT PRIMARY KEY,
    profile_kind TEXT NOT NULL CHECK(profile_kind IN ('host','backend')),
    profile_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','disabled','revoked')),
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    reason_hash TEXT NOT NULL CHECK(length(reason_hash)=64),
    status_json TEXT NOT NULL,
    status_hash TEXT NOT NULL UNIQUE CHECK(length(status_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(profile_kind, profile_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_portability_profile_status_current_idx
    ON max_portability_profile_status_events(profile_kind, profile_id, sequence_no DESC);

CREATE TABLE IF NOT EXISTS max_host_installations(
    installation_id TEXT PRIMARY KEY,
    host_profile_id TEXT NOT NULL REFERENCES max_agent_host_profiles(host_profile_id) ON DELETE RESTRICT,
    package_identity_hash TEXT NOT NULL CHECK(length(package_identity_hash)=64),
    canonical_skill_hash TEXT NOT NULL CHECK(length(canonical_skill_hash)=64),
    adapter_hash TEXT NOT NULL CHECK(length(adapter_hash)=64),
    capability_artifact_hash TEXT NOT NULL CHECK(length(capability_artifact_hash)=64),
    attestation_id TEXT NOT NULL,
    registered INTEGER NOT NULL CHECK(registered IN (0,1)),
    attested INTEGER NOT NULL CHECK(attested IN (0,1)),
    bindable INTEGER NOT NULL CHECK(bindable IN (0,1)),
    installation_json TEXT NOT NULL,
    installation_hash TEXT NOT NULL UNIQUE CHECK(length(installation_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(host_profile_id, installation_hash)
);

CREATE INDEX IF NOT EXISTS max_host_installations_host_idx
    ON max_host_installations(host_profile_id, created_at, installation_id);

CREATE TRIGGER IF NOT EXISTS max_normalized_agent_results_v2_no_update
BEFORE UPDATE ON max_normalized_agent_results_v2 BEGIN SELECT RAISE(ABORT, 'Normalized Agent Results v2 are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_normalized_agent_results_v2_no_delete
BEFORE DELETE ON max_normalized_agent_results_v2 BEGIN SELECT RAISE(ABORT, 'Normalized Agent Results v2 are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_backend_handoff_lineage_no_update
BEFORE UPDATE ON max_backend_handoff_lineage BEGIN SELECT RAISE(ABORT, 'Backend handoff lineage is append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_backend_handoff_lineage_no_delete
BEFORE DELETE ON max_backend_handoff_lineage BEGIN SELECT RAISE(ABORT, 'Backend handoff lineage is append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packets_no_update
BEFORE UPDATE ON max_rehydration_packets BEGIN SELECT RAISE(ABORT, 'Rehydration packets are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packets_no_delete
BEFORE DELETE ON max_rehydration_packets BEGIN SELECT RAISE(ABORT, 'Rehydration packets are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packet_acks_no_update
BEFORE UPDATE ON max_rehydration_packet_acks BEGIN SELECT RAISE(ABORT, 'Rehydration packet acknowledgements are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packet_acks_no_delete
BEFORE DELETE ON max_rehydration_packet_acks BEGIN SELECT RAISE(ABORT, 'Rehydration packet acknowledgements are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packet_events_no_update
BEFORE UPDATE ON max_rehydration_packet_events BEGIN SELECT RAISE(ABORT, 'Rehydration packet events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_rehydration_packet_events_no_delete
BEFORE DELETE ON max_rehydration_packet_events BEGIN SELECT RAISE(ABORT, 'Rehydration packet events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_portability_profile_status_events_no_update
BEFORE UPDATE ON max_portability_profile_status_events BEGIN SELECT RAISE(ABORT, 'Portability profile status events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_portability_profile_status_events_no_delete
BEFORE DELETE ON max_portability_profile_status_events BEGIN SELECT RAISE(ABORT, 'Portability profile status events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_host_installations_no_update
BEFORE UPDATE ON max_host_installations BEGIN SELECT RAISE(ABORT, 'Host installations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_host_installations_no_delete
BEFORE DELETE ON max_host_installations BEGIN SELECT RAISE(ABORT, 'Host installations are append-only'); END;
