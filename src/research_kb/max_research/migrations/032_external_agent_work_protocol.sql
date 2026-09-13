-- External Agent Work Protocol v1.
--
-- These tables are deliberately separate from provider execution.  An
-- already-running, authenticated Agent receives a server-owned work packet,
-- reads permitted material through the research gateway, and submits only a
-- bounded candidate result.  Historical protocol records are append-only;
-- the two *_current tables are projections owned by the control service.

CREATE TABLE IF NOT EXISTS max_external_agent_sessions(
    session_id TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL UNIQUE,
    project_id TEXT NOT NULL,
    authenticated_actor_id TEXT NOT NULL,
    authenticated_actor_kind TEXT NOT NULL,
    authenticated_actor_role TEXT NOT NULL,
    authenticated_actor_framework TEXT NOT NULL,
    authenticated_actor_session TEXT NOT NULL,
    authenticated_model TEXT,
    claimed_agent_id TEXT NOT NULL,
    claimed_model TEXT,
    auth_method TEXT NOT NULL CHECK(auth_method='server_injected'),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    session_json TEXT NOT NULL,
    session_hash TEXT NOT NULL UNIQUE CHECK(length(session_hash)=64)
);

CREATE INDEX IF NOT EXISTS max_external_agent_sessions_project_idx
    ON max_external_agent_sessions(project_id, created_at, session_id);

CREATE TABLE IF NOT EXISTS max_external_agent_session_events(
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES max_external_agent_sessions(session_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL CHECK(event_type IN ('opened','closed','expired')),
    event_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(session_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_external_agent_session_events_session_idx
    ON max_external_agent_session_events(session_id, sequence_no, event_id);

CREATE TABLE IF NOT EXISTS max_external_agent_work_packets(
    work_packet_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    round_no INTEGER NOT NULL CHECK(round_no >= 1),
    task_kind TEXT NOT NULL,
    role TEXT NOT NULL,
    state_version INTEGER NOT NULL CHECK(state_version >= 1),
    state_hash TEXT NOT NULL CHECK(length(state_hash)=64),
    checkpoint_id TEXT REFERENCES max_checkpoints(checkpoint_id) ON DELETE RESTRICT,
    prior_result_id TEXT REFERENCES max_external_agent_results(result_id) ON DELETE RESTRICT,
    question_json TEXT NOT NULL,
    question_hash TEXT NOT NULL CHECK(length(question_hash)=64),
    allowed_operations_json TEXT NOT NULL,
    allowed_operations_hash TEXT NOT NULL CHECK(length(allowed_operations_hash)=64),
    source_refs_json TEXT NOT NULL,
    source_refs_hash TEXT NOT NULL CHECK(length(source_refs_hash)=64),
    result_contract_json TEXT NOT NULL,
    result_contract_hash TEXT NOT NULL CHECK(length(result_contract_hash)=64),
    packet_json TEXT NOT NULL,
    packet_hash TEXT NOT NULL UNIQUE CHECK(length(packet_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(run_id, round_no)
);

CREATE INDEX IF NOT EXISTS max_external_agent_work_packets_run_idx
    ON max_external_agent_work_packets(run_id, round_no, created_at, work_packet_id);

CREATE TABLE IF NOT EXISTS max_external_agent_work_current(
    work_packet_id TEXT PRIMARY KEY REFERENCES max_external_agent_work_packets(work_packet_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('available','claimed','released','submitted','expired')),
    generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
    claim_id TEXT,
    result_id TEXT,
    updated_at TEXT NOT NULL,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64)
);

CREATE INDEX IF NOT EXISTS max_external_agent_work_current_scope_idx
    ON max_external_agent_work_current(project_id, run_id, state, updated_at, work_packet_id);

CREATE TABLE IF NOT EXISTS max_external_agent_work_claims(
    claim_id TEXT PRIMARY KEY,
    work_packet_id TEXT NOT NULL REFERENCES max_external_agent_work_packets(work_packet_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    session_id TEXT NOT NULL REFERENCES max_external_agent_sessions(session_id) ON DELETE RESTRICT,
    authenticated_actor_id TEXT NOT NULL,
    claimed_agent_id TEXT NOT NULL,
    fencing_token_hash TEXT NOT NULL CHECK(length(fencing_token_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    claim_hash TEXT NOT NULL UNIQUE CHECK(length(claim_hash)=64),
    UNIQUE(work_packet_id, generation)
);

CREATE INDEX IF NOT EXISTS max_external_agent_work_claims_packet_idx
    ON max_external_agent_work_claims(work_packet_id, generation, created_at, claim_id);

CREATE TABLE IF NOT EXISTS max_external_agent_work_claim_current(
    claim_id TEXT PRIMARY KEY REFERENCES max_external_agent_work_claims(claim_id) ON DELETE RESTRICT,
    work_packet_id TEXT NOT NULL REFERENCES max_external_agent_work_packets(work_packet_id) ON DELETE RESTRICT,
    session_id TEXT NOT NULL REFERENCES max_external_agent_sessions(session_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('active','released','expired')),
    updated_at TEXT NOT NULL,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64)
);

CREATE INDEX IF NOT EXISTS max_external_agent_work_claim_current_packet_idx
    ON max_external_agent_work_claim_current(work_packet_id, state, updated_at, claim_id);

CREATE TABLE IF NOT EXISTS max_external_agent_work_claim_events(
    event_id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES max_external_agent_work_claims(claim_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    event_type TEXT NOT NULL CHECK(event_type IN ('claimed','released','expired')),
    event_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(claim_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_external_agent_work_claim_events_claim_idx
    ON max_external_agent_work_claim_events(claim_id, sequence_no, event_id);

CREATE TABLE IF NOT EXISTS max_external_agent_results(
    result_id TEXT PRIMARY KEY,
    work_packet_id TEXT NOT NULL REFERENCES max_external_agent_work_packets(work_packet_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    session_id TEXT NOT NULL REFERENCES max_external_agent_sessions(session_id) ON DELETE RESTRICT,
    authenticated_actor_id TEXT NOT NULL,
    claimed_agent_id TEXT NOT NULL,
    claimed_model TEXT,
    claim_id TEXT NOT NULL REFERENCES max_external_agent_work_claims(claim_id) ON DELETE RESTRICT,
    state_version INTEGER NOT NULL CHECK(state_version >= 1),
    state_hash TEXT NOT NULL CHECK(length(state_hash)=64),
    idempotency_key TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_hash TEXT NOT NULL UNIQUE CHECK(length(result_hash)=64),
    usage_json TEXT NOT NULL,
    usage_hash TEXT NOT NULL CHECK(length(usage_hash)=64),
    usage_status TEXT NOT NULL CHECK(usage_status IN ('unknown','self_reported')),
    result_status TEXT NOT NULL CHECK(result_status='candidate'),
    created_at TEXT NOT NULL,
    UNIQUE(work_packet_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS max_external_agent_results_packet_idx
    ON max_external_agent_results(work_packet_id, created_at, result_id);

CREATE TABLE IF NOT EXISTS max_external_agent_events(
    event_id TEXT PRIMARY KEY,
    stream_key TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(stream_key, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_external_agent_events_run_idx
    ON max_external_agent_events(run_id, sequence_no, event_id);

CREATE TRIGGER IF NOT EXISTS max_external_agent_sessions_no_update
BEFORE UPDATE ON max_external_agent_sessions BEGIN SELECT RAISE(ABORT, 'External Agent sessions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_sessions_no_delete
BEFORE DELETE ON max_external_agent_sessions BEGIN SELECT RAISE(ABORT, 'External Agent sessions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_session_events_no_update
BEFORE UPDATE ON max_external_agent_session_events BEGIN SELECT RAISE(ABORT, 'External Agent session events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_session_events_no_delete
BEFORE DELETE ON max_external_agent_session_events BEGIN SELECT RAISE(ABORT, 'External Agent session events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_work_packets_no_update
BEFORE UPDATE ON max_external_agent_work_packets BEGIN SELECT RAISE(ABORT, 'External Agent work packets are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_work_packets_no_delete
BEFORE DELETE ON max_external_agent_work_packets BEGIN SELECT RAISE(ABORT, 'External Agent work packets are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_work_claims_no_update
BEFORE UPDATE ON max_external_agent_work_claims BEGIN SELECT RAISE(ABORT, 'External Agent work claims are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_work_claims_no_delete
BEFORE DELETE ON max_external_agent_work_claims BEGIN SELECT RAISE(ABORT, 'External Agent work claims are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_work_claim_events_no_update
BEFORE UPDATE ON max_external_agent_work_claim_events BEGIN SELECT RAISE(ABORT, 'External Agent work claim events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_work_claim_events_no_delete
BEFORE DELETE ON max_external_agent_work_claim_events BEGIN SELECT RAISE(ABORT, 'External Agent work claim events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_results_no_update
BEFORE UPDATE ON max_external_agent_results BEGIN SELECT RAISE(ABORT, 'External Agent results are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_results_no_delete
BEFORE DELETE ON max_external_agent_results BEGIN SELECT RAISE(ABORT, 'External Agent results are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_events_no_update
BEFORE UPDATE ON max_external_agent_events BEGIN SELECT RAISE(ABORT, 'External Agent events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_external_agent_events_no_delete
BEFORE DELETE ON max_external_agent_events BEGIN SELECT RAISE(ABORT, 'External Agent events are append-only'); END;
