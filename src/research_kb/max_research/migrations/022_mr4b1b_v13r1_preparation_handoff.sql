-- MR-4B1B-v13R1: durable preparation handoff and JIT runner lifecycle.
--
-- Preparation authority is deliberately short lived.  The immutable handoff
-- records the complete server-owned binding after Snapshot/Preview/DNS-request
-- creation, while its current projection is the only state used for recovery.
-- The group remains open for the runner verifier, but its lifecycle state makes
-- the absence of a live invocation claim explicit and auditable.

ALTER TABLE max_runner_call_group_current
    ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'OPEN_WITH_PREPARATION_CLAIM';

CREATE TABLE IF NOT EXISTS max_runner_preparation_handoffs(
    handoff_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    iteration_id TEXT NOT NULL REFERENCES max_iterations(iteration_id) ON DELETE RESTRICT,
    call_group_id TEXT NOT NULL UNIQUE REFERENCES max_runner_call_groups(group_id) ON DELETE RESTRICT,
    intent_id TEXT NOT NULL REFERENCES max_model_call_intents(intent_id) ON DELETE RESTRICT,
    request_manifest_id TEXT NOT NULL REFERENCES max_runner_intent_manifests(intent_id) ON DELETE RESTRICT,
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    dns_authority_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_authorities(authority_id) ON DELETE RESTRICT,
    dns_authority_hash TEXT NOT NULL CHECK(length(dns_authority_hash)=64),
    dns_request_id TEXT NOT NULL REFERENCES max_live_canary_preparation_dns_requests(request_id) ON DELETE RESTRICT,
    dns_request_hash TEXT NOT NULL CHECK(length(dns_request_hash)=64),
    source_binding_hash TEXT NOT NULL CHECK(length(source_binding_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    reservation_id TEXT REFERENCES max_budget_ledger(entry_id) ON DELETE RESTRICT,
    reservation_hash TEXT NOT NULL CHECK(length(reservation_hash)=64),
    preparation_claim_id TEXT NOT NULL REFERENCES max_runner_invocation_claims(claim_id) ON DELETE RESTRICT,
    released_claim_id TEXT NOT NULL REFERENCES max_runner_invocation_claims(claim_id) ON DELETE RESTRICT,
    preparation_lease_id TEXT NOT NULL,
    released_lease_id TEXT NOT NULL,
    last_fencing_token INTEGER NOT NULL CHECK(last_fencing_token > 0),
    handoff_state TEXT NOT NULL CHECK(handoff_state='PREPARED_AWAITING_AUTHORIZATION'),
    handoff_json TEXT NOT NULL,
    handoff_hash TEXT NOT NULL UNIQUE CHECK(length(handoff_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_preparation_handoff_current(
    handoff_id TEXT PRIMARY KEY REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    call_group_id TEXT NOT NULL UNIQUE REFERENCES max_runner_call_groups(group_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('PREPARED_AWAITING_AUTHORIZATION','JIT_EXECUTING','SUCCEEDED','FAILED','UNKNOWN','CANCELLED','EXPIRED','CLOSED')),
    current_event_sequence INTEGER NOT NULL CHECK(current_event_sequence > 0),
    current_event_hash TEXT NOT NULL CHECK(length(current_event_hash)=64),
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_runner_preparation_handoff_events(
    event_id TEXT PRIMARY KEY,
    handoff_id TEXT NOT NULL REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    call_group_id TEXT NOT NULL REFERENCES max_runner_call_groups(group_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    state TEXT NOT NULL CHECK(state IN ('PREPARED_AWAITING_AUTHORIZATION','JIT_EXECUTING','SUCCEEDED','FAILED','UNKNOWN','CANCELLED','EXPIRED','CLOSED')),
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(handoff_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS max_runner_preparation_handoffs_run_idx
    ON max_runner_preparation_handoffs(run_id, created_at, handoff_id);
CREATE INDEX IF NOT EXISTS max_runner_preparation_handoff_current_run_idx
    ON max_runner_preparation_handoff_current(run_id, state, call_group_id);
CREATE INDEX IF NOT EXISTS max_runner_preparation_handoff_events_run_idx
    ON max_runner_preparation_handoff_events(run_id, handoff_id, sequence_no);

CREATE TRIGGER IF NOT EXISTS max_runner_preparation_handoffs_no_update
BEFORE UPDATE ON max_runner_preparation_handoffs
BEGIN SELECT RAISE(ABORT, 'preparation handoffs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_preparation_handoffs_no_delete
BEFORE DELETE ON max_runner_preparation_handoffs
BEGIN SELECT RAISE(ABORT, 'preparation handoffs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_preparation_handoff_events_no_update
BEFORE UPDATE ON max_runner_preparation_handoff_events
BEGIN SELECT RAISE(ABORT, 'preparation handoff events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_runner_preparation_handoff_events_no_delete
BEFORE DELETE ON max_runner_preparation_handoff_events
BEGIN SELECT RAISE(ABORT, 'preparation handoff events are append-only'); END;
