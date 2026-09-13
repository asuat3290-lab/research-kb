-- MR-4B1C: append-only Execution Window renewal.
--
-- The application runs this migration with foreign-key enforcement disabled
-- only inside the migration transaction, then validates and re-enables it
-- before commit.  The old rows are copied byte-for-byte into a structurally
-- equivalent table without the obsolete approval_id UNIQUE constraint.

DROP TRIGGER IF EXISTS max_live_canary_native_execution_previews_no_update;
DROP TRIGGER IF EXISTS max_live_canary_native_execution_previews_no_delete;

CREATE TABLE max_live_canary_native_execution_previews_v026(
    execution_preview_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL REFERENCES max_live_canary_native_approvals_v2(approval_id) ON DELETE RESTRICT,
    approval_hash TEXT NOT NULL CHECK(length(approval_hash)=64),
    approval_preview_id TEXT NOT NULL REFERENCES max_live_canary_approval_previews(approval_preview_id) ON DELETE RESTRICT,
    approval_preview_hash TEXT NOT NULL CHECK(length(approval_preview_hash)=64),
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preparation_preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preparation_preview_hash TEXT NOT NULL CHECK(length(preparation_preview_hash)=64),
    handoff_id TEXT NOT NULL REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    handoff_hash TEXT NOT NULL CHECK(length(handoff_hash)=64),
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    dns_attempt_id TEXT NOT NULL REFERENCES max_live_canary_dns_attempts(attempt_id) ON DELETE RESTRICT,
    dns_receipt_id TEXT NOT NULL REFERENCES max_live_canary_dns_attempt_receipts(receipt_id) ON DELETE RESTRICT,
    dns_receipt_hash TEXT NOT NULL CHECK(length(dns_receipt_hash)=64),
    bounded_dns_result_hash TEXT NOT NULL CHECK(length(bounded_dns_result_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    source_tree_hash TEXT NOT NULL CHECK(length(source_tree_hash)=64),
    wheel_hash TEXT NOT NULL CHECK(length(wheel_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    current_state_hash TEXT NOT NULL CHECK(length(current_state_hash)=64),
    current_state_version INTEGER NOT NULL CHECK(current_state_version >= 0),
    human_cost_ceiling INTEGER NOT NULL CHECK(human_cost_ceiling >= 0),
    profile_worst_case_cost INTEGER NOT NULL CHECK(profile_worst_case_cost >= 0),
    effective_cost_cap INTEGER NOT NULL CHECK(effective_cost_cap >= 0),
    max_provider_calls INTEGER NOT NULL CHECK(max_provider_calls=1),
    max_input_tokens INTEGER NOT NULL CHECK(max_input_tokens >= 0),
    max_output_tokens INTEGER NOT NULL CHECK(max_output_tokens >= 0),
    max_cache_read_tokens INTEGER NOT NULL CHECK(max_cache_read_tokens >= 0),
    max_reasoning_tokens INTEGER NOT NULL CHECK(max_reasoning_tokens >= 0),
    state TEXT NOT NULL CHECK(state='AWAITING_EXPLICIT_EXECUTION_AUTHORIZATION'),
    execution_phrase_hash TEXT NOT NULL CHECK(length(execution_phrase_hash)=64),
    execution_preview_json TEXT NOT NULL,
    execution_preview_hash TEXT NOT NULL UNIQUE CHECK(length(execution_preview_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
    supersedes_execution_preview_id TEXT REFERENCES max_live_canary_native_execution_previews(execution_preview_id) ON DELETE RESTRICT,
    supersedes_execution_preview_hash TEXT CHECK(supersedes_execution_preview_hash IS NULL OR length(supersedes_execution_preview_hash)=64),
    renewal_reason TEXT CHECK(renewal_reason IS NULL OR renewal_reason='expired_before_execution'),
    UNIQUE(approval_id, generation),
    CHECK((generation=0 AND supersedes_execution_preview_id IS NULL AND supersedes_execution_preview_hash IS NULL AND renewal_reason IS NULL) OR (generation>0 AND supersedes_execution_preview_id IS NOT NULL AND supersedes_execution_preview_hash IS NOT NULL AND renewal_reason='expired_before_execution'))
);

INSERT INTO max_live_canary_native_execution_previews_v026(
    execution_preview_id,approval_id,approval_hash,approval_preview_id,approval_preview_hash,project_id,run_id,snapshot_id,snapshot_hash,preparation_preview_id,preparation_preview_hash,handoff_id,handoff_hash,request_manifest_hash,dns_attempt_id,dns_receipt_id,dns_receipt_hash,bounded_dns_result_hash,provider_profile_hash,model_identity,pricing_hash,network_policy_hash,source_policy_hash,endpoint_origin_hash,credential_reference_hash,release_identity_hash,source_tree_hash,wheel_hash,budget_hash,current_state_hash,current_state_version,human_cost_ceiling,profile_worst_case_cost,effective_cost_cap,max_provider_calls,max_input_tokens,max_output_tokens,max_cache_read_tokens,max_reasoning_tokens,state,execution_phrase_hash,execution_preview_json,execution_preview_hash,created_at,expires_at,actor_id,actor_kind,actor_session,generation,supersedes_execution_preview_id,supersedes_execution_preview_hash,renewal_reason
)
SELECT
    execution_preview_id,approval_id,approval_hash,approval_preview_id,approval_preview_hash,project_id,run_id,snapshot_id,snapshot_hash,preparation_preview_id,preparation_preview_hash,handoff_id,handoff_hash,request_manifest_hash,dns_attempt_id,dns_receipt_id,dns_receipt_hash,bounded_dns_result_hash,provider_profile_hash,model_identity,pricing_hash,network_policy_hash,source_policy_hash,endpoint_origin_hash,credential_reference_hash,release_identity_hash,source_tree_hash,wheel_hash,budget_hash,current_state_hash,current_state_version,human_cost_ceiling,profile_worst_case_cost,effective_cost_cap,max_provider_calls,max_input_tokens,max_output_tokens,max_cache_read_tokens,max_reasoning_tokens,state,execution_phrase_hash,execution_preview_json,execution_preview_hash,created_at,expires_at,actor_id,actor_kind,actor_session,0,NULL,NULL,NULL
FROM max_live_canary_native_execution_previews;

DROP TABLE max_live_canary_native_execution_previews;
ALTER TABLE max_live_canary_native_execution_previews_v026 RENAME TO max_live_canary_native_execution_previews;

CREATE TABLE max_live_canary_native_execution_preview_current(
    approval_id TEXT PRIMARY KEY REFERENCES max_live_canary_native_approvals_v2(approval_id) ON DELETE RESTRICT,
    execution_preview_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_native_execution_previews(execution_preview_id) ON DELETE RESTRICT,
    execution_preview_hash TEXT NOT NULL CHECK(length(execution_preview_hash)=64),
    generation INTEGER NOT NULL CHECK(generation >= 0),
    state TEXT NOT NULL CHECK(state='AWAITING_EXPLICIT_EXECUTION_AUTHORIZATION'),
    expires_at TEXT NOT NULL,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL
);

CREATE TABLE max_live_canary_native_execution_preview_events(
    event_id TEXT PRIMARY KEY,
    execution_preview_id TEXT NOT NULL REFERENCES max_live_canary_native_execution_previews(execution_preview_id) ON DELETE RESTRICT,
    approval_id TEXT NOT NULL REFERENCES max_live_canary_native_approvals_v2(approval_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    event_type TEXT NOT NULL CHECK(event_type IN ('created','renewed')),
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(execution_preview_id, sequence_no)
);

CREATE INDEX max_live_canary_native_execution_previews_run_idx ON max_live_canary_native_execution_previews(run_id, created_at, execution_preview_id);
CREATE INDEX max_live_canary_native_execution_previews_approval_idx ON max_live_canary_native_execution_previews(approval_id, generation, created_at, execution_preview_id);

CREATE TRIGGER max_live_canary_native_execution_previews_no_update BEFORE UPDATE ON max_live_canary_native_execution_previews BEGIN SELECT RAISE(ABORT, 'native execution previews are append-only'); END;
CREATE TRIGGER max_live_canary_native_execution_previews_no_delete BEFORE DELETE ON max_live_canary_native_execution_previews BEGIN SELECT RAISE(ABORT, 'native execution previews are append-only'); END;
CREATE TRIGGER max_live_canary_native_execution_preview_events_no_update BEFORE UPDATE ON max_live_canary_native_execution_preview_events BEGIN SELECT RAISE(ABORT, 'native execution preview events are append-only'); END;
CREATE TRIGGER max_live_canary_native_execution_preview_events_no_delete BEFORE DELETE ON max_live_canary_native_execution_preview_events BEGIN SELECT RAISE(ABORT, 'native execution preview events are append-only'); END;
