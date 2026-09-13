-- MR-4B1B-v15R2: server-owned Live Canary Approval Preview closure.
--
-- This migration is deliberately separate from the v12R1 native approval
-- tables.  A v14R3 durable DNS receipt is authoritative for this boundary;
-- it must never be copied into the legacy native-DNS receipt table merely to
-- make an Approval look compatible.

CREATE TABLE IF NOT EXISTS max_live_canary_approval_previews(
    approval_preview_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    snapshot_state_hash TEXT NOT NULL CHECK(length(snapshot_state_hash)=64),
    preparation_preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preparation_preview_hash TEXT NOT NULL CHECK(length(preparation_preview_hash)=64),
    handoff_id TEXT NOT NULL REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    handoff_hash TEXT NOT NULL CHECK(length(handoff_hash)=64),
    handoff_state TEXT NOT NULL CHECK(handoff_state='PREPARED_AWAITING_AUTHORIZATION'),
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    dns_attempt_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_dns_attempts(attempt_id) ON DELETE RESTRICT,
    dns_attempt_hash TEXT NOT NULL CHECK(length(dns_attempt_hash)=64),
    dns_receipt_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_dns_attempt_receipts(receipt_id) ON DELETE RESTRICT,
    dns_receipt_hash TEXT NOT NULL CHECK(length(dns_receipt_hash)=64),
    bounded_dns_result_hash TEXT NOT NULL CHECK(length(bounded_dns_result_hash)=64),
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    human_cost_ceiling INTEGER NOT NULL CHECK(human_cost_ceiling >= 0),
    profile_cost_ceiling INTEGER NOT NULL CHECK(profile_cost_ceiling >= 0),
    effective_cost_cap INTEGER NOT NULL CHECK(effective_cost_cap >= 0),
    max_input_tokens INTEGER NOT NULL CHECK(max_input_tokens >= 0),
    max_output_tokens INTEGER NOT NULL CHECK(max_output_tokens >= 0),
    max_provider_calls INTEGER NOT NULL CHECK(max_provider_calls=1),
    approval_expires_at TEXT NOT NULL,
    preview_expires_at TEXT NOT NULL,
    confirmation_phrase_hash TEXT NOT NULL CHECK(length(confirmation_phrase_hash)=64),
    state TEXT NOT NULL CHECK(state='AWAITING_HUMAN_APPROVAL'),
    preview_json TEXT NOT NULL,
    approval_preview_hash TEXT NOT NULL UNIQUE CHECK(length(approval_preview_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(dns_receipt_id, release_identity_hash)
);

CREATE INDEX IF NOT EXISTS max_live_canary_approval_previews_run_idx
    ON max_live_canary_approval_previews(run_id, created_at, approval_preview_id);
CREATE INDEX IF NOT EXISTS max_live_canary_approval_previews_receipt_idx
    ON max_live_canary_approval_previews(dns_receipt_id, release_identity_hash, state);

-- A future human confirmation is stored separately from the Preview.  The
-- table references the v14R3 receipt directly and is not the v12R1 legacy
-- native approval table.  This keeps Preview generation side-effect free.
CREATE TABLE IF NOT EXISTS max_live_canary_native_approvals_v2(
    approval_id TEXT PRIMARY KEY,
    approval_preview_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_approval_previews(approval_preview_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    snapshot_id TEXT NOT NULL REFERENCES max_live_canary_preparation_snapshots(snapshot_id) ON DELETE RESTRICT,
    snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64),
    preparation_preview_id TEXT NOT NULL REFERENCES max_live_canary_preparation_previews(preview_id) ON DELETE RESTRICT,
    preparation_preview_hash TEXT NOT NULL CHECK(length(preparation_preview_hash)=64),
    handoff_id TEXT NOT NULL REFERENCES max_runner_preparation_handoffs(handoff_id) ON DELETE RESTRICT,
    handoff_hash TEXT NOT NULL CHECK(length(handoff_hash)=64),
    dns_attempt_id TEXT NOT NULL REFERENCES max_live_canary_dns_attempts(attempt_id) ON DELETE RESTRICT,
    dns_attempt_hash TEXT NOT NULL CHECK(length(dns_attempt_hash)=64),
    dns_receipt_id TEXT NOT NULL REFERENCES max_live_canary_dns_attempt_receipts(receipt_id) ON DELETE RESTRICT,
    dns_receipt_hash TEXT NOT NULL CHECK(length(dns_receipt_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    model_identity TEXT NOT NULL,
    pricing_hash TEXT NOT NULL CHECK(length(pricing_hash)=64),
    network_policy_hash TEXT NOT NULL CHECK(length(network_policy_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    budget_hash TEXT NOT NULL CHECK(length(budget_hash)=64),
    effective_cost_cap INTEGER NOT NULL CHECK(effective_cost_cap >= 0),
    max_provider_calls INTEGER NOT NULL CHECK(max_provider_calls=1),
    confirmation_phrase_hash TEXT NOT NULL CHECK(length(confirmation_phrase_hash)=64),
    approval_json TEXT NOT NULL,
    approval_hash TEXT NOT NULL UNIQUE CHECK(length(approval_hash)=64),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_native_approval_v2_consumptions(
    consumption_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE REFERENCES max_live_canary_native_approvals_v2(approval_id) ON DELETE RESTRICT,
    approval_preview_id TEXT NOT NULL REFERENCES max_live_canary_approval_previews(approval_preview_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    approval_hash TEXT NOT NULL CHECK(length(approval_hash)=64),
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE CHECK(length(consumption_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS max_live_canary_approval_previews_no_update
BEFORE UPDATE ON max_live_canary_approval_previews
BEGIN SELECT RAISE(ABORT, 'Live Approval Previews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_approval_previews_no_delete
BEFORE DELETE ON max_live_canary_approval_previews
BEGIN SELECT RAISE(ABORT, 'Live Approval Previews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approvals_v2_no_update
BEFORE UPDATE ON max_live_canary_native_approvals_v2
BEGIN SELECT RAISE(ABORT, 'native v2 approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approvals_v2_no_delete
BEFORE DELETE ON max_live_canary_native_approvals_v2
BEGIN SELECT RAISE(ABORT, 'native v2 approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approval_v2_consumptions_no_update
BEFORE UPDATE ON max_live_canary_native_approval_v2_consumptions
BEGIN SELECT RAISE(ABORT, 'native v2 approval consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_native_approval_v2_consumptions_no_delete
BEFORE DELETE ON max_live_canary_native_approval_v2_consumptions
BEGIN SELECT RAISE(ABORT, 'native v2 approval consumptions are append-only'); END;
