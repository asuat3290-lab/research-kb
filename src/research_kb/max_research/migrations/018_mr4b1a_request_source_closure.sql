-- MR-4B1A-R: deterministic request manifests and one-time source-egress permits.
-- Only hashes, identifiers, bounded counts and policy metadata are stored.
-- Source text, full prompts, provider bodies and credentials never enter this
-- migration's durable records.

CREATE TABLE IF NOT EXISTS max_live_canary_request_manifests(
    manifest_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL REFERENCES max_live_canary_authority_bindings(authority_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    logical_call_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
    provider_profile_hash TEXT NOT NULL CHECK(length(provider_profile_hash)=64),
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    passage_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    source_role TEXT NOT NULL,
    evidential_function TEXT NOT NULL,
    purpose TEXT NOT NULL,
    document_content_hash TEXT NOT NULL CHECK(length(document_content_hash)=64),
    passage_content_hash TEXT NOT NULL CHECK(length(passage_content_hash)=64),
    input_state_hash TEXT NOT NULL CHECK(length(input_state_hash)=64),
    wire_template_hash TEXT NOT NULL CHECK(length(wire_template_hash)=64),
    wire_request_hash TEXT NOT NULL CHECK(length(wire_request_hash)=64),
    request_bytes INTEGER NOT NULL CHECK(request_bytes > 0 AND request_bytes <= 65536),
    prompt_chars INTEGER NOT NULL CHECK(prompt_chars > 0 AND prompt_chars <= 12000),
    max_input_tokens INTEGER NOT NULL CHECK(max_input_tokens > 0),
    max_output_tokens INTEGER NOT NULL CHECK(max_output_tokens > 0),
    max_cache_read_tokens INTEGER NOT NULL CHECK(max_cache_read_tokens >= 0),
    max_reasoning_tokens INTEGER NOT NULL CHECK(max_reasoning_tokens >= 0),
    manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL UNIQUE CHECK(length(manifest_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(authority_id, manifest_hash)
);

CREATE INDEX IF NOT EXISTS max_live_canary_request_manifests_run_idx
    ON max_live_canary_request_manifests(run_id, created_at, manifest_id);

CREATE TABLE IF NOT EXISTS max_live_canary_source_permits(
    source_permit_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL REFERENCES max_live_canary_authority_bindings(authority_id) ON DELETE RESTRICT,
    preview_id TEXT NOT NULL REFERENCES max_live_canary_previews(preview_id) ON DELETE RESTRICT,
    approval_id TEXT NOT NULL REFERENCES max_live_canary_approvals(approval_id) ON DELETE RESTRICT,
    canary_permit_id TEXT REFERENCES max_live_canary_execution_permits(permit_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    passage_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    purpose TEXT NOT NULL,
    source_role TEXT NOT NULL,
    evidential_function TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL CHECK(length(source_policy_hash)=64),
    request_manifest_hash TEXT NOT NULL CHECK(length(request_manifest_hash)=64),
    worker_id TEXT NOT NULL,
    worker_session TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    expires_at TEXT NOT NULL,
    max_source_characters INTEGER NOT NULL CHECK(max_source_characters > 0 AND max_source_characters <= 2000),
    max_source_tokens INTEGER NOT NULL CHECK(max_source_tokens > 0),
    permit_json TEXT NOT NULL,
    permit_hash TEXT NOT NULL UNIQUE CHECK(length(permit_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(approval_id, request_manifest_hash)
);

CREATE TABLE IF NOT EXISTS max_live_canary_source_permit_current(
    source_permit_id TEXT PRIMARY KEY REFERENCES max_live_canary_source_permits(source_permit_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('issued','consumed','expired','revoked')),
    consumed_at TEXT,
    current_json TEXT NOT NULL,
    current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS max_live_canary_source_permit_events(
    source_permit_event_id TEXT PRIMARY KEY,
    source_permit_id TEXT NOT NULL REFERENCES max_live_canary_source_permits(source_permit_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no > 0),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    UNIQUE(source_permit_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS max_live_canary_review_marks(
    review_mark_id TEXT PRIMARY KEY,
    preview_hash TEXT NOT NULL CHECK(length(preview_hash)=64),
    status TEXT NOT NULL CHECK(status IN ('REJECTED_BY_INDEPENDENT_REVIEW','SUPERSEDED_INCOMPLETE_PREVIEW')),
    reason_hash TEXT NOT NULL CHECK(length(reason_hash)=64),
    review_json TEXT NOT NULL,
    review_hash TEXT NOT NULL UNIQUE CHECK(length(review_hash)=64),
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS max_live_canary_source_permits_run_idx
    ON max_live_canary_source_permits(run_id, created_at, source_permit_id);
CREATE INDEX IF NOT EXISTS max_live_canary_review_marks_preview_idx
    ON max_live_canary_review_marks(preview_hash, created_at);

CREATE TRIGGER IF NOT EXISTS max_live_canary_request_manifests_no_update
BEFORE UPDATE ON max_live_canary_request_manifests
BEGIN SELECT RAISE(ABORT, 'canary request manifests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_request_manifests_no_delete
BEFORE DELETE ON max_live_canary_request_manifests
BEGIN SELECT RAISE(ABORT, 'canary request manifests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_source_permits_no_update
BEFORE UPDATE ON max_live_canary_source_permits
BEGIN SELECT RAISE(ABORT, 'canary source permits are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_source_permits_no_delete
BEFORE DELETE ON max_live_canary_source_permits
BEGIN SELECT RAISE(ABORT, 'canary source permits are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_source_permit_events_no_update
BEFORE UPDATE ON max_live_canary_source_permit_events
BEGIN SELECT RAISE(ABORT, 'canary source permit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_source_permit_events_no_delete
BEFORE DELETE ON max_live_canary_source_permit_events
BEGIN SELECT RAISE(ABORT, 'canary source permit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_review_marks_no_update
BEFORE UPDATE ON max_live_canary_review_marks
BEGIN SELECT RAISE(ABORT, 'canary review marks are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_live_canary_review_marks_no_delete
BEFORE DELETE ON max_live_canary_review_marks
BEGIN SELECT RAISE(ABORT, 'canary review marks are append-only'); END;
