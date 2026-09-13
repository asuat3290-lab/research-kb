-- MR-4A2: canonical, bounded source-egress receipts.  The Max control DB
-- stores only hashes, IDs, counts and safe locator metadata.  Source text is
-- obtained at runtime through the controlled local research-kb gateway and is
-- never written to this database.

CREATE TABLE IF NOT EXISTS max_source_egress_policies(
    policy_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    charter_hash TEXT NOT NULL,
    source_policy_hash TEXT NOT NULL,
    provider_profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    model_identity TEXT NOT NULL,
    allowed_purposes_json TEXT NOT NULL,
    allowed_projects_json TEXT NOT NULL,
    allow_document_ids_json TEXT NOT NULL,
    allow_passage_ids_json TEXT NOT NULL,
    allowed_source_versions_json TEXT NOT NULL,
    deny_document_ids_json TEXT NOT NULL,
    source_role_policy_json TEXT NOT NULL,
    reliability_policy_json TEXT NOT NULL,
    verification_policy_json TEXT NOT NULL,
    max_packets INTEGER NOT NULL CHECK(max_packets > 0),
    max_documents INTEGER NOT NULL CHECK(max_documents > 0),
    max_passages INTEGER NOT NULL CHECK(max_passages > 0),
    max_excerpt_characters INTEGER NOT NULL CHECK(max_excerpt_characters > 0),
    max_context_characters INTEGER NOT NULL CHECK(max_context_characters >= 0),
    max_document_characters INTEGER NOT NULL CHECK(max_document_characters > 0),
    max_passage_characters INTEGER NOT NULL CHECK(max_passage_characters > 0),
    max_source_characters INTEGER NOT NULL CHECK(max_source_characters > 0),
    max_source_tokens INTEGER NOT NULL CHECK(max_source_tokens > 0),
    max_packet_source_tokens INTEGER NOT NULL CHECK(max_packet_source_tokens > 0),
    full_document_prohibited INTEGER NOT NULL CHECK(full_document_prohibited=1),
    expires_at TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    authority_kind TEXT NOT NULL,
    authority_session TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    policy_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    CHECK(length(charter_hash)=64), CHECK(length(source_policy_hash)=64),
    CHECK(length(provider_profile_hash)=64), CHECK(length(policy_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_source_packet_requests(
    request_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES max_source_egress_policies(policy_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK(purpose IN ('discovery','supports','counters','contextualizes','adjudication','rehydration')),
    target_claim_hash TEXT,
    query_hash TEXT,
    requested_roles_json TEXT NOT NULL,
    request_json TEXT NOT NULL,
    request_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_session TEXT NOT NULL,
    CHECK(target_claim_hash IS NULL OR length(target_claim_hash)=64),
    CHECK(query_hash IS NULL OR length(query_hash)=64), CHECK(length(request_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_source_handles(
    handle_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES max_source_egress_policies(policy_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    passage_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    packet_id TEXT NOT NULL UNIQUE,
    handle_json TEXT NOT NULL,
    handle_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    CHECK(length(handle_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_canonical_source_packets(
    packet_id TEXT PRIMARY KEY,
    handle_id TEXT NOT NULL UNIQUE REFERENCES max_source_handles(handle_id) ON DELETE RESTRICT,
    policy_id TEXT NOT NULL REFERENCES max_source_egress_policies(policy_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    passage_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    document_content_hash TEXT NOT NULL,
    passage_content_hash TEXT NOT NULL,
    excerpt_hash TEXT NOT NULL,
    context_hash TEXT NOT NULL,
    locator_hash TEXT NOT NULL,
    packet_hash TEXT NOT NULL UNIQUE,
    reliability_status TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    source_role TEXT NOT NULL,
    evidential_function TEXT NOT NULL,
    purpose TEXT NOT NULL,
    truncated INTEGER NOT NULL CHECK(truncated IN (0,1)),
    excerpt_characters INTEGER NOT NULL CHECK(excerpt_characters >= 0),
    context_characters INTEGER NOT NULL CHECK(context_characters >= 0),
    source_tokens INTEGER NOT NULL CHECK(source_tokens >= 0),
    locator_json TEXT NOT NULL,
    packet_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK(length(document_content_hash)=64), CHECK(length(passage_content_hash)=64),
    CHECK(length(excerpt_hash)=64), CHECK(length(context_hash)=64),
    CHECK(length(locator_hash)=64), CHECK(length(packet_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_source_packet_receipts(
    receipt_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES max_canonical_source_packets(packet_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL REFERENCES max_source_packet_requests(request_id) ON DELETE RESTRICT,
    policy_id TEXT NOT NULL REFERENCES max_source_egress_policies(policy_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    window_id TEXT REFERENCES max_long_run_windows(window_id) ON DELETE RESTRICT,
    permit_id TEXT REFERENCES max_long_run_iteration_permits(permit_id) ON DELETE RESTRICT,
    provider_profile_hash TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    packet_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    passage_count INTEGER NOT NULL CHECK(passage_count >= 0),
    document_count INTEGER NOT NULL CHECK(document_count >= 0),
    character_count INTEGER NOT NULL CHECK(character_count >= 0),
    token_count INTEGER NOT NULL CHECK(token_count >= 0),
    truncated INTEGER NOT NULL CHECK(truncated IN (0,1)),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    CHECK(length(packet_hash)=64), CHECK(length(policy_hash)=64), CHECK(length(receipt_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_source_packet_consumptions(
    consumption_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE REFERENCES max_source_packet_receipts(receipt_id) ON DELETE RESTRICT,
    packet_id TEXT NOT NULL REFERENCES max_canonical_source_packets(packet_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    window_id TEXT,
    permit_id TEXT,
    consumer_id TEXT NOT NULL,
    consumer_kind TEXT NOT NULL,
    consumer_session TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    consumption_json TEXT NOT NULL,
    consumption_hash TEXT NOT NULL UNIQUE,
    CHECK(length(consumption_hash)=64)
);

CREATE TABLE IF NOT EXISTS max_source_egress_events(
    event_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES max_source_egress_policies(policy_id) ON DELETE RESTRICT,
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
    UNIQUE(policy_id, sequence_no),
    CHECK(length(payload_hash)=64), CHECK(length(event_hash)=64)
);

CREATE INDEX IF NOT EXISTS max_source_egress_policies_run_idx ON max_source_egress_policies(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_source_packet_requests_run_idx ON max_source_packet_requests(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_source_packets_run_idx ON max_canonical_source_packets(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_source_receipts_run_idx ON max_source_packet_receipts(run_id, created_at);
CREATE INDEX IF NOT EXISTS max_source_egress_events_run_idx ON max_source_egress_events(run_id, sequence_no);

CREATE TRIGGER IF NOT EXISTS max_source_egress_policies_no_update BEFORE UPDATE ON max_source_egress_policies BEGIN SELECT RAISE(ABORT, 'Max source-egress policies are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_egress_policies_no_delete BEFORE DELETE ON max_source_egress_policies BEGIN SELECT RAISE(ABORT, 'Max source-egress policies are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_packet_requests_no_update BEFORE UPDATE ON max_source_packet_requests BEGIN SELECT RAISE(ABORT, 'Max source packet requests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_packet_requests_no_delete BEFORE DELETE ON max_source_packet_requests BEGIN SELECT RAISE(ABORT, 'Max source packet requests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_handles_no_update BEFORE UPDATE ON max_source_handles BEGIN SELECT RAISE(ABORT, 'Max source handles are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_handles_no_delete BEFORE DELETE ON max_source_handles BEGIN SELECT RAISE(ABORT, 'Max source handles are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_canonical_source_packets_no_update BEFORE UPDATE ON max_canonical_source_packets BEGIN SELECT RAISE(ABORT, 'Canonical source packets are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_canonical_source_packets_no_delete BEFORE DELETE ON max_canonical_source_packets BEGIN SELECT RAISE(ABORT, 'Canonical source packets are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_packet_receipts_no_update BEFORE UPDATE ON max_source_packet_receipts BEGIN SELECT RAISE(ABORT, 'Source packet receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_packet_receipts_no_delete BEFORE DELETE ON max_source_packet_receipts BEGIN SELECT RAISE(ABORT, 'Source packet receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_packet_consumptions_no_update BEFORE UPDATE ON max_source_packet_consumptions BEGIN SELECT RAISE(ABORT, 'Source packet consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_packet_consumptions_no_delete BEFORE DELETE ON max_source_packet_consumptions BEGIN SELECT RAISE(ABORT, 'Source packet consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_egress_events_no_update BEFORE UPDATE ON max_source_egress_events BEGIN SELECT RAISE(ABORT, 'Source-egress events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS max_source_egress_events_no_delete BEFORE DELETE ON max_source_egress_events BEGIN SELECT RAISE(ABORT, 'Source-egress events are append-only'); END;
