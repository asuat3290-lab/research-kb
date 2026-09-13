-- MR-4B1C-NP0: durable, server-owned network-policy binding.
--
-- Migration 009 already stores the immutable content-addressed policy
-- payload.  This additive table closes the missing relational binding: a
-- policy is not executable for a Run until this immutable row ties it to the
-- Run, project, provider profile, endpoint, credential-reference hash,
-- release identity, and reviewed DNS cap.  There is no backfill: historical
-- databases remain read-only until an explicit release migration is approved.

CREATE TABLE IF NOT EXISTS max_live_network_policy_bindings(
    binding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES max_runs(run_id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL,
    profile_hash TEXT NOT NULL REFERENCES max_provider_profiles(profile_hash) ON DELETE RESTRICT,
    network_policy_hash TEXT NOT NULL REFERENCES max_live_network_policies(network_policy_hash) ON DELETE RESTRICT,
    policy_hash TEXT NOT NULL CHECK(length(policy_hash)=64),
    provider_name TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    endpoint_origin_hash TEXT NOT NULL CHECK(length(endpoint_origin_hash)=64),
    credential_reference_hash TEXT NOT NULL CHECK(length(credential_reference_hash)=64),
    release_identity_hash TEXT NOT NULL CHECK(length(release_identity_hash)=64),
    dns_policy_hash TEXT NOT NULL CHECK(length(dns_policy_hash)=64),
    max_getaddrinfo_calls INTEGER NOT NULL CHECK(max_getaddrinfo_calls=1),
    max_dns_candidates INTEGER NOT NULL CHECK(max_dns_candidates BETWEEN 1 AND 16),
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL UNIQUE CHECK(length(binding_hash)=64),
    created_at TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    authority_kind TEXT NOT NULL,
    authority_session TEXT NOT NULL,
    UNIQUE(run_id, profile_hash, network_policy_hash),
    CHECK(network_policy_hash=policy_hash)
);

CREATE INDEX IF NOT EXISTS max_live_network_policy_bindings_run_idx
    ON max_live_network_policy_bindings(run_id, created_at, binding_id);
CREATE INDEX IF NOT EXISTS max_live_network_policy_bindings_policy_idx
    ON max_live_network_policy_bindings(network_policy_hash, run_id, binding_id);

CREATE TRIGGER IF NOT EXISTS max_live_network_policy_bindings_no_update
BEFORE UPDATE ON max_live_network_policy_bindings BEGIN
    SELECT RAISE(ABORT, 'Max live network policy bindings are append-only');
END;
CREATE TRIGGER IF NOT EXISTS max_live_network_policy_bindings_no_delete
BEFORE DELETE ON max_live_network_policy_bindings BEGIN
    SELECT RAISE(ABORT, 'Max live network policy bindings are append-only');
END;
