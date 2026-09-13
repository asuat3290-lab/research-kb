"""Disposable schema-22 fixture for MR-4B1B current-invariant tests.

This helper deliberately creates a fresh control database and a tiny,
read-only-shaped local source database for every test.  It never opens the
governed Pilot, V11, V12, or V13 databases and it never constructs a real
network transport.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from research_kb.max_research.intent_preparer import LiveCanaryIntentPreparer
from research_kb.max_research.lifetime_separation import PreparationSnapshotStore
from research_kb.max_research.long_run import LocalCoreEvidenceGateway, SourceEgressStore
from research_kb.max_research.persistence.repository import MaxControlRepository
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.preparation_execution import (
    NativePreparationStore,
    PreparationCanaryExecutor,
)
from research_kb.max_research.preparation_handoff import PreparationHandoffStore
from research_kb.max_research.provider import (
    ProviderProfile,
    ProviderStore,
    network_policy_hash,
)
from research_kb.max_research.request_builder import ServerOwnedRequestBuilder
from research_kb.max_research.scheduler import provider_runner_profile
from research_kb.policy import Actor


class FixtureClock:
    """Stable test clock; no wall-clock or network dependency is involved."""

    def __init__(self) -> None:
        self.value = datetime(2026, 8, 16, 14, 0, 10, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


def provider_profile_mapping(*, credential_kind: str = "injected", credential_name: str = "schema22-hermetic-fixture") -> dict[str, Any]:
    return {
        "profile_id": "schema22-hermetic-profile",
        "profile_version": "1",
        "protocol": "openai-compatible/v1",
        "provider_name": "schema22-hermetic-provider",
        "model_identity": "schema22-hermetic-model/v1",
        "endpoint_origin": "https://provider.invalid",
        "endpoint_path_policy": "/v1/chat/completions",
        "capabilities": {
            "structured_json": True,
            "idempotency": True,
            "result_query": True,
            "usage_reporting": True,
        },
        "inference_defaults": {
            "temperature": 0,
            "top_p": 1,
            "max_output_tokens": 128,
            "seed": 0,
        },
        "timeout_policy": {
            "connect_ms": 1000,
            "write_ms": 1000,
            "read_ms": 1000,
            "total_ms": 5000,
        },
        "retry_policy": {"max_attempts": 1, "backoff_ms": 1, "retry_statuses": [429]},
        "request_limits": {
            "max_request_bytes": 100000,
            "max_response_bytes": 100000,
            "max_prompt_chars": 10000,
            "max_json_depth": 12,
            "max_input_tokens": 4096,
            "max_output_tokens": 256,
            "max_cache_read_tokens": 4096,
            "max_reasoning_tokens": 256,
        },
        "rate_policy": {"max_concurrency": 1, "per_minute": 60},
        "credential_ref": {"kind": credential_kind, "name": credential_name},
        "network_policy_hash": network_policy_hash(network_policy_mapping()),
        "pricing": {
            "pricing_id": "schema22-hermetic-price",
            "pricing_version": "1",
            "currency": "USD",
            "unit": "cost_units",
            # The native one-shot ceiling is 729 micro-cost units.  The
            # disposable profile must be able to represent that ceiling so
            # the formal network-authority verifier is exercised, while the
            # HermeticTransport still performs no external operation.
            "input_per_1k": "169",
            "output_per_1k": "140",
            "cache_per_1k": "0",
            "reasoning_per_1k": "0",
            "effective_at": "2026-01-01T00:00:00.000Z",
            "source_label": "schema22-test-fixture",
        },
    }


def network_policy_mapping() -> dict[str, Any]:
    """The immutable, offline-only policy bound to the hermetic profile."""

    return {
        "policy_version": "schema22-test/v1",
        "allowed_schemes": ["https"],
        "allow_redirects": False,
        "allow_proxy_env": False,
        "resolve_all_candidates": True,
        "reject_private_addresses": True,
        "max_dns_candidates": 16,
        "max_request_bytes": 100000,
        "max_response_bytes": 100000,
        "max_json_depth": 12,
        "timeout_ms": 5000,
    }


class Schema22NativeFixture:
    """Build one complete, server-owned preparation-to-JIT test graph."""

    document_id = "schema22-document"
    passage_id = "schema22-passage"
    source_version = "publisher-pdf"
    document_hash = "1" * 64
    passage_hash = "2" * 64

    def __init__(self, *, complete: bool = True, legacy_dns_receipt: bool = True, release_residual_runner_claim: bool = False, fixture_control: bool = False, credential_kind: str = "injected", credential_name: str = "schema22-hermetic-fixture") -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr4b1b-schema22-")
        root = Path(self.temp.name)
        self.database = root / "control.db"
        self.source_database = root / "source.db"
        self._create_source_fixture()
        self.clock = FixtureClock()
        self.admin = Actor("schema22-admin", "schema22-admin-session", "user", "admin", "mr4b1b-schema22-tests")
        self.worker = Actor("schema22-worker", "schema22-worker-session", "worker", "runner", "mr4b1b-schema22-tests")
        self.repo = MaxControlRepository(self.database, clock=self.clock)
        self.repo.initialize(fixture=fixture_control)

        self.provider_store = ProviderStore(self.repo)
        registered = self.provider_store.register_profile(
            profile=ProviderProfile.from_mapping(provider_profile_mapping(credential_kind=credential_kind, credential_name=credential_name)),
            actor=self.admin,
        )
        self.profile = self.provider_store.get_profile(profile_hash=registered["profile_hash"])
        self.network_policy = self.provider_store.register_network_policy(
            policy=network_policy_mapping(), actor=self.admin
        )
        self.run_id = self._create_running_run()
        self.provider_store.bind_run_profile(
            run_id=self.run_id, profile_hash=self.profile.profile_hash, actor=self.admin
        )
        self.runner_profile = provider_runner_profile(self.profile)
        self.runner = RunnerPersistence(self.repo)
        self.runner.register_profile(profile=self.runner_profile, actor=self.admin)
        self._handoff_runner()
        if release_residual_runner_claim:
            with closing(self.repo._connect(read_only=True)) as connection:
                residual = connection.execute(
                    "SELECT claim_id, fencing_token FROM max_runner_invocation_claims WHERE run_id=? AND status='active' LIMIT 1",
                    (self.run_id,),
                ).fetchone()
            if residual is not None:
                self.runner.release_invocation(
                    run_id=self.run_id,
                    claim_id=residual["claim_id"],
                    actor=self.worker,
                    fencing_token=int(residual["fencing_token"]),
                )
                self.repo.release_lease(
                    run_id=self.run_id,
                    actor=self.worker,
                    fencing_token=int(residual["fencing_token"]),
                )
        self.policy = SourceEgressStore(self.repo).create_policy(
            run_id=self.run_id,
            value=self._source_policy_value(),
            actor=self.admin,
        )

        self.gateway = LocalCoreEvidenceGateway(self.source_database)
        self.preparer = LiveCanaryIntentPreparer(
            self.repo, worker_actor=self.worker, gateway=self.gateway
        )
        runtime = NativePreparationStore.current_runtime_identity()
        self.release = self._release_identity()
        self.source = {
            "document_id": self.document_id,
            "passage_id": self.passage_id,
            "source_version": self.source_version,
            "document_content_hash": self.document_hash,
            "passage_content_hash": self.passage_hash,
            "source_role": "primary",
            "evidential_function": "supports",
            "purpose": "supports",
        }
        self.preparation_kwargs = {
            "run_id": self.run_id,
            "provider_profile_hash": self.profile.profile_hash,
            "source_egress_policy_hash": self.policy["policy_hash"],
            "candidate_wheel_sha256": "3" * 64,
            "source_manifest_sha256": "4" * 64,
            "source_tree_sha256": "5" * 64,
            "engine_version": runtime["package_version"],
            "caps": self.native_caps(),
        }
        # The production builder owns the source gateway.  For an isolated
        # current-invariant test, bind that same formal builder to the
        # disposable local source fixture for the duration of preparation;
        # this is not a production bypass and never points at Pilot.
        import research_kb.max_research.request_builder as request_builder_module

        if not complete:
            return
        prior_core_database = request_builder_module.CORE_DATABASE
        request_builder_module.CORE_DATABASE = self.source_database
        try:
            self.preparation = self.preparer.prepare(**self.preparation_kwargs)
        finally:
            request_builder_module.CORE_DATABASE = prior_core_database
        self.snapshots = PreparationSnapshotStore(
            self.repo, source_database=self.source_database
        )
        self.store = NativePreparationStore(
            self.repo,
            source_database=self.source_database,
            expected_release_identity=self.release,
        )
        self.snapshot = self.snapshots.create_snapshot(
            run_id=self.run_id,
            source_binding=self.source,
            preparation={
                "request_hash": self.preparation["request_hash"],
                "wire_request_hash": self.preparation["wire_request_hash"],
                "request_manifest_hash": self.preparation["request_manifest_hash"],
                "source_manifest_sha256": "4" * 64,
            },
            caps=self.native_caps(),
            release_identity=self.release,
            actor=self.admin,
        )
        self.preview = self.snapshots.preview_from_snapshot(
            snapshot_id=self.snapshot["snapshot_id"],
            dns_policy=self.dns_policy(),
            actor=self.admin,
        )
        self.dns_request = self.snapshots.create_dns_only_request(
            preview_id=self.preview["preview_id"], actor=self.admin
        )
        self.dns_result = None
        if legacy_dns_receipt:
            self.dns_result = self.store.record_dns_receipt(
                preview_id=self.preview["preview_id"],
                request_id=self.dns_request["request_id"],
                bounded_result=self.passed_dns_result(),
                actor=self.worker,
            )
        self.phrase = "APPROVE MR-4B1 SNAPSHOT " + self.preview["preview_hash"]
        self.expiry = "2026-08-16T20:00:00.000Z"
        self.pre_handoff_database = root / "pre-handoff.db"
        shutil.copy2(self.database, self.pre_handoff_database)
        self.handoffs = PreparationHandoffStore(
            self.repo, source_database=self.source_database
        )
        self.handoff = self.handoffs.handoff_preparation(
            run_id=self.run_id,
            snapshot_id=self.snapshot["snapshot_id"],
            preview_id=self.preview["preview_id"],
            dns_authority_id=self.dns_request["authority_id"],
            dns_request_id=self.dns_request["request_id"],
            preparation_claim_id=self.preparation["claim_id"],
            fencing_token=self.preparation["fencing_token"],
            worker=self.worker,
            reservation_id=self.preparation["reservation_id"],
        )
        self.executor = PreparationCanaryExecutor(
            self.repo,
            store=self.store,
            admin_actor=self.admin,
            worker_actor=self.worker,
            source_database=self.source_database,
            expected_release_identity=self.release,
            request_builder=ServerOwnedRequestBuilder(gateway=self.gateway),
        )

    def close(self) -> None:
        self.temp.cleanup()

    def _create_source_fixture(self) -> None:
        with closing(sqlite3.connect(self.source_database)) as connection:
            connection.executescript(
                """
                CREATE TABLE projects(project_id TEXT PRIMARY KEY, status TEXT NOT NULL);
                CREATE TABLE documents(
                    document_id TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    reliability_status TEXT NOT NULL,
                    verification_status TEXT NOT NULL
                );
                CREATE TABLE passages(
                    passage_id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL,
                    text_hash TEXT NOT NULL,
                    text TEXT NOT NULL,
                    location_json TEXT NOT NULL
                );
                CREATE TABLE project_sources(project_id TEXT NOT NULL, document_id TEXT NOT NULL);
                """
            )
            connection.execute("INSERT INTO projects VALUES ('pilot', 'active')")
            connection.execute(
                "INSERT INTO documents VALUES (?, ?, ?, 'unverified', 'unverified')",
                (self.document_id, self.document_hash, self.source_version),
            )
            connection.execute(
                "INSERT INTO passages VALUES (?, ?, ?, ?, ?)",
                (
                    self.passage_id,
                    self.document_id,
                    self.passage_hash,
                    "bounded synthetic source fixture",
                    json.dumps({"page": 1, "ordinal": 1}),
                ),
            )
            connection.execute(
                "INSERT INTO project_sources VALUES ('pilot', ?)", (self.document_id,)
            )
            connection.commit()

    def _create_running_run(self) -> str:
        charter = {
            "question": "Can the schema-22 native bridge remain bounded and replay-safe?",
            "scope": "MR-4B1B current schema-22 invariant tests",
            "invariants": ["one start approval", "native approval is separate", "no external network"],
            "non_goals": ["real provider", "source acquisition", "OCR", "ingest"],
            "deliverables": ["current invariant evidence"],
            "model_identity": self.profile.model_identity,
            "budget": {
                "iteration_count": 16,
                "input_tokens": 10000,
                "output_tokens": 10000,
                "cost_units": 1000,
            },
            "source_policy": {"network_allowed": False, "roles": ["primary"]},
            "quality_gates": {
                "require_human_approval": True,
                "required_strategy_families": ["direct"],
            },
        }
        proposed = self.repo.propose(project_id="pilot", charter=charter, actor=self.admin)
        self.repo.approve(
            run_id=proposed["run_id"],
            charter_hash_value=proposed["charter_hash"],
            reason="MR-4B1B schema-22 current invariant fixture",
            actor=self.admin,
        )
        self.started = self.repo.start(
            run_id=proposed["run_id"], actor=self.admin, lease_ttl=900
        )
        return proposed["run_id"]

    def _handoff_runner(self) -> None:
        self.runner_handoff = self.runner.handoff_runner(
            run_id=self.run_id,
            profile=self.runner_profile,
            admin_actor=self.admin,
            runner_actor=self.worker,
            admin_fencing_token=int(self.started["lease"]["fencing_token"]),
            lease_ttl=7200,
        )

    def _source_policy_value(self) -> dict[str, Any]:
        return {
            "allowed_purposes": ["supports"],
            "allow_document_ids": [self.document_id],
            "allow_passage_ids": [self.passage_id],
            "allowed_source_versions": [self.source_version],
            "deny_document_ids": [],
            "source_role_policy": {
                "allowed_roles": ["primary"],
                "allowed_functions": ["supports"],
            },
            "reliability_policy": {"allowed_statuses": ["unverified"]},
            "verification_policy": {"allowed_statuses": ["unverified"]},
            "max_packets": 8,
            "max_documents": 1,
            "max_passages": 8,
            "max_excerpt_characters": 200,
            "max_context_characters": 0,
            "max_document_characters": 500,
            "max_passage_characters": 300,
            "max_source_characters": 2000,
            "max_source_tokens": 500,
            "max_packet_source_tokens": 100,
            "full_document_prohibited": True,
            "expires_at": "2999-01-01T00:00:00.000Z",
            "authority_reason": "MR-4B1B schema-22 current invariant fixture",
        }

    @staticmethod
    def native_caps() -> dict[str, int]:
        return {
            "max_provider_calls": 1,
            "max_ticks": 1,
            "max_iterations": 1,
            "max_acquisition_requests": 0,
            "max_ocr_requests": 0,
            "max_ingest_operations": 0,
            "max_input_tokens": 4096,
            "max_output_tokens": 256,
            "max_cache_read_tokens": 4096,
            "max_reasoning_tokens": 256,
            "max_cost_units": 729,
            "max_wall_clock_seconds": 120,
            "max_source_passages": 1,
            "max_source_characters": 2000,
        }

    @staticmethod
    def dns_policy() -> dict[str, Any]:
        return {
            "hostname": "opencode.ai",
            "port": 443,
            "scheme": "https",
            "max_dns_candidates": 16,
            "credential_reads": 0,
            "tcp_connections": 0,
            "tls_https_calls": 0,
            "provider_calls": 0,
            "cost_units": 0,
        }

    @staticmethod
    def passed_dns_result() -> dict[str, Any]:
        return {
            "max_getaddrinfo_calls": 1,
            "getaddrinfo_attempts": 1,
            "max_dns_candidates": 16,
            "candidate_count": 4,
            "ipv4_count": 4,
            "ipv6_count": 0,
            "all_global": True,
            "ssrf_safe": True,
        }

    @staticmethod
    def _release_identity() -> dict[str, Any]:
        runtime = NativePreparationStore.current_runtime_identity()
        return {
            **runtime,
            "wheel_sha256": "6" * 64,
            "sdist_sha256": "7" * 64,
            "source_tree_sha256": "8" * 64,
            "release_manifest_sha256": "9" * 64,
            "migration_release_manifest_sha256": "a" * 64,
        }


__all__ = ["Schema22NativeFixture", "FixtureClock", "provider_profile_mapping"]
