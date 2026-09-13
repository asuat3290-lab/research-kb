"""Offline acceptance tests for the dev19 transport/closure convergence.

The tests deliberately use disposable control/source databases.  The
non-fixture cases exercise the production-shaped nominal factory and the
formal native bridge with sealed DNS/credential/HTTPS seams; no socket,
environment credential, or external provider is reachable from this module.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

from _mr4b1b_schema22_fixture import Schema22NativeFixture, provider_profile_mapping
from research_kb.max_research.convergence import (
    LiveExecutionCapsuleError,
    LiveExecutionCapsuleStore,
    _OneShotCachingResolver,
)
from research_kb.max_research.native_live import (
    FixtureCredentialResolver,
    NativeLiveCanaryError,
    NativeLiveCanaryExecutor,
)
from research_kb.max_research.persistence.repository import (
    MaxControlError,
    MaxControlRepository,
    normalize_budget_limits,
)
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.provider import (
    InjectedDNSResolver,
    InjectedHTTPSConnector,
    ProviderTransportError,
    ProviderUsageAuthority,
    TransportResponse,
    network_policy_hash,
)
from research_kb.max_research.provider.live import (
    LiveProviderTransportFactory,
    is_trusted_live_transport_factory,
    make_convergence_transport_factory,
)
from research_kb.policy import Actor


def _provider_response(model: str) -> dict[str, object]:
    proposal = {
        "objects": [],
        "relations": [],
        "artifact_links": [],
        "record_refs": [],
        "strategy": None,
        "output_summary": "bounded production-shaped hermetic result",
        "role_outputs": [],
        "deliberation": None,
    }
    return {
        "id": "mr-convergence-dev19-hermetic-call",
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": json.dumps(proposal, separators=(",", ":")),
            },
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


class _DeniedCredentialResolver:
    """A deterministic pre-send credential failure; never returns a secret."""

    read_count = 0

    def resolve(self, _reference: object) -> str:
        self.read_count += 1
        raise ProviderTransportError(
            "CREDENTIAL_RESOLUTION_FAILED",
            "sealed test credential boundary",
            dispatch_known=True,
        )


class _SpoofFactory(LiveProviderTransportFactory):
    convergence_owned = True


class Dev19ConvergenceTests(unittest.TestCase):
    def test_budget_normalization_precedes_any_database_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mr-convergence-dev19-budget-") as root:
            database = f"{root}\\invalid.db"
            repo = MaxControlRepository(database)
            actor = Actor("dev19-budget-admin", "dev19-budget-session", "user", "admin", "dev19-tests")
            charter = {
                "question": "bounded budget contract",
                "scope": "offline contract test",
                "invariants": ["no unsupported budget units"],
                "non_goals": ["network"],
                "deliverables": ["normalized budget"],
                "model_identity": "dev19-hermetic-model/v1",
                "budget": {
                    "iteration_count": 1,
                    "wall_clock_seconds": 120,
                    "input_tokens": 4096,
                    "output_tokens": 256,
                    "cost_units": 729,
                    "human_cost_ceiling": 1000,
                },
                "source_policy": {"network_allowed": False},
                "quality_gates": {"require_human_approval": True},
            }
            with self.assertRaises(MaxControlError):
                repo.propose(project_id="pilot", charter=charter, actor=actor)
            self.assertFalse(repo.settings.database.exists())

            normalized = normalize_budget_limits({
                "iteration_count": 1,
                "wall_clock_seconds": 120,
                "input_tokens": 4096,
                "output_tokens": 256,
                "cost_units": 729,
            })
            self.assertEqual(
                set(normalized),
                {"iteration_count", "wall_clock_seconds", "input_tokens", "output_tokens", "cost_units"},
            )

    def test_nominal_factory_is_package_owned_and_spoofs_are_rejected(self) -> None:
        resolver = InjectedDNSResolver({"opencode.ai": ("93.184.216.34",)})
        factory = make_convergence_transport_factory(resolver)
        self.assertTrue(is_trusted_live_transport_factory(factory))
        self.assertFalse(is_trusted_live_transport_factory(_SpoofFactory()))
        with self.assertRaises(TypeError):
            make_convergence_transport_factory(object())  # type: ignore[arg-type]

        fixture = Schema22NativeFixture(complete=False, fixture_control=False)
        try:
            with self.assertRaises(NativeLiveCanaryError):
                NativeLiveCanaryExecutor(
                    fixture.repo,
                    admin_actor=fixture.admin,
                    worker_actor=fixture.worker,
                    expected_release_identity=fixture.release,
                    transport_factory=_SpoofFactory(),
                    live_network_enabled=True,
                )
        finally:
            fixture.close()

    def test_non_fixture_production_shaped_e2e_reuses_one_resolver(self) -> None:
        fixture = Schema22NativeFixture(legacy_dns_receipt=False, fixture_control=False)
        try:
            self.assertFalse(fixture.repo.is_fixture_database())
            store = LiveExecutionCapsuleStore(
                fixture.repo,
                source_database=fixture.source_database,
                expected_release_identity=fixture.release,
            )
            injected = InjectedDNSResolver({
                "opencode.ai": ("93.184.216.34",),
                "provider.invalid": ("93.184.216.34",),
            })
            cached = _OneShotCachingResolver(injected)
            connector = InjectedHTTPSConnector(
                TransportResponse(
                    200,
                    _provider_response(fixture.profile.model_identity),
                    {"content-type": "application/json"},
                    "mr-convergence-dev19-hermetic-call",
                    True,
                )
            )
            credential = FixtureCredentialResolver("sealed-test-secret")
            factory = make_convergence_transport_factory(
                cached,
                connector=connector,
                credential_resolver=credential,
            )
            import research_kb.max_research.request_builder as request_builder_module

            with patch.object(request_builder_module, "CORE_DATABASE", fixture.source_database):
                preview = store.create_preview(
                    preparation_preview_id=fixture.preview["preview_id"],
                    actor=fixture.admin,
                    ttl_seconds=3600,
                )
                result = store.execute(
                    capsule_hash=str(preview["capsule_hash"]),
                    confirmation=str(preview["confirmation"]),
                    actor=fixture.admin,
                    resolver=cached,
                    transport_factory=factory,
                    usage_authority=ProviderUsageAuthority(),
                    live_network_enabled=True,
                )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["outcome"], "AUTHORITATIVE_PROVIDER_RESULT")
            self.assertEqual(injected.lookup_count, 1)
            self.assertEqual(cached.lookup_count, 1)
            self.assertEqual(connector.network_call_count, 1)
            self.assertEqual(credential.read_count, 1)
            self.assertFalse(fixture.repo.is_fixture_database())
            self.assertTrue(store.verify(capsule_hash=str(preview["capsule_hash"]))["ok"])
        finally:
            fixture.close()

    def test_pre_fix_missing_closure_probe_reproduces_residual_state(self) -> None:
        """Model the pre-dev19 no-op closure and retain its evidence locally."""

        fixture = Schema22NativeFixture(legacy_dns_receipt=False, fixture_control=False)
        try:
            store = LiveExecutionCapsuleStore(
                fixture.repo,
                source_database=fixture.source_database,
                expected_release_identity=fixture.release,
            )
            injected = InjectedDNSResolver({
                "opencode.ai": ("93.184.216.34",),
                "provider.invalid": ("93.184.216.34",),
            })
            cached = _OneShotCachingResolver(injected)
            factory = make_convergence_transport_factory(
                cached,
                connector=InjectedHTTPSConnector(),
                credential_resolver=_DeniedCredentialResolver(),
            )
            import research_kb.max_research.request_builder as request_builder_module

            with patch.object(request_builder_module, "CORE_DATABASE", fixture.source_database), \
                    patch.object(NativeLiveCanaryExecutor, "_close_pre_send_permissions", return_value=[]), \
                    patch.object(NativeLiveCanaryExecutor, "_record_native_terminal", return_value=None), \
                    patch.object(NativeLiveCanaryExecutor, "_cleanup_runner", return_value=[]), \
                    patch.object(RunnerPersistence, "abort_pre_send", return_value={"legacy": True}):
                preview = store.create_preview(
                    preparation_preview_id=fixture.preview["preview_id"],
                    actor=fixture.admin,
                    ttl_seconds=3600,
                )
                result = store.execute(
                    capsule_hash=str(preview["capsule_hash"]),
                    confirmation=str(preview["confirmation"]),
                    actor=fixture.admin,
                    resolver=cached,
                    transport_factory=factory,
                    usage_authority=ProviderUsageAuthority(),
                    live_network_enabled=True,
                )
            self.assertEqual(result["outcome"], "KNOWN_PRE_SEND_FAILURE")
            with closing(sqlite3.connect(fixture.database)) as connection:
                connection.row_factory = sqlite3.Row
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM max_live_canary_native_live_jit_authorities WHERE state='ready'"
                    ).fetchone()[0],
                    1,
                )
                self.assertNotEqual(
                    connection.execute(
                        "SELECT state FROM max_live_canary_native_live_jit_events ORDER BY sequence_no DESC LIMIT 1"
                    ).fetchone()[0],
                    "closed",
                )
                self.assertGreater(
                    connection.execute(
                        "SELECT COUNT(*) FROM max_runner_call_group_current WHERE status='open'"
                    ).fetchone()[0],
                    0,
                )
            budget = fixture.repo.reconstruct_budget(run_id=fixture.run_id)
            self.assertEqual(budget["reserved"]["input_tokens"], 4096)
            self.assertEqual(budget["reserved"]["output_tokens"], 256)
            self.assertEqual(budget["reserved"]["cost_units"], 729)
        finally:
            fixture.close()

    def test_unknown_after_send_preserves_reconciliation_and_does_not_retry(self) -> None:
        fixture = Schema22NativeFixture(legacy_dns_receipt=False, fixture_control=False)
        try:
            store = LiveExecutionCapsuleStore(
                fixture.repo,
                source_database=fixture.source_database,
                expected_release_identity=fixture.release,
            )
            injected = InjectedDNSResolver({
                "opencode.ai": ("93.184.216.34",),
                "provider.invalid": ("93.184.216.34",),
            })
            cached = _OneShotCachingResolver(injected)
            connector = InjectedHTTPSConnector(
                error=TimeoutError("sealed hermetic provider timeout")
            )
            factory = make_convergence_transport_factory(
                cached,
                connector=connector,
                credential_resolver=FixtureCredentialResolver("sealed-test-secret"),
            )
            import research_kb.max_research.request_builder as request_builder_module

            with patch.object(request_builder_module, "CORE_DATABASE", fixture.source_database):
                preview = store.create_preview(
                    preparation_preview_id=fixture.preview["preview_id"],
                    actor=fixture.admin,
                    ttl_seconds=3600,
                )
                result = store.execute(
                    capsule_hash=str(preview["capsule_hash"]),
                    confirmation=str(preview["confirmation"]),
                    actor=fixture.admin,
                    resolver=cached,
                    transport_factory=factory,
                    usage_authority=ProviderUsageAuthority(),
                    live_network_enabled=True,
                )
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["outcome"], "UNKNOWN_AFTER_SEND")
            self.assertEqual(connector.network_call_count, 1)
            self.assertEqual(injected.lookup_count, 1)
            self.assertEqual(cached.lookup_count, 1)
            with closing(sqlite3.connect(fixture.database)) as connection:
                connection.row_factory = sqlite3.Row
                self.assertEqual(
                    connection.execute(
                        "SELECT state FROM max_provider_dispatch_attempt_current ORDER BY updated_at DESC LIMIT 1"
                    ).fetchone()[0],
                    "unknown",
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT state FROM max_live_canary_native_live_jit_events ORDER BY sequence_no DESC LIMIT 1"
                    ).fetchone()[0],
                    "closed",
                )
            budget = fixture.repo.reconstruct_budget(run_id=fixture.run_id)
            self.assertEqual(budget["reserved"]["cost_units"], 729)
        finally:
            fixture.close()

    def test_known_pre_send_failure_closes_jit_runner_and_budget(self) -> None:
        fixture = Schema22NativeFixture(legacy_dns_receipt=False, fixture_control=False)
        try:
            store = LiveExecutionCapsuleStore(
                fixture.repo,
                source_database=fixture.source_database,
                expected_release_identity=fixture.release,
            )
            injected = InjectedDNSResolver({
                "opencode.ai": ("93.184.216.34",),
                "provider.invalid": ("93.184.216.34",),
            })
            cached = _OneShotCachingResolver(injected)
            credential = _DeniedCredentialResolver()
            factory = make_convergence_transport_factory(
                cached,
                connector=InjectedHTTPSConnector(),
                credential_resolver=credential,
            )
            import research_kb.max_research.request_builder as request_builder_module

            with patch.object(request_builder_module, "CORE_DATABASE", fixture.source_database):
                preview = store.create_preview(
                    preparation_preview_id=fixture.preview["preview_id"],
                    actor=fixture.admin,
                    ttl_seconds=3600,
                )
                result = store.execute(
                    capsule_hash=str(preview["capsule_hash"]),
                    confirmation=str(preview["confirmation"]),
                    actor=fixture.admin,
                    resolver=cached,
                    transport_factory=factory,
                    usage_authority=ProviderUsageAuthority(),
                    live_network_enabled=True,
                )
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["outcome"], "KNOWN_PRE_SEND_FAILURE")
            self.assertEqual(injected.lookup_count, 1)
            self.assertEqual(cached.lookup_count, 1)
            self.assertEqual(credential.read_count, 1)
            self.assertEqual(connector_count(fixture.database, "max_provider_dispatch_attempts"), 1)
            with closing(sqlite3.connect(fixture.database)) as connection:
                connection.row_factory = sqlite3.Row
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM max_live_canary_native_jit_authorities WHERE state IN ('ready','running')"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM max_live_canary_native_live_jit_events WHERE state='closed'"
                    ).fetchone()[0],
                    1,
                    result,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM max_runner_invocation_claims c WHERE c.status='active' AND NOT EXISTS (SELECT 1 FROM max_runner_invocation_claims r WHERE r.claim_id=c.claim_id || ':released' AND r.status='released')"
                    ).fetchone()[0],
                    0,
                )
            budget = fixture.repo.reconstruct_budget(run_id=fixture.run_id)
            self.assertEqual(budget["reserved"], {unit: 0 for unit in budget["limits"]})
            self.assertEqual(budget["used"]["cost_units"], 0)
            self.assertEqual(budget["used"]["input_tokens"], 0)
            self.assertEqual(budget["used"]["output_tokens"], 0)
            self.assertTrue(store.verify(capsule_hash=str(preview["capsule_hash"]))["ok"])
        finally:
            fixture.close()


def connector_count(database: str, table: str) -> int:
    with closing(sqlite3.connect(database)) as connection:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
