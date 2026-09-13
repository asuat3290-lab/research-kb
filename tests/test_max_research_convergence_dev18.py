"""Hermetic end-to-end coverage for the MR-CONVERGENCE-DEV18 capsule flow.

The fixture is disposable and explicitly marked as fixture-only.  The test
transport uses the production live adapter with sealed resolver, credential,
and HTTPS seams; it never opens a socket or reads a real environment secret.
"""

from __future__ import annotations

import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from _mr4b1b_schema22_fixture import FixtureClock, Schema22NativeFixture
from research_kb.max_research.convergence import (
    LiveExecutionCapsuleError,
    LiveExecutionCapsuleStore,
    _OneShotCachingResolver,
)
from research_kb.max_research.native_live import FixtureCredentialResolver, FixtureLiveProviderTransportFactory
from research_kb.max_research.persistence.repository import MaxControlRepository
from research_kb.max_research.provider import InjectedDNSResolver, InjectedHTTPSConnector, ProviderUsageAuthority, TransportResponse
from research_kb.policy import Actor


def _provider_response(model: str) -> dict[str, object]:
    proposal = {
        "objects": [],
        "relations": [],
        "artifact_links": [],
        "record_refs": [],
        "strategy": None,
        "output_summary": "bounded hermetic result",
        "role_outputs": [],
        "deliberation": None,
    }
    return {
        "id": "mr-convergence-hermetic-call",
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


class ConvergenceCapsuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Schema22NativeFixture(
            legacy_dns_receipt=False,
            fixture_control=True,
        )
        self.store = LiveExecutionCapsuleStore(
            self.fixture.repo,
            source_database=self.fixture.source_database,
            expected_release_identity=self.fixture.release,
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def _preview(self) -> dict[str, object]:
        return self.store.create_preview(
            preparation_preview_id=self.fixture.preview["preview_id"],
            actor=self.fixture.admin,
            ttl_seconds=3600,
        )

    def _fixture_transport(self):
        # The outer wrapper is owned by the capsule flow; the inner wrapper is
        # shared with the fixture transport so the logical DNS lookup is
        # cached and no second resolver operation can occur at send time.
        injected_resolver = InjectedDNSResolver({"opencode.ai": ("93.184.216.34",)})
        cached_resolver = _OneShotCachingResolver(injected_resolver)
        connector = InjectedHTTPSConnector(
            TransportResponse(
                200,
                _provider_response(self.fixture.profile.model_identity),
                {"content-type": "application/json"},
                "mr-convergence-hermetic-call",
                True,
            )
        )
        credential = FixtureCredentialResolver("fixture-secret")
        factory = FixtureLiveProviderTransportFactory(
            resolver=cached_resolver,
            connector=connector,
            credential_resolver=credential,
        )
        return injected_resolver, cached_resolver, connector, credential, factory

    def _rw(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.fixture.database)
        connection.row_factory = sqlite3.Row
        return connection

    def test_preview_is_server_owned_hash_bound_and_idempotent(self) -> None:
        first = self._preview()
        second = self._preview()
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["capsule_hash"], second["capsule_hash"])
        self.assertEqual(first["confirmation"], "EXECUTE MAX CANARY " + first["capsule_hash"])
        with closing(self._rw()) as connection:
            row = connection.execute(
                "SELECT capsule_json, confirmation_phrase_hash FROM max_live_execution_capsule_previews WHERE capsule_hash=?",
                (first["capsule_hash"],),
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertNotIn(first["confirmation"], row["capsule_json"])
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_execution_capsule_events").fetchone()[0], 1)
        verified = self.store.verify(capsule_hash=str(first["capsule_hash"]))
        self.assertTrue(verified["ok"], verified)

    def test_full_hermetic_execute_closes_jit_budget_and_replay(self) -> None:
        preview = self._preview()
        injected_resolver, cached_resolver, connector, credential, factory = self._fixture_transport()
        result = self.store.execute(
            capsule_hash=str(preview["capsule_hash"]),
            confirmation=str(preview["confirmation"]),
            actor=self.fixture.admin,
            resolver=cached_resolver,
            transport_factory=factory,
            usage_authority=ProviderUsageAuthority(),
            live_network_enabled=True,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["outcome"], "AUTHORITATIVE_PROVIDER_RESULT")
        self.assertEqual(injected_resolver.lookup_count, 1)
        self.assertEqual(cached_resolver.lookup_count, 1)
        self.assertEqual(connector.network_call_count, 1)
        self.assertEqual(credential.read_count, 1)
        self.assertEqual(result["external_actions"]["provider_calls"], 1)
        verified = self.store.verify(capsule_hash=str(preview["capsule_hash"]))
        self.assertTrue(verified["ok"], verified)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_execution_capsule_consumptions").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_execution_capsule_events").fetchone()[0], 3)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approval_v2_consumptions").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_live_jit_authorities").fetchone()[0], 1)
        with self.assertRaises(LiveExecutionCapsuleError):
            self.store.execute(
                capsule_hash=str(preview["capsule_hash"]),
                confirmation=str(preview["confirmation"]),
                actor=self.fixture.admin,
                resolver=cached_resolver,
                transport_factory=factory,
                live_network_enabled=True,
            )
        self.assertEqual(injected_resolver.lookup_count, 1)
        self.assertEqual(connector.network_call_count, 1)

    def test_compact_surface_uses_server_owned_model_identity(self) -> None:
        """The CLI-shaped path must not synthesize a different model name."""

        preview = self._preview()
        resolver = InjectedDNSResolver({"opencode.ai": ("93.184.216.34",)})
        result = self.store.execute(
            capsule_hash=str(preview["capsule_hash"]),
            confirmation=str(preview["confirmation"]),
            actor=self.fixture.admin,
            resolver=resolver,
            live_network_enabled=True,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["outcome"], "AUTHORITATIVE_PROVIDER_RESULT")
        self.assertEqual(resolver.lookup_count, 1)

    def test_twenty_concurrent_execute_calls_have_one_authoritative_send(self) -> None:
        preview = self._preview()
        injected_resolver, cached_resolver, connector, _credential, factory = self._fixture_transport()

        def attempt() -> str:
            try:
                result = self.store.execute(
                    capsule_hash=str(preview["capsule_hash"]),
                    confirmation=str(preview["confirmation"]),
                    actor=self.fixture.admin,
                    resolver=cached_resolver,
                    transport_factory=factory,
                    live_network_enabled=True,
                )
                return str(result["outcome"])
            except Exception as exc:  # each loser is expected to fail closed
                return type(exc).__name__

        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(lambda _index: attempt(), range(20)))
        self.assertEqual(outcomes.count("AUTHORITATIVE_PROVIDER_RESULT"), 1, outcomes)
        self.assertEqual(injected_resolver.lookup_count, 1)
        self.assertEqual(connector.network_call_count, 1)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_execution_capsule_consumptions").fetchone()[0], 1)

    def test_dns_pre_send_failure_is_terminal_and_not_retried(self) -> None:
        preview = self._preview()
        resolver = InjectedDNSResolver({})
        result = self.store.execute(
            capsule_hash=str(preview["capsule_hash"]),
            confirmation=str(preview["confirmation"]),
            actor=self.fixture.admin,
            resolver=resolver,
            live_network_enabled=False,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["outcome"], "KNOWN_PRE_SEND_FAILURE")
        self.assertEqual(resolver.lookup_count, 1)
        with self.assertRaises(LiveExecutionCapsuleError):
            self.store.execute(
                capsule_hash=str(preview["capsule_hash"]),
                confirmation=str(preview["confirmation"]),
                actor=self.fixture.admin,
                resolver=resolver,
                live_network_enabled=False,
            )
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals_v2").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0], 0)

    def test_crash_recovery_closes_executing_capsule_without_retry(self) -> None:
        preview = self._preview()
        claim = self.store._claim_capsule(
            str(preview["capsule_hash"]),
            str(preview["confirmation"]),
            self.fixture.admin,
        )
        recovered = self.store.recover(
            capsule_hash=str(preview["capsule_hash"]),
            actor=self.fixture.admin,
            reason="fixture_crash_boundary",
        )
        self.assertEqual(recovered["state"], "UNKNOWN_AFTER_SEND")
        self.assertEqual(claim["capsule"]["capsule_hash"], preview["capsule_hash"])
        status = self.store.status(capsule_hash=str(preview["capsule_hash"]))
        self.assertEqual(status["state"], "UNKNOWN_AFTER_SEND")
        with self.assertRaises(LiveExecutionCapsuleError):
            self.store.execute(
                capsule_hash=str(preview["capsule_hash"]),
                confirmation=str(preview["confirmation"]),
                actor=self.fixture.admin,
                live_network_enabled=False,
            )

    def test_released_lease_is_reusable_across_process_clock_skew(self) -> None:
        """A released lease must not be blocked by its former future expiry."""

        def future_clock_init(clock: FixtureClock) -> None:
            clock.value = datetime.now(timezone.utc) + timedelta(seconds=30)

        with patch.object(FixtureClock, "__init__", future_clock_init):
            fixture = Schema22NativeFixture(
                legacy_dns_receipt=False,
                release_residual_runner_claim=True,
                fixture_control=True,
            )
        try:
            repo = MaxControlRepository(fixture.database)
            worker = Actor(
                "mr-convergence-dev18-worker",
                "mr-convergence-dev18-worker-session",
                "worker",
                "runner",
                "research-kb-convergence",
            )
            lease = repo.acquire_lease(run_id=fixture.run_id, actor=worker, ttl_seconds=60)
            self.assertEqual(lease["owner_id"], worker.actor_id)
            repo.release_lease(
                run_id=fixture.run_id,
                actor=worker,
                fencing_token=int(lease["fencing_token"]),
            )
        finally:
            fixture.close()


if __name__ == "__main__":
    unittest.main()
