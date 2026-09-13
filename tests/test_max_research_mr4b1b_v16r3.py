"""Offline adversarial checks for the v16R3 Native JIT/live bridge."""

from __future__ import annotations

import json
import hashlib
import sqlite3
import unittest
from contextlib import closing
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor

from _mr4b1b_schema22_fixture import Schema22NativeFixture
from research_kb.max_research.approval_preview import LiveApprovalPreviewStore
from research_kb.max_research.contract import canonical_sha256
from research_kb.max_research.dns_attempt import DNSAttemptStore
from research_kb.max_research.native_live import (
    FixtureCredentialResolver,
    FixtureLiveProviderTransportFactory,
    NativeLiveCanaryError,
    NativeLiveCanaryExecutor,
    NativeLiveExecutionStore,
    _execution_preview_hash,
)
from research_kb.max_research.persistence.version import CONTROL_SCHEMA_VERSION
from research_kb.max_research.provider.live import InjectedDNSResolver, InjectedHTTPSConnector, TransportResponse


class NativeLiveBridgeClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Schema22NativeFixture(legacy_dns_receipt=False, release_residual_runner_claim=True, fixture_control=True)
        self.dns_result = DNSAttemptStore(self.fixture.repo).execute(
            preview_id=self.fixture.preview["preview_id"],
            request_id=self.fixture.dns_request["request_id"],
            confirmation_phrase="APPROVE MR-4B1 DNS PREFLIGHT " + self.fixture.dns_request["request_hash"],
            actor=self.fixture.admin,
            resolver=InjectedDNSResolver({"opencode.ai": ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")} ),
            allow_execute=True,
        )
        self.live_preview = LiveApprovalPreviewStore(self.fixture.repo, expected_release_identity=self.fixture.release).create_approval_preview(
            preparation_preview_id=self.fixture.preview["preview_id"], actor=self.fixture.admin,
        )
        self.approval = LiveApprovalPreviewStore(self.fixture.repo, expected_release_identity=self.fixture.release).authorize(
            approval_preview_id=self.live_preview["approval_preview_id"],
            confirmation_phrase=self.live_preview["confirmation_phrase"],
            actor=self.fixture.admin,
        )
        self.store = NativeLiveExecutionStore(self.fixture.repo, expected_release_identity=self.fixture.release)

    def tearDown(self) -> None:
        self.fixture.close()

    def _create(self, **kwargs):
        return self.store.create_execution_preview(approval_id=self.approval["approval_id"], actor=self.fixture.admin, **kwargs)

    def _authorize(self, created):
        return self.store.authorize_execution(
            execution_preview_id=created["execution_preview_id"],
            confirmation_phrase=created["confirmation_phrase"],
            actor=self.fixture.admin,
        )

    def _rw(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.fixture.database)
        connection.row_factory = sqlite3.Row
        return connection

    def test_01_current_schema_and_fixture_is_external_action_free(self) -> None:
        self.assertEqual(CONTROL_SCHEMA_VERSION, 32)
        verified = self.fixture.repo.verify_database()
        self.assertTrue(verified["ok"], verified)
        self.assertTrue(verified["quick_check"])
        self.assertTrue(verified["foreign_keys"])
        self.assertEqual(verified["provider"]["counts"]["calls"], 0)

    def test_02_execution_preview_is_server_owned_and_hash_bound(self) -> None:
        created = self._create()
        self.assertEqual(created["state"], "AWAITING_EXPLICIT_EXECUTION_AUTHORIZATION")
        self.assertEqual(created["confirmation_phrase"], "EXECUTE MR-4B1 CANARY " + created["execution_preview_hash"])
        with closing(self._rw()) as connection:
            row = connection.execute("SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?", (created["execution_preview_id"],)).fetchone()
        value = json.loads(row["execution_preview_json"])
        self.assertEqual(_execution_preview_hash(value), row["execution_preview_hash"])
        self.assertEqual(value["execution_preview_hash"], row["execution_preview_hash"])
        self.assertNotIn(created["confirmation_phrase"], row["execution_preview_json"])

    def test_03_execution_preview_binds_dns_receipt_and_release(self) -> None:
        created = self._create()
        with closing(self._rw()) as connection:
            row = connection.execute("SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?", (created["execution_preview_id"],)).fetchone()
            receipt = connection.execute("SELECT r.*,a.release_identity_hash AS attempt_release_identity_hash FROM max_live_canary_dns_attempt_receipts r JOIN max_live_canary_dns_attempts a ON a.attempt_id=r.attempt_id WHERE r.receipt_id=?", (row["dns_receipt_id"],)).fetchone()
        self.assertEqual(row["dns_receipt_hash"], receipt["receipt_hash"])
        self.assertEqual(row["bounded_dns_result_hash"], receipt["bounded_result_hash"])
        self.assertEqual(row["preparation_preview_hash"], receipt["preview_hash"])
        self.assertEqual(row["handoff_hash"], receipt["handoff_hash"])
        self.assertEqual(row["release_identity_hash"], receipt["attempt_release_identity_hash"])

    def test_04_wrong_execution_phrase_writes_nothing(self) -> None:
        created = self._create()
        with self.assertRaises(NativeLiveCanaryError):
            self.store.authorize_execution(
                execution_preview_id=created["execution_preview_id"],
                confirmation_phrase="EXECUTE MR-4B1 CANARY " + "0" * 64,
                actor=self.fixture.admin,
            )
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_authorizations").fetchone()[0], 0)

    def test_05_execution_authorization_is_idempotent_but_not_replayable(self) -> None:
        created = self._create()
        first = self._authorize(created)
        second = self._authorize(created)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["execution_authorization_id"], second["execution_authorization_id"])
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_authorizations").fetchone()[0], 1)

    def test_06_expired_human_approval_fails_closed_before_new_preview(self) -> None:
        self.fixture.clock.value += timedelta(hours=2)
        with self.assertRaises(NativeLiveCanaryError):
            self._create()
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_previews").fetchone()[0], 0)

    def test_07_dns_receipt_is_append_only_before_preflight(self) -> None:
        with closing(self._rw()) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE max_live_canary_dns_attempt_receipts SET bounded_result_hash=? WHERE receipt_id=?", ("f" * 64, self.dns_result["receipt_id"]))

    def test_08_consuming_execution_authorization_consumes_human_approval_once(self) -> None:
        created = self._create()
        authorization = self._authorize(created)
        consumed = self.store.consume_execution(
            execution_authorization_id=authorization["execution_authorization_id"],
            execution_authorization_hash=authorization["execution_authorization_hash"],
            actor=self.fixture.worker,
        )
        self.assertIn("approval_consumption_id", consumed)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_authorization_consumptions").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approval_v2_consumptions").fetchone()[0], 1)

    def test_09_second_execution_consumption_fails_closed(self) -> None:
        created = self._create()
        authorization = self._authorize(created)
        self.store.consume_execution(
            execution_authorization_id=authorization["execution_authorization_id"],
            execution_authorization_hash=authorization["execution_authorization_hash"],
            actor=self.fixture.worker,
        )
        with self.assertRaises(NativeLiveCanaryError):
            self.store.consume_execution(
                execution_authorization_id=authorization["execution_authorization_id"],
                execution_authorization_hash=authorization["execution_authorization_hash"],
                actor=self.fixture.worker,
            )

    def test_10_non_admin_cannot_create_execution_preview(self) -> None:
        with self.assertRaises(NativeLiveCanaryError):
            self.store.create_execution_preview(approval_id=self.approval["approval_id"], actor=self.fixture.worker)

    def test_11_non_worker_cannot_consume_execution_authorization(self) -> None:
        created = self._create()
        authorization = self._authorize(created)
        with self.assertRaises(NativeLiveCanaryError):
            self.store.consume_execution(
                execution_authorization_id=authorization["execution_authorization_id"],
                execution_authorization_hash=authorization["execution_authorization_hash"],
                actor=self.fixture.admin,
            )

    def test_12_preview_and_authorization_have_zero_external_actions(self) -> None:
        created = self._create()
        self._authorize(created)
        with closing(self._rw()) as connection:
            counts = {
                "provider": connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0],
                "network": connection.execute("SELECT COUNT(*) FROM max_live_network_attempt_records").fetchone()[0],
                "jit": connection.execute("SELECT COUNT(*) FROM max_live_canary_native_live_jit_authorities").fetchone()[0],
            }
        self.assertEqual(counts, {"provider": 0, "network": 0, "jit": 0})

    def test_13_execution_preview_verify_passes(self) -> None:
        created = self._create()
        self.assertTrue(self.store.verify(run_id=self.fixture.run_id)["ok"])
        self.assertEqual(self.store.status(execution_preview_id=created["execution_preview_id"])["execution_previews"][0]["execution_preview_id"], created["execution_preview_id"])

    def test_14_preview_ttl_is_bounded(self) -> None:
        with self.assertRaises(NativeLiveCanaryError):
            self._create(ttl_seconds=59)
        with self.assertRaises(NativeLiveCanaryError):
            self._create(ttl_seconds=3601)

    def test_15_confirmation_phrase_hash_is_not_plaintext(self) -> None:
        created = self._create()
        with closing(self._rw()) as connection:
            row = connection.execute("SELECT execution_preview_json,execution_phrase_hash FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?", (created["execution_preview_id"],)).fetchone()
        self.assertNotIn("EXECUTE MR-4B1 CANARY", row["execution_preview_json"])
        self.assertEqual(row["execution_phrase_hash"], canonical_sha256(created["confirmation_phrase"]))

    def test_16_fixture_executor_closes_native_jit_and_settles_usage(self) -> None:
        created = self._create()
        authorization = self._authorize(created)
        response_body = json.dumps(
            {
                "id": "offline-native-live-call",
                "object": "chat.completion",
                "created": 1,
                "model": self.fixture.profile.model_identity,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps({"objects": [], "relations": [], "artifact_links": [], "record_refs": [], "strategy": None, "output_summary": "bounded offline live-shape result", "role_outputs": [], "deliberation": None}, separators=(",", ":"))}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        resolver = InjectedDNSResolver({"provider.invalid": ("8.8.8.8",)})
        connector = InjectedHTTPSConnector(
            TransportResponse(200, response_body, {"content-type": "application/json"}, "offline-native-live-call", True)
        )
        credential = FixtureCredentialResolver()
        executor = NativeLiveCanaryExecutor(
            self.fixture.repo,
            admin_actor=self.fixture.admin,
            worker_actor=self.fixture.worker,
            source_database=str(self.fixture.source_database),
            expected_release_identity=self.fixture.release,
            request_builder=self.fixture.executor.request_builder,
            transport_factory=FixtureLiveProviderTransportFactory(
                resolver=resolver,
                connector=connector,
                credential_resolver=credential,
            ),
        )
        result = executor.execute(
            execution_authorization_id=authorization["execution_authorization_id"],
            execution_authorization_hash=authorization["execution_authorization_hash"],
            allow_execute=True,
        )
        if not result["ok"]:
            with closing(self._rw()) as connection:
                grant_row = connection.execute("SELECT grant_id FROM max_live_execution_grants ORDER BY granted_at DESC LIMIT 1").fetchone()
                auth_row = connection.execute("SELECT authorization_id FROM max_live_network_authorizations ORDER BY issued_at DESC LIMIT 1").fetchone()
            result["provider_preflight"] = self.fixture.provider_store.provider_live_preflight(
                run_id=self.fixture.run_id,
                grant_id=None if grant_row is None else grant_row["grant_id"],
                authorization_id=None if auth_row is None else auth_row["authorization_id"],
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["outcome"], "AUTHORITATIVE_PROVIDER_RESULT")
        self.assertEqual(connector.network_call_count, 1)
        self.assertEqual(resolver.lookup_count, 1)
        self.assertEqual(credential.read_count, 1)
        with closing(self._rw()) as connection:
            jit = connection.execute("SELECT * FROM max_live_canary_native_live_jit_authorities").fetchone()
            events = list(connection.execute("SELECT state FROM max_live_canary_native_live_jit_events ORDER BY sequence_no"))
            calls = connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0]
            grants = connection.execute("SELECT COUNT(*) FROM max_live_execution_grant_closures").fetchone()[0]
            permits = list(connection.execute("SELECT state FROM max_live_dispatch_permit_current"))
        self.assertIsNotNone(jit)
        self.assertEqual(events[-1]["state"], "closed")
        self.assertEqual(calls, 1)
        self.assertEqual(grants, 0)
        self.assertEqual([row["state"] for row in permits], ["settled"])
        self.assertTrue(executor.verify(run_id=self.fixture.run_id)["ok"])

    def test_17_live_executor_rejects_client_factory_on_non_fixture_database(self) -> None:
        self.assertTrue(NativeLiveCanaryExecutor.one_shot_only)
        self.assertFalse(NativeLiveCanaryExecutor.hermetic)

    def test_18_wrong_authorization_hash_consumes_nothing(self) -> None:
        created = self._create()
        authorization = self._authorize(created)
        with self.assertRaises(NativeLiveCanaryError):
            self.store.consume_execution(
                execution_authorization_id=authorization["execution_authorization_id"],
                execution_authorization_hash="0" * 64,
                actor=self.fixture.worker,
            )
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_authorization_consumptions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approval_v2_consumptions").fetchone()[0], 0)

    def test_19_expired_execution_authorization_fails_closed(self) -> None:
        created = self._create(ttl_seconds=60)
        authorization = self._authorize(created)
        self.fixture.clock.value += timedelta(seconds=61)
        with self.assertRaises(NativeLiveCanaryError):
            self.store.consume_execution(
                execution_authorization_id=authorization["execution_authorization_id"],
                execution_authorization_hash=authorization["execution_authorization_hash"],
                actor=self.fixture.worker,
            )
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_authorization_consumptions").fetchone()[0], 0)

    def test_20_explicit_execute_flag_and_network_gate_are_separate(self) -> None:
        created = self._create()
        authorization = self._authorize(created)
        executor = NativeLiveCanaryExecutor(self.fixture.repo, live_network_enabled=False)
        with self.assertRaises(NativeLiveCanaryError):
            executor.execute(
                execution_authorization_id=authorization["execution_authorization_id"],
                execution_authorization_hash=authorization["execution_authorization_hash"],
                allow_execute=False,
            )
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_authorization_consumptions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_live_jit_authorities").fetchone()[0], 0)

    def test_21_fixture_factory_is_rejected_for_unmarked_database(self) -> None:
        fixture = Schema22NativeFixture(complete=False, fixture_control=False)
        try:
            with self.assertRaises(NativeLiveCanaryError):
                NativeLiveCanaryExecutor(
                    fixture.repo,
                    transport_factory=FixtureLiveProviderTransportFactory(
                        resolver=InjectedDNSResolver({"provider.invalid": ("8.8.8.8",)}),
                        connector=InjectedHTTPSConnector(),
                        credential_resolver=FixtureCredentialResolver(),
                    ),
                )
        finally:
            fixture.close()

    def test_22_twenty_concurrent_authorizations_collapse_to_one(self) -> None:
        created = self._create()

        def authorize_once(_index: int) -> dict[str, object]:
            return NativeLiveExecutionStore(self.fixture.repo).authorize_execution(
                execution_preview_id=created["execution_preview_id"],
                confirmation_phrase=created["confirmation_phrase"],
                actor=self.fixture.admin,
            )

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(authorize_once, range(20)))
        self.assertEqual({item["execution_authorization_id"] for item in results}, {results[0]["execution_authorization_id"]})
        self.assertEqual(sum(not bool(item["idempotent"]) for item in results), 1)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_authorizations").fetchone()[0], 1)

    def test_23_twenty_concurrent_consumers_have_one_winner(self) -> None:
        created = self._create()
        authorization = self._authorize(created)

        def consume_once(_index: int) -> str:
            try:
                NativeLiveExecutionStore(self.fixture.repo).consume_execution(
                    execution_authorization_id=authorization["execution_authorization_id"],
                    execution_authorization_hash=authorization["execution_authorization_hash"],
                    actor=self.fixture.worker,
                )
                return "winner"
            except NativeLiveCanaryError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(consume_once, range(20)))
        self.assertEqual(results.count("winner"), 1)
        self.assertEqual(results.count("rejected"), 19)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_authorization_consumptions").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approval_v2_consumptions").fetchone()[0], 1)

    def test_24_source_database_is_byte_frozen_during_preview_authorization(self) -> None:
        before = hashlib.sha256(self.fixture.source_database.read_bytes()).hexdigest()
        created = self._create()
        self._authorize(created)
        after = hashlib.sha256(self.fixture.source_database.read_bytes()).hexdigest()
        self.assertEqual(before, after)

    def test_25_status_projection_keeps_jit_and_provider_zero_before_execute(self) -> None:
        created = self._create()
        self._authorize(created)
        status = self.store.status(execution_preview_id=created["execution_preview_id"])
        self.assertEqual(len(status["execution_previews"]), 1)
        self.assertEqual(len(status["authorizations"]), 1)
        self.assertFalse(status["authorizations"][0]["consumed"])
        self.assertEqual(status["jit_authority_count"], 0)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0], 0)

    def test_26_twenty_concurrent_execute_attempts_have_one_send(self) -> None:
        created = self._create()
        authorization = self._authorize(created)
        response_body = json.dumps(
            {
                "id": "offline-concurrent-live-call",
                "object": "chat.completion",
                "created": 1,
                "model": self.fixture.profile.model_identity,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps({"objects": [], "relations": [], "artifact_links": [], "record_refs": [], "strategy": None, "output_summary": "bounded concurrent fixture result", "role_outputs": [], "deliberation": None}, separators=(",", ":"))}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        seams: list[tuple[InjectedDNSResolver, InjectedHTTPSConnector, FixtureCredentialResolver]] = []

        def execute_once(_index: int) -> str:
            resolver = InjectedDNSResolver({"provider.invalid": ("8.8.8.8",)})
            connector = InjectedHTTPSConnector(TransportResponse(200, response_body, {"content-type": "application/json"}, "offline-concurrent-live-call", True))
            credential = FixtureCredentialResolver()
            seams.append((resolver, connector, credential))
            executor = NativeLiveCanaryExecutor(
                self.fixture.repo,
                admin_actor=self.fixture.admin,
                worker_actor=self.fixture.worker,
                source_database=str(self.fixture.source_database),
                expected_release_identity=self.fixture.release,
                request_builder=self.fixture.executor.request_builder,
                transport_factory=FixtureLiveProviderTransportFactory(resolver=resolver, connector=connector, credential_resolver=credential),
            )
            try:
                result = executor.execute(
                    execution_authorization_id=authorization["execution_authorization_id"],
                    execution_authorization_hash=authorization["execution_authorization_hash"],
                    allow_execute=True,
                )
                return "success" if result.get("ok") else str(result.get("outcome"))
            except NativeLiveCanaryError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(execute_once, range(20)))
        self.assertEqual(outcomes.count("success"), 1)
        self.assertEqual(sum(item[1].network_call_count for item in seams), 1)
        self.assertEqual(sum(item[0].lookup_count for item in seams), 1)
        self.assertEqual(sum(item[2].read_count for item in seams), 1)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_provider_call_records").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_live_jit_authorities").fetchone()[0], 1)

    def test_27_production_live_cli_surface_has_no_response_json_option(self) -> None:
        from research_kb.cli import _parser

        parser = _parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["max", "live-canary-snapshot-live-execute", "--execution-authorization-id", "a", "--execution-authorization-hash", "b", "--response-json", "{}"])


if __name__ == "__main__":
    unittest.main()
