"""Current schema-22 native Preparation-to-JIT invariants.

Every test uses :class:`Schema22NativeFixture`, which creates a fresh control
database and a disposable local source database.  The tests never open the
official Pilot/V11/V12/V13 databases, resolve DNS, read credentials, or use a
physical Provider transport.
"""

from __future__ import annotations

import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

from _mr4b1b_schema22_fixture import Schema22NativeFixture
from research_kb.max_research.contract import canonical_sha256
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION
from research_kb.max_research.intent_preparer import (
    LiveCanaryIntentPreparationError,
    LiveCanaryIntentPreparer,
)
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.preparation_execution import (
    NativePreparationBridgeError,
    NativePreparationStore,
    PreparationCanaryExecutor,
)
from research_kb.max_research.preparation_handoff import PreparationHandoffError
from research_kb.max_research.provider import HermeticTransport, TransportResponse
from research_kb.max_research.release_identity import ReleaseIdentityError, normalize_release_identity
from research_kb.max_research.request_builder import ServerOwnedRequestBuilder
from research_kb.max_research.service import NativePreparationService


class CurrentNativeBridgeBehaviorTests(unittest.TestCase):
    """The schema-22 successor for the former schema-21 behavior class."""

    def setUp(self) -> None:
        self.fixture = Schema22NativeFixture()
        self.database = self.fixture.database
        self.repo = self.fixture.repo
        self.admin = self.fixture.admin
        self.worker = self.fixture.worker
        self.run_id = self.fixture.run_id
        self.store = self.fixture.store
        self.snapshots = self.fixture.snapshots
        self.snapshot = self.fixture.snapshot
        self.preview = self.fixture.preview
        self.dns_request = self.fixture.dns_request
        self.dns_result = self.fixture.dns_result
        self.phrase = self.fixture.phrase
        self.expiry = self.fixture.expiry
        self.executor = self.fixture.executor

    def tearDown(self) -> None:
        self.fixture.close()

    def _approval(self) -> dict[str, object]:
        return self.store.create_approval(
            preview_id=self.preview["preview_id"],
            confirmation_phrase=self.phrase,
            expires_at=self.expiry,
            actor=self.admin,
        )

    def _rw(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def test_01_schema22_manifest_and_quick_check(self) -> None:
        result = self.repo.verify_database()
        self.assertTrue(result["quick_check"])
        self.assertTrue(result["foreign_keys"])
        self.assertEqual(result["schema_version"], CONTROL_SCHEMA_VERSION)

    def test_02_dns_receipt_is_one_shot_and_bounded(self) -> None:
        self.assertTrue(self.dns_result["ok"])
        self.assertEqual(self.dns_result["candidate_count"], 4)
        self.assertFalse(self.dns_result["raw_ip_persisted"])
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_dns_receipts"
                ).fetchone()[0],
                1,
            )

    def test_03_dns_receipt_replay_is_idempotent(self) -> None:
        replay = self.store.record_dns_receipt(
            preview_id=self.preview["preview_id"],
            request_id=self.dns_request["request_id"],
            bounded_result=self.fixture.passed_dns_result(),
            actor=self.worker,
        )
        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["receipt_hash"], self.dns_result["receipt_hash"])

    def test_04_dns_receipt_conflicting_replay_fails_closed(self) -> None:
        with self.assertRaises(NativePreparationBridgeError):
            self.store.record_dns_receipt(
                preview_id=self.preview["preview_id"],
                request_id=self.dns_request["request_id"],
                bounded_result={
                    **self.fixture.passed_dns_result(),
                    "candidate_count": 3,
                    "ipv4_count": 3,
                },
                actor=self.worker,
            )

    def test_05_dns_raw_ip_is_rejected(self) -> None:
        with self.assertRaises(NativePreparationBridgeError):
            self.store.record_dns_receipt(
                preview_id=self.preview["preview_id"],
                request_id=self.dns_request["request_id"],
                bounded_result={
                    **self.fixture.passed_dns_result(),
                    "candidate_count": 1,
                    "ipv4_count": 1,
                    "addresses": ["203.0.113.10"],
                },
                actor=self.worker,
            )

    def test_06_dns_candidate_cap_and_family_count_fail_closed(self) -> None:
        with self.assertRaises(NativePreparationBridgeError):
            self.store.record_dns_receipt(
                preview_id=self.preview["preview_id"],
                request_id=self.dns_request["request_id"],
                bounded_result={
                    **self.fixture.passed_dns_result(),
                    "ipv4_count": 3,
                },
                actor=self.worker,
            )

    def test_07_dns_retry_is_forbidden(self) -> None:
        with self.assertRaises(NativePreparationBridgeError):
            self.store.record_dns_receipt(
                preview_id=self.preview["preview_id"],
                request_id=self.dns_request["request_id"],
                bounded_result={**self.fixture.passed_dns_result(), "retry_count": 1},
                actor=self.worker,
            )

    def test_08_dns_unsafe_result_does_not_authorize(self) -> None:
        with self.assertRaises(NativePreparationBridgeError):
            self.store.record_dns_receipt(
                preview_id=self.preview["preview_id"],
                request_id=self.dns_request["request_id"],
                bounded_result={
                    **self.fixture.passed_dns_result(),
                    "candidate_count": 0,
                    "ipv4_count": 0,
                    "all_global": False,
                    "ssrf_safe": False,
                },
                actor=self.worker,
            )

    def test_09_approval_requires_exact_phrase(self) -> None:
        with self.assertRaises(NativePreparationBridgeError):
            self.store.create_approval(
                preview_id=self.preview["preview_id"],
                confirmation_phrase=self.phrase.lower(),
                expires_at=self.expiry,
                actor=self.admin,
            )

    def test_10_approval_is_idempotent_and_phrase_is_not_persisted(self) -> None:
        first = self._approval()
        second = self._approval()
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        with closing(self._rw()) as connection:
            value = connection.execute(
                "SELECT approval_json FROM max_live_canary_native_approvals WHERE approval_id=?",
                (first["approval_id"],),
            ).fetchone()[0]
            self.assertNotIn(self.phrase, value)

    def test_11_second_approval_with_different_phrase_is_rejected(self) -> None:
        self._approval()
        with self.assertRaises(NativePreparationBridgeError):
            self.store.create_approval(
                preview_id=self.preview["preview_id"],
                confirmation_phrase="APPROVE MR-4B1 SNAPSHOT " + "f" * 64,
                expires_at=self.expiry,
                actor=self.admin,
            )

    def test_12_approval_binds_all_native_hashes(self) -> None:
        approval = self._approval()
        with closing(self._rw()) as connection:
            row = connection.execute(
                "SELECT * FROM max_live_canary_native_approvals WHERE approval_id=?",
                (approval["approval_id"],),
            ).fetchone()
            for field in (
                "snapshot_hash", "preview_hash", "snapshot_state_hash",
                "request_manifest_hash", "dns_receipt_hash", "provider_profile_hash",
                "pricing_hash", "network_policy_hash", "source_policy_hash",
                "credential_reference_hash", "release_identity_hash", "budget_hash",
                "caps_hash", "confirmation_phrase_hash",
            ):
                self.assertTrue(row[field])

    def test_13_revocation_is_append_only_and_blocks_jit(self) -> None:
        approval = self._approval()
        revoked = self.store.revoke_approval(
            approval_id=approval["approval_id"], actor=self.admin, reason="operator_stop"
        )
        self.assertEqual(revoked["status"], "revoked")
        with self.assertRaises(NativePreparationBridgeError):
            self.executor._create_jit(preview_id=self.preview["preview_id"])

    def test_14_start_approval_is_separate_from_native_approval(self) -> None:
        self._approval()
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?",
                    (self.run_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_approval_consumptions"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals").fetchone()[0],
                0,
            )

    def test_15_old_live_canary_tables_are_not_created_or_consumed(self) -> None:
        self._approval()
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM max_live_canary_previews").fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_authority_bindings"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals").fetchone()[0],
                0,
            )

    def test_16_native_execute_requires_explicit_flag_without_writing(self) -> None:
        with self.assertRaises(NativePreparationBridgeError):
            self.executor.execute_from_preview(
                preview_id=self.preview["preview_id"], allow_execute=False
            )
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_approval_consumptions"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_jit_authorities"
                ).fetchone()[0],
                0,
            )

    def test_17_jit_consumes_native_approval_once(self) -> None:
        self._approval()
        first = self.executor._create_jit(preview_id=self.preview["preview_id"])
        self.assertEqual(first["state"], "ready")
        with self.assertRaises(NativePreparationBridgeError):
            self.executor._create_jit(preview_id=self.preview["preview_id"])

    def test_18_jit_has_fresh_lease_claim_and_fence(self) -> None:
        self._approval()
        result = self.executor._create_jit(preview_id=self.preview["preview_id"])
        self.assertGreater(result["fencing_token"], self.fixture.preparation["fencing_token"])
        with closing(self._rw()) as connection:
            row = connection.execute(
                "SELECT state,claim_id,fencing_token FROM max_live_canary_native_jit_authorities WHERE authority_id=?",
                (result["authority_id"],),
            ).fetchone()
            self.assertEqual(tuple(row), ("ready", result["claim_id"], result["fencing_token"]))

    def test_19_jit_state_machine_rejects_skip_to_success(self) -> None:
        self._approval()
        result = self.executor._create_jit(preview_id=self.preview["preview_id"])
        with self.assertRaises(NativePreparationBridgeError):
            self.executor._append_event(
                authority_id=result["authority_id"],
                state="succeeded",
                actor=self.worker,
                payload={"response_hash": "a" * 64},
            )

    def test_20_jit_state_machine_terminal_close_is_irreversible(self) -> None:
        self._approval()
        result = self.executor._create_jit(preview_id=self.preview["preview_id"])
        self.executor._append_event(
            authority_id=result["authority_id"],
            state="known_pre_send_failure",
            actor=self.worker,
            payload={"error_code": "TEST_PRE_SEND", "send_boundary_reached": False},
        )
        self.executor._append_event(
            authority_id=result["authority_id"],
            state="closed",
            actor=self.worker,
            payload={"terminal_state": "known_pre_send_failure"},
        )
        with self.assertRaises(NativePreparationBridgeError):
            self.executor._append_event(
                authority_id=result["authority_id"],
                state="ready",
                actor=self.worker,
                payload={},
            )

    def test_21_native_tables_are_append_only(self) -> None:
        approval = self._approval()
        with self.assertRaises(sqlite3.DatabaseError):
            with closing(self._rw()) as connection:
                connection.execute(
                    "UPDATE max_live_canary_native_approvals SET approved_by='x' WHERE approval_id=?",
                    (approval["approval_id"],),
                )
        with self.assertRaises(sqlite3.DatabaseError):
            with closing(self._rw()) as connection:
                connection.execute(
                    "DELETE FROM max_live_canary_native_dns_receipts WHERE receipt_id=?",
                    (self.dns_result["receipt_id"],),
                )

    def test_22_native_status_is_redacted(self) -> None:
        self._approval()
        status = self.store.status(preview_id=self.preview["preview_id"])
        serialized = json.dumps(status, sort_keys=True).casefold()
        self.assertNotIn("addresses", serialized)
        self.assertNotIn("credential_value", serialized)
        self.assertNotIn("source_text", serialized)

    def test_23_release_identity_rejects_old_runtime(self) -> None:
        old = {
            **self.fixture.release,
            "package_version": "0.1.1.dev9",
            "max_control_schema_version": 20,
        }
        with self.assertRaises(NativePreparationBridgeError):
            self.store._check_release(old)

    def test_24_release_identity_rejects_unknown_fields(self) -> None:
        with self.assertRaises(ReleaseIdentityError):
            normalize_release_identity({**self.fixture.release, "unexpected": True})

    def test_25_release_identity_accepts_legacy_alias_but_emits_canonical_field(self) -> None:
        legacy = {
            key: value
            for key, value in self.fixture.release.items()
            if key != "max_control_schema_version"
        }
        legacy["control_schema_version"] = 22
        normalized = normalize_release_identity(legacy)
        self.assertEqual(normalized["max_control_schema_version"], 22)
        self.assertNotIn("control_schema_version", normalized)

    def test_26_concurrent_approval_requests_create_at_most_one_row(self) -> None:
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(lambda _: self._approval(), range(20)))
        self.assertTrue(all(item["approval_id"] == results[0]["approval_id"] for item in results))
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_approvals"
                ).fetchone()[0],
                1,
            )

    def test_27_concurrent_jit_requests_create_at_most_one_authority(self) -> None:
        self._approval()

        def attempt(_: int) -> object:
            try:
                return self.executor._create_jit(preview_id=self.preview["preview_id"])
            except Exception as exc:  # classify the losing one-shot races
                return exc

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(attempt, range(20)))
        successes = [item for item in results if isinstance(item, dict)]
        self.assertEqual(len(successes), 1)
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_jit_authorities"
                ).fetchone()[0],
                1,
            )

    def test_28_non_hermetic_transport_is_rejected_before_provider_state(self) -> None:
        self._approval()
        executor = PreparationCanaryExecutor(
            self.repo,
            store=self.store,
            admin_actor=self.admin,
            worker_actor=self.worker,
            source_database=self.fixture.source_database,
            expected_release_identity=self.fixture.release,
            transport=object(),
            request_builder=ServerOwnedRequestBuilder(gateway=self.fixture.gateway),
        )
        with self.assertRaises(NativePreparationBridgeError):
            executor.execute_from_preview(preview_id=self.preview["preview_id"], allow_execute=True)
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_jit_authorities"
                ).fetchone()[0],
                0,
            )

    def test_29_hermetic_transport_has_zero_credential_and_dns_counters_before_execute(self) -> None:
        transport = HermeticTransport()
        executor = PreparationCanaryExecutor(
            self.repo,
            store=self.store,
            admin_actor=self.admin,
            worker_actor=self.worker,
            source_database=self.fixture.source_database,
            expected_release_identity=self.fixture.release,
            transport=transport,
            request_builder=ServerOwnedRequestBuilder(gateway=self.fixture.gateway),
        )
        self.assertEqual(transport.network_call_count, 0)
        self.assertEqual(transport.credential_read_count, 0)
        self.assertEqual(getattr(transport, "dns_lookup_count", 0), 0)
        self.assertIsNotNone(executor)

    def test_30_dns_receipt_hash_is_stable_and_no_raw_ip_column_exists(self) -> None:
        with closing(self._rw()) as connection:
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(max_live_canary_native_dns_receipts)"
                )
            }
            self.assertFalse(columns & {"ip", "ips", "addresses", "raw_ip", "raw_ips"})
            row = connection.execute(
                "SELECT receipt_json,receipt_hash FROM max_live_canary_native_dns_receipts"
            ).fetchone()
            value = json.loads(row[0])
            value_hash = value.pop("receipt_hash", None)
            self.assertIsNone(value_hash)
            self.assertEqual(canonical_sha256(value), row[1])

    def test_31_formal_service_hermetic_e2e_closes_native_chain(self) -> None:
        self._approval()
        model_identity = self.fixture.profile.model_identity
        response = {
            "id": "schema22-hermetic-call",
            "object": "chat.completion",
            "model": model_identity,
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": json.dumps({
                        "objects": [],
                        "relations": [],
                        "artifact_links": [],
                        "record_refs": [],
                        "strategy": None,
                        "output_summary": "bounded hermetic result",
                        "role_outputs": [],
                        "deliberation": None,
                    }, separators=(",", ":")),
                },
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }
        transport = HermeticTransport([
            TransportResponse(200, response, {"content-type": "application/json"}, "schema22-hermetic-call", True)
        ])
        import research_kb.max_research.request_builder as request_builder_module

        prior_core_database = request_builder_module.CORE_DATABASE
        request_builder_module.CORE_DATABASE = self.fixture.source_database
        try:
            service = NativePreparationService(
                self.repo,
                self.admin,
                worker_actor=self.worker,
                source_database=self.fixture.source_database,
                expected_release_identity=self.fixture.release,
                transport=transport,
            )
            result = service.execute_from_preview(
                preview_id=self.preview["preview_id"], allow_execute=True
            )
        finally:
            request_builder_module.CORE_DATABASE = prior_core_database
        self.assertEqual(result["outcome"], "CANARY_SUCCEEDED")
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(transport.network_call_count, 0)
        self.assertEqual(transport.credential_read_count, 0)
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_native_approval_consumptions"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM max_live_canary_native_jit_events ORDER BY rowid DESC LIMIT 1"
                ).fetchone()[0],
                "closed",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_provider_call_records WHERE run_id=?",
                    (self.run_id,),
                ).fetchone()[0],
                1,
            )
        self.assertTrue(self.repo.verify_database()["ok"])

    def test_33_schema22_crash_after_preparation_claim_recovers_without_duplicates(self) -> None:
        """The former schema-19 crash seam is current schema-22 coverage."""

        fixture = Schema22NativeFixture(complete=False)
        try:
            import research_kb.max_research.request_builder as request_builder_module

            prior_core_database = request_builder_module.CORE_DATABASE
            request_builder_module.CORE_DATABASE = fixture.source_database
            failing = LiveCanaryIntentPreparer(
                fixture.repo,
                worker_actor=fixture.worker,
                gateway=fixture.gateway,
                failure_injection="claim_after",
            )
            try:
                with self.assertRaises(LiveCanaryIntentPreparationError):
                    failing.prepare(**fixture.preparation_kwargs)

                recovered = LiveCanaryIntentPreparer(
                    fixture.repo,
                    worker_actor=fixture.worker,
                    gateway=fixture.gateway,
                ).prepare(**fixture.preparation_kwargs)
            finally:
                request_builder_module.CORE_DATABASE = prior_core_database
            self.assertTrue(recovered["ok"])
            self.assertFalse(recovered["idempotent"])
            self.assertEqual(recovered["counts"]["active_leases"], 1)
            self.assertEqual(recovered["counts"]["active_invocation_claims"], 1)
            self.assertEqual(recovered["counts"]["open_iterations"], 1)
            self.assertEqual(recovered["counts"]["intents"], 1)
            for key in (
                "dispatch_acks",
                "attempts",
                "results",
                "usage_bindings",
                "iteration_outcomes",
                "live_approvals",
                "provider_calls",
            ):
                self.assertEqual(recovered["counts"][key], 0)

            verification = fixture.repo.verify_database()
            self.assertTrue(verification["quick_check"])
            self.assertTrue(verification["foreign_keys"])
            with closing(fixture.repo._connect(read_only=True)) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM max_model_call_intents WHERE run_id=?",
                        (fixture.run_id,),
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM max_runner_intent_manifests WHERE run_id=?",
                        (fixture.run_id,),
                    ).fetchone()[0],
                    1,
                )
        finally:
            fixture.close()

    def test_32_known_pre_send_failure_closes_runner_and_jit(self) -> None:
        class BrokenRequestBuilder:
            def build_from_row(self, **_: object) -> object:
                raise RuntimeError("injected pre-send request-build failure")

        self._approval()
        transport = HermeticTransport()
        executor = PreparationCanaryExecutor(
            self.repo,
            store=self.store,
            admin_actor=self.admin,
            worker_actor=self.worker,
            source_database=self.fixture.source_database,
            expected_release_identity=self.fixture.release,
            transport=transport,
            request_builder=BrokenRequestBuilder(),
        )
        result = executor.execute_from_preview(
            preview_id=self.preview["preview_id"], allow_execute=True
        )
        self.assertEqual(result["outcome"], "KNOWN_PRE_SEND_FAILURE")
        self.assertEqual(len(transport.requests), 0)
        self.assertEqual(transport.network_call_count, 0)
        self.assertEqual(transport.credential_read_count, 0)
        with closing(self._rw()) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM max_live_execution_grants").fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM max_live_canary_native_jit_events ORDER BY rowid DESC LIMIT 1"
                ).fetchone()[0],
                "closed",
            )
        self.assertTrue(self.repo.verify_database()["ok"])


if __name__ == "__main__":
    unittest.main()
