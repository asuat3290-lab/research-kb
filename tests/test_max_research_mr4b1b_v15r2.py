"""Offline MR-4B1B-v15R2 Live Approval Preview closure tests."""

from __future__ import annotations

import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta

from _mr4b1b_schema22_fixture import Schema22NativeFixture
from research_kb.max_research.approval_preview import (
    LiveApprovalPreviewError,
    LiveApprovalPreviewStore,
)
from research_kb.max_research.dns_attempt import DNSAttemptError, DNSAttemptStore
from research_kb.max_research.persistence import MaxControlError, MaxControlRepository
from research_kb.max_research.provider.live import InjectedDNSResolver
from research_kb.max_research.service import NativePreparationService
from research_kb.max_research.persistence.version import CONTROL_SCHEMA_VERSION
from research_kb.max_research.contract import canonical_sha256
from research_kb.policy import Actor


class LiveApprovalPreviewClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Schema22NativeFixture(
            legacy_dns_receipt=False,
            release_residual_runner_claim=True,
        )
        self.dns = DNSAttemptStore(self.fixture.repo)
        self.dns_result = self.dns.execute(
            preview_id=self.fixture.preview["preview_id"],
            request_id=self.fixture.dns_request["request_id"],
            confirmation_phrase="APPROVE MR-4B1 DNS PREFLIGHT " + self.fixture.dns_request["request_hash"],
            actor=self.fixture.admin,
            resolver=InjectedDNSResolver({"opencode.ai": ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")}),
            allow_execute=True,
        )
        self.store = LiveApprovalPreviewStore(
            self.fixture.repo,
            expected_release_identity=self.fixture.release,
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def _create(self, **kwargs):
        return self.store.create_approval_preview(
            preparation_preview_id=self.fixture.preview["preview_id"],
            actor=self.fixture.admin,
            **kwargs,
        )

    def _control_text(self) -> str:
        with closing(sqlite3.connect(self.fixture.database)) as connection:
            rows = connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL "
                "UNION ALL SELECT 'preview',preview_json FROM max_live_canary_approval_previews "
                "UNION ALL SELECT 'approval',approval_json FROM max_live_canary_native_approvals_v2"
            ).fetchall()
        return "\n".join(str(item) for row in rows for item in row)

    def _rw(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.fixture.database)
        connection.row_factory = sqlite3.Row
        return connection

    def test_01_current_schema_and_zero_baseline(self) -> None:
        verified = self.fixture.repo.verify_database()
        self.assertTrue(verified["ok"], verified)
        self.assertEqual(CONTROL_SCHEMA_VERSION, 32)
        self.assertEqual(verified["schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertTrue(verified["quick_check"])
        self.assertTrue(verified["foreign_keys"])
        self.assertEqual(verified["provider"]["counts"]["calls"], 0)

    def test_02_preview_is_awaiting_human_approval(self) -> None:
        result = self._create()
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "AWAITING_HUMAN_APPROVAL")
        self.assertEqual(result["live_canary_approval_created"], 0)
        self.assertEqual(result["jit_authority_created"], 0)

    def test_03_preview_binds_durable_dns_objects(self) -> None:
        result = self._create()
        with closing(self._rw()) as connection:
            row = connection.execute(
                "SELECT * FROM max_live_canary_approval_previews WHERE approval_preview_id=?",
                (result["approval_preview_id"],),
            ).fetchone()
            receipt = connection.execute(
                "SELECT * FROM max_live_canary_dns_attempt_receipts WHERE receipt_id=?",
                (result["dns_receipt_id"],),
            ).fetchone()
        self.assertEqual(row["dns_attempt_id"], self.dns_result["attempt_id"])
        self.assertEqual(row["dns_receipt_hash"], receipt["receipt_hash"])
        self.assertEqual(row["bounded_dns_result_hash"], receipt["bounded_result_hash"])
        self.assertEqual(row["handoff_state"], "PREPARED_AWAITING_AUTHORIZATION")

    def test_04_new_phrase_is_hash_bound(self) -> None:
        result = self._create()
        self.assertEqual(
            result["confirmation_phrase"],
            "APPROVE MR-4B1 CANARY " + result["approval_preview_hash"],
        )
        self.assertEqual(result["confirmation_phrase_hash"], canonical_sha256(result["confirmation_phrase"]))

    def test_05_phrase_plaintext_is_not_persisted(self) -> None:
        result = self._create()
        text = self._control_text()
        self.assertNotIn(result["confirmation_phrase"], text)
        self.assertNotIn("APPROVE MR-4B1 CANARY", text)
        self.assertIn(result["confirmation_phrase_hash"], text)

    def test_06_preview_creation_is_idempotent(self) -> None:
        first = self._create()
        second = self._create()
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["approval_preview_id"], second["approval_preview_id"])
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_approval_previews").fetchone()[0], 1)

    def test_07_twenty_preview_replays_have_one_row(self) -> None:
        def create_one(_: int):
            try:
                return self._create()["approval_preview_id"]
            except LiveApprovalPreviewError as exc:  # pragma: no cover - diagnostic result
                return type(exc).__name__

        values = list(ThreadPoolExecutor(max_workers=20).map(create_one, range(20)))
        self.assertEqual(len(set(values)), 1)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_approval_previews").fetchone()[0], 1)

    def test_08_preview_does_not_create_any_approval_or_jit(self) -> None:
        self._create()
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals_v2").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_jit_authorities").fetchone()[0], 0)

    def test_09_preview_requires_durable_receipt(self) -> None:
        fixture = Schema22NativeFixture(legacy_dns_receipt=True, release_residual_runner_claim=True)
        try:
            store = LiveApprovalPreviewStore(fixture.repo, expected_release_identity=fixture.release)
            with self.assertRaises(LiveApprovalPreviewError):
                store.create_approval_preview(preparation_preview_id=fixture.preview["preview_id"], actor=fixture.admin)
        finally:
            fixture.close()

    def test_10_unknown_preparation_selector_fails_closed(self) -> None:
        with self.assertRaises(LiveApprovalPreviewError):
            self.store.create_approval_preview(preparation_preview_id="preparation-preview-not-found", actor=self.fixture.admin)

    def test_11_non_admin_cannot_create_preview(self) -> None:
        actor = Actor("researcher", "researcher-session", "agent", "researcher", "offline-test")
        with self.assertRaises(LiveApprovalPreviewError):
            self.store.create_approval_preview(preparation_preview_id=self.fixture.preview["preview_id"], actor=actor)

    def test_12_ttl_boolean_is_rejected(self) -> None:
        with self.assertRaises(LiveApprovalPreviewError):
            self._create(preview_ttl_seconds=True)

    def test_13_ttl_outside_bound_is_rejected(self) -> None:
        with self.assertRaises(LiveApprovalPreviewError):
            self._create(preview_ttl_seconds=299)
        with self.assertRaises(LiveApprovalPreviewError):
            self._create(approval_ttl_seconds=24 * 3600 + 1)

    def test_14_approval_ttl_cannot_outlive_preview(self) -> None:
        with self.assertRaises(LiveApprovalPreviewError):
            self._create(preview_ttl_seconds=300, approval_ttl_seconds=301)

    def test_15_status_is_redacted(self) -> None:
        created = self._create()
        status = self.store.status(approval_preview_id=created["approval_preview_id"])
        rendered = json.dumps(status, sort_keys=True)
        self.assertNotIn(created["confirmation_phrase"], rendered)
        self.assertNotIn("source_text", rendered)
        self.assertNotIn("credential_reference_hash", rendered.casefold())

    def test_16_formal_service_rejects_old_authorize_shape(self) -> None:
        service = NativePreparationService(self.fixture.repo, self.fixture.admin, source_database=self.fixture.source_database)
        with self.assertRaises(MaxControlError):
            service.authorize(
                preview_id=self.fixture.preview["preview_id"],
                confirmation_phrase=self.fixture.phrase,
                expires_at=self.fixture.expiry,
            )

    def test_17_old_preparation_phrase_is_not_a_live_preview_phrase(self) -> None:
        created = self._create()
        with self.assertRaises(LiveApprovalPreviewError):
            self.store.authorize(
                approval_preview_id=created["approval_preview_id"],
                confirmation_phrase=self.fixture.phrase,
                actor=self.fixture.admin,
            )

    def test_18_preparation_preview_id_cannot_authorize_directly(self) -> None:
        with self.assertRaises(LiveApprovalPreviewError):
            self.store.authorize(
                approval_preview_id=self.fixture.preview["preview_id"],
                confirmation_phrase="APPROVE MR-4B1 CANARY " + "0" * 64,
                actor=self.fixture.admin,
            )

    def test_19_wrong_live_phrase_fails_before_approval_write(self) -> None:
        created = self._create()
        with self.assertRaises(LiveApprovalPreviewError):
            self.store.authorize(
                approval_preview_id=created["approval_preview_id"],
                confirmation_phrase="APPROVE MR-4B1 CANARY " + "0" * 64,
                actor=self.fixture.admin,
            )
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals_v2").fetchone()[0], 0)

    def test_20_authorize_uses_server_owned_bindings_and_creates_v2_only(self) -> None:
        created = self._create()
        approval = self.store.authorize(
            approval_preview_id=created["approval_preview_id"],
            confirmation_phrase=created["confirmation_phrase"],
            actor=self.fixture.admin,
        )
        self.assertTrue(approval["ok"])
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals_v2").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approval_v2_consumptions").fetchone()[0], 0)

    def test_21_authorize_is_idempotent_for_same_preview(self) -> None:
        created = self._create()
        first = self.store.authorize(approval_preview_id=created["approval_preview_id"], confirmation_phrase=created["confirmation_phrase"], actor=self.fixture.admin)
        second = self.store.authorize(approval_preview_id=created["approval_preview_id"], confirmation_phrase=created["confirmation_phrase"], actor=self.fixture.admin)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["approval_id"], second["approval_id"])

    def test_22_twenty_authorize_replays_have_one_v2_approval(self) -> None:
        created = self._create()

        def authorize_one(_: int):
            try:
                return self.store.authorize(approval_preview_id=created["approval_preview_id"], confirmation_phrase=created["confirmation_phrase"], actor=self.fixture.admin)["approval_id"]
            except LiveApprovalPreviewError as exc:  # pragma: no cover - diagnostic result
                return type(exc).__name__

        values = list(ThreadPoolExecutor(max_workers=20).map(authorize_one, range(20)))
        self.assertEqual(len(set(values)), 1)
        with closing(self._rw()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals_v2").fetchone()[0], 1)

    def test_23_expired_preview_cannot_authorize(self) -> None:
        created = self._create()
        self.fixture.clock.value += timedelta(hours=2)
        with self.assertRaises(LiveApprovalPreviewError):
            self.store.authorize(approval_preview_id=created["approval_preview_id"], confirmation_phrase=created["confirmation_phrase"], actor=self.fixture.admin)

    def test_24_preview_rows_are_append_only(self) -> None:
        created = self._create()
        with closing(self._rw()) as connection:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("UPDATE max_live_canary_approval_previews SET state='SUPERSEDED' WHERE approval_preview_id=?", (created["approval_preview_id"],))

    def test_25_v2_approval_rows_are_append_only(self) -> None:
        created = self._create()
        approval = self.store.authorize(approval_preview_id=created["approval_preview_id"], confirmation_phrase=created["confirmation_phrase"], actor=self.fixture.admin)
        with closing(self._rw()) as connection:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("UPDATE max_live_canary_native_approvals_v2 SET model_identity='tampered' WHERE approval_id=?", (approval["approval_id"],))

    def test_26_preview_hash_and_phrase_hash_are_recomputed(self) -> None:
        created = self._create()
        with closing(self._rw()) as connection:
            row = connection.execute("SELECT preview_json,approval_preview_hash,confirmation_phrase_hash FROM max_live_canary_approval_previews WHERE approval_preview_id=?", (created["approval_preview_id"],)).fetchone()
        value = json.loads(row[0])
        phrase_hash = value.pop("confirmation_phrase_hash")
        self.assertEqual(phrase_hash, row[2])
        self.assertEqual(canonical_sha256(value), row[1])

    def test_27_no_raw_ip_or_phrase_is_written_by_preview_layer(self) -> None:
        created = self._create()
        text = self._control_text()
        self.assertNotIn("8.8.8.8", text)
        self.assertNotIn("1.1.1.1", text)
        self.assertNotIn(created["confirmation_phrase"], text)

    def test_28_all_external_counters_remain_zero(self) -> None:
        created = self._create()
        self.assertEqual(created["credential_reads"], 0)
        self.assertEqual(created["provider_calls"], 0)
        self.assertEqual(created["cost_units"], 0)
        verified = self.store.verify(approval_preview_id=created["approval_preview_id"])
        self.assertEqual(verified["jit_authority_created"], 0)
        self.assertEqual(verified["provider_calls"], 0)

    def test_29_cost_cap_is_effective_and_bounded(self) -> None:
        created = self._create()
        with closing(self._rw()) as connection:
            row = connection.execute("SELECT human_cost_ceiling,profile_cost_ceiling,effective_cost_cap,max_input_tokens,max_output_tokens,max_provider_calls FROM max_live_canary_approval_previews WHERE approval_preview_id=?", (created["approval_preview_id"],)).fetchone()
        self.assertLessEqual(row[2], row[0])
        self.assertLessEqual(row[2], row[1])
        self.assertEqual(tuple(row[3:]), (4096, 256, 1))

    def test_30_release_source_provider_and_budget_hashes_match_handoff(self) -> None:
        created = self._create()
        with closing(self._rw()) as connection:
            row = connection.execute("SELECT * FROM max_live_canary_approval_previews WHERE approval_preview_id=?", (created["approval_preview_id"],)).fetchone()
            handoff = connection.execute("SELECT * FROM max_runner_preparation_handoffs WHERE handoff_id=?", (row["handoff_id"],)).fetchone()
        for key in ("release_identity_hash", "provider_profile_hash", "pricing_hash", "network_policy_hash", "source_policy_hash", "credential_reference_hash", "budget_hash"):
            self.assertEqual(row[key], handoff[key])

    def test_31_verify_and_repository_integrity_pass(self) -> None:
        created = self._create()
        self.assertTrue(self.store.verify(approval_preview_id=created["approval_preview_id"])["ok"])
        verified = self.fixture.repo.verify_database()
        self.assertTrue(verified["ok"], verified)
        self.assertTrue(verified["quick_check"])
        self.assertTrue(verified["foreign_keys"])

    def test_32_backup_restore_preserves_preview_without_approval(self) -> None:
        created = self._create()
        root = self.fixture.temp.name
        backup = root + "\\v15r2-preview-backup.db"
        restored = root + "\\v15r2-preview-restored.db"
        self.fixture.repo.backup(backup)
        MaxControlRepository(restored, clock=self.fixture.clock).restore(backup)
        restored_store = LiveApprovalPreviewStore(MaxControlRepository(restored, clock=self.fixture.clock), expected_release_identity=self.fixture.release)
        self.assertEqual(restored_store.status(approval_preview_id=created["approval_preview_id"])["approval_preview_hash"], created["approval_preview_hash"])
        with closing(sqlite3.connect(restored)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals_v2").fetchone()[0], 0)

    def test_33_failed_dns_receipt_cannot_create_live_preview(self) -> None:
        fixture = Schema22NativeFixture(legacy_dns_receipt=False, release_residual_runner_claim=True)
        try:
            result = DNSAttemptStore(fixture.repo).execute(
                preview_id=fixture.preview["preview_id"],
                request_id=fixture.dns_request["request_id"],
                confirmation_phrase="APPROVE MR-4B1 DNS PREFLIGHT " + fixture.dns_request["request_hash"],
                actor=fixture.admin,
                resolver=InjectedDNSResolver({"opencode.ai": ("127.0.0.1",)}),
                allow_execute=True,
            )
            self.assertEqual(result["state"], "FAILED_WITH_BOUNDED_RESULT")
            store = LiveApprovalPreviewStore(fixture.repo, expected_release_identity=fixture.release)
            with self.assertRaises(LiveApprovalPreviewError):
                store.create_approval_preview(preparation_preview_id=fixture.preview["preview_id"], actor=fixture.admin)
        finally:
            fixture.close()

    def test_34_start_and_live_approval_counters_are_separate(self) -> None:
        created = self._create()
        with closing(self._rw()) as connection:
            start_consumptions = connection.execute("SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?", (self.fixture.run_id,)).fetchone()[0]
            old_live = connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals WHERE run_id=?", (self.fixture.run_id,)).fetchone()[0]
            new_live = connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals_v2 WHERE run_id=?", (self.fixture.run_id,)).fetchone()[0]
        self.assertEqual(start_consumptions, 1)
        self.assertEqual(old_live, 0)
        self.assertEqual(new_live, 0)
        self.assertEqual(created["live_canary_approval_created"], 0)


if __name__ == "__main__":
    unittest.main()
