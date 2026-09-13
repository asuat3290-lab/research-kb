"""MR-4B1C execution-window renewal tests.

Every test uses the marked disposable schema fixture.  No Pilot/V19 database,
credential resolver, system DNS, transport, or Provider is opened here.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path

from _mr4b1b_schema22_fixture import Schema22NativeFixture
from research_kb.max_research.approval_preview import LiveApprovalPreviewStore
from research_kb.max_research.dns_attempt import DNSAttemptStore
from research_kb.max_research.native_live import (
    NativeLiveCanaryError,
    NativeLiveExecutionStore,
)
from research_kb.max_research.persistence.repository import MaxControlRepository
from research_kb.max_research.provider.live import InjectedDNSResolver


class ExecutionWindowRenewalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Schema22NativeFixture(
            legacy_dns_receipt=False,
            release_residual_runner_claim=True,
            fixture_control=True,
        )
        DNSAttemptStore(self.fixture.repo).execute(
            preview_id=self.fixture.preview["preview_id"],
            request_id=self.fixture.dns_request["request_id"],
            confirmation_phrase="APPROVE MR-4B1 DNS PREFLIGHT " + self.fixture.dns_request["request_hash"],
            actor=self.fixture.admin,
            resolver=InjectedDNSResolver({"opencode.ai": ("8.8.8.8", "1.1.1.1")}),
            allow_execute=True,
        )
        live_preview = LiveApprovalPreviewStore(
            self.fixture.repo, expected_release_identity=self.fixture.release
        ).create_approval_preview(
            preparation_preview_id=self.fixture.preview["preview_id"], actor=self.fixture.admin
        )
        self.approval = LiveApprovalPreviewStore(
            self.fixture.repo, expected_release_identity=self.fixture.release
        ).authorize(
            approval_preview_id=live_preview["approval_preview_id"],
            confirmation_phrase=live_preview["confirmation_phrase"],
            actor=self.fixture.admin,
        )
        self.store = NativeLiveExecutionStore(
            self.fixture.repo, expected_release_identity=self.fixture.release
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def create(self, *, ttl_seconds: int = 300) -> dict[str, object]:
        return self.store.create_execution_preview(
            approval_id=self.approval["approval_id"], actor=self.fixture.admin, ttl_seconds=ttl_seconds
        )

    def test_unexpired_preview_is_idempotent(self) -> None:
        first = self.create()
        second = self.create()
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["execution_preview_id"], second["execution_preview_id"])
        self.assertEqual(first["generation"], 0)
        with closing(self.fixture.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_previews").fetchone()[0], 1)

    def test_expired_preview_creates_append_only_successor(self) -> None:
        first = self.create(ttl_seconds=60)
        self.fixture.clock.value += timedelta(seconds=61)
        successor = self.create(ttl_seconds=300)
        self.assertFalse(successor["idempotent"])
        self.assertEqual(successor["generation"], 1)
        self.assertEqual(successor["supersedes_execution_preview_id"], first["execution_preview_id"])
        self.assertEqual(successor["supersedes_execution_preview_hash"], first["execution_preview_hash"])
        self.assertEqual(successor["renewal_reason"], "expired_before_execution")
        self.assertNotEqual(successor["execution_preview_id"], first["execution_preview_id"])
        self.assertTrue(self.store.verify(run_id=self.fixture.run_id)["ok"])

    def test_multiple_expired_generations_are_contiguous(self) -> None:
        first = self.create(ttl_seconds=60)
        self.fixture.clock.value += timedelta(seconds=61)
        second = self.create(ttl_seconds=60)
        self.fixture.clock.value += timedelta(seconds=61)
        third = self.create(ttl_seconds=60)
        self.assertEqual([first["generation"], second["generation"], third["generation"]], [0, 1, 2])
        self.assertEqual(second["supersedes_execution_preview_id"], first["execution_preview_id"])
        self.assertEqual(third["supersedes_execution_preview_id"], second["execution_preview_id"])
        with closing(self.fixture.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_preview_current").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_preview_events").fetchone()[0], 3)
        self.assertTrue(self.store.verify(run_id=self.fixture.run_id)["ok"])

    def test_human_approval_expiry_blocks_successor(self) -> None:
        self.create(ttl_seconds=60)
        self.fixture.clock.value += timedelta(hours=2)
        with self.assertRaises(NativeLiveCanaryError):
            self.create()

    def test_consumed_human_approval_blocks_renewal(self) -> None:
        first = self.create(ttl_seconds=60)
        authorization = self.store.authorize_execution(
            execution_preview_id=first["execution_preview_id"],
            confirmation_phrase=first["confirmation_phrase"],
            actor=self.fixture.admin,
        )
        self.store.consume_execution(
            execution_authorization_id=authorization["execution_authorization_id"],
            execution_authorization_hash=authorization["execution_authorization_hash"],
            actor=self.fixture.worker,
        )
        self.fixture.clock.value += timedelta(seconds=61)
        with self.assertRaises(NativeLiveCanaryError):
            self.create()

    def test_active_lease_blocks_renewal(self) -> None:
        self.create(ttl_seconds=60)
        lease = self.fixture.repo.acquire_lease(run_id=self.fixture.run_id, actor=self.fixture.worker, ttl_seconds=900)
        self.fixture.clock.value += timedelta(seconds=61)
        with self.assertRaises(NativeLiveCanaryError) as raised:
            self.create()
        self.assertIn("active_lease_exists", str(raised.exception))
        self.fixture.repo.release_lease(run_id=self.fixture.run_id, actor=self.fixture.worker, fencing_token=lease["fencing_token"])

    def test_active_invocation_claim_blocks_renewal(self) -> None:
        self.create(ttl_seconds=60)
        lease = self.fixture.repo.acquire_lease(run_id=self.fixture.run_id, actor=self.fixture.worker, ttl_seconds=900)
        claim = self.fixture.runner.claim_invocation(run_id=self.fixture.run_id, actor=self.fixture.worker, fencing_token=lease["fencing_token"], ttl_seconds=900)
        self.fixture.clock.value += timedelta(seconds=61)
        with self.assertRaises(NativeLiveCanaryError) as raised:
            self.create()
        self.assertIn("active_lease_exists", str(raised.exception))
        self.fixture.runner.release_invocation(run_id=self.fixture.run_id, claim_id=claim["claim_id"], actor=self.fixture.worker, fencing_token=lease["fencing_token"])
        self.fixture.repo.release_lease(run_id=self.fixture.run_id, actor=self.fixture.worker, fencing_token=lease["fencing_token"])

    def test_old_phrase_cannot_authorize_successor(self) -> None:
        first = self.create(ttl_seconds=60)
        old_authorization = self.store.authorize_execution(
            execution_preview_id=first["execution_preview_id"],
            confirmation_phrase=first["confirmation_phrase"],
            actor=self.fixture.admin,
        )
        self.fixture.clock.value += timedelta(seconds=61)
        successor = self.create()
        with self.assertRaises(NativeLiveCanaryError):
            self.store.authorize_execution(
                execution_preview_id=first["execution_preview_id"],
                confirmation_phrase=first["confirmation_phrase"],
                actor=self.fixture.admin,
            )
        new_authorization = self.store.authorize_execution(
            execution_preview_id=successor["execution_preview_id"],
            confirmation_phrase=successor["confirmation_phrase"],
            actor=self.fixture.admin,
        )
        self.assertNotEqual(old_authorization["execution_authorization_id"], new_authorization["execution_authorization_id"])

    def test_forced_client_lineage_arguments_are_not_accepted(self) -> None:
        with self.assertRaises(TypeError):
            self.store.create_execution_preview(approval_id=self.approval["approval_id"], actor=self.fixture.admin, generation=99)  # type: ignore[call-arg]

    def test_restart_and_backup_restore_preserve_current_lineage(self) -> None:
        first = self.create(ttl_seconds=60)
        self.fixture.clock.value += timedelta(seconds=61)
        successor = self.create()
        restarted = MaxControlRepository(self.fixture.database, clock=self.fixture.clock)
        restarted_store = NativeLiveExecutionStore(restarted, expected_release_identity=self.fixture.release)
        self.assertEqual(restarted_store.status(execution_preview_id=successor["execution_preview_id"])["execution_previews"][-1]["generation"], 1)
        backup = Path(self.fixture.temp.name) / "backup.db"
        restored_path = Path(self.fixture.temp.name) / "restored.db"
        self.fixture.repo.backup(backup)
        MaxControlRepository(restored_path, clock=self.fixture.clock).restore(backup)
        restored = MaxControlRepository(restored_path, clock=self.fixture.clock)
        self.assertTrue(NativeLiveExecutionStore(restored).verify(run_id=self.fixture.run_id)["ok"])

    def test_twenty_concurrent_renewals_have_one_successor(self) -> None:
        first = self.create(ttl_seconds=60)
        self.fixture.clock.value += timedelta(seconds=61)

        def renew(_: int) -> dict[str, object] | str:
            try:
                return NativeLiveExecutionStore(self.fixture.repo, expected_release_identity=self.fixture.release).create_execution_preview(
                    approval_id=self.approval["approval_id"], actor=self.fixture.admin, ttl_seconds=300
                )
            except NativeLiveCanaryError as exc:
                return "rejected:" + str(exc)

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(renew, range(20)))
        successful = [item for item in results if isinstance(item, dict)]
        self.assertEqual(len(successful), 20)
        self.assertEqual(sum(not bool(item["idempotent"]) for item in successful), 1)
        self.assertEqual({item["execution_preview_id"] for item in successful}, {successful[0]["execution_preview_id"]})
        self.assertEqual(successful[0]["generation"], 1)
        self.assertEqual(first["generation"], 0)
        with closing(self.fixture.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_previews").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_execution_preview_current").fetchone()[0], 1)
        self.assertTrue(self.store.verify(run_id=self.fixture.run_id)["ok"])


if __name__ == "__main__":
    unittest.main()
