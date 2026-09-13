"""MR-4B1B-v11R1 lifetime-separation tests.

Every test operates on a temporary copy of the frozen V11 control DB.  The
frozen source DB is never opened writable and no DNS, credential resolver,
transport, or Provider adapter is constructed.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from research_kb.max_research.lifetime_separation import PreparationSnapshotError, PreparationSnapshotStore
from research_kb.max_research.persistence.db import MaxControlError, connect_control_db
from research_kb.max_research.persistence.migrations import apply_migrations
from research_kb.max_research.persistence.repository import MaxControlRepository
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.persistence.version import CONTROL_SCHEMA_VERSION
from research_kb.policy import Actor


V11_DB = Path(os.environ.get("MR4B1B_V11_DB", r"D:\research-kb-canary\control\max-canary-v11-preview.db"))
V10_DB = Path(os.environ.get("MR4B1B_V10_DB", r"D:\research-kb-canary\control\max-canary-v10-preview.db"))
PILOT_DB = Path(os.environ.get("MR4B1B_PILOT_DB", r"D:\research-kb-pilot\data\research.db"))


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 16, 14, 0, 10, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


@unittest.skipUnless(V11_DB.is_file() and PILOT_DB.is_file(), "production-shaped V11/Pilot fixtures are unavailable")
class MR4B1BV11R1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr4b1b-v11r1-")
        self.database = Path(self.temp.name) / "control.db"
        self.frozen_hash = hashlib.sha256(V11_DB.read_bytes()).hexdigest()
        shutil.copy2(V11_DB, self.database)
        connection = connect_control_db(self.database, read_only=False)
        try:
            apply_migrations(connection)
        finally:
            connection.close()
        self.clock = _Clock()
        self.repo = MaxControlRepository(self.database, clock=self.clock)
        self.store = PreparationSnapshotStore(self.repo, source_database=PILOT_DB)
        self.admin = Actor("mr4b1b-v11r1-test-admin", "mr4b1b-v11r1-test-admin-session", "user", "admin", "mr4b1b-v11r1-tests")
        self.run_id = "mr1:run:ced5e62e91525bfac27d5dc1c414de294c0e81b7c1130860"
        self.source_policy_hash = "e6e14bb69f331abd3e54400b75d053c38eed319fff18a2b4311285220073964b"
        with closing(sqlite3.connect(self.database)) as connection:
            connection.row_factory = sqlite3.Row
            lease = connection.execute("SELECT owner_id,session_id,fencing_token FROM max_leases WHERE run_id=?", (self.run_id,)).fetchone()
            claim = connection.execute("SELECT claim_id FROM max_runner_invocation_claims WHERE run_id=? AND status='active' ORDER BY rowid DESC LIMIT 1", (self.run_id,)).fetchone()
            request = connection.execute("SELECT request_hash,wire_request_hash,manifest_hash FROM max_live_canary_request_manifests WHERE run_id=? LIMIT 1", (self.run_id,)).fetchone()
        self.worker = Actor(lease["owner_id"], lease["session_id"], "worker", "runner", "mr4b1b-v11r1-tests")
        if claim is not None:
            RunnerPersistence(self.repo).release_invocation(run_id=self.run_id, claim_id=claim["claim_id"], actor=self.worker, fencing_token=int(lease["fencing_token"]))
        self.repo.release_lease(run_id=self.run_id, actor=self.worker, fencing_token=int(lease["fencing_token"]))
        self.request = dict(request)
        self.source = {
            "document_id": "doc_6102ba2b793e3983c38e",
            "passage_id": "psg_00000000000000000001",
            "source_version": "publisher-pdf",
            "document_content_hash": "6102ba2b793e3983c38ee20167f06fa300eddc58f9988e75ad1f511805e9b8f8",
            "passage_content_hash": "4e61fef6d56184685892ec934ef4f7fc76cb7a24ee9fbae00a932be1ba44583c",
            "source_role": "core_research_object", "evidential_function": "supports", "purpose": "supports",
        }
        self.caps = {
            "max_provider_calls": 1, "max_ticks": 1, "max_iterations": 1,
            "max_acquisition_requests": 0, "max_ocr_requests": 0, "max_ingest_operations": 0,
            "max_input_tokens": 4096, "max_output_tokens": 256, "max_cache_read_tokens": 4096,
            "max_reasoning_tokens": 256, "max_cost_units": 729, "max_wall_clock_seconds": 120,
            "max_source_passages": 1, "max_source_characters": 2000,
        }
        self.release = {
            "package": "research-kb", "package_version": "0.1.1.dev9",
            "wheel_sha256": "1" * 64, "sdist_sha256": "2" * 64, "source_tree_sha256": "3" * 64,
            "release_manifest_sha256": "4" * 64, "migration_release_manifest_sha256": "5" * 64,
            "core_schema_version": 5, "control_schema_version": 20,
        }
        self.preparation = {
            "request_hash": self.request["request_hash"],
            "wire_request_hash": self.request["wire_request_hash"],
            "request_manifest_hash": self.request["manifest_hash"],
            "source_manifest_sha256": "6" * 64,
        }
        self.snapshot = self.store.create_snapshot(run_id=self.run_id, source_binding=self.source, preparation=self.preparation, caps=self.caps, release_identity=self.release, actor=self.admin)

    def tearDown(self) -> None:
        self.assertEqual(self.frozen_hash, hashlib.sha256(V11_DB.read_bytes()).hexdigest())
        self.temp.cleanup()

    def _dns(self) -> dict[str, object]:
        return {"hostname": "opencode.ai", "port": 443, "scheme": "https", "max_dns_candidates": 16, "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0, "provider_calls": 0, "cost_units": 0}

    def test_snapshot_is_idempotent_and_non_executable(self) -> None:
        repeated = self.store.create_snapshot(run_id=self.run_id, source_binding=self.source, preparation=self.preparation, caps=self.caps, release_identity=self.release, actor=self.admin)
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(repeated["snapshot_hash"], self.snapshot["snapshot_hash"])
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute("SELECT snapshot_json FROM max_live_canary_preparation_snapshots WHERE snapshot_id=?", (self.snapshot["snapshot_id"],)).fetchone()
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_jit_execution_authorities").fetchone()[0], 0)
        serialized = row[0].casefold()
        for forbidden in ('"prompt":', '"messages":', '"source_text":', '"endpoint":', '"endpoint_origin":', '"credential":', '"fencing_token":', '"claim_id":', '"lease_id":'):
            self.assertNotIn(forbidden, serialized)

    def test_snapshot_survives_clock_past_old_lease_and_claim(self) -> None:
        self.clock.advance(minutes=2)
        status = self.store.status(snapshot_id=self.snapshot["snapshot_id"], release_identity=self.release)
        self.assertTrue(status["ok"], status)
        self.assertFalse(status["active_lease_required"])
        self.assertFalse(status["active_claim_required"])

    def test_preview_does_not_require_lease_or_claim(self) -> None:
        preview = self.store.preview_from_snapshot(snapshot_id=self.snapshot["snapshot_id"], dns_policy=self._dns(), actor=self.admin)
        self.assertEqual(preview["status"], "AWAITING_DNS_PREFLIGHT_AUTHORIZATION")
        self.assertEqual(preview["human_approval_consumed"], 0)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_jit_execution_authorities").fetchone()[0], 0)

    def test_preview_replay_is_idempotent(self) -> None:
        first = self.store.preview_from_snapshot(snapshot_id=self.snapshot["snapshot_id"], dns_policy=self._dns(), actor=self.admin)
        second = self.store.preview_from_snapshot(snapshot_id=self.snapshot["snapshot_id"], dns_policy=self._dns(), actor=self.admin)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["preview_hash"], second["preview_hash"])

    def test_dns_request_is_fresh_and_never_executes(self) -> None:
        preview = self.store.preview_from_snapshot(snapshot_id=self.snapshot["snapshot_id"], dns_policy=self._dns(), actor=self.admin)
        request = self.store.create_dns_only_request(preview_id=preview["preview_id"], actor=self.admin)
        self.assertEqual(request["status"], "AWAITING_DNS_PREFLIGHT_AUTHORIZATION")
        self.assertEqual(request["dns_executed"], 0)
        self.assertEqual(request["credential_reads"], 0)
        self.assertEqual(request["provider_calls"], 0)

    def test_invalid_dns_policy_fails_closed(self) -> None:
        with self.assertRaises(PreparationSnapshotError):
            self.store.preview_from_snapshot(snapshot_id=self.snapshot["snapshot_id"], dns_policy={**self._dns(), "tcp_connections": 1}, actor=self.admin)

    def test_explicit_invalidation_is_append_only(self) -> None:
        result = self.store.invalidate(snapshot_id=self.snapshot["snapshot_id"], reason_code="source_version_drift", actor=self.admin)
        self.assertEqual(result["status"], "invalidated")
        status = self.store.status(snapshot_id=self.snapshot["snapshot_id"], release_identity=self.release)
        self.assertFalse(status["ok"])
        self.assertEqual(status["status"], "invalidated")

    def test_approval_binds_snapshot_not_old_authority(self) -> None:
        preview = self.store.preview_from_snapshot(snapshot_id=self.snapshot["snapshot_id"], dns_policy=self._dns(), actor=self.admin)
        approval = self.store.create_human_approval(preview_id=preview["preview_id"], actor=self.admin, expires_at="2026-08-16T20:00:00.000Z", reason_hash="a" * 64)
        self.assertIn("approval_id", approval)
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute("SELECT snapshot_id,preview_id FROM max_live_canary_preparation_approvals WHERE approval_id=?", (approval["approval_id"],)).fetchone()
            self.assertEqual(tuple(row), (self.snapshot["snapshot_id"], preview["preview_id"]))

    def test_jit_consumes_once_and_creates_fresh_fence_atomically(self) -> None:
        preview = self.store.preview_from_snapshot(snapshot_id=self.snapshot["snapshot_id"], dns_policy=self._dns(), actor=self.admin)
        approval = self.store.create_human_approval(preview_id=preview["preview_id"], actor=self.admin, expires_at="2026-08-16T20:00:00.000Z", reason_hash="b" * 64)
        jit = self.store.issue_jit_authority(approval_id=approval["approval_id"], worker=self.worker, ttl_seconds=600)
        self.assertTrue(jit["must_send_immediately"])
        self.assertEqual(jit["retry"], 0)
        self.assertGreater(jit["lease"]["fencing_token"], 0)
        with self.assertRaises(PreparationSnapshotError):
            self.store.issue_jit_authority(approval_id=approval["approval_id"], worker=self.worker, ttl_seconds=600)

    def test_jit_requires_approval_and_never_creates_one(self) -> None:
        with self.assertRaises(PreparationSnapshotError):
            self.store.issue_jit_authority(approval_id="missing", worker=self.worker)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_preparation_approval_consumptions").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_live_canary_jit_execution_authorities").fetchone()[0], 0)

    def test_append_only_tables_reject_update_and_delete(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            with closing(sqlite3.connect(self.database)) as connection:
                connection.execute("UPDATE max_live_canary_preparation_snapshots SET project_id='x' WHERE snapshot_id=?", (self.snapshot["snapshot_id"],))
        with self.assertRaises(sqlite3.DatabaseError):
            with closing(sqlite3.connect(self.database)) as connection:
                connection.execute("DELETE FROM max_live_canary_preparation_snapshots WHERE snapshot_id=?", (self.snapshot["snapshot_id"],))

    def test_migration_twenty_is_repeatable_and_integrity_is_clean(self) -> None:
        connection = connect_control_db(self.database, read_only=False)
        try:
            self.assertEqual(apply_migrations(connection), CONTROL_SCHEMA_VERSION)
            self.assertEqual(connection.execute("pragma quick_check").fetchone()[0], "ok")
            self.assertEqual(list(connection.execute("pragma foreign_key_check")), [])
        finally:
            connection.close()

@unittest.skipUnless(V10_DB.is_file(), "production-shaped V10 fixture is unavailable")
class MR4B1BV11R1LegacySchemaTests(unittest.TestCase):
    """Schema-19 history is inspectable but is never auto-upgraded."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr4b1b-v11r1-legacy-")
        self.database = Path(self.temp.name) / "control.db"
        self.frozen_hash = hashlib.sha256(V10_DB.read_bytes()).hexdigest()
        shutil.copy2(V10_DB, self.database)

    def tearDown(self) -> None:
        self.assertEqual(self.frozen_hash, hashlib.sha256(V10_DB.read_bytes()).hexdigest())
        self.temp.cleanup()

    def test_schema19_is_read_only_and_not_a_snapshot(self) -> None:
        repo = MaxControlRepository(self.database)
        with closing(repo._connect(read_only=True)) as connection:
            versions = tuple(row[0] for row in connection.execute("SELECT version FROM max_schema_migrations ORDER BY version"))
            self.assertEqual(versions[-1], 19)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='max_live_canary_preparation_snapshots'").fetchone()[0], 0)
        with self.assertRaises(MaxControlError):
            repo._connect(read_only=False)


if __name__ == "__main__":
    unittest.main()
