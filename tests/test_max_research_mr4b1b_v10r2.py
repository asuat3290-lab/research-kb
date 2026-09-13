"""MR-4B1B-v10R2 durable-intent prepare-only tests.

The integration fixture is a byte-for-byte temporary copy of the frozen V10
control DB.  The frozen DB itself is never opened writable.  No adapter,
transport, resolver, credential resolver, or Provider call is constructed.
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
from pathlib import Path

from research_kb.max_research.intent_preparer import LiveCanaryIntentPreparationError, LiveCanaryIntentPreparer
from research_kb.max_research.long_run import LocalCoreEvidenceGateway
from research_kb.max_research.persistence.repository import MaxControlRepository
from research_kb.max_research.persistence.runner import RunnerPersistence
from research_kb.max_research.persistence.db import connect_control_db
from research_kb.max_research.persistence.migrations import apply_migrations
from research_kb.max_research.provider import ProviderStore
from research_kb.max_research.scheduler import provider_runner_profile
from research_kb.max_research.persistence.version import CONTROL_SCHEMA_VERSION
from research_kb.policy import Actor


V10_DB = Path(os.environ.get("MR4B1B_V10_DB", r"D:\research-kb-canary\control\max-canary-v10-preview.db"))
PILOT_DB = Path(os.environ.get("MR4B1B_PILOT_DB", r"D:\research-kb-pilot\data\research.db"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(
    V10_DB.is_file() and PILOT_DB.is_file() and CONTROL_SCHEMA_VERSION == 19,
    "historical schema-19 fixture test is not run by the dev11 control plane",
)
class MR4B1BV10R2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr4b1b-v10r2-")
        self.database = Path(self.temp.name) / "control.db"
        self.v10_before = _sha256(V10_DB)
        shutil.copy2(V10_DB, self.database)
        connection = connect_control_db(self.database, read_only=False)
        try:
            apply_migrations(connection)
        finally:
            connection.close()
        self.admin = Actor("mr4b1b-v10r2-test-admin", "mr4b1b-v10r2-test-admin-session", "user", "admin", "mr4b1b-v10r2-tests")
        self.repo = MaxControlRepository(self.database)
        self.provider_store = ProviderStore(self.repo)
        self.profile = self.provider_store.get_profile(profile_hash="5096861576c547a5f4246f33ed707dd7cc14c29844b34f403ac5d105c67b8e11")
        self.runner_profile = provider_runner_profile(self.profile)
        RunnerPersistence(self.repo).register_profile(profile=self.runner_profile, actor=self.admin)
        with closing(self.repo._connect(read_only=True)) as connection:
            lease = connection.execute("SELECT owner_id, session_id FROM max_leases WHERE run_id=?", ("mr1:run:a7e40ac3244b2ec7d3a21c5dd393ac299cce6489fad06d86",)).fetchone()
            claim = connection.execute("SELECT claim_id, fencing_token FROM max_runner_invocation_claims WHERE run_id=? AND status='active' ORDER BY rowid DESC LIMIT 1", ("mr1:run:a7e40ac3244b2ec7d3a21c5dd393ac299cce6489fad06d86",)).fetchone()
            self.policy_hash = connection.execute("SELECT policy_hash FROM max_source_egress_policies WHERE run_id=?", ("mr1:run:a7e40ac3244b2ec7d3a21c5dd393ac299cce6489fad06d86",)).fetchone()[0]
        self.worker = Actor(lease["owner_id"], lease["session_id"], "worker", "runner", "mr4b1b-v10r2-tests")
        self.run_id = "mr1:run:a7e40ac3244b2ec7d3a21c5dd393ac299cce6489fad06d86"
        if claim is not None:
            RunnerPersistence(self.repo).release_invocation(
                run_id=self.run_id,
                claim_id=claim["claim_id"],
                actor=self.worker,
                fencing_token=int(claim["fencing_token"]),
            )
        self.kwargs = {
            "run_id": self.run_id,
            "provider_profile_hash": self.profile.profile_hash,
            "source_egress_policy_hash": self.policy_hash,
            "candidate_wheel_sha256": "a" * 64,
            "source_manifest_sha256": "b" * 64,
            "source_tree_sha256": "c" * 64,
            "engine_version": "0.1.1.dev8",
            "caps": {
                "max_provider_calls": 1, "max_ticks": 1, "max_iterations": 1,
                "max_acquisition_requests": 0, "max_ocr_requests": 0, "max_ingest_operations": 0,
                "max_input_tokens": 4096, "max_output_tokens": 256,
                "max_cache_read_tokens": 4096, "max_reasoning_tokens": 256,
                "max_cost_units": 729, "max_wall_clock_seconds": 120,
                "max_source_passages": 1, "max_source_characters": 2000,
            },
        }

    def tearDown(self) -> None:
        self.assertEqual(self.v10_before, _sha256(V10_DB))
        self.temp.cleanup()

    def _preparer(self, *, failure=None) -> LiveCanaryIntentPreparer:
        return LiveCanaryIntentPreparer(
            self.repo,
            worker_actor=self.worker,
            gateway=LocalCoreEvidenceGateway(PILOT_DB),
            failure_injection=failure,
        )

    def test_prepare_replay_is_idempotent_and_has_no_execution_facts(self) -> None:
        first = self._preparer().prepare(**self.kwargs)
        second = self._preparer().prepare(**self.kwargs)
        self.assertTrue(first["ok"])
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        for key in ("plan_hash", "iteration_id", "group_id", "intent_id", "intent_hash", "request_hash", "wire_request_hash", "request_manifest_hash", "reservation_id"):
            self.assertEqual(first[key], second[key])
        self.assertEqual(first["counts"], second["counts"])
        self.assertEqual(first["counts"]["active_leases"], 1)
        self.assertEqual(first["counts"]["active_invocation_claims"], 1)
        self.assertEqual(first["counts"]["open_iterations"], 1)
        self.assertEqual(first["counts"]["intents"], 1)
        for key in ("dispatch_acks", "attempts", "results", "usage_bindings", "iteration_outcomes", "live_approvals", "provider_calls"):
            self.assertEqual(first["counts"][key], 0)
        with closing(self.repo._connect(read_only=True)) as connection:
            durable = connection.execute("SELECT intent_json, manifest_json FROM max_model_call_intents i JOIN max_runner_intent_manifests m ON m.intent_id=i.intent_id WHERE i.run_id=?", (self.run_id,)).fetchone()
            self.assertNotIn('"text"', durable[0].casefold())
            self.assertNotIn('"text"', durable[1].casefold())

    def test_crash_after_claim_recovers_without_duplicate_claim_or_intent(self) -> None:
        with self.assertRaises(LiveCanaryIntentPreparationError):
            self._preparer(failure="claim_after").prepare(**self.kwargs)
        recovered = self._preparer().prepare(**self.kwargs)
        self.assertTrue(recovered["ok"])
        self.assertFalse(recovered["idempotent"])
        self.assertEqual(recovered["counts"]["active_invocation_claims"], 1)
        self.assertEqual(recovered["counts"]["intents"], 1)

    def test_mismatched_replay_payload_fails_closed(self) -> None:
        self._preparer().prepare(**self.kwargs)
        changed = dict(self.kwargs)
        changed["caps"] = {**self.kwargs["caps"], "max_cost_units": 728}
        with self.assertRaises(LiveCanaryIntentPreparationError):
            self._preparer().prepare(**changed)

    def test_client_request_material_is_rejected_before_state_change(self) -> None:
        with self.assertRaises(LiveCanaryIntentPreparationError):
            self._preparer().prepare(**self.kwargs, request_fields={"logical_call_id": "caller-supplied"})
        with closing(self.repo._connect(read_only=True)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_runner_plans WHERE run_id=?", (self.run_id,)).fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_model_call_intents WHERE run_id=?", (self.run_id,)).fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
