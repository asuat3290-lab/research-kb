"""MR-4B0 offline canary authority tests.

The full concurrency and tamper matrix is also exercised by the independent
``tools/mr4b0_audit_probe.py``; these tests keep the package-facing contract
discoverable by the normal test runner.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
import uuid
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from research_kb.max_research.contract import canonical_sha256
from research_kb.max_research.live_canary import LiveCanaryAuthorityError, LiveCanaryAuthorityStore
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION
from research_kb.max_research.persistence.repository import MaxControlRepository
from research_kb.max_research.production_bridge import LiveCanaryExecutor
from research_kb.policy import Actor


ROOT = Path(os.environ.get("MR4B0_TEST_ROOT", ".mr4b0-test-fixtures")).resolve()


class MR4B0AuthorityTest(unittest.TestCase):
    def setUp(self) -> None:
        ROOT.mkdir(parents=True, exist_ok=True)
        self.root = ROOT / uuid.uuid4().hex
        self.root.mkdir()
        self.database = self.root / "control.db"
        self.admin = Actor("test-admin", "test-admin-session", "user", "admin", "mr4b0")
        self.worker = Actor("test-worker", "test-worker-session", "worker", "runner", "mr4b0")
        self.repository = MaxControlRepository(self.database)
        self.repository.initialize(fixture=True)
        charter = {
            "question": "MR-4B0 authority",
            "scope": "offline fixture",
            "invariants": ["one-shot", "bounded"],
            "non_goals": ["network"],
            "deliverables": ["audit"],
            "model_identity": "fixture-model/v1",
            "budget": {"iteration_count": 1, "input_tokens": 16, "output_tokens": 16, "cost_units": 1},
            "source_policy": {"network_allowed": False},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        proposed = self.repository.propose(project_id="mr4b0-test", charter=charter, actor=self.admin)
        self.repository.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="test", actor=self.admin, ttl_seconds=3600)
        started = self.repository.start(run_id=proposed["run_id"], actor=self.admin, lease_ttl=3600)
        from research_kb.max_research.persistence.runner import RunnerPersistence
        from research_kb.max_research.runner.contracts import RunnerProfile
        self.run = self.repository.get_run(proposed["run_id"])
        profile = RunnerProfile("mr4b0-runner", self.run["model_identity"], {"max_output_tokens": 16})
        persistence = RunnerPersistence(self.repository)
        persistence.register_profile(profile=profile, actor=self.admin)
        handoff = persistence.handoff_runner(run_id=self.run["run_id"], profile=profile, admin_actor=self.admin, runner_actor=self.worker, admin_fencing_token=int(started["lease"]["fencing_token"]), lease_ttl=3600)
        claim = persistence.claim_invocation(run_id=self.run["run_id"], actor=self.worker, fencing_token=int(handoff["lease"]["fencing_token"]), ttl_seconds=3600)
        h = "a" * 64
        self.value = {
        "project_id": self.run["project_id"], "run_id": self.run["run_id"], "charter_hash": self.run["charter_hash"], "current_state_hash": self.run["current_state_hash"], "current_checkpoint_id": self.run["current_checkpoint_id"], "current_state_version": self.run["state_version"], "engine_package": "research-kb", "engine_version": "0.1.1.dev1", "core_schema_version": 5, "control_schema_version": CONTROL_SCHEMA_VERSION, "candidate_wheel_sha256": h, "source_manifest_sha256": h, "source_tree_sha256": h, "provider_profile_hash": h, "provider_name": "fixture-provider", "model_identity": self.run["model_identity"], "model_version": "v1", "pricing_hash": h, "budget_hash": self.run["budget_hash"], "endpoint_origin_hash": h, "endpoint_path_policy_hash": h, "network_policy_hash": h, "credential_ref_hash": h, "source_egress_policy_hash": h, "source_allowlist": [{"passage_id": "p1", "document_id": "d1", "document_version_id": "v1", "source_role": "primary", "evidential_function": "supports", "verification_status": "verified", "reliability_status": "reviewed"}], "source_policy": {"network_allowed": False}, "runner_profile_hash": h, "worker_id": self.worker.actor_id, "worker_session": self.worker.session_id, "fencing_token": handoff["lease"]["fencing_token"], "claim_id": claim["claim_id"], "caps": {"max_provider_calls": 1, "max_ticks": 1, "max_iterations": 1, "max_acquisition_requests": 0, "max_ocr_requests": 0, "max_ingest_operations": 0, "max_input_tokens": 16, "max_output_tokens": 16, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0, "max_cost_units": 1, "max_wall_clock_seconds": 60, "max_source_passages": 1, "max_source_characters": 2000}, "transport_policy": {"redirect": False, "retry": False, "timeout_seconds": 30}, "kill_rollback_incident_policy": {"kill": "revoke", "rollback": "stop", "incident": "pause"},
        }
        self.authority = LiveCanaryAuthorityStore(self.repository)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _approval(self) -> tuple[dict, dict]:
        preview = self.authority.preview(value=self.value, actor=self.admin)
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        approval = self.authority.authorize(preview_id=preview["preview_id"], preview_hash=preview["preview_hash"], confirmation_phrase=preview["confirmation_phrase"], expires_at=expiry, actor=self.admin, reason="test approval")
        return preview, approval

    def test_preview_hash_is_deterministic_and_redacted(self) -> None:
        first = self.authority.preview(value=self.value, actor=self.admin)
        second = self.authority.preview(value=json.loads(json.dumps(self.value)), actor=self.admin)
        self.assertEqual(first["preview_hash"], second["preview_hash"])
        self.assertEqual(first["preview_hash"], canonical_sha256(first["preview"]))
        self.assertNotIn("source_text", json.dumps(first))

    def test_preview_and_bridge_fail_closed(self) -> None:
        with self.assertRaises(LiveCanaryAuthorityError):
            self.authority.preview(value={**self.value, "source_policy": {"content": "secret source"}}, actor=self.admin)
        bridge = LiveCanaryExecutor(self.repository, self.authority)
        with self.assertRaises(LiveCanaryAuthorityError):
            bridge.execute()

    def test_twenty_consumers_and_preparers_have_one_winner(self) -> None:
        preview, approval = self._approval()
        consumed = []
        lock = threading.Lock()
        def consume() -> None:
            try:
                value = self.authority.consume_approval(approval_id=approval["approval_id"], preview_hash=preview["preview_hash"], consumer=self.worker, worker_id=self.worker.actor_id, worker_session=self.worker.session_id, fencing_token=self.value["fencing_token"], claim_id=self.value["claim_id"])
                with lock: consumed.append(value)
            except Exception:
                pass
        threads = [threading.Thread(target=consume) for _ in range(20)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(len(consumed), 1)
        permits = []
        def prepare() -> None:
            try:
                value = self.authority.prepare_permit(consumption_id=consumed[0]["consumption_id"], consumer=self.worker, request_hash="a" * 64, idempotency_key_hash="b" * 64)
                with lock: permits.append(value)
            except Exception:
                pass
        threads = [threading.Thread(target=prepare) for _ in range(20)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(len(permits), 1)

    def test_crash_unknown_tamper_and_no_network(self) -> None:
        preview, approval = self._approval()
        consumed = self.authority.consume_approval(approval_id=approval["approval_id"], preview_hash=preview["preview_hash"], consumer=self.worker, worker_id=self.worker.actor_id, worker_session=self.worker.session_id, fencing_token=self.value["fencing_token"], claim_id=self.value["claim_id"])
        permit = self.authority.prepare_permit(consumption_id=consumed["consumption_id"], consumer=self.worker, request_hash="a" * 64, idempotency_key_hash="b" * 64)
        self.assertEqual(self.authority.record_outcome(permit_id=permit["permit_id"], outcome="aborted", usage={}, cost_units=0, actor=self.worker)["outcome"], "aborted")
        with self.assertRaises(LiveCanaryAuthorityError):
            self.authority.prepare_permit(consumption_id=consumed["consumption_id"], consumer=self.worker, request_hash="a" * 64, idempotency_key_hash="b" * 64)
        self.assertEqual(self.authority.status()["network"]["provider_calls"], 0)


if __name__ == "__main__":
    unittest.main()
