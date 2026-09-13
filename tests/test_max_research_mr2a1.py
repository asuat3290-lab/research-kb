from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from research_kb.max_research.contract import canonical_sha256, model_to_dict
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository, RunnerPersistence
from research_kb.max_research.runner import (
    BoundedRunner,
    FixtureResearchGateway,
    FixtureUsageAuthority,
    InferenceProfile,
    RunnerProfile,
    ScriptedFakeAdapter,
    build_plan,
)
from research_kb.max_research.service import MaxRunnerService
from research_kb.policy import Actor


class SecretGateway(FixtureResearchGateway):
    def context(self, **kwargs):
        value = dict(super().context(**kwargs))
        value["source_text"] = "SOURCE-TEXT-MUST-NOT-PERSIST"
        value["api_key"] = "API-KEY-MUST-NOT-PERSIST"
        return value


class ForgedUsageAdapter(ScriptedFakeAdapter):
    def dispatch(self, request, *, idempotency_key):
        response = super().dispatch(request, idempotency_key=idempotency_key)
        receipt = dict(response.usage_receipt)
        receipt["authority_id"] = "unregistered-authority"
        receipt["amount"] = {"iteration_count": 1, "input_tokens": 777, "output_tokens": 33, "cost_units": 17}
        payload = {key: receipt[key] for key in ("receipt_id", "run_id", "iteration_id", "model_identity", "amount", "issued_at", "authority_id")}
        receipt["payload_hash"] = canonical_sha256(payload)
        receipt["receipt_hash"] = canonical_sha256({"payload": payload, "payload_hash": receipt["payload_hash"]})
        return type(response)(
            logical_call_id=response.logical_call_id,
            intent_hash=response.intent_hash,
            model_identity=response.model_identity,
            inference_profile_hash=response.inference_profile_hash,
            status=response.status,
            proposal=model_to_dict(response.proposal),
            usage_receipt=receipt,
            provider_call_id=response.provider_call_id,
        )


class SlowAdapter(ScriptedFakeAdapter):
    def __post_init__(self) -> None:
        super().__post_init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def dispatch(self, request, *, idempotency_key):
        self.started.set()
        if not self.release.wait(10):
            raise RuntimeError("slow fixture was not released")
        return super().dispatch(request, idempotency_key=idempotency_key)


class MR2A1ClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr2a1-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("mr2a1-admin", "mr2a1-admin-session", "user", "admin", "mr2a1-tests")
        self.worker = Actor("mr2a1-worker", "mr2a1-worker-session", "worker", "runner", "mr2a1-tests")
        self.profile = RunnerProfile("mr2a1-profile", "fixture-model/v1", InferenceProfile(max_output_tokens=256))
        self.charter = {
            "question": "How does the bounded runner close its authority chain?",
            "scope": "MR-2A.1 fixture",
            "invariants": ["append-only authority"],
            "non_goals": ["network and real provider"],
            "deliverables": ["auditable runner trace"],
            "model_identity": "fixture-model/v1",
            "budget": {"iteration_count": 100, "input_tokens": 200000, "output_tokens": 50000, "cost_units": 1000},
            "source_policy": {"network_allowed": False, "roles": ["primary", "counterevidence"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize(fixture=True)
        self.repo.usage_authority = FixtureUsageAuthority(self.repo)
        self.project_counter = 0

    def tearDown(self) -> None:
        self.temp.cleanup()

    def prepare(self, *, adapter=None, gateway=None):
        self.project_counter += 1
        project_id = f"mr2a1-project-{self.project_counter}"
        proposed = self.repo.propose(project_id=project_id, charter=self.charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="explicit MR-2A.1 fixture approval", actor=self.admin)
        persistence = RunnerPersistence(self.repo)
        persistence.register_profile(profile=self.profile, actor=self.admin)
        handoff = persistence.handoff_runner(run_id=proposed["run_id"], profile=self.profile, admin_actor=self.admin, runner_actor=self.worker, lease_ttl=300)
        runner = BoundedRunner(
            self.repo,
            self.worker,
            self.profile,
            adapter or ScriptedFakeAdapter(),
            gateway=gateway or FixtureResearchGateway(),
            usage_authority=self.repo.usage_authority,
            fixture=True,
            lease_ttl=300,
        )
        return proposed["run_id"], runner, persistence, handoff

    def test_01_production_defaults_fail_closed_and_fixture_is_explicit(self) -> None:
        missing = Path(self.temp.name) / "never-created.db"
        with self.assertRaisesRegex(MaxControlError, "ADAPTER_NOT_CONFIGURED"):
            MaxRunnerService(missing, self.worker, self.profile).run_next(run_id="missing")
        with self.assertRaisesRegex(MaxControlError, "GATEWAY_NOT_CONFIGURED"):
            MaxRunnerService(missing, self.worker, self.profile, adapter=ScriptedFakeAdapter()).run_next(run_id="missing")
        with self.assertRaisesRegex(MaxControlError, "USAGE_AUTHORITY_NOT_CONFIGURED"):
            MaxRunnerService(missing, self.worker, self.profile, adapter=ScriptedFakeAdapter(), gateway=FixtureResearchGateway()).run_next(run_id="missing")
        with self.assertRaisesRegex(MaxControlError, "FIXTURE_EXECUTION_REQUIRES_SIMULATE_NEXT"):
            MaxRunnerService(missing, self.worker, self.profile, adapter=ScriptedFakeAdapter(), gateway=FixtureResearchGateway(), usage_authority=FixtureUsageAuthority()).run_next(run_id="missing")
        self.assertFalse(missing.exists())
        self.assertTrue(self.repo.is_fixture_database())

    def test_02_gateway_and_usage_durability_are_metadata_only_and_authoritative(self) -> None:
        run_id, secret_runner, persistence, _ = self.prepare(gateway=SecretGateway())
        with self.assertRaisesRegex(MaxControlError, "GATEWAY_CONTEXT_REJECTED"):
            secret_runner.run_next(run_id=run_id)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_model_call_intents WHERE run_id=?", (run_id,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_model_call_results WHERE run_id=?", (run_id,)).fetchone()[0], 0)

        usage_run, forged_runner, forged_persistence, _ = self.prepare(adapter=ForgedUsageAdapter())
        self.assertEqual(forged_runner.run_next(run_id=usage_run)["status"], "paused")
        self.assertEqual(self.repo.reconstruct_budget(run_id=usage_run)["used"]["input_tokens"], 0)
        self.assertTrue(self.repo.reconstruct_budget(run_id=usage_run)["reserved"])
        self.assertTrue(forged_persistence.verify_run(run_id=usage_run)["ok"])

        clean_run, clean_runner, _, _ = self.prepare()
        self.assertEqual(clean_runner.run_next(run_id=clean_run)["status"], "completed")
        with closing(sqlite3.connect(self.path)) as db:
            intent_json = db.execute("SELECT intent_json FROM max_model_call_intents WHERE run_id=?", (clean_run,)).fetchone()[0]
            result_json = db.execute("SELECT result_json FROM max_model_call_results WHERE run_id=?", (clean_run,)).fetchone()[0]
            manifest_json = db.execute("SELECT manifest_json FROM max_runner_intent_manifests WHERE run_id=?", (clean_run,)).fetchone()[0]
        self.assertNotIn('"request"', intent_json)
        self.assertNotIn('"context"', intent_json)
        self.assertNotIn('"response"', result_json)
        for payload in (intent_json, manifest_json, result_json):
            lowered = payload.casefold()
            self.assertNotIn("source-text-must-not-persist", lowered)
            self.assertNotIn("api-key-must-not-persist", lowered)
            self.assertNotIn("c:\\", lowered)

    def test_03_authoritative_history_drives_cycle_and_adjudication_uses_five_calls(self) -> None:
        run_id, runner, persistence, _ = self.prepare()
        for _ in range(5):
            self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        history = persistence.list_history(run_id=run_id)
        self.assertEqual([item["round_type"] for item in history], ["exploration", "acquisition_review", "adjudication", "attack", "acquisition_review"])
        with closing(sqlite3.connect(self.path)) as db:
            specs = db.execute("SELECT s.call_id, s.phase, s.role, s.upstream_call_ids_json FROM max_runner_call_specs s JOIN max_runner_call_groups g ON g.group_id=s.group_id WHERE s.run_id=? AND g.phase='adjudication' ORDER BY s.call_index", (run_id,)).fetchall()
            self.assertEqual([row[0] for row in specs], ["lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response", "adjudicator"])
            self.assertEqual([row[2] for row in specs], ["lead", "rival", "rival", "lead", "adjudicator"])
            self.assertEqual(json.loads(specs[2][3]), ["lead_position", "rival_position"])
            self.assertEqual(json.loads(specs[4][3]), ["lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response"])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_call_groups WHERE run_id=? AND phase='adjudication'", (run_id,)).fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_model_call_intents WHERE run_id=? AND round_type='adjudication'", (run_id,)).fetchone()[0], 5)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_model_call_results WHERE run_id=? AND iteration_id IN (SELECT iteration_id FROM max_iterations WHERE run_id=? AND round_type='adjudication')", (run_id, run_id)).fetchone()[0], 5)

        state = {"state_hash": "a" * 64, "latest_by_id": {}, "active_leading_hypothesis_id": None}
        history_input = []
        for sequence in range(1, 101):
            first = build_plan(project_id="p", run_id="r", sequence=sequence, state=state, history=history_input, profile=self.profile)
            second = build_plan(project_id="p", run_id="r", sequence=sequence, state=state, history=history_input, profile=self.profile)
            self.assertEqual(model_to_dict(first), model_to_dict(second))
            history_input.append({"sequence_no": sequence, "iteration_id": first.iteration_id, "round_type": first.round_type, "status": "completed"})
        self.assertEqual([item["round_type"] for item in history_input[:5]], ["exploration", "acquisition_review", "adjudication", "attack", "acquisition_review"])
        self.assertEqual(history_input[11]["round_type"], "rehydration")

    def test_04_rehydration_is_server_owned_and_drift_pauses(self) -> None:
        run_id, runner, persistence, _ = self.prepare()
        for _ in range(11):
            self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        self.assertEqual(runner.run_next(run_id=run_id)["round_type"], "rehydration")
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT artifact_json FROM max_runner_cognitive_artifacts WHERE run_id=? AND artifact_type='rehydration_output'", (run_id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertNotIn('"rehydration_review"', row[0])
            self.assertTrue(json.loads(row[0])["accepted"])
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_05_supporting_evidence_is_not_counterevidence_and_public_verify_catches_tamper(self) -> None:
        run_id, runner, persistence, _ = self.prepare()
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        with closing(sqlite3.connect(self.path)) as db:
            outcome = db.execute("SELECT counterevidence_snapshots_json FROM max_iteration_outcomes WHERE run_id=?", (run_id,)).fetchone()[0]
            self.assertEqual(json.loads(outcome), [])
            db.execute("DROP TRIGGER max_runner_plans_no_update")
            db.execute("UPDATE max_runner_plans SET plan_json='{}' WHERE run_id=?", (run_id,))
            db.commit()
        verified = self.repo.verify_run(run_id=run_id)
        self.assertFalse(verified["ok"])
        self.assertFalse(verified["runner"]["ok"])
        self.assertTrue(any("runner plan JSON" in issue for issue in verified["runner"]["issues"]))
        self.assertFalse(persistence.verify_run(run_id=run_id)["ok"])

    def test_06_admin_recovery_consumption_is_one_time_and_retry_reuses_exact_intent(self) -> None:
        adapter = ScriptedFakeAdapter(provider_idempotency=False, result_query=False)
        adapter.inject_failure("dispatch_unknown")
        run_id, runner, persistence, _ = self.prepare(adapter=adapter)
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "paused")
        unfinished = persistence.latest_unfinished(run_id=run_id)
        self.assertIsNotNone(unfinished)
        logical_call_id = unfinished["logical_call_id"]
        first = runner.admin_decision(run_id=run_id, logical_call_id=logical_call_id, decision="retry", admin_actor=self.admin)
        second = runner.admin_decision(run_id=run_id, logical_call_id=logical_call_id, decision="retry", admin_actor=self.admin)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        with self.assertRaises(MaxControlError):
            runner.admin_decision(run_id=run_id, logical_call_id=logical_call_id, decision="abort", admin_actor=self.admin)
        with self.assertRaises(MaxControlError):
            runner.admin_decision(run_id=run_id, logical_call_id=logical_call_id, decision="retry", admin_actor=self.worker)
        resumed = self.repo.resume(run_id=run_id, actor=self.admin, lease_ttl=300)
        persistence.handoff_runner(run_id=run_id, profile=self.profile, admin_actor=self.admin, runner_actor=self.worker, admin_fencing_token=resumed["lease"]["fencing_token"], lease_ttl=300)
        retry_runner = BoundedRunner(self.repo, self.worker, self.profile, adapter, gateway=FixtureResearchGateway(), usage_authority=self.repo.usage_authority, fixture=True, lease_ttl=300)
        self.assertEqual(retry_runner.run_next(run_id=run_id)["status"], "completed")
        self.assertEqual(adapter.dispatch_count, 2)
        self.assertEqual(adapter.dispatch_log[0], adapter.dispatch_log[1])
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_07_twenty_concurrent_run_next_calls_have_one_invocation_and_one_dispatch(self) -> None:
        adapter = SlowAdapter()
        run_id, runner, persistence, _ = self.prepare(adapter=adapter)
        original_claim = runner.persistence.claim_invocation
        count = {"value": 0}
        count_lock = threading.Lock()
        all_claims_attempted = threading.Event()

        def counted_claim(*, run_id, actor, fencing_token, ttl_seconds=60):
            with count_lock:
                count["value"] += 1
                if count["value"] == 20:
                    all_claims_attempted.set()
            return original_claim(run_id=run_id, actor=actor, fencing_token=fencing_token, ttl_seconds=ttl_seconds)

        runner.persistence.claim_invocation = counted_claim
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(runner.run_next, run_id=run_id) for _ in range(20)]
            self.assertTrue(adapter.started.wait(10))
            self.assertTrue(all_claims_attempted.wait(10))
            time.sleep(0.1)
            adapter.release.set()
            results = []
            errors = []
            for future in futures:
                try:
                    results.append(future.result())
                except Exception as exc:
                    errors.append(str(exc))
        self.assertEqual(adapter.dispatch_count, 1)
        self.assertEqual(sum(item.get("status") == "completed" for item in results), 1)
        self.assertEqual(sum("RUN_NEXT_BUSY" in item for item in errors), 19)
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_08_fixture_migration_is_five_and_legacy_runner_backfill_fails_closed(self) -> None:
        self.assertEqual(self.repo.verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)
        run_id, runner, _, _ = self.prepare()
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_schema_migrations").fetchone()[0], CONTROL_SCHEMA_VERSION)
            self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE name='max_runner_intent_manifests'").fetchone())
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute("UPDATE max_runner_intent_manifests SET manifest_json='{}'")
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute("DELETE FROM max_runner_cognitive_artifacts")


if __name__ == "__main__":
    unittest.main()
