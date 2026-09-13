from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from research_kb.cli import _parser, _redact_max_output, _run
from research_kb.max_research.contract import canonical_sha256, model_to_dict
from research_kb.max_research.persistence import MaxControlError, MaxControlRepository, RunnerPersistence
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION
from research_kb.max_research.runner import (
    BoundedRunner,
    InferenceProfile,
    InjectedRunnerCrash,
    ModelResponseEnvelope,
    RunnerProfile,
    RunnerProposal,
    ScriptedFakeAdapter,
    FixtureResearchGateway,
    FixtureUsageAuthority,
    build_plan,
)
from research_kb.policy import Actor


class MR2AClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr2a-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("admin", "admin-session", "user", "admin", "mr2a-tests")
        self.worker = Actor("worker", "worker-session", "worker", "runner", "mr2a-tests")
        self.clock_value = 0
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize(fixture=True)
        self.repo.usage_authority = FixtureUsageAuthority(self.repo)
        self.charter = {
            "question": "How can one bounded call be recovered deterministically?",
            "scope": "MR-2A fixture",
            "invariants": ["append-only evidence"],
            "non_goals": ["network and real models"],
            "deliverables": ["audit trace"],
            "model_identity": "fixture-model/v1",
            "budget": {"iteration_count": 20, "input_tokens": 5000, "output_tokens": 2000, "cost_units": 100},
            "source_policy": {"network_allowed": False, "roles": ["primary", "counterevidence"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        self.profile = RunnerProfile("mr2a-profile", "fixture-model/v1", InferenceProfile(max_output_tokens=256))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def prepare(self, *, adapter=None, project: str = "mr2a-project"):
        proposed = self.repo.propose(project_id=project, charter=self.charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="explicit MR-2A fixture approval", actor=self.admin)
        persistence = RunnerPersistence(self.repo)
        persistence.register_profile(profile=self.profile, actor=self.admin)
        handoff = persistence.handoff_runner(run_id=proposed["run_id"], profile=self.profile, admin_actor=self.admin, runner_actor=self.worker)
        return proposed["run_id"], BoundedRunner(self.repo, self.worker, self.profile, adapter or ScriptedFakeAdapter(), gateway=FixtureResearchGateway(), usage_authority=self.repo.usage_authority, fixture=True), persistence, handoff

    def test_01_schema5_is_independent_and_runner_tables_are_append_only(self) -> None:
        self.assertEqual(self.repo.verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_schema_migrations").fetchone()[0], CONTROL_SCHEMA_VERSION)
            for name in ("max_runner_profiles", "max_model_call_intents", "max_model_call_attempts", "max_model_call_results", "max_runner_recovery_decisions", "max_runner_call_specs", "max_runner_usage_bindings", "max_runner_artifact_bindings", "max_epistemic_conflicts"):
                self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE name=?", (name,)).fetchone())
        db.close()

    def test_02_contract_unknown_fields_and_hashes_fail_closed(self) -> None:
        with self.assertRaises(Exception):
            RunnerProfile.from_mapping({"profile_id": "p", "model_identity": "m", "inference_profile": {}, "unknown": True})
        with self.assertRaises(Exception):
            RunnerProposal.from_mapping({"unknown": True})
        profile = RunnerProfile.from_mapping({"profile_id": "p", "model_identity": {"identity": "m"}, "inference_profile": {}})
        self.assertEqual(profile.profile_hash, canonical_sha256({"profile_id": "p", "model_identity": "m", "inference_profile": model_to_dict(profile.inference_profile), "role_names": profile.role_names, "gateway_name": profile.gateway_name, "call_budget": dict(profile.call_budget)}))

    def test_03_planner_is_deterministic_and_rehydration_packet_excludes_working_history(self) -> None:
        state = {"state_hash": "a" * 64, "latest_by_id": {}, "active_leading_hypothesis_id": None}
        first = build_plan(project_id="p", run_id="r", sequence=1, state=state, profile=self.profile)
        second = build_plan(project_id="p", run_id="r", sequence=1, state=state, profile=self.profile)
        self.assertEqual(model_to_dict(first), model_to_dict(second))
        self.assertTrue(all(not packet.sees_other_role_outputs for packet in first.role_packets))
        recovery = build_plan(project_id="p", run_id="r", sequence=2, state=state, profile=self.profile, recovery_required=True)
        self.assertEqual(recovery.round_type, "rehydration")
        self.assertIn("working_summary", recovery.metadata["excluded_sections"])

    def test_04_run_next_requires_explicit_handoff_and_one_call_succeeds(self) -> None:
        proposed = self.repo.propose(project_id="handoff-gate-project", charter=self.charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="approval", actor=self.admin)
        with self.assertRaises(MaxControlError):
            BoundedRunner(self.repo, self.worker, self.profile, ScriptedFakeAdapter(), gateway=FixtureResearchGateway(), usage_authority=self.repo.usage_authority, fixture=True).run_next(run_id=proposed["run_id"])
        run_id, runner, persistence, _ = self.prepare()
        result = runner.run_next(run_id=run_id)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(persistence.verify_run(run_id=run_id)["result_count"], 1)
        self.assertEqual(persistence.verify_run(run_id=run_id)["outcome_count"], 1)

    def test_05_second_run_next_is_one_new_iteration_and_not_a_replay(self) -> None:
        run_id, runner, persistence, _ = self.prepare()
        adapter = runner.adapter
        self.assertEqual(runner.run_next(run_id=run_id)["iteration_number"], 1)
        self.assertEqual(runner.run_next(run_id=run_id)["iteration_number"], 2)
        self.assertEqual(adapter.dispatch_count, 2)
        self.assertEqual(persistence.verify_run(run_id=run_id)["plan_count"], 2)

    def test_06_crash_after_each_boundary_recovers_without_duplicate_dispatch(self) -> None:
        for stage in ("plan_before", "plan_after", "begin_before", "begin_after", "reserve_before", "reserve_after", "intent_before", "intent_after", "dispatch_before", "dispatch_after_unknown", "result_before", "result_after", "change_set_before", "change_set_after", "usage_before", "usage_after", "finish_before", "finish_after"):
            with self.subTest(stage=stage):
                adapter = ScriptedFakeAdapter()
                if stage == "dispatch_after_unknown":
                    adapter.inject_failure("dispatch_unknown")
                run_id, runner, persistence, _ = self.prepare(project=f"mr2a-{stage}", adapter=adapter)
                adapter = runner.adapter
                runner.inject_failure(stage)
                with self.assertRaises(InjectedRunnerCrash):
                    runner.run_next(run_id=run_id)
                recovered = BoundedRunner(self.repo, self.worker, self.profile, adapter, gateway=FixtureResearchGateway(), usage_authority=self.repo.usage_authority, fixture=True).run_next(run_id=run_id)
                self.assertEqual(recovered["status"], "completed")
                self.assertEqual(adapter.dispatch_count, 1)
                self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_07_invalid_model_output_aborts_without_canonical_partial_write(self) -> None:
        run_id, runner, persistence, _ = self.prepare(adapter=ScriptedFakeAdapter())
        runner.adapter.inject_failure("response_invalid")
        result = runner.run_next(run_id=run_id)
        self.assertEqual(result["status"], "aborted")
        self.assertEqual(len(self.repo.list_objects(project_id="mr2a-project", run_id=run_id)["objects"]), 1)
        self.assertEqual(self.repo.reconstruct_budget(run_id=run_id)["reserved"], {"cost_units": 0, "input_tokens": 0, "iteration_count": 0, "output_tokens": 0})
        self.assertEqual(persistence.verify_run(run_id=run_id)["result_count"], 0)

    def test_08_usage_receipt_invalid_pauses_with_reservation_retained(self) -> None:
        run_id, runner, persistence, _ = self.prepare(adapter=ScriptedFakeAdapter())
        runner.adapter.inject_failure("usage_invalid")
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "paused")
        balance = self.repo.reconstruct_budget(run_id=run_id)
        self.assertEqual(balance["used"]["iteration_count"], 0)
        self.assertTrue(balance["reserved"])
        self.assertEqual(self.repo.get_run(run_id)["status"], "PAUSED")
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_09_sent_unknown_without_provider_recovery_pauses_and_never_retries(self) -> None:
        adapter = ScriptedFakeAdapter(provider_idempotency=False, result_query=False)
        adapter.inject_failure("dispatch_unknown")
        run_id, runner, persistence, _ = self.prepare(adapter=adapter)
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "paused")
        self.assertEqual(adapter.dispatch_count, 1)
        with self.assertRaises(MaxControlError):
            BoundedRunner(self.repo, self.worker, self.profile, adapter, gateway=FixtureResearchGateway(), usage_authority=self.repo.usage_authority, fixture=True).run_next(run_id=run_id)
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_10_provider_idempotency_and_query_consume_unknown_result_once(self) -> None:
        adapter = ScriptedFakeAdapter()
        adapter.inject_failure("dispatch_unknown")
        run_id, runner, persistence, _ = self.prepare(adapter=adapter)
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        self.assertEqual(adapter.dispatch_count, 1)
        verification = persistence.verify_run(run_id=run_id)
        self.assertTrue(verification["ok"])
        self.assertEqual(verification["result_count"], 1)

    def test_11_model_final_status_is_rejected_before_canonical_apply(self) -> None:
        class BadAdapter(ScriptedFakeAdapter):
            def dispatch(self, request, *, idempotency_key):
                response = super().dispatch(request, idempotency_key=idempotency_key)
                proposal = model_to_dict(response.proposal)
                proposal["objects"][0]["payload"]["status"] = "verified"
                return ModelResponseEnvelope(logical_call_id=response.logical_call_id, intent_hash=response.intent_hash, model_identity=response.model_identity, inference_profile_hash=response.inference_profile_hash, status=response.status, proposal=proposal, usage_receipt=model_to_dict(response.usage_receipt), provider_call_id=response.provider_call_id)
        run_id, runner, _, _ = self.prepare(adapter=BadAdapter())
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "aborted")
        self.assertEqual(len(self.repo.list_objects(project_id="mr2a-project", run_id=run_id)["objects"]), 1)

        class BadMetadataAdapter(ScriptedFakeAdapter):
            def dispatch(self, request, *, idempotency_key):
                response = super().dispatch(request, idempotency_key=idempotency_key)
                proposal = model_to_dict(response.proposal)
                proposal["objects"][0]["payload"]["citation"] = {"doi": "client-supplied"}
                return ModelResponseEnvelope(logical_call_id=response.logical_call_id, intent_hash=response.intent_hash, model_identity=response.model_identity, inference_profile_hash=response.inference_profile_hash, status=response.status, proposal=proposal, usage_receipt=model_to_dict(response.usage_receipt), provider_call_id=response.provider_call_id)
        metadata_run, metadata_runner, _, _ = self.prepare(project="mr2a-client-metadata", adapter=BadMetadataAdapter())
        self.assertEqual(metadata_runner.run_next(run_id=metadata_run)["status"], "aborted")
        self.assertEqual(len(self.repo.list_objects(project_id="mr2a-client-metadata", run_id=metadata_run)["objects"]), 1)

    def test_12_stale_runner_fence_and_foreign_actor_are_rejected(self) -> None:
        run_id, runner, _, handoff = self.prepare()
        other = Actor("other", "other-session", "worker", "runner", "mr2a-tests")
        with self.assertRaises(MaxControlError):
            BoundedRunner(self.repo, other, self.profile, ScriptedFakeAdapter(), gateway=FixtureResearchGateway(), usage_authority=self.repo.usage_authority, fixture=True).run_next(run_id=run_id)
        with self.assertRaises(MaxControlError):
            self.repo.begin_iteration(run_id=run_id, round_type="exploration", actor=self.worker, fencing_token=handoff["lease"]["fencing_token"] + 1)

    def test_13_expired_admin_takeover_increments_fence_and_old_worker_cannot_write(self) -> None:
        clock = type("Clock", (), {"__init__": lambda self: setattr(self, "value", __import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc)), "__call__": lambda self: self.value, "advance": lambda self, seconds: setattr(self, "value", self.value + __import__("datetime").timedelta(seconds=seconds))})()
        repo = MaxControlRepository(Path(self.temp.name) / "expiry.db", clock=clock)
        repo.initialize(); proposed = repo.propose(project_id="expiry-project", charter=self.charter, actor=self.admin); repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="approval", actor=self.admin)
        persistence = RunnerPersistence(repo); persistence.register_profile(profile=self.profile, actor=self.admin); first = persistence.handoff_runner(run_id=proposed["run_id"], profile=self.profile, admin_actor=self.admin, runner_actor=self.worker, lease_ttl=5); clock.advance(6)
        replacement = Actor("replacement", "replacement-session", "worker", "runner", "mr2a-tests")
        taken = persistence.handoff_runner(run_id=proposed["run_id"], profile=self.profile, admin_actor=self.admin, runner_actor=replacement, lease_ttl=5)
        self.assertGreater(taken["lease"]["fencing_token"], first["lease"]["fencing_token"])
        with self.assertRaises(MaxControlError):
            repo.pause(run_id=proposed["run_id"], actor=self.worker, fencing_token=first["lease"]["fencing_token"])

    def test_14_twenty_concurrent_approved_handoffs_have_one_winner(self) -> None:
        proposed = self.repo.propose(project_id="concurrent-project", charter=self.charter, actor=self.admin); self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="approval", actor=self.admin)
        persistence = RunnerPersistence(self.repo); persistence.register_profile(profile=self.profile, actor=self.admin)
        def attempt(index):
            actor = Actor(f"worker-{index}", f"session-{index}", "worker", "runner", "mr2a-tests")
            try:
                return persistence.handoff_runner(run_id=proposed["run_id"], profile=self.profile, admin_actor=self.admin, runner_actor=actor)
            except MaxControlError:
                return None
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(attempt, range(20)))
        self.assertEqual(sum(item is not None for item in results), 1)

    def test_15_append_only_attempt_and_result_triggers_reject_mutation(self) -> None:
        run_id, runner, _, _ = self.prepare(); runner.run_next(run_id=run_id)
        with closing(sqlite3.connect(self.path)) as db:
            attempt_id = db.execute("SELECT attempt_id FROM max_model_call_attempts LIMIT 1").fetchone()[0]
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute("UPDATE max_model_call_attempts SET stage='failed' WHERE attempt_id=?", (attempt_id,))
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute("DELETE FROM max_model_call_attempts WHERE attempt_id=?", (attempt_id,))

    def test_16_tampered_runner_record_is_detected_by_verify(self) -> None:
        run_id, runner, persistence, _ = self.prepare(); runner.run_next(run_id=run_id)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DROP TRIGGER max_model_call_attempts_no_update")
            db.execute("UPDATE max_model_call_attempts SET attempt_json='{}' WHERE run_id=?", (run_id,)); db.commit()
        self.assertFalse(persistence.verify_run(run_id=run_id)["ok"])

    def test_17_backup_restore_preserves_runner_chain_and_budget(self) -> None:
        run_id, runner, persistence, _ = self.prepare(); runner.run_next(run_id=run_id)
        backup = Path(self.temp.name) / "backup.db"; restored = Path(self.temp.name) / "restored.db"
        self.assertTrue(self.repo.backup(backup)["verification"]["ok"])
        self.assertTrue(MaxControlRepository(restored).restore(backup)["verification"]["ok"])
        self.assertTrue(RunnerPersistence(MaxControlRepository(restored)).verify_run(run_id=run_id)["ok"])

    def test_18_cli_register_handoff_run_next_and_redacted_status(self) -> None:
        profile_json = json.dumps(model_to_dict(self.profile), ensure_ascii=False)
        charter_json = json.dumps(self.charter, ensure_ascii=False)
        database = str(Path(self.temp.name) / "cli.db")
        base = ["--config", "config.toml", "max", "--database", database]
        def call(args):
            return _run(_parser().parse_args(base + args))
        self.assertEqual(call(["init", "--fixture"])["schema_version"], CONTROL_SCHEMA_VERSION)
        call(["register-profile", "--profile-json", profile_json])
        proposed = call(["propose", "--project", "cli-project", "--charter-json", charter_json])
        call(["approve", "--run-id", proposed["run_id"], "--charter-hash", proposed["charter_hash"], "--reason", "cli approval"])
        call(["handoff", "--run-id", proposed["run_id"], "--runner-id", "cli-worker", "--runner-session", "cli-session", "--profile-json", profile_json])
        self.assertEqual(call(["simulate-next", "--fixture", "--run-id", proposed["run_id"], "--runner-id", "cli-worker", "--runner-session", "cli-session", "--profile-json", profile_json])["status"], "completed")
        redacted = _redact_max_output(call(["status", "--run-id", proposed["run_id"]]))
        encoded = json.dumps(redacted)
        self.assertNotIn("fencing_token", encoded)
        self.assertNotIn(str(Path(database).resolve()), encoded)

    def test_19_missing_database_read_only_status_fails_closed(self) -> None:
        missing = Path(self.temp.name) / "missing.db"
        with self.assertRaises(MaxControlError):
            RunnerPersistence(MaxControlRepository(missing)).status(run_id="mr1:run:missing")

    def test_20_completion_is_not_called_or_persisted_by_runner(self) -> None:
        run_id, runner, persistence, _ = self.prepare(); result = runner.run_next(run_id=run_id)
        self.assertEqual(result["status"], "completed")
        run = self.repo.get_run(run_id)
        self.assertNotIn("completion_result_id", run)
        self.assertIsNone(self.repo.status(run_id=run_id)["run"].get("completion_result_id"))
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])


if __name__ == "__main__":
    unittest.main()
