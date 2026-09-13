from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from typing import Any

from research_kb.max_research.contract import canonical_sha256, model_to_dict
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository, RunnerPersistence
from research_kb.max_research.persistence.migrations import _statements, migration_files
from research_kb.max_research.runner import (
    BoundedRunner,
    FixtureResearchGateway,
    FixtureUsageAuthority,
    InjectedRunnerCrash,
    InferenceProfile,
    ModelResponseEnvelope,
    RunnerPlan,
    RunnerProfile,
    ScriptedFakeAdapter,
    build_plan,
)
from research_kb.policy import Actor


class RequestSpyAdapter(ScriptedFakeAdapter):
    def __post_init__(self) -> None:
        super().__post_init__()
        self.requests = []

    def dispatch(self, request, *, idempotency_key):
        self.requests.append(request)
        return super().dispatch(request, idempotency_key=idempotency_key)


class ReplayedReceiptAdapter(ScriptedFakeAdapter):
    def __post_init__(self) -> None:
        super().__post_init__()
        self._receipt_by_iteration: dict[str, dict[str, object]] = {}

    def dispatch(self, request, *, idempotency_key):
        response = super().dispatch(request, idempotency_key=idempotency_key)
        receipt = self._receipt_by_iteration.setdefault(request.iteration_id, dict(model_to_dict(response.usage_receipt)))
        return ModelResponseEnvelope(
            logical_call_id=response.logical_call_id,
            intent_hash=response.intent_hash,
            model_identity=response.model_identity,
            inference_profile_hash=response.inference_profile_hash,
            status=response.status,
            proposal=model_to_dict(response.proposal),
            usage_receipt=receipt,
            provider_call_id=response.provider_call_id,
        )


class RejectedProposalAdapter(ScriptedFakeAdapter):
    def dispatch(self, request, *, idempotency_key):
        response = super().dispatch(request, idempotency_key=idempotency_key)
        proposal = dict(model_to_dict(response.proposal))
        if proposal.get("objects"):
            proposal["objects"][0]["payload"]["status"] = "verified"
        return ModelResponseEnvelope(
            logical_call_id=response.logical_call_id,
            intent_hash=response.intent_hash,
            model_identity=response.model_identity,
            inference_profile_hash=response.inference_profile_hash,
            status=response.status,
            proposal=proposal,
            usage_receipt=model_to_dict(response.usage_receipt),
            provider_call_id=response.provider_call_id,
        )


class FailedBillableAdapter(ScriptedFakeAdapter):
    def dispatch(self, request, *, idempotency_key):
        response = super().dispatch(request, idempotency_key=idempotency_key)
        return ModelResponseEnvelope(
            logical_call_id=response.logical_call_id,
            intent_hash=response.intent_hash,
            model_identity=response.model_identity,
            inference_profile_hash=response.inference_profile_hash,
            status="failed",
            proposal=model_to_dict(response.proposal),
            usage_receipt=model_to_dict(response.usage_receipt),
            provider_call_id=response.provider_call_id,
            error_code="provider_declared_failure",
        )


class FailedUnbilledAdapter(ScriptedFakeAdapter):
    def dispatch(self, request, *, idempotency_key):
        response = super().dispatch(request, idempotency_key=idempotency_key)
        return ModelResponseEnvelope(
            logical_call_id=response.logical_call_id,
            intent_hash=response.intent_hash,
            model_identity=response.model_identity,
            inference_profile_hash=response.inference_profile_hash,
            status="failed",
            proposal={},
            usage_receipt={},
            provider_call_id=response.provider_call_id,
            error_code="provider_declared_failure_without_usage",
        )


class InvalidAdjudicationAdapter(ScriptedFakeAdapter):
    def dispatch(self, request, *, idempotency_key):
        response = super().dispatch(request, idempotency_key=idempotency_key)
        proposal = dict(model_to_dict(response.proposal))
        if request.request_payload.get("call_spec_id") == "adjudicator":
            deliberation = dict(proposal.get("deliberation", {}))
            deliberation["unknown_field"] = "must fail closed"
            proposal["deliberation"] = deliberation
        return ModelResponseEnvelope(
            logical_call_id=response.logical_call_id,
            intent_hash=response.intent_hash,
            model_identity=response.model_identity,
            inference_profile_hash=response.inference_profile_hash,
            status=response.status,
            proposal=proposal,
            usage_receipt=model_to_dict(response.usage_receipt),
            provider_call_id=response.provider_call_id,
        )


class NestedContractAttackAdapter(ScriptedFakeAdapter):
    """Mutate exactly one provider-owned nested deliberation field."""

    def __init__(self, phase: str, mode: str, *, nested: str | None = None):
        self.phase = phase
        self.mode = mode
        self.nested = nested
        super().__init__()

    @staticmethod
    def _mutate_required(target: dict[str, Any], key: str, mode: str) -> None:
        if mode == "missing":
            target.pop(key, None)
        elif mode == "empty":
            target[key] = ""
        elif mode == "whitespace":
            target[key] = "   \t"
        elif mode == "wrong_type":
            target[key] = []
        elif mode == "unknown":
            target["unknown_nested_field"] = "must fail closed"
        else:
            raise ValueError(mode)

    def dispatch(self, request, *, idempotency_key):
        response = super().dispatch(request, idempotency_key=idempotency_key)
        proposal = dict(model_to_dict(response.proposal))
        call = str(request.request_payload.get("call_spec_id", ""))
        if call != self.phase:
            return response
        deliberation = dict(proposal.get("deliberation", {}))
        if self.nested is None:
            key = {
                "lead_position": "position",
                "rival_position": "position",
                "rival_cross_examination": "question",
                "lead_cross_examination_response": "correction",
            }.get(call, "rationale")
            target = deliberation.get("adjudication", deliberation) if call == "adjudicator" else deliberation
            self._mutate_required(target, key, self.mode)
        elif self.nested == "validity_audit":
            audit = dict(deliberation.get("validity_audit", {}))
            if self.mode == "unknown":
                audit["unknown_nested_field"] = True
            elif self.mode == "wrong_type":
                audit["passed"] = "true"
            elif self.mode == "missing":
                audit.pop("facts_evidence_true", None)
            else:
                audit["rationale"] = "   "
                audit["findings"] = []
            deliberation["validity_audit"] = audit
        elif self.nested == "adjudication":
            adjudication = dict(deliberation.get("adjudication", {}))
            if self.mode == "unknown":
                adjudication["unknown_nested_field"] = True
            elif self.mode == "wrong_type":
                adjudication["rationale"] = {"not": "text"}
            else:
                adjudication["rationale"] = "   "
            deliberation["adjudication"] = adjudication
        elif self.nested == "minority_reports":
            report = {"role": "minority", "position": "minority position", "preserved_reason": "preserved uncertainty"}
            if self.mode == "unknown":
                report["unknown_nested_field"] = True
            elif self.mode == "wrong_type":
                report["position"] = ["not", "text"]
            elif self.mode == "missing":
                report.pop("preserved_reason")
            else:
                report["preserved_reason"] = "   "
            deliberation["minority_reports"] = [report]
        proposal["deliberation"] = deliberation
        return ModelResponseEnvelope(
            logical_call_id=response.logical_call_id,
            intent_hash=response.intent_hash,
            model_identity=response.model_identity,
            inference_profile_hash=response.inference_profile_hash,
            status=response.status,
            proposal=proposal,
            usage_receipt=model_to_dict(response.usage_receipt),
            provider_call_id=response.provider_call_id,
        )


class DriftingFixtureGateway(FixtureResearchGateway):
    gateway_name = "fixture-gateway"
    gateway_identity = "fixture-gateway/v1"
    config_hash = "fixture-gateway-config-v1"
    source_version = "document-version-v1"

    def context(self, *, project_id: str, run_id: str, state_hash: str, allowed_ids, cold: bool = False):
        value = dict(super().context(project_id=project_id, run_id=run_id, state_hash=state_hash, allowed_ids=allowed_ids, cold=cold))
        value["source_references"] = [{"document_version_id": self.source_version}]
        return value



class MR2A2ClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr2a2-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("mr2a2-admin", "mr2a2-admin-session", "user", "admin", "mr2a2-tests")
        self.worker = Actor("mr2a2-worker", "mr2a2-worker-session", "worker", "runner", "mr2a2-tests")
        self.profile = RunnerProfile("mr2a2-profile", "fixture-model/v1", InferenceProfile(max_output_tokens=256))
        self.charter = {
            "question": "How does a bounded multi-call deliberation remain authoritative?",
            "scope": "MR-2A.2 fixture",
            "invariants": ["exact call authority", "append-only usage"],
            "non_goals": ["network and real models"],
            "deliverables": ["auditable deliberation"],
            "model_identity": "fixture-model/v1",
            "budget": {"iteration_count": 100, "input_tokens": 200000, "output_tokens": 50000, "cost_units": 1000},
            "source_policy": {"network_allowed": False, "roles": ["primary", "counterevidence"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize(fixture=True)
        self.repo.usage_authority = FixtureUsageAuthority(self.repo)
        self.counter = 0

    def tearDown(self) -> None:
        self.temp.cleanup()

    def prepare(self, *, adapter=None, gateway=None, project_id: str | None = None):
        self.counter += 1
        project = project_id or f"mr2a2-project-{self.counter}"
        proposed = self.repo.propose(project_id=project, charter=self.charter, actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="explicit MR-2A.2 fixture approval", actor=self.admin)
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

    def run_to_adjudication(self, *, adapter=None):
        run_id, runner, persistence, handoff = self.prepare(adapter=adapter)
        first = runner.run_next(run_id=run_id)
        second = runner.run_next(run_id=run_id)
        third = runner.run_next(run_id=run_id)
        self.assertEqual(first["status"], "completed")
        self.assertEqual(second["status"], "completed")
        return run_id, runner, persistence, handoff, third

    def _rows(self, sql: str, args=()):
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(sql, args)]

    def test_01_schema5_migration_is_independent_and_idempotent(self) -> None:
        self.assertEqual(self.repo.verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertEqual(self.repo.initialize()["schema_version"], CONTROL_SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_schema_migrations").fetchone()[0], CONTROL_SCHEMA_VERSION)
            self.assertEqual(db.execute("SELECT name FROM max_schema_migrations WHERE version=5").fetchone()[0], "mr2a2_deliberation_usage")
            self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE name='max_runner_result_call_bindings'").fetchone())

    def test_02_fixture_creation_rejects_existing_and_does_not_retrofit(self) -> None:
        empty = Path(self.temp.name) / "empty.db"
        empty.touch()
        with self.assertRaisesRegex(MaxControlError, "created exactly once"):
            MaxControlRepository(empty).initialize(fixture=True)
        production = Path(self.temp.name) / "production.db"
        production_repo = MaxControlRepository(production)
        production_repo.initialize()
        with self.assertRaisesRegex(MaxControlError, "created exactly once"):
            production_repo.initialize(fixture=True)
        self.assertFalse(production_repo.is_fixture_database())

    def test_03_concurrent_fixture_creation_has_one_creator_and_no_half_schema(self) -> None:
        path = Path(self.temp.name) / "concurrent-fixture.db"

        def attempt(_index: int):
            try:
                return MaxControlRepository(path).initialize(fixture=True)
            except MaxControlError:
                return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(attempt, range(20)))
        self.assertEqual(sum(item is not None for item in results), 1)
        self.assertEqual(MaxControlRepository(path).verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertTrue(MaxControlRepository(path).is_fixture_database())

    def test_04_adjudication_has_five_calls_and_strict_input_partitions(self) -> None:
        adapter = RequestSpyAdapter()
        run_id, runner, persistence, _, outcome = self.run_to_adjudication(adapter=adapter)
        self.assertEqual(outcome["status"], "completed")
        adjudication_iteration = self._rows("SELECT iteration_id FROM max_iterations WHERE run_id=? AND round_type='adjudication'", (run_id,))[0]["iteration_id"]
        requests = [item for item in adapter.requests if item.iteration_id == adjudication_iteration]
        self.assertEqual([item.request_payload["call_spec_id"] for item in requests], ["lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response", "adjudicator"])
        self.assertEqual(requests[0].request_payload["public_upstream"], {})
        self.assertEqual(requests[1].request_payload["public_upstream"], {})
        self.assertEqual(set(requests[2].request_payload["public_upstream"]), {"lead_position", "rival_position"})
        self.assertEqual(set(requests[3].request_payload["public_upstream"]), {"lead_position", "rival_position", "rival_cross_examination"})
        self.assertEqual(set(requests[4].request_payload["public_upstream"]), {"lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response"})
        self.assertEqual(persistence.verify_run(run_id=run_id)["result_count"], 7)

    def test_05_result_call_usage_and_artifact_bindings_are_unique(self) -> None:
        run_id, _, persistence, _, outcome = self.run_to_adjudication()
        self.assertEqual(outcome["status"], "completed")
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_result_call_bindings WHERE run_id=?", (run_id,)).fetchone()[0], 7)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_usage_bindings WHERE run_id=?", (run_id,)).fetchone()[0], 7)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_artifact_bindings WHERE run_id=?", (run_id,)).fetchone()[0], 10)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_result_call_bindings WHERE run_id=? AND result_id IS NULL", (run_id,)).fetchone()[0], 0)
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_06_usage_totals_reconstruct_and_iteration_is_charged_once(self) -> None:
        run_id, _, persistence, _, outcome = self.run_to_adjudication()
        self.assertEqual(outcome["status"], "completed")
        with closing(sqlite3.connect(self.path)) as db:
            result_amounts = [json.loads(row[0]) for row in db.execute("SELECT usage_json FROM max_model_call_results WHERE run_id=?", (run_id,))]
            provider_amounts = [json.loads(row[0]) for row in db.execute("SELECT amount_json FROM max_budget_ledger WHERE run_id=? AND operation='usage' AND provenance_json NOT LIKE '%server_owned%'", (run_id,))]
            iteration_charges = [json.loads(row[0]) for row in db.execute("SELECT amount_json FROM max_budget_ledger WHERE run_id=? AND operation='usage' AND provenance_json LIKE '%server_owned%'", (run_id,))]
            open_reservations = db.execute("SELECT COUNT(*) FROM max_budget_ledger r WHERE r.run_id=? AND r.operation='reserve' AND NOT EXISTS (SELECT 1 FROM max_budget_ledger x WHERE x.reservation_id=r.reservation_id AND x.operation IN ('commit','release'))", (run_id,)).fetchone()[0]
        totals = {}
        for amount in result_amounts:
            for key, value in amount.get("amount", {}).items():
                totals[key] = totals.get(key, 0) + value
        provider_totals = {}
        for amount in provider_amounts:
            for key, value in amount.items():
                provider_totals[key] = provider_totals.get(key, 0) + value
        self.assertEqual(totals, provider_totals)
        self.assertEqual(iteration_charges, [{"iteration_count": 1}] * 3)
        self.assertEqual(open_reservations, 0)
        self.assertEqual(persistence.verify_run(run_id=run_id)["ok"], True)

    def test_07_rejected_success_is_still_billed_once(self) -> None:
        run_id, runner, persistence, _, = self.prepare(adapter=RejectedProposalAdapter())
        result = runner.run_next(run_id=run_id)
        self.assertEqual(result["status"], "aborted")
        balance = self.repo.reconstruct_budget(run_id=run_id)
        self.assertGreater(balance["used"].get("input_tokens", 0), 0)
        self.assertEqual(balance["used"]["iteration_count"], 1)
        self.assertFalse(any(balance["reserved"].values()))
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_usage_bindings WHERE run_id=?", (run_id,)).fetchone()[0], 1)
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_08_failed_billable_result_is_charged_and_failed_unbilled_result_is_released(self) -> None:
        billable_run, billable_runner, billable_persistence, _ = self.prepare(adapter=FailedBillableAdapter())
        self.assertEqual(billable_runner.run_next(run_id=billable_run)["status"], "aborted")
        billable_balance = self.repo.reconstruct_budget(run_id=billable_run)
        self.assertGreater(billable_balance["used"].get("input_tokens", 0), 0)
        self.assertEqual(billable_balance["used"]["iteration_count"], 1)
        self.assertTrue(billable_persistence.verify_run(run_id=billable_run)["ok"])

        free_run, free_runner, free_persistence, _ = self.prepare(adapter=FailedUnbilledAdapter())
        self.assertEqual(free_runner.run_next(run_id=free_run)["status"], "aborted")
        free_balance = self.repo.reconstruct_budget(run_id=free_run)
        self.assertEqual(free_balance["used"]["iteration_count"], 1)
        self.assertFalse(any(free_balance["reserved"].values()))
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_usage_bindings WHERE run_id=?", (free_run,)).fetchone()[0], 0)
        self.assertTrue(free_persistence.verify_run(run_id=free_run)["ok"])

    def test_09_receipt_replay_across_role_calls_pauses_with_reservation_retained(self) -> None:
        run_id, runner, persistence, _, = self.prepare(adapter=ReplayedReceiptAdapter())
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "paused")
        balance = self.repo.reconstruct_budget(run_id=run_id)
        self.assertTrue(balance["reserved"])
        self.assertEqual(self.repo.get_run(run_id)["status"], "PAUSED")
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_10_invalid_adjudicator_output_is_not_promoted_to_discussion(self) -> None:
        run_id, runner, persistence, _, = self.prepare(adapter=InvalidAdjudicationAdapter())
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "aborted")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_cognitive_artifacts WHERE run_id=? AND artifact_type='discussion_session'", (run_id,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_epistemic_conflicts WHERE run_id=?", (run_id,)).fetchone()[0], 1)
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_11_legacy_two_role_adjudication_plan_fails_at_contract_boundary(self) -> None:
        state = {"state_hash": "a" * 64, "latest_by_id": {}, "active_leading_hypothesis_id": None}
        canonical_plan = build_plan(project_id="p", run_id="r", sequence=3, state=state, profile=self.profile, history=[{"sequence_no": 2, "round_type": "acquisition_review", "status": "completed"}])
        with self.assertRaises(Exception):
            replace(canonical_plan, role_packets=canonical_plan.role_packets[:2], call_specs=canonical_plan.call_specs[:2])

    def test_12_conflict_escalation_is_persisted_and_pauses_on_threshold(self) -> None:
        run_id, runner, persistence, _, = self.prepare(adapter=RejectedProposalAdapter())
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "aborted")
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "aborted")
        self.assertEqual(runner.run_next(run_id=run_id)["status"], "paused")
        conflicts = self._rows("SELECT repeat_count, resolution FROM max_epistemic_conflicts WHERE run_id=? ORDER BY repeat_count", (run_id,))
        self.assertEqual(conflicts, [{"repeat_count": 1, "resolution": "rejected"}, {"repeat_count": 2, "resolution": "rehydration_required"}, {"repeat_count": 3, "resolution": "paused"}])
        self.assertEqual(self.repo.get_run(run_id)["status"], "PAUSED")
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_13_new_authority_tables_are_append_only(self) -> None:
        run_id, runner, _, _, = self.prepare()
        runner.run_next(run_id=run_id)
        with closing(sqlite3.connect(self.path)) as db:
            rows = {
                "max_runner_call_specs": ("spec_id", "UPDATE max_runner_call_specs SET call_id='tampered' WHERE spec_id=?"),
                "max_runner_result_call_bindings": ("binding_id", "UPDATE max_runner_result_call_bindings SET role='tampered' WHERE binding_id=?"),
                "max_runner_usage_bindings": ("binding_id", "UPDATE max_runner_usage_bindings SET status='tampered' WHERE binding_id=?"),
                "max_runner_artifact_bindings": ("binding_id", "UPDATE max_runner_artifact_bindings SET artifact_type='tampered' WHERE binding_id=?"),
            }
            for table, (key, statement) in rows.items():
                value = db.execute(f"SELECT {key} FROM {table} WHERE run_id=? LIMIT 1", (run_id,)).fetchone()[0]
                with self.assertRaises(sqlite3.DatabaseError, msg=table):
                    db.execute(statement, (value,))
                with self.assertRaises(sqlite3.DatabaseError, msg=table):
                    db.execute(f"DELETE FROM {table} WHERE {key}=?", (value,))

    def test_14_tampered_result_call_binding_fails_public_verify(self) -> None:
        run_id, runner, persistence, _, = self.prepare()
        runner.run_next(run_id=run_id)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DROP TRIGGER max_runner_result_call_binding_no_update")
            db.execute("UPDATE max_runner_result_call_bindings SET binding_json='{}' WHERE run_id=?", (run_id,))
            db.commit()
        self.assertFalse(self.repo.verify_run(run_id=run_id)["ok"])
        self.assertFalse(persistence.verify_run(run_id=run_id)["ok"])

    def test_15_backup_restore_recomputes_mr2a2_closure(self) -> None:
        run_id, runner, persistence, _, = self.run_to_adjudication()[:4]
        runner.run_next(run_id=run_id) if self.repo.get_run(run_id)["status"] == "RUNNING" else None
        backup = Path(self.temp.name) / "mr2a2-backup.db"
        restored = Path(self.temp.name) / "mr2a2-restored.db"
        self.assertTrue(self.repo.backup(backup)["verification"]["ok"])
        restored_repo = MaxControlRepository(restored)
        self.assertTrue(restored_repo.restore(backup)["verification"]["ok"])
        self.assertTrue(RunnerPersistence(restored_repo).verify_run(run_id=run_id)["ok"])
        self.assertEqual(restored_repo.verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)

    def test_16_import_and_read_only_missing_database_do_not_create_control_store(self) -> None:
        missing = Path(self.temp.name) / "never-created.db"
        self.assertFalse(missing.exists())
        with self.assertRaises(MaxControlError):
            MaxControlRepository(missing).verify_database()
        self.assertFalse(missing.exists())

    def test_17_plan_hash_binds_five_call_specs_deterministically(self) -> None:
        state = {"state_hash": "a" * 64, "latest_by_id": {}, "active_leading_hypothesis_id": None}
        history = [{"sequence_no": 2, "round_type": "acquisition_review", "status": "completed"}]
        first = build_plan(project_id="p", run_id="r", sequence=3, state=state, profile=self.profile, history=history)
        second = build_plan(project_id="p", run_id="r", sequence=3, state=state, profile=self.profile, history=history)
        self.assertEqual(model_to_dict(first), model_to_dict(second))
        self.assertEqual(first.plan_hash, canonical_sha256({"project_id": first.project_id, "run_id": first.run_id, "sequence": first.sequence, "input_state_hash": first.input_state_hash, "round_type": first.round_type, "cognitive_kind": first.cognitive_kind, "priority_reason": first.priority_reason, "model_identity": first.model_identity, "inference_profile_hash": first.inference_profile_hash, "iteration_id": first.iteration_id, "role_packets": model_to_dict(first.role_packets), "call_specs": model_to_dict(first.call_specs), "metadata": first.metadata}))

    def _adjudication_iteration(self, run_id: str) -> str:
        rows = self._rows("SELECT iteration_id FROM max_iterations WHERE run_id=? AND round_type='adjudication' ORDER BY sequence_no", (run_id,))
        self.assertTrue(rows)
        return str(rows[-1]["iteration_id"])

    def _assert_aborted_adjudication_closure(self, run_id: str, persistence: RunnerPersistence) -> None:
        iteration_id = self._adjudication_iteration(run_id)
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_cognitive_artifacts WHERE run_id=? AND artifact_type='discussion_session'", (run_id,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_canonical_change_sets WHERE run_id=? AND iteration_id=?", (run_id, iteration_id)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT status FROM max_iteration_outcomes WHERE run_id=? AND iteration_id=?", (run_id, iteration_id)).fetchone()[0], "aborted")
            self.assertEqual(db.execute("SELECT status FROM max_runner_call_group_current WHERE group_id IN (SELECT group_id FROM max_runner_call_groups WHERE run_id=? AND iteration_id=?)", (run_id, iteration_id)).fetchone()[0], "aborted")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_epistemic_conflicts WHERE run_id=?", (run_id,)).fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_model_call_results WHERE run_id=? AND iteration_id=?", (run_id, iteration_id)).fetchone()[0], 5)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_result_call_bindings WHERE run_id=? AND iteration_id=?", (run_id, iteration_id)).fetchone()[0], 5)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_usage_bindings WHERE run_id=? AND iteration_id=?", (run_id, iteration_id)).fetchone()[0], 5)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_budget_ledger WHERE run_id=? AND iteration_id=? AND operation='usage' AND provenance_json LIKE '%server_owned%'", (run_id, iteration_id)).fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_budget_ledger r WHERE r.run_id=? AND r.iteration_id=? AND r.operation='reserve' AND NOT EXISTS (SELECT 1 FROM max_budget_ledger x WHERE x.reservation_id=r.reservation_id AND x.operation IN ('commit','release'))", (run_id, iteration_id)).fetchone()[0], 0)
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_18_five_phase_nested_contract_attack_matrix_is_controlled(self) -> None:
        phases = ("lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response", "adjudicator")
        modes = ("missing", "empty", "whitespace", "wrong_type", "unknown")
        for phase in phases:
            for mode in modes:
                with self.subTest(phase=phase, mode=mode):
                    run_id, runner, persistence, _ = self.prepare(adapter=NestedContractAttackAdapter(phase, mode))
                    self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
                    self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
                    outcome = runner.run_next(run_id=run_id)
                    self.assertEqual(outcome["status"], "aborted")
                    self._assert_aborted_adjudication_closure(run_id, persistence)

    def test_19_nested_validity_adjudication_and_minority_contracts_fail_closed(self) -> None:
        for nested, mode in (("validity_audit", "unknown"), ("adjudication", "wrong_type"), ("minority_reports", "missing")):
            with self.subTest(nested=nested):
                run_id, runner, persistence, _ = self.prepare(adapter=NestedContractAttackAdapter("adjudicator", mode, nested=nested))
                self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
                self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
                self.assertEqual(runner.run_next(run_id=run_id)["status"], "aborted")
                self._assert_aborted_adjudication_closure(run_id, persistence)

    def test_20_repeated_nested_failure_uses_frozen_conflict_escalation(self) -> None:
        run_id, runner, persistence, _ = self.prepare(adapter=NestedContractAttackAdapter("adjudicator", "empty"))
        first = [runner.run_next(run_id=run_id) for _ in range(3)]
        self.assertEqual([item["status"] for item in first], ["completed", "completed", "aborted"])
        first_iteration = self._adjudication_iteration(run_id)
        first_dispatches = runner.adapter.dispatch_count
        second = runner.run_next(run_id=run_id)
        third = runner.run_next(run_id=run_id)
        self.assertEqual([second["status"], third["status"]], ["aborted", "paused"])
        self.assertGreaterEqual(runner.adapter.dispatch_count, first_dispatches)
        self.assertEqual(self._rows("SELECT COUNT(*) AS n FROM max_runner_call_groups WHERE run_id=? AND iteration_id=?", (run_id, first_iteration))[0]["n"], 1)
        self.assertFalse(self._rows("SELECT 1 AS n FROM max_runner_call_group_current c JOIN max_runner_call_groups g ON g.group_id=c.group_id WHERE g.run_id=? AND g.iteration_id=? AND c.status='open'", (run_id, first_iteration)))
        self.assertEqual(self._rows("SELECT repeat_count, resolution FROM max_epistemic_conflicts WHERE run_id=? ORDER BY repeat_count", (run_id,)), [{"repeat_count": 1, "resolution": "rejected"}, {"repeat_count": 2, "resolution": "rehydration_required"}, {"repeat_count": 3, "resolution": "paused"}])
        self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_21_crash_recovery_is_idempotent_at_validation_conflict_finish_and_group_boundaries(self) -> None:
        invalid_stages = {"conflict_before", "conflict_after", "iteration_finish_before", "iteration_finish_after"}
        stages = ("validation_before", "validation_after", "conflict_before", "conflict_after", "iteration_finish_before", "iteration_finish_after", "group_finalize_before", "group_finalize_after")
        for stage in stages:
            with self.subTest(stage=stage):
                adapter = NestedContractAttackAdapter("adjudicator", "empty") if stage in invalid_stages else ScriptedFakeAdapter()
                run_id, runner, persistence, _ = self.prepare(adapter=adapter)
                self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
                self.assertEqual(runner.run_next(run_id=run_id)["status"], "completed")
                runner.inject_failure(stage)
                with self.assertRaises(InjectedRunnerCrash):
                    runner.run_next(run_id=run_id)
                iteration_id = self._adjudication_iteration(run_id)
                recovered = runner.run_next(run_id=run_id)
                self.assertIn(recovered["status"], {"completed", "aborted"})
                with closing(sqlite3.connect(self.path)) as db:
                    db.row_factory = sqlite3.Row
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM max_budget_ledger WHERE run_id=? AND iteration_id=? AND operation='usage' AND provenance_json LIKE '%server_owned%'", (run_id, iteration_id)).fetchone()[0], 1)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM max_model_call_results WHERE run_id=? AND iteration_id=?", (run_id, iteration_id)).fetchone()[0], 5)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM max_runner_usage_bindings WHERE run_id=? AND iteration_id=?", (run_id, iteration_id)).fetchone()[0], 5)
                    self.assertFalse(db.execute("SELECT 1 FROM max_runner_call_group_current c JOIN max_runner_call_groups g ON g.group_id=c.group_id WHERE g.run_id=? AND g.iteration_id=? AND c.status='open'", (run_id, iteration_id)).fetchone())
                    if stage in invalid_stages:
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM max_epistemic_conflicts WHERE run_id=?", (run_id,)).fetchone()[0], 1)
                self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_22_public_verify_distinguishes_terminal_orphan_from_real_inflight_group(self) -> None:
        orphan_run, orphan_runner, orphan_persistence, _ = self.prepare()
        orphan_runner.inject_failure("group_finalize_before")
        with self.assertRaises(InjectedRunnerCrash):
            orphan_runner.run_next(run_id=orphan_run)
        orphan_check = orphan_persistence.verify_run(run_id=orphan_run)
        self.assertFalse(orphan_check["ok"])
        self.assertIn("terminal_ready_group_not_finalized", orphan_check["issues"])
        self.assertFalse(self.repo.verify_run(run_id=orphan_run)["ok"])
        self.assertEqual(orphan_runner.run_next(run_id=orphan_run)["status"], "completed")
        self.assertTrue(orphan_persistence.verify_run(run_id=orphan_run)["ok"])

        inflight_run, inflight_runner, inflight_persistence, _ = self.prepare()
        run_state, charter, state, budget, _ = inflight_runner._read_context(inflight_run)
        lease = inflight_persistence.claim_runner_lease(run_id=inflight_run, profile=self.profile, actor=self.worker, lease_ttl=300)
        inflight_runner._persist_plan_and_iteration(run_state=run_state, charter=charter, state=state, budget=budget, fencing_token=int(lease["fencing_token"]))
        claim = inflight_persistence.claim_invocation(run_id=inflight_run, actor=self.worker, fencing_token=int(lease["fencing_token"]), ttl_seconds=300)
        self.assertTrue(inflight_persistence.verify_run(run_id=inflight_run)["ok"])
        self.assertTrue(self.repo.verify_run(run_id=inflight_run)["ok"])
        inflight_persistence.release_invocation(run_id=inflight_run, claim_id=claim["claim_id"], actor=self.worker, fencing_token=int(lease["fencing_token"]))

    def test_23_terminal_group_outcome_conflict_and_result_binding_tamper_are_detected(self) -> None:
        run_id, runner, persistence, _ = self.prepare()
        runner.run_next(run_id=run_id)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE max_runner_call_group_current SET status='open' WHERE group_id=(SELECT group_id FROM max_runner_call_groups WHERE run_id=? ORDER BY created_at LIMIT 1)", (run_id,))
            db.commit()
        self.assertFalse(persistence.verify_run(run_id=run_id)["ok"])

        outcome_run, outcome_runner, outcome_persistence, _ = self.prepare()
        outcome_runner.run_next(run_id=outcome_run)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DROP TRIGGER max_iteration_outcomes_no_update")
            db.execute("UPDATE max_iteration_outcomes SET status='aborted' WHERE run_id=?", (outcome_run,))
            db.commit()
        self.assertFalse(outcome_persistence.verify_run(run_id=outcome_run)["ok"])

        # The first two branches intentionally corrupt the shared database.
        # A schema-manifest mismatch must then block further writes, so the
        # third branch uses a fresh disposable control store.
        self.path = Path(self.temp.name) / "conflict.db"
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize(fixture=True)
        self.repo.usage_authority = FixtureUsageAuthority(self.repo)
        conflict_run, conflict_runner, conflict_persistence, _ = self.prepare(adapter=RejectedProposalAdapter())
        self.assertEqual(conflict_runner.run_next(run_id=conflict_run)["status"], "aborted")
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DROP TRIGGER max_epistemic_conflicts_no_update")
            db.execute("UPDATE max_epistemic_conflicts SET conflict_json='{}' WHERE run_id=?", (conflict_run,))
            db.commit()
        self.assertFalse(conflict_persistence.verify_run(run_id=conflict_run)["ok"])

    def test_24_gateway_identity_config_and_source_version_drift_fail_recovery_closed(self) -> None:
        for attribute, value in (("gateway_name", "fixture-gateway-v2"), ("gateway_identity", "fixture-gateway/v2"), ("config_hash", "fixture-gateway-config-v2"), ("source_version", "document-version-v2")):
            with self.subTest(attribute=attribute):
                gateway = DriftingFixtureGateway()
                run_id, runner, persistence, _ = self.prepare(gateway=gateway)
                runner.inject_failure("intent_after")
                with self.assertRaises(InjectedRunnerCrash):
                    runner.run_next(run_id=run_id)
                setattr(gateway, attribute, value)
                recovered = runner.run_next(run_id=run_id)
                self.assertEqual(recovered["status"], "aborted")
                self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])

    def test_25_schema4_to5_compatibility_and_unsafe_states_fail_closed(self) -> None:
        def create_schema4(path: Path) -> None:
            with closing(sqlite3.connect(path)) as db:
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("BEGIN IMMEDIATE")
                db.execute("CREATE TABLE max_schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
                for version, name, migration_path in migration_files()[:4]:
                    for statement in _statements(migration_path.read_text(encoding="utf-8")):
                        db.execute(statement)
                    db.execute("INSERT INTO max_schema_migrations(version, name, applied_at) VALUES (?, ?, '2026-01-01T00:00:00.000Z')", (version, name))
                db.commit()

        empty = Path(self.temp.name) / "schema4-empty.db"
        create_schema4(empty)
        upgraded = MaxControlRepository(empty).initialize()
        self.assertEqual(upgraded["schema_version"], CONTROL_SCHEMA_VERSION)
        self.assertTrue(MaxControlRepository(empty).verify_database()["ok"])

        # A database that advertises schema 4 while containing any schema-5
        # state must never be interpreted as a compatible legacy fixture.
        for label, adapter, run_steps in (
            ("single", ScriptedFakeAdapter(), 1),
            ("completed_group", ScriptedFakeAdapter(), 2),
            ("open_inflight", ScriptedFakeAdapter(), 0),
            ("ambiguous_paused", ReplayedReceiptAdapter(), 3),
        ):
            path = Path(self.temp.name) / f"schema4-{label}.db"
            local_repo = MaxControlRepository(path)
            local_repo.initialize(fixture=True)
            local_repo.usage_authority = FixtureUsageAuthority(local_repo)
            proposed = local_repo.propose(project_id=f"schema4-{label}", charter=self.charter, actor=self.admin)
            local_repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="schema matrix", actor=self.admin)
            local_persistence = RunnerPersistence(local_repo)
            local_persistence.register_profile(profile=self.profile, actor=self.admin)
            local_persistence.handoff_runner(run_id=proposed["run_id"], profile=self.profile, admin_actor=self.admin, runner_actor=self.worker, lease_ttl=300)
            local_runner = BoundedRunner(local_repo, self.worker, self.profile, adapter, gateway=FixtureResearchGateway(), usage_authority=local_repo.usage_authority, fixture=True, lease_ttl=300)
            if run_steps:
                for _ in range(run_steps):
                    local_runner.run_next(run_id=proposed["run_id"])
            else:
                local_runner.inject_failure("intent_before")
                with self.assertRaises(InjectedRunnerCrash):
                    local_runner.run_next(run_id=proposed["run_id"])
            with closing(sqlite3.connect(path)) as db:
                db.execute("DELETE FROM max_schema_migrations WHERE version=7")
                db.commit()
            with self.assertRaises(MaxControlError):
                MaxControlRepository(path).verify_database()

    def test_26_hundred_deterministic_plans_and_twenty_four_fixture_runner_rounds(self) -> None:
        state = {"state_hash": "b" * 64, "latest_by_id": {}, "active_leading_hypothesis_id": None}
        histories = ((), ({"sequence_no": 1, "round_type": "exploration", "status": "completed"},), ({"sequence_no": 1, "round_type": "acquisition_review", "status": "completed"},), ({"sequence_no": 1, "round_type": "adjudication", "status": "completed"},), ({"sequence_no": 1, "round_type": "attack", "status": "completed"},))
        seen_rounds = set()
        for index in range(100):
            history = histories[index % len(histories)]
            first = build_plan(project_id="planner-project", run_id="planner-run", sequence=index + 1, state=state, history=history, profile=self.profile, recovery_required=index % 17 == 0, policy_triggers=("recovery",) if index % 19 == 0 else ())
            second = build_plan(project_id="planner-project", run_id="planner-run", sequence=index + 1, state=state, history=history, profile=self.profile, recovery_required=index % 17 == 0, policy_triggers=("recovery",) if index % 19 == 0 else ())
            self.assertEqual(model_to_dict(first), model_to_dict(second))
            seen_rounds.add(first.round_type)
        self.assertTrue({"rehydration", "exploration", "acquisition_review", "adjudication", "attack"}.issubset(seen_rounds))

        completed_rounds = 0
        for _ in range(8):
            run_id, runner, persistence, _ = self.run_to_adjudication()[:4]
            completed_rounds += 3
            self.assertTrue(persistence.verify_run(run_id=run_id)["ok"])
            self.assertFalse(self._rows("SELECT 1 FROM max_runner_call_group_current c JOIN max_runner_call_groups g ON g.group_id=c.group_id WHERE g.run_id=? AND c.status='open'", (run_id,)))
        self.assertEqual(completed_rounds, 24)


if __name__ == "__main__":
    unittest.main()
