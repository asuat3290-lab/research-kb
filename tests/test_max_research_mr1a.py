from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from research_kb.max_research.contract import (
    AttackRecord,
    CanonicalObject,
    CanonicalObjectKind,
    CanonicalRelation,
    ClaimSnapshot,
    ColdReviewPacket,
    ColdReviewResult,
    CoverageLedger,
    DiscussionSession,
    FormalCompletionEvidence,
    MaxResearchCharter,
    MaxRunState,
    Checkpoint,
    ResearchState,
    RunStatus,
    WorkingState,
    RehydrationOutput,
    SearchStrategy,
    canonical_sha256,
    canonical_json,
    make_claim_snapshot,
    make_evidence_snapshot,
    make_stable_id,
    make_event_id,
    charter_hash,
    model_to_dict,
    project_report,
)
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION
from research_kb.max_research.persistence import (
    CanonicalChangeSet,
    MaxControlError,
    MaxControlRepository,
    UsageReceipt,
    connect_control_db,
)
from research_kb.max_research.persistence.migrations import _statements
from research_kb.policy import Actor
from tests.test_max_research_contracts import FIXED_TIME, MaxResearchContractTests


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class Authority:
    def verify_usage_receipt(self, receipt: UsageReceipt, **_: object):
        return {"authority": "fixture", "receipt_id": receipt.receipt_id}


class Resolver:
    def resolve_reference(self, *, project_id: str, reference):
        return {"project_id": project_id, "verified_source_version_id": reference["verified_source_version_id"]}


class MR1AClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr1a-")
        self.path = Path(self.temp.name) / "control.db"
        self.clock = Clock()
        self.admin = Actor("admin", "admin-session", "user", "admin", "mr1a")
        self.worker = Actor("worker", "worker-session", "worker", "runner", "mr1a")
        self.repo = MaxControlRepository(self.path, clock=self.clock)
        self.repo.initialize()
        self.charter = {
            "question": "How does a persistent control plane preserve exact history?",
            "scope": "MR-1A",
            "invariants": ["append-only canonical history"],
            "non_goals": ["runner and model execution"],
            "deliverables": ["auditable state"],
            "model_identity": "fixture-model/v1",
            "budget": {"iteration_count": 20, "input_tokens": 1000, "output_tokens": 1000, "cost_units": 100},
            "source_policy": {"network_allowed": False, "roles": ["primary", "counterevidence"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct", "counterevidence"]},
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run(self, *args, **kwargs):
        # Keep the fixture helper name while preserving unittest.TestCase.run.
        if args:
            return super().run(*args, **kwargs)
        project = kwargs.pop("project", "mr1a-project")
        question = kwargs.pop("question", None)
        repository = kwargs.pop("repository", None)
        repo = repository or self.repo
        charter = dict(self.charter)
        if question is not None:
            charter["question"] = question
        proposed = repo.propose(project_id=project, charter=charter, actor=self.admin)
        repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="human fixture approval", actor=self.admin)
        started = repo.start(run_id=proposed["run_id"], actor=self.admin, lease_ttl=10)
        return proposed, started["lease"]["fencing_token"]

    def begin(self, run_id: str, token: int, kind: str = "exploration") -> str:
        return self.repo.begin_iteration(run_id=run_id, round_type=kind, actor=self.admin, fencing_token=token)["iteration_id"]

    def obj(self, opaque: str, kind: str = "decision", *, payload=None, project: str = "mr1a-project") -> CanonicalObject:
        return CanonicalObject(make_stable_id(kind, opaque), kind, project, payload=payload or {"status": "candidate", "label": opaque})

    def cs(self, run_id: str, iteration_id: str, token: int, *, objects=(), relations=(), expected=None):
        state_hash = self.repo.get_state(run_id=run_id)["state_hash"]
        return self.repo.apply_change_set(
            run_id=run_id,
            change_set=CanonicalChangeSet("mr1a-project", run_id, iteration_id, state_hash, tuple(objects), tuple(relations), expected_output_state_hash=expected),
            actor=self.admin,
            fencing_token=token,
        )

    def test_01_schema3_and_idempotent_migration(self) -> None:
        self.assertEqual(self.repo.initialize()["schema_version"], CONTROL_SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_schema_migrations").fetchone()[0], CONTROL_SCHEMA_VERSION)
            self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE name='max_run_object_memberships'").fetchone())

    def test_02_schema1_empty_upgrade_is_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schema1.db"
            self._make_schema1(path)
            repo = MaxControlRepository(path, clock=self.clock)
            self.assertEqual(repo.initialize()["schema_version"], CONTROL_SCHEMA_VERSION)
            self.assertEqual(repo.verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)

    def test_03_schema1_unbound_object_upgrade_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ambiguous.db"
            self._make_schema1(path)
            obj = self.obj("unbound")
            with closing(sqlite3.connect(path)) as db:
                db.execute("BEGIN")
                db.execute("INSERT INTO max_canonical_objects(project_id, stable_id, kind, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?)", (obj.project_id, obj.stable_id, "decision", "2026-01-01T00:00:00.000Z", "legacy", "legacy"))
                db.execute("INSERT INTO max_canonical_object_versions(version_id, project_id, stable_id, kind, version, supersedes_version_id, object_json, payload_hash, source_reference_json, source_reference_hash, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, '[]', ?, ?, ?, ?)", (obj.version_id, obj.project_id, obj.stable_id, "decision", 1, json.dumps(model_to_dict(obj)), canonical_sha256(obj.payload), canonical_sha256([]), "2026-01-01T00:00:00.000Z", "legacy", "legacy"))
                db.commit()
            with self.assertRaises(Exception):
                MaxControlRepository(path, clock=self.clock).initialize()

    def test_04_two_runs_same_project_are_isolated(self) -> None:
        first, token1 = self.run(question="first")
        second, token2 = self.run(question="second")
        iteration = self.begin(first["run_id"], token1)
        item = self.obj("only-first")
        self.cs(first["run_id"], iteration, token1, objects=(item,))
        self.repo.finish_iteration(run_id=first["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token1)
        self.assertTrue(self.repo.verify_run(run_id=first["run_id"])["ok"])
        self.assertTrue(self.repo.verify_run(run_id=second["run_id"])["ok"])
        self.assertNotIn(item.stable_id, {x["stable_id"] for x in self.repo.list_objects(project_id="mr1a-project", run_id=second["run_id"])["objects"]})

    def test_05_explicit_adopt_is_required_for_reuse(self) -> None:
        first, token1 = self.run(question="first")
        second, token2 = self.run(question="second")
        i1 = self.begin(first["run_id"], token1); item = self.obj("shared")
        self.cs(first["run_id"], i1, token1, objects=(item,)); self.repo.finish_iteration(run_id=first["run_id"], iteration_id=i1, actor=self.admin, fencing_token=token1)
        i2 = self.begin(second["run_id"], token2)
        self.assertRaises(MaxControlError, self.cs, second["run_id"], i2, token2, objects=(item,))
        state = self.repo.get_state(run_id=second["run_id"])["state_hash"]
        result = self.repo.apply_change_set(run_id=second["run_id"], change_set=CanonicalChangeSet("mr1a-project", second["run_id"], i2, state, adopt_object_version_ids=(item.version_id,)), actor=self.admin, fencing_token=token2)
        self.assertNotEqual(state, result["output_state_hash"])

    def test_06_unbound_canonical_object_and_relation_fail(self) -> None:
        item = self.obj("unbound")
        with self.assertRaises(MaxControlError):
            self.repo.append_canonical_object(project_id=item.project_id, value=item, actor=self.admin)
        with self.assertRaises(MaxControlError):
            self.repo.append_canonical_relation(project_id=item.project_id, value=CanonicalRelation(item.stable_id, item.stable_id, "derived_from", item.project_id, source_version_id=item.version_id, target_version_id=item.version_id), actor=self.admin)

    def test_07_awaiting_and_approved_mutations_fail(self) -> None:
        proposed = self.repo.propose(project_id="mr1a-project", charter=self.charter, actor=self.admin)
        item = self.obj("awaiting")
        with self.assertRaises(MaxControlError):
            self.repo.append_canonical_object(project_id=item.project_id, value=item, actor=self.admin, run_id=proposed["run_id"], fencing_token=1, iteration_id="missing")
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="approval", actor=self.admin)
        with self.assertRaises(MaxControlError):
            self.repo.begin_iteration(run_id=proposed["run_id"], round_type="exploration", actor=self.admin, fencing_token=1)

    def test_08_paused_and_terminal_mutations_fail(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token)
        self.repo.pause(run_id=proposed["run_id"], actor=self.admin, fencing_token=token)
        with self.assertRaises(MaxControlError):
            self.repo.apply_change_set(run_id=proposed["run_id"], change_set=CanonicalChangeSet("mr1a-project", proposed["run_id"], iteration, self.repo.get_state(run_id=proposed["run_id"])["state_hash"], objects=(self.obj("paused"),)), actor=self.admin, fencing_token=token)
        self.repo.resume(run_id=proposed["run_id"], actor=self.admin)
        new_token = self.repo.status(run_id=proposed["run_id"])["lease"]["fencing_token"]
        self.repo.cancel(run_id=proposed["run_id"], actor=self.admin, fencing_token=new_token)
        with self.assertRaises(MaxControlError):
            self.repo.acquire_lease(run_id=proposed["run_id"], actor=self.admin)

    def test_09_atomic_invalid_change_set_has_zero_writes(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); before = self.repo.list_events(run_id=proposed["run_id"], limit=200)["events"]
        source = self.obj("source"); bad = CanonicalRelation(source.stable_id, make_stable_id("decision", "missing"), "derived_from", source.project_id, source_version_id=source.version_id, target_version_id=make_stable_id("decision-version", "missing"))
        with self.assertRaises(MaxControlError):
            self.cs(proposed["run_id"], iteration, token, objects=(source,), relations=(bad,))
        with closing(connect_control_db(self.path, read_only=True)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_canonical_change_sets").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_canonical_object_versions WHERE stable_id=?", (source.stable_id,)).fetchone()[0], 0)
        self.assertEqual(len(before), len(self.repo.list_events(run_id=proposed["run_id"], limit=200)["events"]))

    def test_10_mutation_event_failure_rolls_back_the_change_set(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); original = self.repo._append_event
        def fail(*args, **kwargs):
            raise MaxControlError("injected event failure")
        self.repo._append_event = fail  # type: ignore[method-assign]
        try:
            with self.assertRaises(MaxControlError):
                self.cs(proposed["run_id"], iteration, token, objects=(self.obj("rolled-back"),))
        finally:
            self.repo._append_event = original  # type: ignore[method-assign]
        with closing(connect_control_db(self.path, read_only=True)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM max_canonical_change_sets").fetchone()[0], 0)

    def test_11_verified_source_reference_uses_server_resolver(self) -> None:
        repo = MaxControlRepository(self.path, clock=self.clock, source_resolver=Resolver())
        proposed, token = self.run(repository=repo); iteration = repo.begin_iteration(run_id=proposed["run_id"], round_type="exploration", actor=self.admin, fencing_token=token)["iteration_id"]
        document = self.obj("doc", "document_version"); evidence = self.obj("evidence", "evidence", payload={"status": "verified", "verification_record_id": self.obj("verification", "verification_record").stable_id, "verified_source_version_id": document.version_id})
        verification = self.obj("verification", "verification_record")
        result = repo.apply_change_set(run_id=proposed["run_id"], change_set=CanonicalChangeSet("mr1a-project", proposed["run_id"], iteration, repo.get_state(run_id=proposed["run_id"])["state_hash"], objects=(document, verification, evidence)), actor=self.admin, fencing_token=token)
        self.assertTrue(result["output_state_hash"])

    def test_12_source_project_or_hash_forgery_fails(self) -> None:
        class WrongResolver:
            def resolve_reference(self, *, project_id, reference):
                return {"project_id": project_id, "verified_source_version_id": "other-version", "reference_hash": "forged"}
        repo = MaxControlRepository(self.path, clock=self.clock, source_resolver=WrongResolver())
        proposed, token = self.run(repository=repo); iteration = repo.begin_iteration(run_id=proposed["run_id"], round_type="exploration", actor=self.admin, fencing_token=token)["iteration_id"]
        doc = self.obj("doc", "document_version"); verification = self.obj("verification", "verification_record"); evidence = self.obj("evidence", "evidence", payload={"status": "verified", "verification_record_id": verification.stable_id, "verified_source_version_id": doc.version_id})
        with self.assertRaises(MaxControlError):
            repo.apply_change_set(run_id=proposed["run_id"], change_set=CanonicalChangeSet("mr1a-project", proposed["run_id"], iteration, repo.get_state(run_id=proposed["run_id"])["state_hash"], objects=(doc, verification, evidence)), actor=self.admin, fencing_token=token)

    def test_13_state_changing_iteration_is_s0_to_s1(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); s0 = self.repo.get_state(run_id=proposed["run_id"])["state_hash"]; applied = self.cs(proposed["run_id"], iteration, token, objects=(self.obj("s1"),)); self.assertNotEqual(s0, applied["output_state_hash"]); finished = self.repo.finish_iteration(run_id=proposed["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token); self.assertEqual(finished["input_state_hash"], s0); self.assertEqual(finished["output_state_hash"], applied["output_state_hash"])

    def test_14_one_run_has_one_open_iteration(self) -> None:
        proposed, token = self.run(); self.begin(proposed["run_id"], token)
        with self.assertRaises(MaxControlError):
            self.begin(proposed["run_id"], token)

    def test_15_iteration_outcome_is_exactly_once(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); self.repo.finish_iteration(run_id=proposed["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token, status="aborted")
        with self.assertRaises(MaxControlError):
            self.repo.finish_iteration(run_id=proposed["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token, status="completed")

    def test_16_stale_iteration_and_fence_fail(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token)
        with self.assertRaises(MaxControlError):
            self.repo.apply_change_set(run_id=proposed["run_id"], change_set=CanonicalChangeSet("mr1a-project", proposed["run_id"], iteration, "0" * 64, objects=(self.obj("stale"),)), actor=self.admin, fencing_token=token)
        self.clock.advance(20)
        with self.assertRaises(MaxControlError):
            self.repo.finish_iteration(run_id=proposed["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token)

    def test_17_snapshot_wrong_version_is_rejected(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token)
        question = self.repo.get_state(run_id=proposed["run_id"])["objects"][0]
        forged = ClaimSnapshot(question["stable_id"], question["version_id"], "final", "forged")
        with self.assertRaises(MaxControlError):
            self.repo.finish_iteration(run_id=proposed["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token, claim_snapshots=(forged,))

    def test_18_empty_round_labels_do_not_complete(self) -> None:
        proposed, token = self.run();
        for kind in ("attack", "adjudication", "rehydration", "cold_review"):
            iteration = self.begin(proposed["run_id"], token, kind); self.repo.finish_iteration(run_id=proposed["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token, strategy_ledger=CoverageLedger())
        with self.assertRaises(MaxControlError):
            self.repo.evaluate_completion(run_id=proposed["run_id"], actor=self.admin, fencing_token=token)

    def test_19_payload_only_completion_fails(self) -> None:
        proposed, token = self.run()
        with self.assertRaises(MaxControlError):
            self.repo.persist_completion(run_id=proposed["run_id"], evaluation_input={"attack_records": [{"fake": True}]}, result={"passed": True}, actor=self.admin, fencing_token=token)

    def test_20_self_asserted_usage_fails(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token)
        with self.assertRaises(MaxControlError):
            self.repo.record_authoritative_usage(run_id=proposed["run_id"], iteration_id=iteration, amount={"input_tokens": 1}, provenance={"authoritative": True, "authority": "any", "record_id": "fake"}, idempotency_key="u", actor=self.admin, fencing_token=token)

    def test_21_registered_usage_receipt_succeeds(self) -> None:
        repo = MaxControlRepository(self.path, clock=self.clock, usage_authority=Authority()); proposed, token = self.run(repository=repo); iteration = repo.begin_iteration(run_id=proposed["run_id"], round_type="exploration", actor=self.admin, fencing_token=token)["iteration_id"]
        receipt = UsageReceipt("receipt-1", proposed["run_id"], iteration, self.charter["model_identity"], {"input_tokens": 1}, "2026-01-01T00:00:00Z", "fixture", "")
        receipt = replace(receipt, payload_hash=receipt.computed_payload_hash())
        receipt = replace(receipt, receipt_hash=receipt.computed_receipt_hash())
        self.assertEqual(repo.record_authoritative_usage(run_id=proposed["run_id"], iteration_id=iteration, amount={"input_tokens": 1}, receipt=receipt, idempotency_key="u", actor=self.admin, fencing_token=token)["operation"], "usage")

    def test_22_idempotency_same_request_replays(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); first = self.repo.reserve_budget(run_id=proposed["run_id"], iteration_id=iteration, amount={"input_tokens": 2}, idempotency_key="same", actor=self.admin, fencing_token=token); second = self.repo.reserve_budget(run_id=proposed["run_id"], iteration_id=iteration, amount={"input_tokens": 2}, idempotency_key="same", actor=self.admin, fencing_token=token); self.assertEqual(first["entry_id"], second["entry_id"])

    def test_23_idempotency_conflict_is_not_silent(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); self.repo.reserve_budget(run_id=proposed["run_id"], iteration_id=iteration, amount={"input_tokens": 2}, idempotency_key="same", actor=self.admin, fencing_token=token)
        with self.assertRaisesRegex(MaxControlError, "CONFLICT"):
            self.repo.reserve_budget(run_id=proposed["run_id"], iteration_id=iteration, amount={"input_tokens": 3}, idempotency_key="same", actor=self.admin, fencing_token=token)

    def test_24_lease_state_rules_are_closed(self) -> None:
        proposed = self.repo.propose(project_id="mr1a-project", charter=self.charter, actor=self.admin)
        with self.assertRaises(MaxControlError): self.repo.acquire_lease(run_id=proposed["run_id"], actor=self.admin)
        self.repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="approval", actor=self.admin)
        with self.assertRaises(MaxControlError): self.repo.acquire_lease(run_id=proposed["run_id"], actor=self.admin)
        started = self.repo.start(run_id=proposed["run_id"], actor=self.admin); self.repo.pause(run_id=proposed["run_id"], actor=self.admin, fencing_token=started["lease"]["fencing_token"])
        with self.assertRaises(MaxControlError): self.repo.acquire_lease(run_id=proposed["run_id"], actor=self.admin)

    def test_24a_unapproved_cancel_has_no_approval_consumption(self) -> None:
        proposed = self.repo.propose(project_id="mr1a-cancel-before-approval", charter=self.charter, actor=self.admin)
        cancelled = self.repo.cancel(run_id=proposed["run_id"], actor=self.admin)
        self.assertEqual(cancelled["run"]["status"], "CANCELLED")
        verification = self.repo.verify_run(run_id=proposed["run_id"])
        self.assertTrue(verification["ok"], verification["issues"])
        self.assertEqual(verification["approval_consumptions"], 0)

    def test_25_pause_ttl_resume_uses_new_fence(self) -> None:
        proposed, token = self.run(); self.repo.pause(run_id=proposed["run_id"], actor=self.admin, fencing_token=token); self.clock.advance(100); resumed = self.repo.resume(run_id=proposed["run_id"], actor=self.admin); self.assertGreater(resumed["lease"]["fencing_token"], token)

    def test_26_takeover_rejects_old_worker_mutation(self) -> None:
        proposed, token = self.run(); self.clock.advance(100); takeover = self.repo.acquire_lease(run_id=proposed["run_id"], actor=self.worker); iteration = self.repo.begin_iteration(run_id=proposed["run_id"], round_type="exploration", actor=self.worker, fencing_token=takeover["fencing_token"])["iteration_id"]
        with self.assertRaises(MaxControlError):
            self.repo.apply_change_set(run_id=proposed["run_id"], change_set=CanonicalChangeSet("mr1a-project", proposed["run_id"], iteration, self.repo.get_state(run_id=proposed["run_id"])["state_hash"], objects=(self.obj("old-worker"),)), actor=self.admin, fencing_token=token)

    def test_27_concurrent_lease_competition_has_one_winner(self) -> None:
        proposed, token = self.run(); self.repo.release_lease(run_id=proposed["run_id"], actor=self.admin, fencing_token=token)
        def acquire(index: int) -> bool:
            try: self.repo.acquire_lease(run_id=proposed["run_id"], actor=Actor(f"w-{index}", f"s-{index}", "worker", "runner", "mr1a")); return True
            except MaxControlError: return False
        with ThreadPoolExecutor(max_workers=20) as pool: self.assertEqual(sum(pool.map(acquire, range(20))), 1)

    def test_28_event_chain_and_membership_events_verify(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); self.cs(proposed["run_id"], iteration, token, objects=(self.obj("evented"),)); events = self.repo.list_events(run_id=proposed["run_id"], limit=200)["events"]; self.assertTrue(any(item["event_type"] == "canonical_membership_added" for item in events)); self.assertTrue(self.repo.verify_run(run_id=proposed["run_id"])["event_chain"]["ok"])

    def test_29_orphan_canonical_is_reported_by_database_verify(self) -> None:
        obj = self.obj("orphan")
        with closing(connect_control_db(self.path, read_only=False)) as db:
            db.execute("BEGIN")
            db.execute("INSERT INTO max_canonical_objects(project_id, stable_id, kind, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?)", (obj.project_id, obj.stable_id, "decision", "2026-01-01T00:00:00.000Z", "test", "test"))
            db.execute("INSERT INTO max_canonical_object_versions(version_id, project_id, stable_id, kind, version, object_json, payload_hash, source_reference_json, source_reference_hash, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, 1, ?, ?, '[]', ?, ?, ?, ?)", (obj.version_id, obj.project_id, obj.stable_id, "decision", json.dumps(model_to_dict(obj)), canonical_sha256(obj.payload), canonical_sha256([]), "2026-01-01T00:00:00.000Z", "test", "test"))
            db.commit()
        verified = self.repo.verify_database(); self.assertFalse(verified["ok"]); self.assertGreater(verified["orphan_canonical_versions"], 0)

    def test_30_backup_restore_preserves_schema3_history(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); self.cs(proposed["run_id"], iteration, token, objects=(self.obj("backup"),));
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "backup.db"; restored = Path(directory) / "restored.db"; self.assertTrue(self.repo.backup(backup)["verification"]["ok"]); self.assertTrue(MaxControlRepository(restored, clock=self.clock).restore(backup)["verification"]["ok"]); self.assertEqual(MaxControlRepository(restored, clock=self.clock).verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)

    def test_31_canonical_unknown_field_is_rejected(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); bad = {**model_to_dict(self.obj("unknown")), "unexpected": True}
        with self.assertRaises(MaxControlError):
            self.repo.append_canonical_object(project_id="mr1a-project", value=bad, actor=self.admin, run_id=proposed["run_id"], iteration_id=iteration, fencing_token=token)

    def test_32_read_only_object_listing_requires_run_scope(self) -> None:
        with self.assertRaises(MaxControlError): self.repo.list_objects(project_id="mr1a-project")

    def test_33_completed_iteration_requires_authoritative_output(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); record = self.repo.get_state(run_id=proposed["run_id"])["state_hash"]
        with self.assertRaises(MaxControlError): self.repo.finish_iteration(run_id=proposed["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token, output_state_hash="f" * 64)
        self.assertIsNotNone(self.repo.get_state(run_id=proposed["run_id"])["state_hash"]); self.assertEqual(record, self.repo.get_state(run_id=proposed["run_id"])["state_hash"])

    def test_34_aborted_outcome_is_not_a_stability_round(self) -> None:
        proposed, token = self.run(); iteration = self.begin(proposed["run_id"], token); self.repo.finish_iteration(run_id=proposed["run_id"], iteration_id=iteration, actor=self.admin, fencing_token=token, status="aborted"); self.assertEqual(self.repo.verify_run(run_id=proposed["run_id"])["ok"], True)

    def test_35_control_db_closes_and_is_deletable(self) -> None:
        self.repo.verify_database(); self.assertTrue(self.path.unlink() is None)

    def test_36_complete_persisted_history_passes_mr0b_gate(self) -> None:
        fixture = MaxResearchContractTests()
        fixture.setUp()
        repo = MaxControlRepository(self.path, clock=self.clock, source_resolver=Resolver())
        proposed, token = self.run(project="project-one", repository=repo)
        first = repo.begin_iteration(run_id=proposed["run_id"], round_type="exploration", actor=self.admin, fencing_token=token)
        initial_hash = repo.get_state(run_id=proposed["run_id"])["state_hash"]
        repo.apply_change_set(run_id=proposed["run_id"], change_set=CanonicalChangeSet("project-one", proposed["run_id"], first["iteration_id"], initial_hash, objects=fixture.objects, relations=fixture.relations), actor=self.admin, fencing_token=token)
        state = repo.get_state(run_id=proposed["run_id"])
        state_model = __import__("research_kb.max_research.contract", fromlist=["ResearchState"]).ResearchState.from_mapping(state)
        claim_snapshot = make_claim_snapshot(state_model.latest_by_id[fixture.ids["claim"]])
        evidence_snapshot = make_evidence_snapshot(state_model.latest_by_id[fixture.ids["evidence"]])
        ledger = CoverageLedger((SearchStrategy("project-one", "direct", "mechanism"), SearchStrategy("project-one", "counterevidence", "boundary")), ("direct", "counterevidence"))
        snapshots = {"claim_snapshots": (claim_snapshot, claim_snapshot), "evidence_snapshots": (evidence_snapshot,), "counterevidence_snapshots": (evidence_snapshot,), "strategy_ledger": ledger}
        repo.finish_iteration(run_id=proposed["run_id"], iteration_id=first["iteration_id"], actor=self.admin, fencing_token=token, **snapshots)
        attack_iteration = repo.begin_iteration(run_id=proposed["run_id"], round_type="attack", actor=self.admin, fencing_token=token)
        attack = replace(fixture.attack(state=state_model), run_id=proposed["run_id"], charter_hash=proposed["charter_hash"], iteration_id=attack_iteration["iteration_id"], attack_id="")
        repo.finish_iteration(run_id=proposed["run_id"], iteration_id=attack_iteration["iteration_id"], actor=self.admin, fencing_token=token, artifact_links=({"artifact_type": "attack_record", "artifact": model_to_dict(attack)},), **snapshots)
        adjudication_iteration = repo.begin_iteration(run_id=proposed["run_id"], round_type="adjudication", actor=self.admin, fencing_token=token)
        discussion = fixture.role_session(state=state_model)
        packets = tuple(replace(item, run_id=proposed["run_id"], state_hash=state_model.state_hash, packet_id="") for item in discussion.role_packets)
        discussion = replace(discussion, run_id=proposed["run_id"], state_hash=state_model.state_hash, role_packets=packets, session_id="")
        repo.finish_iteration(run_id=proposed["run_id"], iteration_id=adjudication_iteration["iteration_id"], actor=self.admin, fencing_token=token, artifact_links=({"artifact_type": "discussion_session", "artifact": model_to_dict(discussion)},), **snapshots)
        rehydration_iteration = repo.begin_iteration(run_id=proposed["run_id"], round_type="rehydration", actor=self.admin, fencing_token=token)
        repo.rehydrate_run(run_id=proposed["run_id"], actor=self.admin, fencing_token=token)
        repo.finish_iteration(run_id=proposed["run_id"], iteration_id=rehydration_iteration["iteration_id"], actor=self.admin, fencing_token=token, **snapshots)
        report = project_report(state_model, claim_ids=(fixture.ids["claim"],))
        packet = ColdReviewPacket("project-one", proposed["run_id"], state_model.state_hash, proposed["charter_hash"], report.claim_ids, report.evidence_ids, report.source_links, report.report_id)
        review = ColdReviewResult(packet.packet_id, packet.packet_hash, "project-one", proposed["run_id"], proposed["charter_hash"], state_model.state_hash, report.report_id, self.charter["model_identity"], "inference/v1", True, (), {"passed": True, "claim_ids": report.claim_ids}, {"passed": True, "evidence_ids": report.evidence_ids}, {"passed": True, "source_links": report.source_links}, FIXED_TIME)
        formal = FormalCompletionEvidence("project-one", proposed["run_id"], state_model.state_hash, report.report_id, report.claim_ids, report.evidence_ids, report.source_links, canonical_sha256({"claim_ids": report.claim_ids, "evidence_ids": report.evidence_ids, "source_links": report.source_links}))
        cold_iteration = repo.begin_iteration(run_id=proposed["run_id"], round_type="cold_review", actor=self.admin, fencing_token=token)
        artifacts = tuple({"artifact_type": kind, "artifact": model_to_dict(value)} for kind, value in (("cold_review_packet", packet), ("cold_review_result", review), ("final_report", report), ("formal_completion_evidence", formal)))
        repo.finish_iteration(run_id=proposed["run_id"], iteration_id=cold_iteration["iteration_id"], actor=self.admin, fencing_token=token, artifact_links=artifacts, **snapshots)
        evaluated = repo.evaluate_completion(run_id=proposed["run_id"], actor=self.admin, fencing_token=token)
        self.assertTrue(evaluated["passed"])
        persisted = repo.persist_completion(run_id=proposed["run_id"], expected_input_hash=evaluated["input_hash"], actor=self.admin, fencing_token=token)
        self.assertEqual(persisted["run"]["status"], "COMPLETED")
        self.assertTrue(repo.verify_run(run_id=proposed["run_id"])["ok"])

    def test_37_schema1_event_derived_single_run_upgrade_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-one-run.db"
            self._make_schema1_run(path)
            repo = MaxControlRepository(path, clock=self.clock)
            self.assertEqual(repo.initialize()["schema_version"], CONTROL_SCHEMA_VERSION)
            result = repo.verify_run(run_id="legacy-run-1")
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["canonical_graph"]["object_memberships"], 1)

    def test_38_schema1_event_derived_two_run_upgrade_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-two-run.db"
            self._make_schema1_run(path, run_id="legacy-run-a", question_opaque="legacy-question-a")
            self._make_schema1_run(path, run_id="legacy-run-b", question_opaque="legacy-question-b", initialize=False)
            repo = MaxControlRepository(path, clock=self.clock)
            self.assertEqual(repo.initialize()["schema_version"], CONTROL_SCHEMA_VERSION)
            first = repo.verify_run(run_id="legacy-run-a")
            second = repo.verify_run(run_id="legacy-run-b")
            self.assertTrue(first["ok"], first)
            self.assertTrue(second["ok"], second)
            self.assertEqual(first["canonical_graph"]["object_memberships"], 1)
            self.assertEqual(second["canonical_graph"]["object_memberships"], 1)

    def _make_schema1(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        db = connect_control_db(path, read_only=False)
        try:
            db.execute("BEGIN IMMEDIATE")
            sql_path = Path(__file__).parents[1] / "src" / "research_kb" / "max_research" / "migrations" / "001_control_plane.sql"
            for statement in _statements(sql_path.read_text(encoding="utf-8")):
                db.execute(statement)
            db.execute("CREATE TABLE IF NOT EXISTS max_schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
            db.execute("INSERT INTO max_schema_migrations VALUES (1, 'control_plane', '2026-01-01T00:00:00.000Z')")
            db.commit()
        finally:
            db.close()

    def _make_schema1_run(self, path: Path, *, run_id: str = "legacy-run-1", question_opaque: str = "legacy-question", initialize: bool = True) -> None:
        if initialize:
            self._make_schema1(path)
        project_id = "mr1a-project"
        charter = MaxResearchCharter.from_mapping(self.charter)
        question = self.obj(question_opaque, "research_question")
        state = ResearchState(project_id, run_id, (question,), (), {question.stable_id: question}, None, "")
        state = __import__("research_kb.max_research.contract", fromlist=["rebuild_research_state"]).rebuild_research_state((question,), (), project_id=project_id, run_id=run_id)
        checkpoint = Checkpoint(project_id, run_id, WorkingState(project_id, run_id, 0, charter.budget, (question.stable_id,)), charter.budget, 0, (question.stable_id,), checkpoint_id=make_event_id("checkpoint", project_id, {"run_id": run_id, "legacy": True}), created_at="2026-01-01T00:00:00.000Z")
        run_state = MaxRunState(run_id=run_id, project_id=project_id, status=RunStatus.AWAITING_START_APPROVAL, charter_hash=charter_hash(charter), model_identity=charter.model_identity, budget=charter.budget, source_policy_hash=canonical_sha256(charter.source_policy), state_version=1, current_state_hash=state.state_hash, current_checkpoint_id=checkpoint.checkpoint_id, budget_snapshot_hash=canonical_sha256(charter.budget))
        db = connect_control_db(path, read_only=False)
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO max_runs(run_id, project_id, status, charter_json, charter_hash, model_identity, source_policy_json, source_policy_hash, budget_policy_json, budget_hash, current_state_hash, current_checkpoint_id, state_version, iteration_index, completion_result_id, completion_state_hash, run_state_json, created_at, updated_at, actor_id, actor_session, completion_result_json, completion_result_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, NULL, NULL, ?, ?, ?, ?, ?, NULL, NULL)", (run_id, project_id, run_state.status.value, canonical_json(charter), run_state.charter_hash, charter.model_identity, canonical_json(charter.source_policy), run_state.source_policy_hash, canonical_json(charter.budget), canonical_sha256(charter.budget), state.state_hash, checkpoint.checkpoint_id, canonical_json(run_state), "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "legacy", "legacy"))
            db.execute("INSERT INTO max_canonical_objects(project_id, stable_id, kind, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?)", (project_id, question.stable_id, "research_question", "2026-01-01T00:00:00.000Z", "legacy", "legacy"))
            db.execute("INSERT INTO max_canonical_object_versions(version_id, project_id, stable_id, kind, version, supersedes_version_id, object_json, payload_hash, source_reference_json, source_reference_hash, created_at, actor_id, actor_session) VALUES (?, ?, ?, ?, 1, NULL, ?, ?, '[]', ?, ?, ?, ?)", (question.version_id, project_id, question.stable_id, "research_question", canonical_json(question), canonical_sha256(question.payload), canonical_sha256([]), "2026-01-01T00:00:00.000Z", "legacy", "legacy"))
            db.execute("INSERT INTO max_research_states(run_id, project_id, state_hash, state_json, canonical_frontier_json, working_state_json, rehydration_input_hash, rehydration_output_hash, drift_json, updated_at, actor_id, actor_session) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, '[]', ?, ?, ?)", (run_id, project_id, state.state_hash, canonical_json(state), canonical_json([question.stable_id]), canonical_json(checkpoint.working_state), "2026-01-01T00:00:00.000Z", "legacy", "legacy"))
            db.execute("INSERT INTO max_checkpoints(checkpoint_id, run_id, project_id, checkpoint_version, lineage_version, supersedes_item_id, state_hash, checkpoint_json, fencing_token, created_at, actor_id, actor_session) VALUES (?, ?, ?, 1, 1, NULL, ?, ?, 1, ?, ?, ?)", (checkpoint.checkpoint_id, run_id, project_id, state.state_hash, canonical_json(checkpoint), "2026-01-01T00:00:00.000Z", "legacy", "legacy"))
            db.execute("INSERT INTO max_checkpoint_current(run_id, checkpoint_id, set_at) VALUES (?, ?, ?)", (run_id, checkpoint.checkpoint_id, "2026-01-01T00:00:00.000Z"))
            db.execute("INSERT INTO max_leases(run_id, fencing_token) VALUES (?, 0)", (run_id,))
            previous = ""
            for sequence, event_type, payload in ((1, "run_proposed", {"project_id": project_id, "charter_hash": run_state.charter_hash, "model_identity": charter.model_identity, "state_hash": state.state_hash}), (2, "canonical_version_appended", {"version_id": question.version_id, "stable_id": question.stable_id, "kind": "research_question"})):
                payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                payload_hash = canonical_sha256(payload)
                identity = {"run_id": run_id, "sequence_no": sequence, "event_type": event_type, "payload_hash": payload_hash, "previous_event_hash": previous}
                event_id = make_event_id("event", project_id, identity)
                event_hash = canonical_sha256({"event_id": event_id, **identity, "payload_json": payload_json, "actor_id": "legacy", "actor_kind": "system", "session_id": "legacy", "created_at": "2026-01-01T00:00:00.000Z"})
                db.execute("INSERT INTO max_events(event_id, run_id, sequence_no, event_type, payload_json, payload_hash, previous_event_hash, event_hash, actor_id, actor_kind, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (event_id, run_id, sequence, event_type, payload_json, payload_hash, previous, event_hash, "legacy", "system", "legacy", "2026-01-01T00:00:00.000Z"))
                previous = event_hash
            db.commit()
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
