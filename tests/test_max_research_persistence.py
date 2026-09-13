from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from research_kb.max_research.contract import (
    CanonicalObject,
    CanonicalObjectKind,
    CanonicalRelation,
    Checkpoint,
    CoverageLedger,
    Iteration,
    IterationKind,
    RelationKind,
    make_event_id,
    make_stable_id,
    validate_claim_evidence_trace,
    canonical_sha256,
)
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION
from research_kb.max_research.persistence import (
    MaxControlError,
    MaxControlNotInitialized,
    MaxControlRepository,
    connect_control_db,
    UsageReceipt,
)
from research_kb.max_research.persistence.migrations import apply_migrations
from research_kb.max_research.persistence.repository import IterationRecordInput
from research_kb.policy import Actor


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            return self.value

    def advance(self, seconds: int) -> None:
        with self.lock:
            self.value += timedelta(seconds=seconds)


class FakeUsageAuthority:
    def verify_usage_receipt(self, receipt, **_: object):
        return {"authority": "fixture", "receipt_id": receipt.receipt_id}


class MaxResearchPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="max-control-")
        self.database = Path(self.temp.name) / "control.db"
        self.clock = FakeClock()
        self.admin = Actor("admin", "admin-session", "user", "admin", "test")
        self.worker = Actor("worker", "worker-session", "worker", "runner", "fixture")
        self.repository = MaxControlRepository(self.database, clock=self.clock)
        self.repository.initialize()
        self.charter = {
            "question": "How can an independent control plane preserve recovery?",
            "scope": "MR-1 persistence",
            "invariants": ["append-only history"],
            "non_goals": ["model execution"],
            "deliverables": ["auditable control store"],
            "model_identity": "fixture-model-v1",
            "budget": {
                "iteration_count": 20,
                "input_tokens": 1000,
                "output_tokens": 1000,
                "cost_units": 100,
                "acquisition_requests": 2,
                "acquisition_bytes": 10000,
            },
            "source_policy": {"mode": "server-resolved"},
            "quality_gates": {"require_human_approval": True},
        }
        self.proposed = self.repository.propose(project_id="mr1-test", charter=self.charter, actor=self.admin)
        self.run_id = self.proposed["run_id"]
        self.approved = self.repository.approve(
            run_id=self.run_id,
            charter_hash_value=self.proposed["charter_hash"],
            reason="fixture human approval",
            actor=self.admin,
        )
        self.started = self.repository.start(run_id=self.run_id, actor=self.admin)
        self.fencing_token = self.started["lease"]["fencing_token"]
        self._current_iteration_id = None

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _new_repo(self, *, resolver=None) -> MaxControlRepository:
        return MaxControlRepository(self.database, clock=self.clock, source_resolver=resolver)

    def _object(self, kind: str, opaque: str, *, project_id: str = "mr1-test", version: int = 1, supersedes: str | None = None, payload: dict | None = None) -> CanonicalObject:
        stable_id = make_stable_id(kind, opaque)
        return CanonicalObject(
            stable_id=stable_id,
            kind=kind,
            project_id=project_id,
            version=version,
            supersedes_version_id=supersedes,
            payload=payload or {"status": "candidate", "label": opaque},
        )

    def _checkpoint_successor(self) -> Checkpoint:
        current = Checkpoint.from_mapping(self.repository.get_current_checkpoint(run_id=self.run_id)["checkpoint"])
        working = replace(current.working_state, iteration_index=current.iteration_pointer + 1)
        return replace(
            current,
            checkpoint_id=make_event_id("checkpoint", "mr1-test", {"run_id": self.run_id, "successor": current.checkpoint_id, "nonce": self.clock.value.isoformat()}),
            supersedes_item_id=current.checkpoint_id,
            iteration_pointer=current.iteration_pointer + 1,
            working_state=working,
            created_at="2026-01-01T00:00:01.000Z",
        )

    def _iteration(self, sequence: int, kind: str, *, status: str = "completed", output_hash: str | None = None) -> IterationRecordInput:
        state_hash = self.repository.get_state(run_id=self.run_id)["state_hash"]
        iteration = Iteration(self.proposed["project_id"], self.run_id, sequence, kind, status=status)
        return IterationRecordInput(
            iteration=iteration,
            input_state_hash=state_hash,
            output_state_hash=output_hash or state_hash if status == "completed" else None,
            strategy_ledger=CoverageLedger((), ()),
            budget_delta={},
        )

    def _ensure_iteration(self, kind: str = IterationKind.SOCRATIC_EXPLORATION.value) -> str:
        if self._current_iteration_id is None:
            self._current_iteration_id = self.repository.begin_iteration(run_id=self.run_id, round_type=kind, actor=self.admin, fencing_token=self.fencing_token)["iteration_id"]
        return self._current_iteration_id

    def test_01_empty_control_database_initializes(self) -> None:
        self.assertEqual(self.repository.verify_run(run_id=self.run_id)["schema_version"], CONTROL_SCHEMA_VERSION)

    def test_02_migration_is_idempotent(self) -> None:
        self.assertEqual(self.repository.initialize()["schema_version"], CONTROL_SCHEMA_VERSION)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_schema_migrations").fetchone()[0], CONTROL_SCHEMA_VERSION)

    def test_03_interrupted_migration_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "interrupted.db"
            path.parent.mkdir(parents=True, exist_ok=True)
            connection = connect_control_db(path, read_only=False)
            with self.assertRaises(RuntimeError):
                apply_migrations(connection, fail_after_statement=3)
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE name='max_runs'").fetchone(), None)
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE name='max_schema_migrations'").fetchone(), None)
            connection.close()

    def test_04_control_schema_is_independent_of_core_schema(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertIsNotNone(connection.execute("SELECT 1 FROM max_schema_migrations WHERE version=1").fetchone())
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='schema_migrations'").fetchone())

    def test_05_packaged_control_migration_is_present(self) -> None:
        migration = Path(__file__).parents[1] / "src" / "research_kb" / "max_research" / "migrations" / "001_control_plane.sql"
        self.assertTrue(migration.is_file())
        self.assertIn("max_events", migration.read_text(encoding="utf-8"))

    def test_06_database_is_deletable_after_close(self) -> None:
        path = self.database
        self.repository.status(run_id=self.run_id)
        self.assertTrue(path.unlink() is None)

    def test_07_missing_control_database_is_read_only_failure(self) -> None:
        path = self.database.parent / "missing.db"
        with self.assertRaises(MaxControlNotInitialized):
            MaxControlRepository(path).status(run_id="missing")
        self.assertFalse(path.exists())

    def test_08_proposal_has_no_approval(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_start_approvals").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_approval_consumptions").fetchone()[0], 1)

    def test_09_no_approval_cannot_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = MaxControlRepository(Path(directory) / "control.db")
            repo.initialize()
            proposed = repo.propose(project_id="new-run", charter=self.charter, actor=self.admin)
            with self.assertRaises(MaxControlError):
                repo.start(run_id=proposed["run_id"], actor=self.admin)

    def test_10_charter_hash_mismatch_cannot_approve(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = MaxControlRepository(Path(directory) / "control.db")
            repo.initialize(); proposed = repo.propose(project_id="hash-test", charter=self.charter, actor=self.admin)
            with self.assertRaises(MaxControlError):
                repo.approve(run_id=proposed["run_id"], charter_hash_value="0" * 64, reason="wrong", actor=self.admin)

    def test_10a_runner_cannot_self_approve(self) -> None:
        repo = self._new_repo()
        proposed = repo.propose(project_id="runner-approval", charter=self.charter, actor=self.admin)
        with self.assertRaises(MaxControlError):
            repo.approve(
                run_id=proposed["run_id"],
                charter_hash_value=proposed["charter_hash"],
                reason="runner self approval",
                actor=self.worker,
            )
        self.assertEqual(repo.get_run(proposed["run_id"])["status"], "AWAITING_START_APPROVAL")

    def test_11_reconstructed_approval_cannot_be_consumed_again(self) -> None:
        with self.assertRaises(MaxControlError):
            self.repository.approve(run_id=self.run_id, charter_hash_value=self.proposed["charter_hash"], reason="replay", actor=self.admin)
        with closing(sqlite3.connect(self.database)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO max_approval_consumptions(consumption_id, approval_id, run_id, project_id, charter_hash, prior_state_version, resulting_state_version, consumed_at, consumption_json, consumption_hash, actor_id, actor_session) SELECT consumption_id, approval_id, run_id, project_id, charter_hash, prior_state_version, resulting_state_version, consumed_at, consumption_json, consumption_hash, actor_id, actor_session FROM max_approval_consumptions LIMIT 1")

    def test_12_twenty_concurrent_approvals_have_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.db"; repo = MaxControlRepository(path); repo.initialize(); proposed = repo.propose(project_id="approval-race", charter=self.charter, actor=self.admin)
            def attempt(_: int) -> bool:
                try:
                    repo.approve(run_id=proposed["run_id"], charter_hash_value=proposed["charter_hash"], reason="race", actor=Actor(f"admin-{_}", f"s-{_}", "user", "admin", "test"))
                    return True
                except MaxControlError:
                    return False
            with ThreadPoolExecutor(max_workers=20) as pool:
                outcomes = list(pool.map(attempt, range(20)))
            self.assertEqual(sum(outcomes), 1)

    def test_13_pause_resume_does_not_reconsume_approval(self) -> None:
        self.repository.pause(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)
        resumed = self.repository.resume(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)
        self.fencing_token = resumed["lease"]["fencing_token"]
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?", (self.run_id,)).fetchone()[0], 1)

    def test_14_cancel_is_terminal(self) -> None:
        self.repository.cancel(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)
        with self.assertRaises(MaxControlError):
            self.repository.resume(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)

    def test_15_illegal_transition_has_no_partial_event(self) -> None:
        before = self.repository.list_events(run_id=self.run_id, limit=200)["events"]
        with self.assertRaises(MaxControlError):
            self.repository.start(run_id=self.run_id, actor=self.admin)
        after = self.repository.list_events(run_id=self.run_id, limit=200)["events"]
        self.assertEqual(len(before), len(after))

    def test_16_event_sequence_and_hash_chain_verify(self) -> None:
        verified = self.repository.verify_run(run_id=self.run_id)
        self.assertTrue(verified["event_chain"]["ok"])
        events = self.repository.list_events(run_id=self.run_id, limit=200)["events"]
        self.assertEqual([item["sequence_no"] for item in events], list(range(1, len(events) + 1)))

    def test_17_append_only_triggers_reject_update_delete(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            event_id = connection.execute("SELECT event_id FROM max_events LIMIT 1").fetchone()[0]
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE max_events SET event_type='tampered' WHERE event_id=?", (event_id,))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM max_events WHERE event_id=?", (event_id,))

    def test_18_tampered_fixture_fails_chain_verification(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DROP TRIGGER max_events_no_update")
            connection.execute("UPDATE max_events SET payload_json='{}' WHERE event_id=(SELECT event_id FROM max_events LIMIT 1)")
            connection.commit()
        self.assertFalse(self.repository.verify_run(run_id=self.run_id)["event_chain"]["ok"])

    def test_19_event_cursor_pagination_has_no_overlap(self) -> None:
        first = self.repository.list_events(run_id=self.run_id, limit=2)
        second = self.repository.list_events(run_id=self.run_id, cursor=first["next_cursor"], limit=2)
        self.assertTrue(set(item["sequence_no"] for item in first["events"]).isdisjoint(item["sequence_no"] for item in second["events"]))

    def test_20_concurrent_iteration_events_have_unique_sequences(self) -> None:
        records = [self._iteration(1, IterationKind.SOCRATIC_EXPLORATION.value), self._iteration(1, IterationKind.TARGETED_RETRIEVAL.value)]
        def write(record: IterationRecordInput) -> bool:
            try:
                self.repository.record_iteration(run_id=self.run_id, record=record, actor=self.admin, fencing_token=self.fencing_token)
                return True
            except MaxControlError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(write, records))
        self.assertEqual(sum(outcomes), 1)
        events = self.repository.list_events(run_id=self.run_id, limit=200)["events"]
        self.assertEqual(len({item["sequence_no"] for item in events}), len(events))

    def test_21_canonical_identity_version_relation_append(self) -> None:
        iteration_id = self._ensure_iteration()
        source = self._object("decision", "decision-one")
        target = self._object("hypothesis", "hypothesis-one")
        self.repository.append_canonical_object(project_id="mr1-test", value=source, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token, iteration_id=iteration_id)
        self.repository.append_canonical_object(project_id="mr1-test", value=target, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token, iteration_id=iteration_id)
        relation = CanonicalRelation(source.stable_id, target.stable_id, RelationKind.DERIVED_FROM, "mr1-test", source_version_id=source.version_id, target_version_id=target.version_id)
        self.repository.append_canonical_relation(project_id="mr1-test", value=relation, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token, iteration_id=iteration_id)
        self.assertTrue(self.repository.verify_run(run_id=self.run_id)["canonical_graph"]["ok"])

    def test_22_wrong_predecessor_version_fails(self) -> None:
        iteration_id = self._ensure_iteration()
        first = self._object("hypothesis", "hyp-one")
        self.repository.append_canonical_object(project_id="mr1-test", value=first, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token, iteration_id=iteration_id)
        second = self._object("hypothesis", "hyp-one", version=2, supersedes=make_stable_id("hypothesis-version", "wrong"))
        with self.assertRaises(MaxControlError):
            self.repository.append_canonical_object(project_id="mr1-test", value=second, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token, iteration_id=iteration_id)

    def test_23_relation_old_or_forged_endpoint_fails(self) -> None:
        iteration_id = self._ensure_iteration()
        source = self._object("decision", "decision-one")
        target = self._object("hypothesis", "hypothesis-two")
        self.repository.append_canonical_object(project_id="mr1-test", value=source, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token, iteration_id=iteration_id)
        self.repository.append_canonical_object(project_id="mr1-test", value=target, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token, iteration_id=iteration_id)
        relation = CanonicalRelation(source.stable_id, target.stable_id, RelationKind.DERIVED_FROM, "mr1-test", source_version_id=source.version_id, target_version_id=make_stable_id("hypothesis-version", "missing"))
        with self.assertRaises(MaxControlError):
            self.repository.append_canonical_relation(project_id="mr1-test", value=relation, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token, iteration_id=iteration_id)

    def test_24_cross_project_object_fails_closed(self) -> None:
        object_value = self._object("claim", "cross-project", project_id="other-project")
        with self.assertRaises(MaxControlError):
            self.repository.append_canonical_object(project_id="mr1-test", value=object_value, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token)

    def test_25_unverified_claim_evidence_trace_is_not_final(self) -> None:
        claim = self._object("claim", "trace-claim", payload={"status": "final", "evidence_link_id": make_stable_id("evidence_link", "trace-link")})
        link = self._object("evidence_link", "trace-link", payload={"status": "candidate"})
        evidence = self._object("evidence", "trace-evidence", payload={"status": "unknown"})
        link_relation = CanonicalRelation(claim.stable_id, link.stable_id, RelationKind.HAS_EVIDENCE_LINK, "mr1-test", source_version_id=claim.version_id, target_version_id=link.version_id)
        evidence_relation = CanonicalRelation(link.stable_id, evidence.stable_id, RelationKind.LINKS_EVIDENCE, "mr1-test", source_version_id=link.version_id, target_version_id=evidence.version_id)
        self.assertFalse(validate_claim_evidence_trace(claim, (claim, link, evidence), (link_relation, evidence_relation)).ok)

    def test_26_client_source_reference_requires_server_resolver(self) -> None:
        evidence = self._object("evidence", "source-ref", payload={"status": "candidate", "source_refs": [{"document_version_id": make_stable_id("document_version", "dv1")}]})
        with self.assertRaises(MaxControlError):
            self.repository.append_canonical_object(project_id="mr1-test", value=evidence, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token)

    def test_27_client_citation_metadata_is_rejected(self) -> None:
        resolver = lambda **_: {"project_id": "mr1-test", "document_version_id": make_stable_id("document_version", "dv1")}
        repo = self._new_repo(resolver=resolver)
        evidence = self._object("evidence", "bad-citation", payload={"status": "candidate", "source_refs": [{"document_version_id": make_stable_id("document_version", "dv1"), "page": 3}]})
        with self.assertRaises(MaxControlError):
            repo.append_canonical_object(project_id="mr1-test", value=evidence, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token)

    def test_28_unknown_canonical_mapping_field_fails(self) -> None:
        with self.assertRaises(Exception):
            self.repository.append_canonical_object(project_id="mr1-test", value={"stable_id": make_stable_id("claim", "unknown"), "kind": "claim", "project_id": "mr1-test", "payload": {}, "unknown": 1}, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token)

    def test_29_each_run_has_one_current_checkpoint(self) -> None:
        self.assertTrue(self.repository.verify_run(run_id=self.run_id)["checkpoint_lineage"]["ok"])
        self.assertIsNotNone(self.repository.get_current_checkpoint(run_id=self.run_id)["checkpoint"])

    def test_30_checkpoint_successor_is_atomic_and_current(self) -> None:
        successor = self._checkpoint_successor()
        result = self.repository.create_checkpoint(run_id=self.run_id, checkpoint=successor, actor=self.admin, fencing_token=self.fencing_token)
        self.assertEqual(result["lineage_version"], 2)
        self.assertEqual(self.repository.get_current_checkpoint(run_id=self.run_id)["checkpoint"]["checkpoint_id"], successor.checkpoint_id)

    def test_31_twenty_concurrent_checkpoint_successors_have_one_winner(self) -> None:
        successor = self._checkpoint_successor()
        def write(_: int) -> bool:
            try:
                self.repository.create_checkpoint(run_id=self.run_id, checkpoint=successor, actor=self.admin, fencing_token=self.fencing_token)
                return True
            except MaxControlError:
                return False
        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(write, range(20)))
        self.assertEqual(sum(outcomes), 1)

    def test_32_stale_fencing_token_cannot_write_checkpoint(self) -> None:
        self.repository.release_lease(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)
        takeover = self.repository.acquire_lease(run_id=self.run_id, actor=self.worker)
        with self.assertRaises(MaxControlError):
            self.repository.create_checkpoint(run_id=self.run_id, checkpoint=self._checkpoint_successor(), actor=self.admin, fencing_token=self.fencing_token)
        self.assertGreater(takeover["fencing_token"], self.fencing_token)

    def test_33_state_hash_mismatch_is_detected(self) -> None:
        state = self.repository.get_state(run_id=self.run_id)
        state["state_hash"] = "0" * 64
        with self.assertRaises(MaxControlError):
            self.repository.save_research_state(run_id=self.run_id, state=state, actor=self.admin, fencing_token=self.fencing_token)

    def test_34_rehydration_is_deterministic(self) -> None:
        self._ensure_iteration(IterationKind.REHYDRATION_REVIEW.value)
        first = self.repository.rehydrate_run(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)
        self.repository.finish_iteration(run_id=self.run_id, iteration_id=self._current_iteration_id, actor=self.admin, fencing_token=self.fencing_token, status="completed", claim_snapshots=(), evidence_snapshots=(), counterevidence_snapshots=(), strategy_ledger=CoverageLedger(), budget_delta={})
        self._current_iteration_id = self.repository.begin_iteration(run_id=self.run_id, round_type=IterationKind.REHYDRATION_REVIEW.value, actor=self.admin, fencing_token=self.fencing_token)["iteration_id"]
        second = self.repository.rehydrate_run(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)
        self.assertEqual(first["input_hash"], second["input_hash"])
        self.assertEqual(first["output_hash"], second["output_hash"])

    def test_35_checkpoint_summary_cannot_replace_frontier(self) -> None:
        current = Checkpoint.from_mapping(self.repository.get_current_checkpoint(run_id=self.run_id)["checkpoint"])
        working = replace(current.working_state, iteration_index=current.iteration_pointer + 1, canonical_object_ids=(make_stable_id("claim", "not-stored"),))
        bad = replace(current, checkpoint_id=make_event_id("checkpoint", "mr1-test", {"bad": True}), supersedes_item_id=current.checkpoint_id, iteration_pointer=current.iteration_pointer + 1, working_state=working)
        with self.assertRaises(MaxControlError):
            self.repository.create_checkpoint(run_id=self.run_id, checkpoint=bad, actor=self.admin, fencing_token=self.fencing_token)

    def test_36_iteration_numbers_are_contiguous(self) -> None:
        self.repository.record_iteration(run_id=self.run_id, record=self._iteration(1, IterationKind.SOCRATIC_EXPLORATION.value), actor=self.admin, fencing_token=self.fencing_token)
        with self.assertRaises(MaxControlError):
            self.repository.record_iteration(run_id=self.run_id, record=self._iteration(3, IterationKind.TARGETED_RETRIEVAL.value), actor=self.admin, fencing_token=self.fencing_token)

    def test_37_aborted_iteration_does_not_count_as_stable(self) -> None:
        self.repository.record_iteration(run_id=self.run_id, record=self._iteration(1, IterationKind.SOCRATIC_EXPLORATION.value, status="aborted"), actor=self.admin, fencing_token=self.fencing_token)
        with self.assertRaises(MaxControlError):
            self.repository.persist_completion(run_id=self.run_id, evaluation_input={}, result={}, actor=self.admin, fencing_token=self.fencing_token)

    def test_38_completion_requires_historical_rounds(self) -> None:
        with self.assertRaises(MaxControlError):
            self.repository.persist_completion(run_id=self.run_id, evaluation_input={}, result={}, actor=self.admin, fencing_token=self.fencing_token)

    def test_39_single_payload_cannot_claim_two_stable_rounds(self) -> None:
        self.repository.record_iteration(run_id=self.run_id, record=self._iteration(1, IterationKind.ADVERSARIAL_ATTACK.value), actor=self.admin, fencing_token=self.fencing_token)
        with self.assertRaises(MaxControlError):
            self.repository.persist_completion(run_id=self.run_id, evaluation_input={}, result={}, actor=self.admin, fencing_token=self.fencing_token)

    def test_40_iteration_input_state_hash_is_bound(self) -> None:
        record = self._iteration(1, IterationKind.SOCRATIC_EXPLORATION.value)
        with self.assertRaises(MaxControlError):
            self.repository.record_iteration(run_id=self.run_id, record=replace(record, input_state_hash="0" * 64), actor=self.admin, fencing_token=self.fencing_token)

    def test_41_forged_completion_result_is_rejected(self) -> None:
        with self.assertRaises(MaxControlError):
            self.repository.persist_completion(run_id=self.run_id, evaluation_input={"forged": True}, result={"passed": True}, actor=self.admin, fencing_token=self.fencing_token)

    def test_42_twenty_lease_competitors_have_one_winner(self) -> None:
        self.repository.release_lease(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)
        def acquire(index: int) -> bool:
            try:
                self.repository.acquire_lease(run_id=self.run_id, actor=Actor(f"owner-{index}", f"session-{index}", "worker", "runner", "fixture"))
                return True
            except MaxControlError:
                return False
        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(acquire, range(20)))
        self.assertEqual(sum(outcomes), 1)

    def test_43_expired_lease_takeover_increments_fencing(self) -> None:
        old = self.fencing_token
        self.clock.advance(61)
        takeover = self.repository.acquire_lease(run_id=self.run_id, actor=self.worker)
        self.assertGreater(takeover["fencing_token"], old)

    def test_44_old_worker_cannot_write_after_takeover(self) -> None:
        self.repository.release_lease(run_id=self.run_id, actor=self.admin, fencing_token=self.fencing_token)
        self.repository.acquire_lease(run_id=self.run_id, actor=self.worker)
        with self.assertRaises(MaxControlError):
            self.repository.record_iteration(run_id=self.run_id, record=self._iteration(1, IterationKind.SOCRATIC_EXPLORATION.value), actor=self.admin, fencing_token=self.fencing_token)

    def test_45_budget_reserve_commit_release_reconstructs(self) -> None:
        iteration_id = self._ensure_iteration()
        reserved = self.repository.reserve_budget(run_id=self.run_id, amount={"input_tokens": 10}, idempotency_key="reserve-1", actor=self.admin, fencing_token=self.fencing_token, iteration_id=iteration_id)
        committed = self.repository.commit_budget(run_id=self.run_id, reservation_id=reserved["reservation_id"], amount={"input_tokens": 4}, idempotency_key="commit-1", actor=self.admin, fencing_token=self.fencing_token, iteration_id=iteration_id)
        self.repository.release_budget(run_id=self.run_id, reservation_id=reserved["reservation_id"], amount=None, idempotency_key="release-1", actor=self.admin, fencing_token=self.fencing_token, iteration_id=iteration_id)
        balance = self.repository.reconstruct_budget(run_id=self.run_id)
        self.assertEqual(balance["used"]["input_tokens"], 4)
        self.assertEqual(balance["reserved"]["input_tokens"], 0)
        self.assertEqual(committed["operation"], "commit")

    def test_46_budget_idempotency_does_not_double_charge(self) -> None:
        iteration_id = self._ensure_iteration()
        first = self.repository.reserve_budget(run_id=self.run_id, amount={"input_tokens": 10}, idempotency_key="same-key", actor=self.admin, fencing_token=self.fencing_token, iteration_id=iteration_id)
        second = self.repository.reserve_budget(run_id=self.run_id, amount={"input_tokens": 10}, idempotency_key="same-key", actor=self.admin, fencing_token=self.fencing_token, iteration_id=iteration_id)
        self.assertEqual(first["entry_id"], second["entry_id"])
        self.assertTrue(second["idempotent_retry"])

    def test_47_budget_competition_has_one_success(self) -> None:
        iteration_id = self._ensure_iteration()
        def reserve(index: int) -> bool:
            try:
                self.repository.reserve_budget(run_id=self.run_id, amount={"input_tokens": 1000}, idempotency_key=f"last-{index}", actor=self.admin, fencing_token=self.fencing_token, iteration_id=iteration_id)
                return True
            except MaxControlError:
                return False
        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(reserve, range(20)))
        self.assertEqual(sum(outcomes), 1)

    def test_48_budget_negative_over_limit_and_unknown_unit_fail(self) -> None:
        with self.assertRaises(MaxControlError):
            self.repository.reserve_budget(run_id=self.run_id, amount={"input_tokens": -1}, idempotency_key="negative", actor=self.admin, fencing_token=self.fencing_token)
        with self.assertRaises(MaxControlError):
            self.repository.reserve_budget(run_id=self.run_id, amount={"unknown_units": 1}, idempotency_key="unknown", actor=self.admin, fencing_token=self.fencing_token)
        with self.assertRaises(MaxControlError):
            self.repository.reserve_budget(run_id=self.run_id, amount={"input_tokens": 1001}, idempotency_key="over", actor=self.admin, fencing_token=self.fencing_token)

    def test_49_authoritative_usage_requires_provenance(self) -> None:
        iteration_id = self._ensure_iteration()
        with self.assertRaises(MaxControlError):
            self.repository.record_authoritative_usage(run_id=self.run_id, amount={"input_tokens": 1}, provenance={"authoritative": True, "authority": "fake-adapter", "record_id": "usage-1"}, idempotency_key="usage-bad", actor=self.admin, fencing_token=self.fencing_token, iteration_id=iteration_id)
        receipt = UsageReceipt("usage-1", self.run_id, iteration_id, self.proposed["model_identity"], {"input_tokens": 1}, "2026-01-01T00:00:00Z", "fixture", "")
        receipt = replace(receipt, payload_hash=receipt.computed_payload_hash())
        receipt = replace(receipt, receipt_hash=receipt.computed_receipt_hash())
        repo = MaxControlRepository(self.database, clock=self.clock, usage_authority=FakeUsageAuthority())
        result = repo.record_authoritative_usage(run_id=self.run_id, amount={"input_tokens": 1}, receipt=receipt, idempotency_key="usage-good", actor=self.admin, fencing_token=self.fencing_token, iteration_id=iteration_id)
        self.assertEqual(result["operation"], "usage")

    def test_50_cli_propose_approve_start_flow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="max-cli-") as directory:
            db = Path(directory) / "cli.db"; charter_path = Path(directory) / "charter.json"; charter_path.write_text(json.dumps(self.charter), encoding="utf-8")
            env = dict(os.environ); env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src"); env["PYTHONDONTWRITEBYTECODE"] = "1"
            def cli(*args: str) -> dict:
                completed = subprocess.run([sys.executable, "-m", "research_kb.cli", *args], cwd=Path(__file__).parents[1], env=env, capture_output=True, text=True, check=True)
                return json.loads(completed.stdout)
            cli("max", "init", "--database", str(db))
            proposed = cli("max", "propose", "--database", str(db), "--project", "cli-project", "--charter", str(charter_path))
            approved = cli("max", "approve", "--database", str(db), "--run-id", proposed["run_id"], "--charter-hash", proposed["charter_hash"], "--reason", "cli human reason")
            started = cli("max", "start", "--database", str(db), "--run-id", proposed["run_id"])
            self.assertEqual(started["run"]["status"], "RUNNING")
            self.assertEqual(approved["run"]["status"], "APPROVED")

    def test_51_cli_status_events_verify_are_read_only_and_redacted(self) -> None:
        before = hashlib.sha256(self.database.read_bytes()).hexdigest()
        status = self.repository.status(run_id=self.run_id)
        events = self.repository.list_events(run_id=self.run_id, limit=2)
        verified = self.repository.verify_run(run_id=self.run_id)
        after = hashlib.sha256(self.database.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        output = json.dumps({"status": status, "events": events, "verify": verified})
        self.assertNotIn(str(self.database), output)
        self.assertNotIn("source_text", output)
        self.assertNotIn("api_key", output)

    def test_52_import_does_not_create_a_control_database(self) -> None:
        path = self.database.parent / "import-only.db"
        self.assertFalse(path.exists())
        __import__("research_kb.max_research.persistence")
        self.assertFalse(path.exists())

    def test_53_core_database_is_never_opened_by_repository(self) -> None:
        self.assertFalse((Path(self.temp.name) / "research.db").exists())
        self.repository.status(run_id=self.run_id)
        self.assertFalse((Path(self.temp.name) / "research.db").exists())

    def test_54_event_payload_contains_hashes_not_source_text(self) -> None:
        events = self.repository.list_events(run_id=self.run_id, limit=200)["events"]
        self.assertTrue(all("payload_hash" in item for item in events))
        self.assertTrue(all("payload_json" not in item for item in events))

    def test_55_schema_version_and_foreign_keys_are_reported(self) -> None:
        verified = self.repository.verify_run(run_id=self.run_id)
        self.assertEqual(verified["schema_version"], CONTROL_SCHEMA_VERSION)
        with closing(connect_control_db(self.database, read_only=True)) as connection:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_56_backup_restore_and_verify(self) -> None:
        with tempfile.TemporaryDirectory(prefix="max-backup-") as directory:
            backup_path = Path(directory) / "backup.db"
            restored_path = Path(directory) / "restored.db"
            backed_up = self.repository.backup(backup_path)
            self.assertTrue(backed_up["verification"]["ok"])
            restored = MaxControlRepository(restored_path, clock=self.clock)
            restored_result = restored.restore(backup_path)
            self.assertTrue(restored_result["verification"]["ok"])
            self.assertEqual(restored.verify_run(run_id=self.run_id)["event_chain"]["event_count"], self.repository.verify_run(run_id=self.run_id)["event_chain"]["event_count"])

    def test_57_transition_and_identity_history_is_append_only(self) -> None:
        with closing(connect_control_db(self.database, read_only=False)) as connection:
            transition_id = connection.execute("SELECT transition_id FROM max_run_transition_results LIMIT 1").fetchone()[0]
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE max_run_transition_results SET to_status='tampered' WHERE transition_id=?", (transition_id,))
            identity_id = connection.execute("SELECT stable_id FROM max_canonical_objects LIMIT 1").fetchone()[0]
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE max_canonical_objects SET kind='tampered' WHERE stable_id=?", (identity_id,))

    def test_58_absolute_path_payload_is_rejected(self) -> None:
        value = self._object("decision", "path-payload", payload={"path": "D:\\private\\source.pdf"})
        with self.assertRaises(MaxControlError):
            self.repository.append_canonical_object(project_id="mr1-test", value=value, actor=self.admin, run_id=self.run_id, fencing_token=self.fencing_token)


if __name__ == "__main__":
    unittest.main()
