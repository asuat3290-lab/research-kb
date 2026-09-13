from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

from research_kb.max_research.contract import Checkpoint, canonical_json, canonical_sha256, make_event_id
from research_kb.max_research.persistence import MaxControlError, MaxControlRepository
from research_kb.max_research.portability import AgentHostProfile, MaxPortabilityService, opencode_go_backend_profile
from research_kb.max_research.portability_adapters import InstallationEvidence
from research_kb.policy import Actor


class PortabilityConvergenceR2Tests(unittest.TestCase):
    """Adversarial coverage for the MR-PORTABILITY-0R2 convergence surface."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr-portability-r2-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("r2-admin", "r2-test-admin", "user", "admin", "mr-portability-r2-tests")
        self.old_host = Actor("r2-old", "r2-old-session", "user", "admin", "mr-portability-r2-tests")
        self.target_actor = Actor("r2-target", "r2-target-session", "user", "admin", "mr-portability-r2-tests")
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize(fixture=True)
        self.charter = {
            "question": "bounded portability convergence",
            "scope": "MR-PORTABILITY-0R2 fixture",
            "invariants": ["server owned", "historical binding"],
            "non_goals": ["live provider"],
            "deliverables": ["portability evidence"],
            "model_identity": "fixture-model/v1",
            "budget": {"iteration_count": 1, "input_tokens": 64, "output_tokens": 32, "cost_units": 10},
            "source_policy": {"network_allowed": False, "roles": ["primary"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        proposed = self.repo.propose(project_id="r2-project", charter=self.charter, actor=self.admin)
        self.run_id = proposed["run_id"]
        self.charter_hash = proposed["charter_hash"]
        self.source_policy_hash = proposed["source_policy_hash"]
        self.budget_hash = proposed["budget_hash"]
        self.codex = AgentHostProfile(
            host_kind="codex", host_version="r2-v1", control_surface="r2-test",
            capability_manifest_hash="a" * 64, canonical_skill_hash="b" * 64,
            adapter_hash="c" * 64, allowed_operations=("bind-backend", "handoff", "checkpoint", "resume"),
        )
        self.luna = replace(self.codex, host_kind="luna", host_profile_id="")
        self.backend = opencode_go_backend_profile()
        self.service = MaxPortabilityService(self.repo, self.admin)
        self.service.register_host_profile(profile=self.codex)
        self.service.register_host_profile(profile=self.luna)
        self.service.register_backend_profile(profile=self.backend)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def bind(self, *, run_id: str | None = None, host: AgentHostProfile | None = None) -> dict[str, Any]:
        run_id = run_id or self.run_id
        source_hash = self.source_policy_hash if run_id == self.run_id else self.repo.get_run(run_id)["source_policy_hash"]
        budget_hash = self.budget_hash if run_id == self.run_id else self.repo.get_run(run_id)["budget_hash"]
        return self.service.bind_backend(
            run_id=run_id,
            host_profile_id=(host or self.codex).host_profile_id,
            backend_profile_id=self.backend.backend_profile_id,
            source_policy_hash=source_hash,
            budget_hash=budget_hash,
        )

    def pause(self) -> int:
        self.repo.approve(run_id=self.run_id, charter_hash_value=self.charter_hash, reason="r2 pause", actor=self.admin)
        started = self.repo.start(run_id=self.run_id, actor=self.admin)
        self.repo.pause(run_id=self.run_id, actor=self.admin, fencing_token=started["lease"]["fencing_token"])
        return int(started["lease"]["fencing_token"])

    def result(self, text: str = "bounded") -> dict[str, Any]:
        return {
            "cognitive_artifacts": [{"kind": "observation", "text": text}],
            "proposed_canonical_objects": [], "proposed_relations": [], "objections": [],
            "hypotheses": [], "research_questions": [],
            "usage_receipt": {"input_tokens": 1, "output_tokens": 2, "cost_units": 0},
            "backend_status": "succeeded", "provider_call_ref": None,
            "finish_reason": "stop", "retry_classification": "not_applicable",
        }

    def handoff_fixture(self) -> tuple[dict[str, Any], dict[str, Any]]:
        self.bind()
        self.pause()
        preview = self.service.preview_backend_handoff(
            run_id=self.run_id, new_host_profile_id=self.luna.host_profile_id,
            new_backend_profile_id=self.backend.backend_profile_id, reason="r2 handoff",
        )
        approved = self.service.approve_backend_handoff(
            handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"],
        )
        return preview, approved["rehydration_packet"]

    def nonfixture_store(self, name: str, *, install_hosts: bool = True):
        path = Path(self.temp.name) / f"{name}.db"
        repo = MaxControlRepository(path)
        repo.initialize()
        run = repo.propose(project_id=f"r2-{name}", charter=self.charter, actor=self.admin)
        codex = replace(self.codex, host_profile_id="")
        luna = replace(self.luna, host_profile_id="")
        service = MaxPortabilityService(repo, self.admin)
        service.register_host_profile(profile=codex)
        service.register_host_profile(profile=luna)
        service.register_backend_profile(profile=self.backend)
        installations: dict[str, dict[str, Any]] = {}
        if install_hosts:
            for profile, suffix, package_hash in (
                (codex, "codex", "1" * 64), (luna, "luna", "2" * 64),
            ):
                evidence = InstallationEvidence(
                    package_hash, profile.canonical_skill_hash, profile.adapter_hash,
                    profile.capability_manifest_hash, f"r2-{name}-{suffix}",
                )
                installations[profile.host_profile_id] = service.register_host_installation(
                    host_profile_id=profile.host_profile_id, **evidence.to_mapping()
                )
        binding = service.bind_backend(
            run_id=run["run_id"], host_profile_id=codex.host_profile_id,
            backend_profile_id=self.backend.backend_profile_id,
            source_policy_hash=run["source_policy_hash"], budget_hash=run["budget_hash"],
        ) if install_hosts else None
        return path, repo, service, run, binding["binding"] if binding else None, codex, luna, installations

    def nonfixture_handoff(self, name: str):
        path, repo, service, run, binding, codex, luna, installations = self.nonfixture_store(name)
        repo.approve(run_id=run["run_id"], charter_hash_value=run["charter_hash"], reason="r2 handoff", actor=self.admin)
        started = repo.start(run_id=run["run_id"], actor=self.admin)
        repo.pause(run_id=run["run_id"], actor=self.admin, fencing_token=started["lease"]["fencing_token"])
        preview = service.preview_backend_handoff(
            run_id=run["run_id"], new_host_profile_id=luna.host_profile_id,
            new_backend_profile_id=self.backend.backend_profile_id, reason="r2 target handoff",
        )
        approved = service.approve_backend_handoff(
            handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"],
        )
        return path, repo, service, run, binding, codex, luna, installations, int(started["lease"]["fencing_token"]), approved["rehydration_packet"]

    def test_01_active_runner_claim_is_blocked_before_snapshot_write(self) -> None:
        self.bind()
        self.pause()
        connection = self.repo._connect(read_only=False)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO max_runner_invocation_claims(claim_id,run_id,actor_id,actor_session,fencing_token,attempt_id,expires_at,status,claim_json,claim_hash,created_at,released_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("r2-claim", self.run_id, "worker", "r2-worker", 7, "r2-attempt", "2099-01-01T00:00:00.000Z", "active", "{}", "1" * 64, "2026-01-01T00:00:00.000Z", None),
            )
            connection.commit()
        finally:
            connection.close()
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(MaxControlError):
            self.service.preview_backend_handoff(
                run_id=self.run_id, new_host_profile_id=self.luna.host_profile_id,
                new_backend_profile_id=self.backend.backend_profile_id, reason="claim gate",
            )
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_02_running_run_and_active_lease_are_not_quiescent(self) -> None:
        self.bind()
        self.repo.approve(run_id=self.run_id, charter_hash_value=self.charter_hash, reason="r2 running", actor=self.admin)
        self.repo.start(run_id=self.run_id, actor=self.admin)
        with self.assertRaises(MaxControlError):
            self.service.assert_portability_quiescent(run_id=self.run_id)

    def test_03_paused_handoff_persists_full_quiescence_snapshots(self) -> None:
        _, packet = self.handoff_fixture()
        connection = self.repo._connect(read_only=True)
        try:
            rows = connection.execute(
                "SELECT phase,activity_json,activity_hash FROM max_portability_quiescence_snapshots WHERE run_id=? ORDER BY created_at",
                (self.run_id,),
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual([row["phase"] for row in rows], ["preview", "approval_consume"])
        self.assertGreaterEqual(len(json.loads(rows[0]["activity_json"])), 14)
        self.assertTrue(all(len(row["activity_hash"]) == 64 for row in rows))
        self.assertTrue(self.service.verify(run_id=self.run_id)["ok"])

    def test_04_quiescence_snapshot_hash_covers_all_activity_categories(self) -> None:
        self.handoff_fixture()
        connection = self.repo._connect(read_only=True)
        try:
            row = connection.execute("SELECT activity_json,activity_hash FROM max_portability_quiescence_snapshots LIMIT 1").fetchone()
        finally:
            connection.close()
        activity = json.loads(row["activity_json"])
        counters = {
            key: activity[key]
            for key in (
                "active_runner_claims", "call_groups", "reservations", "acquisition", "scheduler",
                "long_run_authority", "authorization_bundles", "jit_authority", "permits",
                "active_leases", "terminal_provider_records", "runner_dispatches", "network_activity",
                "active_provider_dispatches",
            )
        }
        self.assertEqual(canonical_sha256(counters), row["activity_hash"])

    def test_05_historical_result_survives_successor_checkpoint(self) -> None:
        self.bind()
        token = self.pause()
        resumed = self.repo.resume(run_id=self.run_id, actor=self.admin, fencing_token=token, lease_ttl=3600)
        self.service.record_normalized_result(run_id=self.run_id, binding_id=self.bind()["binding"]["binding_id"], result=self.result())
        current = Checkpoint.from_mapping(self.repo.get_current_checkpoint(run_id=self.run_id)["checkpoint"])
        successor = replace(
            current,
            checkpoint_id=make_event_id("checkpoint", "r2-project", {"successor": current.checkpoint_id, "probe": "historical"}),
            supersedes_item_id=current.checkpoint_id,
            iteration_pointer=current.iteration_pointer + 1,
            working_state=replace(current.working_state, iteration_index=current.iteration_pointer + 1),
            created_at="2026-01-01T00:00:01.000Z",
        )
        self.repo.create_checkpoint(run_id=self.run_id, checkpoint=successor, actor=self.admin, fencing_token=resumed["lease"]["fencing_token"])
        self.assertTrue(self.service.verify(run_id=self.run_id)["ok"])

    def test_06_result_binding_is_run_scoped(self) -> None:
        first_binding = self.bind()["binding"]
        second = self.repo.propose(project_id="r2-project-two", charter=self.charter, actor=self.admin)
        second_binding = self.bind(run_id=second["run_id"])["binding"]
        first = self.service.record_normalized_result(run_id=self.run_id, binding_id=first_binding["binding_id"], result=self.result())
        other = self.service.record_normalized_result(run_id=second["run_id"], binding_id=second_binding["binding_id"], result=self.result())
        self.assertNotEqual(first["result_id"], other["result_id"])
        connection = self.repo._connect(read_only=True)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_portability_result_bindings").fetchone()[0], 2)
        finally:
            connection.close()

    def test_07_production_caller_attribution_is_rejected_without_write(self) -> None:
        path, repo, service, run, binding, codex, luna, installations = self.nonfixture_store("forged")
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(MaxControlError):
            service.record_normalized_result(
                run_id=run["run_id"], binding_id=binding["binding_id"], result=self.result(),
                project_id="forged", iteration_id="forged", invocation_id="forged",
                intent_id="forged", invocation_hash="2" * 64,
            )
        self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_08_fixture_invocation_compatibility_is_explicit(self) -> None:
        binding = self.bind()["binding"]
        stored = self.service.record_normalized_result(
            run_id=self.run_id, binding_id=binding["binding_id"], result=self.result(),
            iteration_id="fixture-iteration", invocation_id="fixture-invocation", intent_id="fixture-intent", invocation_hash="3" * 64,
        )
        connection = self.repo._connect(read_only=True)
        try:
            row = connection.execute("SELECT source_kind FROM max_portability_invocation_bindings WHERE invocation_binding_id=?", (stored["invocation_binding_id"],)).fetchone()
        finally:
            connection.close()
        self.assertEqual(row["source_kind"], "fixture_compat")
        self.assertTrue(self.service.verify(run_id=self.run_id)["ok"])

    def test_09_manifest_has_typed_server_ids_and_hashes(self) -> None:
        _, packet = self.handoff_fixture()
        value = self.service.read_rehydration_packet(packet_id=packet["packet_id"], page_size=256)["packet"]
        self.assertGreater(value["manifest_count"], 0)
        for item in value["manifest_items"]:
            self.assertEqual(set(item), {"ordinal", "item_type", "item_id", "item_hash"})
            self.assertEqual(len(item["item_hash"]), 64)
        self.assertNotIn("packet_json", json.dumps(value, sort_keys=True))

    def test_10_manifest_pagination_is_complete(self) -> None:
        _, packet = self.handoff_fixture()
        items: list[dict[str, Any]] = []
        cursor = None
        while True:
            page = self.service.read_rehydration_packet(packet_id=packet["packet_id"], page_size=1, cursor=cursor)["packet"]
            items.extend(page["manifest_items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual([item["ordinal"] for item in items], list(range(len(items))))
        self.assertEqual(len({item["item_id"] for item in items}), len(items))
        self.assertEqual(len(items), self.service.read_rehydration_packet(packet_id=packet["packet_id"])["packet"]["manifest_count"])

    def test_11_production_blind_ack_is_rejected(self) -> None:
        path, repo, service, run, binding, codex, luna, installations, token, packet = self.nonfixture_handoff("blind")
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(MaxControlError):
            MaxPortabilityService(repo, self.old_host).acknowledge_rehydration(packet_id=packet["packet_id"], packet_hash=packet["packet_hash"])
        self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_12_production_ack_requires_target_installation(self) -> None:
        path, repo, service, run, binding, codex, luna, installations, token, packet = self.nonfixture_handoff("wrong-target")
        read = service.read_rehydration_packet(packet_id=packet["packet_id"])["packet"]
        target_service = MaxPortabilityService(repo, self.target_actor)
        with self.assertRaises(MaxControlError):
            target_service.acknowledge_rehydration(
                packet_id=packet["packet_id"], packet_hash=packet["packet_hash"],
                handoff_id=read["handoff_approval_id"], new_binding_id=read["new_binding_id"],
                target_host_profile_id=luna.host_profile_id, target_installation_id="missing-installation",
                target_installation_hash="4" * 64,
                adapter_capability_hash=canonical_sha256({"adapter_hash": luna.adapter_hash, "capability_manifest_hash": luna.capability_manifest_hash}),
                target_session=self.target_actor.session_id, observed_checkpoint_hash=read["state_hash"],
                observed_state_hash=read["state_hash"], rehydrated_state_hash=read["state_hash"],
                manifest_root=read["manifest_root"], manifest_count=int(read["manifest_count"]), read_complete=True,
            )

    def test_13_production_target_ack_allows_resume(self) -> None:
        path, repo, service, run, binding, codex, luna, installations, token, packet = self.nonfixture_handoff("target")
        read = service.read_rehydration_packet(packet_id=packet["packet_id"])["packet"]
        target_service = MaxPortabilityService(repo, self.target_actor)
        ack = target_service.acknowledge_rehydration(
            packet_id=packet["packet_id"], packet_hash=packet["packet_hash"],
            handoff_id=read["handoff_approval_id"], new_binding_id=read["new_binding_id"],
            target_host_profile_id=luna.host_profile_id,
            target_installation_id=installations[luna.host_profile_id]["installation_id"],
            target_installation_hash=installations[luna.host_profile_id]["installation_hash"],
            adapter_capability_hash=canonical_sha256({"adapter_hash": luna.adapter_hash, "capability_manifest_hash": luna.capability_manifest_hash}),
            target_session=self.target_actor.session_id, observed_checkpoint_hash=read["state_hash"],
            observed_state_hash=read["state_hash"], rehydrated_state_hash=read["state_hash"],
            manifest_root=read["manifest_root"], manifest_count=int(read["manifest_count"]), read_complete=True,
        )
        self.assertTrue(ack["ok"])
        self.assertEqual(repo.resume(run_id=run["run_id"], actor=self.admin, fencing_token=token)["run"]["status"], "RUNNING")

    def test_14_target_ack_replay_is_idempotent(self) -> None:
        _, packet = self.handoff_fixture()
        first = self.service.acknowledge_rehydration(packet_id=packet["packet_id"], packet_hash=packet["packet_hash"])
        second = self.service.acknowledge_rehydration(packet_id=packet["packet_id"], packet_hash=packet["packet_hash"])
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["ack_id"], second["ack_id"])

    def test_15_append_only_invocation_and_result_receipts(self) -> None:
        binding = self.bind()["binding"]
        stored = self.service.record_normalized_result(run_id=self.run_id, binding_id=binding["binding_id"], result=self.result())
        connection = self.repo._connect(read_only=False)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE max_portability_invocation_bindings SET source_kind='server_runner' WHERE invocation_binding_id=?", (stored["invocation_binding_id"],))
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM max_portability_result_bindings WHERE result_id=?", (stored["result_id"],))
            connection.rollback()
        finally:
            connection.close()
        self.assertTrue(self.service.verify(run_id=self.run_id)["ok"])

    def test_16_tampered_quiescence_snapshot_is_detected(self) -> None:
        self.handoff_fixture()
        connection = self.repo._connect(read_only=False)
        try:
            connection.execute("DROP TRIGGER IF EXISTS max_portability_quiescence_snapshots_no_update")
            connection.execute("UPDATE max_portability_quiescence_snapshots SET activity_json='{}' WHERE run_id=?", (self.run_id,))
            connection.commit()
        finally:
            connection.close()
        self.assertFalse(self.service.verify(run_id=self.run_id)["ok"])

    def test_17_nonfixture_installation_attestation_is_idempotent(self) -> None:
        path, repo, service, run, binding, codex, luna, installations = self.nonfixture_store("attestation", install_hosts=False)
        with self.assertRaises(MaxControlError):
            service.bind_backend(
                run_id=run["run_id"], host_profile_id=codex.host_profile_id,
                backend_profile_id=self.backend.backend_profile_id,
                source_policy_hash=run["source_policy_hash"], budget_hash=run["budget_hash"],
            )
        evidence = InstallationEvidence("5" * 64, codex.canonical_skill_hash, codex.adapter_hash, codex.capability_manifest_hash, "r2-attestation-repeat")
        first = service.register_host_installation(host_profile_id=codex.host_profile_id, **evidence.to_mapping())
        second = service.register_host_installation(host_profile_id=codex.host_profile_id, **evidence.to_mapping())
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertTrue(service.bind_backend(
            run_id=run["run_id"], host_profile_id=codex.host_profile_id,
            backend_profile_id=self.backend.backend_profile_id,
            source_policy_hash=run["source_policy_hash"], budget_hash=run["budget_hash"],
        )["ok"])

    def test_18_backup_restore_preserves_convergence_tables(self) -> None:
        self.handoff_fixture()
        backup = Path(self.temp.name) / "r2-backup.db"
        restored = Path(self.temp.name) / "r2-restored.db"
        self.repo.backup(backup)
        target = MaxControlRepository(restored)
        target.restore(backup)
        connection = target._connect(read_only=True)
        try:
            snapshot_count = connection.execute("SELECT COUNT(*) FROM max_portability_quiescence_snapshots").fetchone()[0]
            manifest_count = connection.execute("SELECT COUNT(*) FROM max_rehydration_packet_manifest_items").fetchone()[0]
            packet_count = connection.execute("SELECT COUNT(*) FROM max_rehydration_packets").fetchone()[0]
        finally:
            connection.close()
        self.assertGreaterEqual(snapshot_count, 2)
        self.assertGreater(manifest_count, 0)
        self.assertEqual(packet_count, 1)
        self.assertTrue(MaxPortabilityService(target, self.admin).verify(run_id=self.run_id)["ok"])


if __name__ == "__main__":
    unittest.main()
