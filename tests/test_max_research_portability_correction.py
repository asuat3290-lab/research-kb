from __future__ import annotations

import concurrent.futures
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from research_kb.max_research.contract import canonical_json
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository
from research_kb.max_research.persistence.db import connect_control_db
from research_kb.max_research.persistence.migrations import apply_migrations
from research_kb.max_research.portability import (
    AgentHostProfile,
    MaxPortabilityService,
    NormalizedAgentResult,
    opencode_go_backend_profile,
)
from research_kb.max_research.portability_adapters import (
    CodexPortabilityAdapter,
    HermesPortabilityAdapter,
    InstallationEvidence,
    LunaPortabilityAdapter,
    QoderPortabilityAdapter,
    sha256_file,
)
from research_kb.max_research.provider import ProviderProfile, ProviderStore
from research_kb.policy import Actor


class PortabilityCorrectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr-portability-0r-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("admin", "correction-admin", "user", "admin", "correction-tests")
        self.guest = Actor("guest", "correction-guest", "agent", "researcher", "correction-tests")
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize(fixture=True)
        charter = {
            "question": "bounded portability correction",
            "scope": "MR-PORTABILITY-0R fixture",
            "invariants": ["server owned", "explicit binding"],
            "non_goals": ["live provider"],
            "deliverables": ["portable audit"],
            "model_identity": "fixture-model/v1",
            "budget": {"iteration_count": 1, "input_tokens": 64, "output_tokens": 32, "cost_units": 10},
            "source_policy": {"network_allowed": False, "roles": ["primary"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        proposed = self.repo.propose(project_id="correction-project", charter=charter, actor=self.admin)
        self.run_id = proposed["run_id"]
        self.charter_hash = proposed["charter_hash"]
        self.source_policy_hash = proposed["source_policy_hash"]
        self.budget_hash = proposed["budget_hash"]
        self.codex = AgentHostProfile(
            host_kind="codex", host_version="fixture-v1", control_surface="fixture",
            capability_manifest_hash="a" * 64, canonical_skill_hash="b" * 64,
            adapter_hash="c" * 64, allowed_operations=("bind-backend", "handoff", "checkpoint", "resume"),
        )
        self.luna = replace(self.codex, host_kind="luna", host_profile_id="")
        self.qoder = replace(self.codex, host_kind="qoder", host_profile_id="")
        self.hermes = replace(self.codex, host_kind="hermes", host_profile_id="")
        self.backend = opencode_go_backend_profile()
        service = MaxPortabilityService(self.repo, self.admin)
        self.service = service
        for profile in (self.codex, self.luna, self.qoder, self.hermes):
            service.register_host_profile(profile=profile)
        service.register_backend_profile(profile=self.backend)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def bind(self, *, host: AgentHostProfile | None = None) -> dict:
        return self.service.bind_backend(
            run_id=self.run_id,
            host_profile_id=(host or self.codex).host_profile_id,
            backend_profile_id=self.backend.backend_profile_id,
            source_policy_hash=self.source_policy_hash,
            budget_hash=self.budget_hash,
        )

    def pause(self) -> int:
        self.repo.approve(run_id=self.run_id, charter_hash_value=self.charter_hash, reason="pause for correction", actor=self.admin)
        started = self.repo.start(run_id=self.run_id, actor=self.admin)
        self.repo.pause(run_id=self.run_id, actor=self.admin, fencing_token=started["lease"]["fencing_token"])
        return int(started["lease"]["fencing_token"])

    def result(self, text: str = "bounded") -> dict:
        return {
            "cognitive_artifacts": [{"kind": "observation", "text": text}],
            "proposed_canonical_objects": [], "proposed_relations": [], "objections": [],
            "hypotheses": [], "research_questions": [],
            "usage_receipt": {"input_tokens": 1, "output_tokens": 2, "cost_units": 0},
            "backend_status": "succeeded", "provider_call_ref": None,
            "finish_reason": "stop", "retry_classification": "not_applicable",
        }

    def provider_row(self, *, terminal: bool) -> None:
        profile = ProviderProfile.from_mapping({
            "profile_id": "correction-provider",
            "profile_version": "1",
            "protocol": "openai-compatible/v1",
            "provider_name": "fixture",
            "model_identity": "fixture-model/v1",
            "endpoint_origin": "https://provider.invalid",
            "endpoint_path_policy": "/v1/chat/completions",
            "capabilities": {"structured_json": True, "idempotency": True, "result_query": True, "usage_reporting": True},
            "inference_defaults": {"temperature": 0, "top_p": 1, "max_output_tokens": 128, "seed": 0},
            "timeout_policy": {"connect_ms": 1000, "write_ms": 1000, "read_ms": 1000, "total_ms": 5000},
            "retry_policy": {"max_attempts": 1, "backoff_ms": 1, "retry_statuses": [429]},
            "request_limits": {"max_request_bytes": 100000, "max_response_bytes": 100000, "max_prompt_chars": 10000, "max_json_depth": 12, "max_input_tokens": 2500, "max_output_tokens": 128, "max_cache_read_tokens": 0, "max_reasoning_tokens": 0},
            "rate_policy": {"max_concurrency": 1, "per_minute": 60},
            "credential_ref": {"kind": "injected", "name": "fixture"},
            "network_policy_hash": "d" * 64,
            "pricing": {"pricing_id": "correction-price", "pricing_version": "1", "currency": "USD", "unit": "cost_units", "input_per_1k": "1", "output_per_1k": "2", "cache_per_1k": "0", "reasoning_per_1k": "0", "effective_at": "2026-01-01T00:00:00.000Z", "source_label": "probe"},
        })
        registered = ProviderStore(self.repo).register_profile(profile=profile, actor=self.admin)
        profile_hash = registered["profile_hash"]
        connection = self.repo._connect(read_only=True)
        try:
            pricing_hash = connection.execute("SELECT pricing_hash FROM max_provider_profiles WHERE profile_hash=?", (profile_hash,)).fetchone()[0]
        finally:
            connection.close()
        now = "2026-01-01T00:00:00.000Z"
        empty = "{}"
        connection = self.repo._connect(read_only=False)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO max_provider_call_records(call_record_id,provider_call_id,logical_call_id,intent_id,run_id,project_id,iteration_id,profile_hash,model_identity,intent_hash,request_hash,idempotency_key,transport_status,terminal_status,usage_json,usage_hash,response_manifest_json,response_manifest_hash,pricing_hash,record_json,record_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("correction-call", "correction-provider-call", "correction-logical", None, self.run_id, "correction-project", None, profile_hash, "fixture-model/v1", "e" * 64, "f" * 64, "correction-key", "succeeded" if terminal else "started", "settled" if terminal else "in_flight", empty, "1" * 64, empty, "2" * 64, pricing_hash, empty, "3" * 64, now, self.admin.actor_id, self.admin.actor_kind, self.admin.session_id),
            )
            connection.commit()
        finally:
            connection.close()

    def test_01_builtin_descriptor_has_no_synthetic_hash(self) -> None:
        value = self.service.describe_host(host_kind="codex")["host_profile"]
        self.assertFalse(value["registered"])
        self.assertFalse(value["attested"])
        self.assertFalse(value["bindable"])
        self.assertIsNone(value["canonical_skill_hash"])
        self.assertIsNone(value["adapter_hash"])

    def test_02_same_result_from_two_runs_is_attributed(self) -> None:
        first = self.bind()
        second = self.repo.propose(project_id="correction-project-two", charter={"question": "second", "scope": "fixture", "invariants": ["x"], "non_goals": ["y"], "deliverables": ["z"], "model_identity": "fixture-model/v1", "budget": {"iteration_count": 1, "input_tokens": 64, "output_tokens": 32, "cost_units": 10}, "source_policy": {"network_allowed": False}, "quality_gates": {"require_human_approval": True}}, actor=self.admin)
        second_binding = self.service.bind_backend(run_id=second["run_id"], host_profile_id=self.luna.host_profile_id, backend_profile_id=self.backend.backend_profile_id, source_policy_hash=second["source_policy_hash"], budget_hash=second["budget_hash"])
        value = self.result()
        self.service.record_normalized_result(run_id=self.run_id, binding_id=first["binding"]["binding_id"], result=value)
        stored = self.service.record_normalized_result(run_id=second["run_id"], binding_id=second_binding["binding"]["binding_id"], result=value)
        self.assertFalse(stored["idempotent"])
        connection = self.repo._connect(read_only=True)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_normalized_agent_results_v2").fetchone()[0], 2)
        finally:
            connection.close()

    def test_03_same_invocation_same_payload_is_idempotent(self) -> None:
        binding = self.bind()["binding"]
        value = self.result()
        first = self.service.record_normalized_result(run_id=self.run_id, binding_id=binding["binding_id"], result=value, invocation_id="invocation-1", intent_id="intent-1")
        second = self.service.record_normalized_result(run_id=self.run_id, binding_id=binding["binding_id"], result=value, invocation_id="invocation-1", intent_id="intent-1")
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["result_id"], second["result_id"])

    def test_04_same_invocation_different_payload_fails_closed(self) -> None:
        binding = self.bind()["binding"]
        self.service.record_normalized_result(run_id=self.run_id, binding_id=binding["binding_id"], result=self.result(), invocation_id="invocation-2", intent_id="intent-2")
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(MaxControlError):
            self.service.record_normalized_result(run_id=self.run_id, binding_id=binding["binding_id"], result=self.result("different"), invocation_id="invocation-2", intent_id="intent-2")
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_05_result_size_bound_fails_before_write(self) -> None:
        huge = self.result("x" * 300_000)
        with self.assertRaises(MaxControlError):
            NormalizedAgentResult.from_mapping(huge)

    def test_06_result_structural_bounds_fail_closed(self) -> None:
        deep = self.result()
        value = None
        for _ in range(14):
            value = [value]
        deep["cognitive_artifacts"] = value
        with self.assertRaises(MaxControlError):
            NormalizedAgentResult.from_mapping(deep)
        too_many = self.result()
        too_many["cognitive_artifacts"] = [{} for _ in range(257)]
        with self.assertRaises(MaxControlError):
            NormalizedAgentResult.from_mapping(too_many)

    def test_07_handoff_requires_paused_and_does_not_write(self) -> None:
        self.bind()
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(MaxControlError):
            self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=self.luna.host_profile_id, reason="not paused")
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_08_terminal_provider_history_is_allowed(self) -> None:
        self.bind()
        self.pause()
        self.provider_row(terminal=True)
        preview = self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=self.luna.host_profile_id, reason="terminal history")
        self.assertEqual(preview["state"], "PENDING")

    def test_09_inflight_provider_history_blocks_handoff(self) -> None:
        self.bind()
        self.pause()
        self.provider_row(terminal=False)
        with self.assertRaises(MaxControlError):
            self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=self.luna.host_profile_id, reason="in flight")

    def test_10_three_sequential_handoffs_have_contiguous_lineage(self) -> None:
        self.bind()
        self.pause()
        hosts = (self.luna, self.qoder, self.hermes)
        generations = []
        for host in hosts:
            preview = self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=host.host_profile_id, reason="sequential")
            approved = self.service.approve_backend_handoff(handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"])
            generations.append(preview["generation"])
            self.assertEqual(approved["state"], "CONSUMED")
        self.assertEqual(generations, [1, 2, 3])
        self.assertTrue(self.service.verify(run_id=self.run_id)["ok"])

    def test_11_concurrent_handoff_consumption_is_single_use(self) -> None:
        self.bind()
        self.pause()
        preview = self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=self.luna.host_profile_id, reason="concurrent")

        def consume(_: int):
            try:
                return self.service.approve_backend_handoff(handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"])
            except Exception as exc:  # expected for all but one caller
                return exc

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(consume, range(20)))
        self.assertEqual(sum(isinstance(item, dict) and item.get("state") == "CONSUMED" for item in results), 1)
        self.assertEqual(self.service.status(run_id=self.run_id)["handoff_count"], 1)

    def test_12_profile_disable_and_revoke_are_append_only(self) -> None:
        self.service.disable_profile(profile_kind="backend", profile_id=self.backend.backend_profile_id, reason="maintenance")
        with self.assertRaises(MaxControlError):
            self.bind()
        self.assertTrue(self.service.disable_profile(profile_kind="backend", profile_id=self.backend.backend_profile_id, reason="repeat")["idempotent"])
        self.service.revoke_profile(profile_kind="host", profile_id=self.codex.host_profile_id, reason="retired")
        with self.assertRaises(MaxControlError):
            self.bind()
        self.assertTrue(self.service.verify()["ok"])

    def test_13_nonfixture_binding_requires_attested_installation(self) -> None:
        path = Path(self.temp.name) / "nonfixture.db"
        repo = MaxControlRepository(path)
        repo.initialize()
        proposed = repo.propose(project_id="nonfixture", charter={"question": "q", "scope": "s", "invariants": ["i"], "non_goals": ["n"], "deliverables": ["d"], "model_identity": "m", "budget": {"iteration_count": 1, "input_tokens": 1, "output_tokens": 1, "cost_units": 1}, "source_policy": {"network_allowed": False}, "quality_gates": {"require_human_approval": True}}, actor=self.admin)
        service = MaxPortabilityService(repo, self.admin)
        host = self.codex
        service.register_host_profile(profile=host)
        service.register_backend_profile(profile=self.backend)
        with self.assertRaises(MaxControlError):
            service.bind_backend(run_id=proposed["run_id"], host_profile_id=host.host_profile_id, backend_profile_id=self.backend.backend_profile_id, source_policy_hash=proposed["source_policy_hash"], budget_hash=proposed["budget_hash"])
        evidence = InstallationEvidence("1" * 64, host.canonical_skill_hash, host.adapter_hash, host.capability_manifest_hash, "attestation-1")
        first = service.register_host_installation(host_profile_id=host.host_profile_id, **evidence.to_mapping())
        second = service.register_host_installation(host_profile_id=host.host_profile_id, **evidence.to_mapping())
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertTrue(service.bind_backend(run_id=proposed["run_id"], host_profile_id=host.host_profile_id, backend_profile_id=self.backend.backend_profile_id, source_policy_hash=proposed["source_policy_hash"], budget_hash=proposed["budget_hash"])["ok"])
        self.assertEqual(service.host_installation_status(host_profile_id=host.host_profile_id)["installations"][0]["installation_id"], first["installation_id"])

    def test_14_rehydration_status_read_and_ack_are_idempotent(self) -> None:
        self.bind()
        self.pause()
        preview = self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=self.luna.host_profile_id, reason="packet")
        approved = self.service.approve_backend_handoff(handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"])
        packet = approved["rehydration_packet"]
        self.assertEqual(self.service.rehydration_packet_status(packet_id=packet["packet_id"])["state"], "AWAITING_ACK")
        self.assertNotIn("current_summary", json.dumps(self.service.read_rehydration_packet(packet_id=packet["packet_id"])))
        ack1 = self.service.acknowledge_rehydration(packet_id=packet["packet_id"], packet_hash=packet["packet_hash"])
        ack2 = self.service.acknowledge_rehydration(packet_id=packet["packet_id"], packet_hash=packet["packet_hash"])
        self.assertFalse(ack1["idempotent"])
        self.assertTrue(ack2["idempotent"])
        self.assertEqual(self.service.rehydration_packet_status(packet_id=packet["packet_id"])["state"], "ACKNOWLEDGED")

    def test_15_resume_requires_packet_ack(self) -> None:
        self.bind()
        token = self.pause()
        preview = self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=self.luna.host_profile_id, reason="resume gate")
        approved = self.service.approve_backend_handoff(handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"])
        with self.assertRaises(MaxControlError):
            self.repo.resume(run_id=self.run_id, actor=self.admin, fencing_token=token)
        packet = approved["rehydration_packet"]
        self.service.acknowledge_rehydration(packet_id=packet["packet_id"], packet_hash=packet["packet_hash"])
        self.assertEqual(self.repo.resume(run_id=self.run_id, actor=self.admin, fencing_token=token)["run"]["status"], "RUNNING")

    def test_16_packet_payload_contains_only_server_ids_and_hashes(self) -> None:
        self.bind()
        self.pause()
        preview = self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=self.luna.host_profile_id, reason="payload")
        approved = self.service.approve_backend_handoff(handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"])
        value = json.dumps(approved["rehydration_packet"], ensure_ascii=False)
        for forbidden in ("summary", "transcript", "prompt", "raw_response", "source_text"):
            self.assertNotIn(forbidden, value)

    def test_17_migration_failure_rolls_back_and_retry_is_clean(self) -> None:
        path = Path(self.temp.name) / "migration-failure.db"
        connection = connect_control_db(path, read_only=False)
        try:
            with self.assertRaises(RuntimeError):
                apply_migrations(connection, fail_after_statement=1)
            self.assertIsNone(connection.execute("SELECT 1 FROM sqlite_master WHERE name='max_schema_migrations'").fetchone())
            self.assertEqual(apply_migrations(connection), CONTROL_SCHEMA_VERSION)
        finally:
            connection.close()
        self.assertEqual(MaxControlRepository(path).verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)

    def test_18_backup_restore_preserves_lineage_and_packet(self) -> None:
        self.bind()
        self.pause()
        preview = self.service.preview_backend_handoff(run_id=self.run_id, new_backend_profile_id=self.backend.backend_profile_id, new_host_profile_id=self.luna.host_profile_id, reason="backup")
        self.service.approve_backend_handoff(handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"])
        backup = Path(self.temp.name) / "backup.db"
        restored = Path(self.temp.name) / "restored.db"
        self.repo.backup(backup)
        target = MaxControlRepository(restored)
        target.restore(backup)
        self.assertTrue(MaxPortabilityService(target, self.admin).verify()["ok"])
        connection = target._connect(read_only=True)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_rehydration_packets WHERE run_id=?", (self.run_id,)).fetchone()[0], 1)
        finally:
            connection.close()

    def test_19_current_projection_tamper_is_detected(self) -> None:
        self.bind()
        connection = self.repo._connect(read_only=False)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE max_run_execution_binding_current SET current_json=? WHERE run_id=?", ("{}", self.run_id))
            connection.commit()
        finally:
            connection.close()
        self.assertFalse(self.service.verify(run_id=self.run_id)["ok"])

    def test_20_four_host_adapters_use_same_redacted_protocol(self) -> None:
        calls = []
        def command(args):
            calls.append(tuple(args))
            command_name = args[0]
            if command_name == "host-describe":
                return {"ok": True, "registered": False, "host_profile": {"host_kind": args[2], "canonical_skill_hash": None, "adapter_hash": None, "registered": False}}
            if command_name == "host-installation-status":
                return {"ok": True, "host_kind": "codex", "installations": []}
            if command_name == "rehydration-packet-read":
                return {"ok": True, "packet": {"packet_hash": "a" * 64}}
            return {"ok": True}
        adapters = [CodexPortabilityAdapter(command), LunaPortabilityAdapter(command), QoderPortabilityAdapter(command), HermesPortabilityAdapter(command)]
        for adapter in adapters:
            self.assertFalse(adapter.discover()["host_profile"]["registered"])
            self.assertTrue(adapter.verify(run_id=self.run_id)["ok"])
            self.assertTrue(adapter.recover_packet(packet_id="packet", acknowledge=False)["ok"])
        self.assertEqual({item[0] for item in calls}, {"host-describe", "verify-portability", "rehydration-packet-read"})

    def test_21_adapter_hash_verification_is_byte_exact(self) -> None:
        path = Path(self.temp.name) / "adapter.txt"
        path.write_bytes(b"adapter\n")
        expected = hashlib.sha256(b"adapter\n").hexdigest()
        self.assertEqual(sha256_file(path), expected)
        path.write_bytes(b"adapter\r\n")
        self.assertNotEqual(sha256_file(path), expected)

    def test_22_adapter_result_submission_is_server_attributed(self) -> None:
        calls = []
        def command(args):
            calls.append(tuple(args))
            return {"ok": True, "result_id": "server-result"}
        adapter = CodexPortabilityAdapter(command)
        binding = self.bind()["binding"]
        result = adapter.submit_result(run_id=self.run_id, binding_id=binding["binding_id"], result=self.result())
        self.assertEqual(result["result_id"], "server-result")
        self.assertEqual(calls[0][0], "normalized-result-record")
        self.assertNotIn("OPENCODE_GO_API_KEY", canonical_json(calls[0]))


if __name__ == "__main__":
    unittest.main()
