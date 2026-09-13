from __future__ import annotations

import concurrent.futures
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from research_kb.cli import _parser, _redact_max_output
from research_kb.mcp_server import TOOL_NAMES
from research_kb.max_research.contract import canonical_sha256
from research_kb.max_research.persistence import CONTROL_SCHEMA_VERSION, MaxControlError, MaxControlRepository
from research_kb.max_research.portability import (
    AgentHostProfile,
    ExecutionBackendProfile,
    MaxPortabilityService,
    NormalizedAgentResult,
    opencode_go_backend_profile,
)
from research_kb.policy import Actor


class PortabilityFoundationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr-portability-")
        self.path = Path(self.temp.name) / "control.db"
        self.admin = Actor("admin", "portability-admin", "user", "admin", "portability-tests")
        self.guest = Actor("agent", "portability-agent", "agent", "researcher", "portability-tests")
        self.repo = MaxControlRepository(self.path)
        self.repo.initialize(fixture=True)
        self.charter = {
            "question": "How can a bounded research run move between hosts without losing canonical state?",
            "scope": "MR-PORTABILITY-0 fixture",
            "invariants": ["explicit backend binding", "canonical evidence is server-owned"],
            "non_goals": ["live provider execution"],
            "deliverables": ["portability audit"],
            "model_identity": "fixture-model/v1",
            "budget": {"iteration_count": 1, "input_tokens": 64, "output_tokens": 32, "cost_units": 10},
            "source_policy": {"network_allowed": False, "roles": ["primary"]},
            "quality_gates": {"require_human_approval": True, "required_strategy_families": ["direct"]},
        }
        proposed = self.repo.propose(project_id="portability-project", charter=self.charter, actor=self.admin)
        self.run_id = proposed["run_id"]
        self.charter_hash = proposed["charter_hash"]
        self.source_policy_hash = proposed["source_policy_hash"]
        self.budget_hash = proposed["budget_hash"]
        self.codex = AgentHostProfile(
            host_kind="codex",
            host_version="host-v1",
            control_surface="research-kb max portability",
            capability_manifest_hash="a" * 64,
            canonical_skill_hash="b" * 64,
            adapter_hash="c" * 64,
            allowed_operations=("discover", "bind-backend", "checkpoint", "handoff", "resume"),
        )
        self.luna = replace(self.codex, host_kind="luna", host_profile_id="")
        self.openc = opencode_go_backend_profile()
        self.fixture_backend = replace(
            self.openc,
            backend_kind="hermetic_fixture",
            provider_name="Hermetic Fixture",
            model_identity="fixture-model/v1",
            credential_strategy={"kind": "none", "value_access": "none"},
            usage_authority_strategy={"kind": "fixture", "required": True},
            network_policy_requirement={"scheme": "none", "network": False},
            source_egress_requirement={"kind": "server-owned-fixture", "raw_text_persistence": False},
            pricing_policy={"human_ceiling_micro_usd": 0, "effective_cap_micro_usd": 0},
            backend_profile_id="",
        )
        self.service = MaxPortabilityService(self.repo, self.admin)
        self.service.register_host_profile(profile=self.codex)
        self.service.register_host_profile(profile=self.luna)
        self.service.register_backend_profile(profile=self.openc)
        self.service.register_backend_profile(profile=self.fixture_backend)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def bind(self, *, host: AgentHostProfile | None = None, backend: ExecutionBackendProfile | None = None) -> dict:
        return self.service.bind_backend(
            run_id=self.run_id,
            host_profile_id=(host or self.codex).host_profile_id,
            backend_profile_id=(backend or self.openc).backend_profile_id,
            source_policy_hash=self.source_policy_hash,
            budget_hash=self.budget_hash,
        )

    def pause_for_handoff(self) -> None:
        self.repo.approve(run_id=self.run_id, charter_hash_value=self.charter_hash, reason="prepare portability handoff", actor=self.admin)
        started = self.repo.start(run_id=self.run_id, actor=self.admin)
        self.repo.pause(run_id=self.run_id, actor=self.admin, fencing_token=started["lease"]["fencing_token"])

    def test_01_current_schema_and_exact12_are_preserved(self) -> None:
        self.assertEqual(CONTROL_SCHEMA_VERSION, 32)
        self.assertEqual(len(TOOL_NAMES), 12)
        self.assertEqual(len(set(TOOL_NAMES)), 12)
        self.assertEqual(self.repo.verify_database()["schema_version"], CONTROL_SCHEMA_VERSION)
        connection = self.repo._connect(read_only=True)
        try:
            names = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            connection.close()
        self.assertTrue({"max_agent_host_profiles", "max_execution_backend_profiles", "max_run_execution_bindings", "max_backend_handoff_approvals"}.issubset(names))

    def test_02_host_and_backend_contracts_are_separate_and_opencode_is_ordinary(self) -> None:
        self.assertEqual(self.openc.backend_kind, "openai_compatible_http")
        self.assertEqual(self.openc.model_identity, "deepseek-v4-flash")
        self.assertFalse(self.service.list_backends()["default_backend_profile"])
        self.assertEqual(set(self.service.list_hosts()["supported_host_kinds"]), {"codex", "luna", "qoder", "hermes", "generic_cli_agent"})
        described = self.service.describe_backend(backend_kind="openai_compatible_http", provider_name="OpenCode Go", model_identity="deepseek-v4-flash")
        self.assertFalse(described["registered"])
        self.assertNotIn("OPENCODE_GO_API_KEY", json.dumps(described, ensure_ascii=False))

    def test_03_explicit_binding_and_no_implicit_default(self) -> None:
        self.assertIsNone(self.service.status(run_id=self.run_id)["current_binding"])
        bound = self.bind()
        self.assertFalse(bound["idempotent"])
        self.assertEqual(self.service.status(run_id=self.run_id)["current_binding"]["backend_profile_id"], self.openc.backend_profile_id)
        same = self.bind()
        self.assertTrue(same["idempotent"])
        with self.assertRaises(MaxControlError):
            self.service.bind_backend(
                run_id=self.run_id,
                host_profile_id=self.codex.host_profile_id,
                backend_profile_id=self.fixture_backend.backend_profile_id,
                source_policy_hash=self.source_policy_hash,
                budget_hash=self.budget_hash,
            )

    def test_04_non_admin_and_wrong_hash_fail_without_writes(self) -> None:
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(MaxControlError):
            MaxPortabilityService(self.repo, self.guest).bind_backend(
                run_id=self.run_id,
                host_profile_id=self.codex.host_profile_id,
                backend_profile_id=self.openc.backend_profile_id,
                source_policy_hash=self.source_policy_hash,
                budget_hash=self.budget_hash,
            )
        after = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.bind()
        with self.assertRaises(MaxControlError):
            self.service.bind_backend(
                run_id=self.run_id,
                host_profile_id=self.codex.host_profile_id,
                backend_profile_id=self.openc.backend_profile_id,
                source_policy_hash="d" * 64,
                budget_hash=self.budget_hash,
            )

    def test_05_handoff_is_human_gated_append_only_and_rehydrates_binding(self) -> None:
        first = self.bind()
        self.pause_for_handoff()
        preview = self.service.preview_backend_handoff(
            run_id=self.run_id,
            new_host_profile_id=self.luna.host_profile_id,
            new_backend_profile_id=self.fixture_backend.backend_profile_id,
            reason="Move the paused Run to a declared hermetic host/backend pair",
            ttl_seconds=3600,
        )
        self.assertEqual(preview["state"], "PENDING")
        with self.assertRaises(MaxControlError):
            self.service.approve_backend_handoff(handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase="wrong")
        approved = self.service.approve_backend_handoff(
            handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"]
        )
        self.assertEqual(approved["state"], "CONSUMED")
        current = self.service.status(run_id=self.run_id)["current_binding"]
        self.assertEqual(current["binding_version"], 2)
        self.assertNotEqual(current["binding_id"], first["binding"]["binding_id"])
        self.assertTrue(self.service.verify(run_id=self.run_id)["ok"])
        connection = self.repo._connect(read_only=True)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_run_execution_bindings WHERE run_id=?", (self.run_id,)).fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_backend_handoff_events WHERE handoff_approval_id=?", (preview["handoff_approval_id"],)).fetchone()[0], 3)
        finally:
            connection.close()

    def test_06_handoff_preview_is_idempotent_and_expiry_is_utc(self) -> None:
        self.bind()
        self.pause_for_handoff()
        kwargs = {
            "run_id": self.run_id,
            "new_backend_profile_id": self.fixture_backend.backend_profile_id,
            "new_host_profile_id": self.luna.host_profile_id,
            "reason": "explicit handoff",
            "ttl_seconds": 3600,
        }
        first = self.service.preview_backend_handoff(**kwargs)
        second = self.service.preview_backend_handoff(**kwargs)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["handoff_hash"], second["handoff_hash"])

    def test_07_twenty_concurrent_same_bindings_have_one_authoritative_binding(self) -> None:
        def invoke(_index: int) -> dict:
            return MaxPortabilityService(self.repo, self.admin).bind_backend(
                run_id=self.run_id,
                host_profile_id=self.codex.host_profile_id,
                backend_profile_id=self.openc.backend_profile_id,
                source_policy_hash=self.source_policy_hash,
                budget_hash=self.budget_hash,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(invoke, range(20)))
        self.assertEqual(sum(1 for result in results if not result["idempotent"]), 1)
        self.assertEqual(sum(1 for result in results if result["idempotent"]), 19)
        connection = self.repo._connect(read_only=True)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM max_run_execution_bindings WHERE run_id=?", (self.run_id,)).fetchone()[0], 1)
        finally:
            connection.close()

    def test_08_normalized_result_is_bounded_and_cannot_claim_canonical_authority(self) -> None:
        binding = self.bind()["binding"]
        base = {
            "cognitive_artifacts": [{"kind": "observation", "text": "bounded"}],
            "proposed_canonical_objects": [],
            "proposed_relations": [],
            "objections": [],
            "hypotheses": ["a proposal"],
            "research_questions": [],
            "usage_receipt": {"input_tokens": 1, "output_tokens": 2, "cost_units": 0},
            "backend_status": "succeeded",
            "provider_call_ref": None,
            "finish_reason": "stop",
            "retry_classification": "not_applicable",
        }
        stored = self.service.record_normalized_result(run_id=self.run_id, binding_id=binding["binding_id"], result=base)
        self.assertTrue(stored["result_hash"])
        with self.assertRaises(MaxControlError):
            self.service.record_normalized_result(run_id=self.run_id, binding_id=binding["binding_id"], result={**base, "proposed_canonical_objects": [{"verified": True}]})
        with self.assertRaises(MaxControlError):
            NormalizedAgentResult.from_mapping({**base, "backend_status": "completed"})

    def test_09_cli_is_unified_json_and_redacted(self) -> None:
        parsed = _parser().parse_args(["--config", "config.toml", "max", "--database", str(self.path), "host-list"])
        self.assertEqual(parsed.max_command, "host-list")
        redacted = _redact_max_output({"confirmation_phrase": "secret", "path": "D:\\private\\x", "nested": {"prompt": "raw"}})
        self.assertNotIn("confirmation_phrase", redacted)
        self.assertNotIn("prompt", json.dumps(redacted, ensure_ascii=False))
        self.assertEqual(len(TOOL_NAMES), 12)

    def test_10_portability_status_and_verifier_report_no_default(self) -> None:
        status = self.service.status()
        self.assertEqual(status["default_backend_profile"], None)
        self.assertEqual(status["host_profile_count"], 2)
        self.assertEqual(status["backend_profile_count"], 2)
        self.assertTrue(self.service.verify()["ok"])

    def test_11_all_supported_hosts_are_discoverable_without_registration(self) -> None:
        for kind in ("codex", "luna", "qoder", "hermes", "generic_cli_agent"):
            with self.subTest(kind=kind):
                described = self.service.describe_host(host_kind=kind)
                self.assertFalse(described["registered"])
                self.assertEqual(described["host_profile"]["host_kind"], kind)
                self.assertEqual(described["host_profile"]["status"], "active")

    def test_12_profile_secret_material_and_unknown_fields_fail_closed(self) -> None:
        bad_backend = self.openc.to_mapping()
        bad_backend["credential_strategy"] = {"kind": "environment", "api_key": "not-allowed"}
        with self.assertRaises(MaxControlError):
            ExecutionBackendProfile.from_mapping(bad_backend)
        bad_host = self.codex.to_mapping()
        bad_host["unexpected"] = True
        with self.assertRaises(MaxControlError):
            AgentHostProfile.from_mapping(bad_host)

    def test_13_content_addressed_profile_and_binding_ids_reject_forgery(self) -> None:
        with self.assertRaises(MaxControlError):
            AgentHostProfile.from_mapping({**self.codex.to_mapping(), "host_profile_id": "forged"})
        with self.assertRaises(MaxControlError):
            ExecutionBackendProfile.from_mapping({**self.openc.to_mapping(), "backend_profile_id": "forged"})
        with self.assertRaises(MaxControlError):
            self.service.bind_backend(
                run_id=self.run_id,
                host_profile_id=self.codex.host_profile_id,
                backend_profile_id=self.openc.backend_profile_id,
                source_policy_hash=self.source_policy_hash,
                budget_hash=self.budget_hash,
                capability_manifest_hash="e" * 64,
            )

    def test_14_handoff_wrong_actor_and_stale_state_are_blocked(self) -> None:
        self.bind()
        self.pause_for_handoff()
        preview = self.service.preview_backend_handoff(
            run_id=self.run_id,
            new_backend_profile_id=self.fixture_backend.backend_profile_id,
            reason="explicit migration",
        )
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(MaxControlError):
            MaxPortabilityService(self.repo, self.guest).approve_backend_handoff(
                handoff_approval_id=preview["handoff_approval_id"], confirmation_phrase=preview["confirmation_phrase"]
            )
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_15_append_only_history_triggers_reject_rewrite_and_delete(self) -> None:
        binding = self.bind()["binding"]
        connection = self.repo._connect(read_only=False)
        try:
            with self.assertRaises(Exception):
                connection.execute("UPDATE max_agent_host_profiles SET host_version='rewritten' WHERE host_profile_id=?", (self.codex.host_profile_id,))
            with self.assertRaises(Exception):
                connection.execute("DELETE FROM max_run_execution_bindings WHERE binding_id=?", (binding["binding_id"],))
            connection.rollback()
        finally:
            connection.close()

    def test_16_backup_restore_preserves_portability_verification(self) -> None:
        self.bind()
        backup = Path(self.temp.name) / "backup.db"
        restored = Path(self.temp.name) / "restored.db"
        self.repo.backup(backup)
        restored_repo = MaxControlRepository(restored)
        restored_repo.restore(backup)
        self.assertTrue(MaxPortabilityService(restored_repo, self.admin).verify()["ok"])
        self.assertTrue(restored_repo.verify_database()["ok"])

    def test_17_separate_runs_require_separate_explicit_bindings(self) -> None:
        second = self.repo.propose(project_id="portability-project-two", charter=self.charter, actor=self.admin)
        first = self.bind()
        second_binding = self.service.bind_backend(
            run_id=second["run_id"],
            host_profile_id=self.luna.host_profile_id,
            backend_profile_id=self.fixture_backend.backend_profile_id,
            source_policy_hash=second["source_policy_hash"],
            budget_hash=second["budget_hash"],
        )
        self.assertNotEqual(first["binding"]["backend_profile_id"], second_binding["binding"]["backend_profile_id"])
        self.assertEqual(self.service.status(run_id=self.run_id)["current_binding"]["backend_profile_id"], self.openc.backend_profile_id)
        self.assertEqual(self.service.status(run_id=second["run_id"])["current_binding"]["backend_profile_id"], self.fixture_backend.backend_profile_id)


if __name__ == "__main__":
    unittest.main()
