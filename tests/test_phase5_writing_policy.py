from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from research_kb.config import Limits, Settings
from research_kb.db import SCHEMA_VERSION, connect, migrate
from research_kb.ingest import ingest_file
from research_kb.mcp_server import _REQUIRED_TABLES, _REQUIRED_TRIGGERS
from research_kb.policy import Actor, PolicyError
from research_kb.service import ResearchService
from research_kb.writing_policy import (
    resolve_submission_policy,
    resolve_writing_policy,
    validate_writing_audit_summary,
)


class Phase5WritingPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(dir=os.environ.get("RESEARCH_KB_TEST_TMP")))
        self.settings = Settings(
            config_path=self.root / "config.toml",
            root=self.root,
            database=self.root / "data" / "research.db",
            corpus_roots=(self.root / "corpus",),
            workspace=self.root / "workspace",
            limits=Limits(max_return_chars=12000),
        )
        self.settings.config_path.write_text(
            '[paths]\ndatabase = "data/research.db"\ncorpus_roots = ["corpus"]\nworkspace = "workspace"\n',
            encoding="utf-8",
        )
        migrate(self.settings)
        self.admin_actor = Actor("admin", "admin-session", "user", "admin", "phase5")
        self.admin = ResearchService(self.settings, self.admin_actor)
        self.corpus = self.settings.corpus_roots[0]
        self.corpus.mkdir(parents=True, exist_ok=True)
        self.source = self.corpus / "source.txt"
        self.source.write_text("Source passage about writing policy.", encoding="utf-8")
        self.ingested = ingest_file(
            self.settings, self.admin_actor, self.source, project_id="default",
            title="Explicit source", creator="Fixture", source_type="article",
            language="en", source_date="2026", source_version="v1",
            source_name="fixture",
        )
        with connect(self.settings, read_only=True) as connection:
            self.passage_id = connection.execute(
                "SELECT passage_id FROM passages WHERE document_id = ? ORDER BY ordinal LIMIT 1",
                (self.ingested["document_id"],),
            ).fetchone()[0]
        self.agent = ResearchService(
            self.settings, Actor("agent", "agent-session", "agent", "researcher", "phase5")
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _report(self, **extra: Any) -> tuple[dict, str]:
        checked = self.agent.verify_quote(
            project_id="default",
            passage_id=self.passage_id,
            quote="Source passage about writing policy.",
        )
        evidence = self.agent.submit_verified_evidence(
            project_id="default",
            verification_token=checked["verification_token"],
        )
        result = self.agent.submit_research_report(
            project_id="default",
            question="How is writing policy preserved?",
            summary="A candidate report with writing policy metadata.",
            claims=[
                {
                    "claim_id": "C001",
                    "text": "The quote occurs in the source.",
                    "epistemic_status": "source_fact",
                    "verified_evidence_ids": [evidence["verified_evidence_id"]],
                }
            ],
            strongest_objection="The corpus is small.",
            alternative_explanations=["The match may be incidental."],
            unresolved_questions=["Would more sources change the result?"],
            evidence_limits=["One local source."],
            next_steps=["Ingest another source."],
            **extra,
        )
        return result, evidence["verified_evidence_id"]

    def test_schema_version_and_new_columns(self) -> None:
        self.assertEqual(SCHEMA_VERSION, 5)
        with connect(self.settings, read_only=True) as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(report_manifest)")
            }
        for column in (
            "deliverable_layer",
            "artifact_profile",
            "writing_policy_id",
            "writing_policy_version",
            "writing_policy_snapshot_json",
            "compression_review_status",
            "writing_audit_summary_json",
        ):
            self.assertIn(column, columns)
        self.assertIn("report_manifest", _REQUIRED_TABLES)
        for trigger in (
            "report_manifest_no_update",
            "report_manifest_no_delete",
            "report_manifest_target_exists",
        ):
            self.assertIn(trigger, _REQUIRED_TRIGGERS)

    def test_migration_is_idempotent_and_legacy_submission_reads_back(self) -> None:
        migrate(self.settings)
        migrate(self.settings)
        result, _ = self._report()
        self.assertIsNone(result["deliverable_layer"])
        self.assertIsNone(result["artifact_profile"])
        self.assertIsNone(result["writing_policy_id"])
        self.assertIsNone(result["writing_policy_version"])
        self.assertIsNone(result["writing_policy_snapshot"])
        self.assertIsNone(result["compression_review_status"])
        self.assertIsNone(result["writing_audit_summary"])
        manifest = self.agent.get_report_manifest(
            project_id="default", item_id=result["item_id"]
        )
        for key in (
            "deliverable_layer",
            "artifact_profile",
            "writing_policy_id",
            "writing_policy_version",
            "writing_policy_snapshot",
            "compression_review_status",
            "writing_audit_summary",
        ):
            self.assertIsNone(manifest[key])
        with connect(self.settings, read_only=True) as connection:
            row = connection.execute(
                "SELECT * FROM report_manifest WHERE report_manifest_id = ?",
                (result["report_manifest_id"],),
            ).fetchone()
        self.assertIsNone(row["deliverable_layer"])
        self.assertIsNone(row["writing_policy_snapshot_json"])

    def test_policy_fields_stored_on_submission(self) -> None:
        snapshot = resolve_writing_policy(profile="academic_paper")
        summary = {
            "errors": 0,
            "warnings": 1,
            "review_items": 2,
            "approval_blockers": 0,
        }
        result, _ = self._report(
            deliverable_layer="A",
            artifact_profile="academic_paper",
            writing_policy_id=snapshot["policy_id"],
            writing_policy_version=snapshot["policy_version"],
            writing_policy_snapshot=snapshot,
            compression_review_status="passed",
            writing_audit_summary=summary,
        )
        self.assertEqual(result["deliverable_layer"], "A")
        self.assertEqual(result["artifact_profile"], "academic_paper")
        self.assertEqual(result["writing_policy_id"], snapshot["policy_id"])
        self.assertEqual(result["writing_policy_version"], snapshot["policy_version"])
        self.assertEqual(result["writing_policy_snapshot"]["profile"], "academic_paper")
        self.assertEqual(result["compression_review_status"], "passed")
        self.assertEqual(result["writing_audit_summary"]["review_items"], 2)
        manifest = self.agent.get_report_manifest(
            project_id="default", item_id=result["item_id"]
        )
        self.assertEqual(manifest["writing_policy_version"], snapshot["policy_version"])
        self.assertEqual(manifest["writing_policy_snapshot"]["budget"]["max_chars"], 55000)
        self.assertEqual(manifest["compression_review_status"], "passed")
        self.assertEqual(manifest["writing_audit_summary"]["warnings"], 1)

    def test_invalid_policy_arguments_rejected(self) -> None:
        with self.assertRaises(PolicyError):
            self._report(deliverable_layer="D")
        with self.assertRaises(PolicyError):
            self._report(artifact_profile="not_a_profile")
        with self.assertRaises(PolicyError):
            self._report(compression_review_status="bogus")
        with self.assertRaises(PolicyError):
            self._report(writing_audit_summary={"errors": -1})
        snapshot = resolve_writing_policy(profile="academic_paper")
        with self.assertRaises(PolicyError):
            self._report(
                deliverable_layer="A",
                artifact_profile="academic_paper",
                writing_policy_snapshot=snapshot,
                writing_policy_id="other-policy",
            )

    def test_project_config_override_is_snapshotted(self) -> None:
        with connect(self.settings) as connection:
            connection.execute(
                "UPDATE projects SET config_json = ? WHERE project_id = 'default'",
                (json.dumps({"writing_policy": {"budget": {"max_chars": 60000}}}),),
            )
        resolved = resolve_submission_policy(
            deliverable_layer="A",
            project_config={"writing_policy": {"budget": {"max_chars": 60000}}},
        )
        self.assertEqual(resolved["snapshot"]["budget"]["max_chars"], 60000)
        result, _ = self._report(deliverable_layer="A")
        manifest = self.agent.get_report_manifest(
            project_id="default", item_id=result["item_id"]
        )
        self.assertEqual(manifest["writing_policy_snapshot"]["budget"]["max_chars"], 60000)

    def test_audit_summary_validation_contract(self) -> None:
        clean = validate_writing_audit_summary(
            {"errors": 0, "warnings": 2, "review_items": 1, "approval_blockers": 0}
        )
        self.assertEqual(clean["warnings"], 2)
        self.assertEqual(set(clean), {"errors", "warnings", "review_items", "approval_blockers"})


if __name__ == "__main__":
    unittest.main()
