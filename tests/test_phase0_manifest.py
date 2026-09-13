from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from research_kb.admin import AdminService
from research_kb.catalog import CatalogScanner
from research_kb.config import Limits, Settings
from research_kb.db import SCHEMA_VERSION, connect, migrate
from research_kb.ingest import ingest_file
from research_kb.mcp_server import (
    _REQUIRED_TABLES, _REQUIRED_TRIGGERS, _readiness_check,
)
from research_kb.policy import Actor
from research_kb.service import ResearchService


class Phase0CatalogReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "materials"
        self.output = Path(self.temp.name) / "catalog"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, relative: str, content: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def _scan(self) -> dict:
        return CatalogScanner(
            [("materials", self.root)],
            self.output,
            candidate_limit=20,
            checkpoint_interval=3,
        ).scan()

    def _records(self) -> list[dict]:
        return [
            json.loads(line)
            for line in (self.output / "catalog.jsonl").read_text(encoding="utf-8").splitlines()
        ]

    def test_plain_markdown_has_ingest_ready_only(self) -> None:
        self._write("ordinary.md", "ordinary source text")
        summary = self._scan()
        record = next(item for item in self._records() if item["relative_path"] == "ordinary.md")
        self.assertTrue(record["readiness"]["ingest_ready"])
        self.assertFalse(record["readiness"]["search_ready"])
        self.assertFalse(record["readiness"]["citation_ready"])
        self.assertFalse(record["readiness"]["evidence_ready"])
        self.assertFalse(record["readiness"]["report_ready"])
        self.assertEqual(summary["readiness_counts"]["ingest_ready"], 1)
        self.assertEqual(summary["ingest_ready_count"], 1)
        self.assertEqual(summary["citation_ready_count"], 0)

    def test_epub_with_embedded_bibliography_is_citation_ready(self) -> None:
        self._write("embedded-book.epub", self._epub_bytes())
        summary = self._scan()
        record = next(item for item in self._records() if item["relative_path"] == "embedded-book.epub")
        self.assertTrue(record["readiness"]["ingest_ready"])
        self.assertTrue(record["readiness"]["citation_ready"])
        self.assertFalse(record["readiness"]["search_ready"])
        self.assertFalse(record["readiness"]["evidence_ready"])
        self.assertFalse(record["readiness"]["report_ready"])
        self.assertEqual(record["candidate_kind"], "ready")
        self.assertGreaterEqual(summary["citation_ready_count"], 1)
        self.assertEqual(
            set(summary["readiness_counts"]),
            {"ingest_ready", "search_ready", "citation_ready", "evidence_ready", "report_ready"},
        )
        review = (self.output / "technical-review.jsonl").read_text(encoding="utf-8")
        self.assertIn('"readiness"', review)

    @staticmethod
    def _epub_bytes() -> bytes:
        import io

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("mimetype", "application/epub+zip")
            archive.writestr(
                "META-INF/container.xml",
                "<container version='1.0' xmlns='urn:oasis:names:tc:opendocument:xmlns:container'>"
                "<rootfiles><rootfile full-path='OEBPS/content.opf' media-type='application/oebps-package+xml'/></rootfiles></container>",
            )
            archive.writestr(
                "OEBPS/content.opf",
                "<package xmlns='http://www.idpf.org/2007/opf' version='3.0' "
                "xmlns:dc='http://purl.org/dc/elements/1.1/'>"
                "<metadata><dc:title>Embedded Book</dc:title><dc:creator>Test Author</dc:creator></metadata>"
                "<manifest><item id='c1' href='chapter.xhtml' media-type='application/xhtml+xml'/></manifest>"
                "<spine><itemref idref='c1'/></spine></package>",
            )
            archive.writestr(
                "OEBPS/chapter.xhtml",
                "<html xmlns='http://www.w3.org/1999/xhtml'><body><p>Readable embedded content.</p></body></html>",
            )
        return buffer.getvalue()


class Phase0ReportManifestTests(unittest.TestCase):
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
        self.admin_actor = Actor("admin", "admin-session", "user", "admin", "phase0")
        self.admin = AdminService(self.settings, self.admin_actor)
        self.admin.create_project(project_id="project-two", title="Second", objective="Isolation")
        self.corpus = self.settings.corpus_roots[0]
        self.corpus.mkdir(parents=True, exist_ok=True)
        self.source = self.corpus / "source.txt"
        self.source.write_text("Source passage about manifest immutability.", encoding="utf-8")
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
            self.settings, Actor("agent", "agent-session", "agent", "researcher", "phase0")
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _verified_evidence(self) -> str:
        checked = self.agent.verify_quote(
            project_id="default", passage_id=self.passage_id, quote="Source passage about"
        )
        evidence = self.agent.submit_verified_evidence(
            project_id="default", verification_token=checked["verification_token"]
        )
        return evidence["verified_evidence_id"]

    def _leads(self) -> list[dict]:
        return [
            {
                "idea": f"Lead {index}",
                "source_bridges": ["source A", "source B"],
                "supporting_passage_ids": [self.passage_id],
                "why_not_literature_summary": "It proposes a cross-source mechanism.",
                "possible_counterevidence": ["A competing source"],
                "missing_evidence": ["A comparative case"],
                "next_search": ["Search for a boundary condition"],
                "epistemic_status": "exploratory_hypothesis",
                "confidence": "low",
            }
            for index in range(3)
        ]

    def _report(self) -> tuple[dict, str]:
        evidence_id = self._verified_evidence()
        result = self.agent.submit_research_report(
            project_id="default",
            question="How is manifest identity preserved?",
            summary="A candidate report with one manifest row.",
            claims=[
                {
                    "claim_id": "C001",
                    "text": "The quote occurs in the source.",
                    "epistemic_status": "source_fact",
                    "verified_evidence_ids": [evidence_id],
                },
                {
                    "claim_id": "C002",
                    "text": "The manifest is append-only.",
                    "epistemic_status": "exploratory_hypothesis",
                    "verified_evidence_ids": [],
                },
            ],
            strongest_objection="The corpus is small.",
            alternative_explanations=["The match may be incidental."],
            unresolved_questions=["Would more sources change the result?"],
            evidence_limits=["One local source."],
            next_steps=["Ingest another source."],
            research_leads=self._leads(),
        )
        return result, evidence_id

    def test_report_submission_writes_manifest_in_same_transaction(self) -> None:
        result, evidence_id = self._report()
        self.assertIn("report_manifest_id", result)
        self.assertEqual(result["report_revision_id"], result["version_id"])
        manifest = self.agent.get_report_manifest(project_id="default", item_id=result["item_id"])
        self.assertEqual(manifest["report_manifest_id"], result["report_manifest_id"])
        self.assertEqual(manifest["report_version_id"], result["version_id"])
        self.assertEqual(manifest["protocol_project_id"], "default")
        self.assertEqual(manifest["claim_revision_ids"], ["C001", "C002"])
        self.assertEqual(manifest["evidence_revision_ids"], [evidence_id])
        self.assertEqual(manifest["passage_revision_ids"], [self.passage_id])
        for key in (
            "verification_event_ids", "approval_event_ids", "source_snapshot_ids",
            "project_export_ids", "cross_project_link_ids",
        ):
            self.assertEqual(manifest[key], [])
        self.assertIsNone(manifest["constraint_revision_id"])
        self.assertIsNone(manifest["research_project_id"])
        self.assertEqual(manifest["created_by"], "agent")
        with connect(self.settings, read_only=True) as connection:
            row = connection.execute(
                "SELECT * FROM report_manifest WHERE report_manifest_id = ?",
                (result["report_manifest_id"],),
            ).fetchone()
        self.assertEqual(row["report_version_id"], result["version_id"])
        self.assertEqual(json.loads(row["claim_revision_ids_json"]), ["C001", "C002"])
        self.assertEqual(json.loads(row["evidence_revision_ids_json"]), [evidence_id])

    def test_context_records_expose_read_only_manifest_ids(self) -> None:
        result, _ = self._report()
        context = self.agent.get_research_context(project_id="default", detail="brief")
        item = next(item for item in context["items"] if item["item_id"] == result["item_id"])
        self.assertEqual(item["report_manifest_id"], result["report_manifest_id"])
        self.assertEqual(item["report_revision_id"], result["version_id"])
        with self.assertRaises(KeyError):
            self.agent.get_report_manifest(project_id="project-two", item_id=result["item_id"])

    def test_manifest_is_append_only_and_target_exists(self) -> None:
        result, _ = self._report()
        with connect(self.settings) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE report_manifest SET created_by = 'attacker' WHERE report_manifest_id = ?",
                    (result["report_manifest_id"],),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "DELETE FROM report_manifest WHERE report_manifest_id = ?",
                    (result["report_manifest_id"],),
                )
        note = self.agent.save_research_note(project_id="default", title="Note", body="Body")
        with connect(self.settings) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO report_manifest(
                        report_manifest_id, report_version_id, protocol_project_id,
                        claim_revision_ids_json, evidence_revision_ids_json,
                        passage_revision_ids_json, verification_event_ids_json,
                        approval_event_ids_json, source_snapshot_ids_json,
                        constraint_revision_id, research_project_id,
                        project_export_ids_json, cross_project_link_ids_json,
                        created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    """,
                    (
                        "rmf_bad_note", note["version_id"], "default",
                        "[]", "[]", "[]", "[]", "[]", "[]",
                        None, None, "[]", "[]", "agent",
                    ),
                )
        with connect(self.settings) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO report_manifest(
                        report_manifest_id, report_version_id, protocol_project_id,
                        claim_revision_ids_json, evidence_revision_ids_json,
                        passage_revision_ids_json, verification_event_ids_json,
                        approval_event_ids_json, source_snapshot_ids_json,
                        constraint_revision_id, research_project_id,
                        project_export_ids_json, cross_project_link_ids_json,
                        created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    """,
                    (
                        "rmf_bad_project", result["version_id"], "project-two",
                        "[]", "[]", "[]", "[]", "[]", "[]",
                        None, None, "[]", "[]", "agent",
                    ),
                )

    def test_migration_is_idempotent_and_mcp_readiness_requires_manifest(self) -> None:
        migrate(self.settings)
        migrate(self.settings)
        self.assertEqual(SCHEMA_VERSION, 5)
        self.assertIn("report_manifest", _REQUIRED_TABLES)
        for trigger in (
            "report_manifest_no_update",
            "report_manifest_no_delete",
            "report_manifest_target_exists",
        ):
            self.assertIn(trigger, _REQUIRED_TRIGGERS)
        _readiness_check(self.settings)
        with connect(self.settings, read_only=True) as connection:
            triggers = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                )
            }
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table')"
                )
            }
        self.assertIn("report_manifest", tables)
        self.assertTrue(
            {
                "report_manifest_no_update",
                "report_manifest_no_delete",
                "report_manifest_target_exists",
            }.issubset(triggers)
        )


if __name__ == "__main__":
    unittest.main()
