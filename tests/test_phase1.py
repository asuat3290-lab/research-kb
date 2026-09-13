from __future__ import annotations

import io
import json
import os
import sqlite3
from dataclasses import replace
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from research_kb.admin import AdminService
from research_kb.cli import main as cli_main
from research_kb.config import Limits, Settings
from research_kb.db import SCHEMA_VERSION, connect, migrate, migration_paths
from research_kb.ingest import extract_sections, ingest_file, ingest_manifest
from research_kb.policy import Actor, PolicyError
from research_kb.service import ResearchService


class Phase1Tests(unittest.TestCase):
    def setUp(self) -> None:
        scratch_root = os.environ.get("RESEARCH_KB_TEST_TMP")
        self.temporary = tempfile.TemporaryDirectory(dir=scratch_root)
        self.root = Path(self.temporary.name)
        self.settings = Settings(
            config_path=self.root / "config.toml",
            root=self.root,
            database=self.root / "data" / "research.db",
            corpus_roots=(self.root / "corpus",),
            workspace=self.root / "workspace",
            limits=Limits(),
        )
        migrate(self.settings)
        self.admin_actor = Actor("admin", "admin-session", "user", "admin", "unittest")
        self.agent_actor = Actor("agent", "agent-session", "agent", "researcher", "unittest", "test-model")
        self.admin = AdminService(self.settings, self.admin_actor)
        self.agent = ResearchService(self.settings, self.agent_actor)
        self.admin.create_project(project_id="project-two", title="Second", objective="Isolation")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, name: str, text: str) -> Path:
        path = self.settings.corpus_roots[0] / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _ingest(self, project_id: str = "default", name: str = "source.txt", text: str | None = None) -> dict:
        path = self._write(
            name,
            text or "中文检索测试。这个长中文短语用于验证本地研究知识库。Machine-learning models support multilingual retrieval.",
        )
        return ingest_file(
            self.settings,
            self.admin_actor,
            path,
            project_id=project_id,
            title="Explicit title",
            creator="Explicit creator",
            source_type="article",
            language="zh-en",
            source_date="2026-01-01",
            source_version="v1",
            source_name="Explicit source name",
            reliability_status="unverified",
        )

    def test_migrations_are_ordered_idempotent_and_integrity_is_clean(self) -> None:
        self.assertEqual(SCHEMA_VERSION, migration_paths()[-1][0])
        with connect(self.settings, read_only=True) as connection:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(
                [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")],
                [version for version, _ in migration_paths()],
            )
            token_columns = {row[1] for row in connection.execute("PRAGMA table_info(verification_tokens)")}
            evidence_columns = {row[1] for row in connection.execute("PRAGMA table_info(verified_evidence)")}
        self.assertTrue({"project_id", "source_version"} <= token_columns)
        self.assertIn("source_version", evidence_columns)
        migrate(self.settings)
        with connect(self.settings, read_only=True) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], len(migration_paths()))
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")

    def test_upgrade_from_schema_one_applies_phase1_once(self) -> None:
        legacy_dir = tempfile.TemporaryDirectory(dir=self.root)
        try:
            legacy_root = Path(legacy_dir.name)
            legacy_settings = Settings(
                config_path=legacy_root / "config.toml",
                root=legacy_root,
                database=legacy_root / "data" / "research.db",
                corpus_roots=(legacy_root / "corpus",),
                workspace=legacy_root / "workspace",
                limits=Limits(),
            )
            with connect(legacy_settings) as connection:
                sql = (Path(__file__).parents[1] / "src" / "research_kb" / "migrations" / "001_initial.sql").read_text(encoding="utf-8")
                connection.executescript(sql)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (1, datetime('now'))"
                )
                connection.commit()
            migrate(legacy_settings)
            migrate(legacy_settings)
            with connect(legacy_settings, read_only=True) as connection:
                self.assertEqual(
                    [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")],
                    [version for version, _ in migration_paths()],
                )
                self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        finally:
            legacy_dir.cleanup()

    def test_token_binding_actor_project_expiry_source_version_and_replay(self) -> None:
        ingested = self._ingest()
        other = self._ingest(project_id="default", name="other.txt", text="Different source passage for binding tests.")
        self._ingest(project_id="project-two", name="source.txt")
        checked = self.agent.verify_quote(
            project_id="default",
            passage_id=self._passage_id(ingested["document_id"]),
            quote="Machine-learning models support multilingual retrieval",
        )
        with connect(self.settings, read_only=True) as connection:
            row = connection.execute(
                "SELECT project_id, source_version, document_hash, passage_id, quote_hash, issued_to FROM verification_tokens"
            ).fetchone()
        self.assertEqual(row["project_id"], "default")
        self.assertEqual(row["source_version"], "v1")
        self.assertEqual(row["passage_id"], checked["passage_id"])
        self.assertEqual(row["issued_to"], "agent")
        with self.assertRaises(sqlite3.IntegrityError):
            with connect(self.settings) as connection:
                connection.execute(
                    "UPDATE verification_tokens SET passage_id = ? WHERE token_hash = ?",
                    (self._passage_id(other["document_id"]), self._token_hash(checked["verification_token"])),
                )
                connection.commit()

        other_actor = ResearchService(
            self.settings,
            Actor("other", "other-session", "agent", "researcher", "unittest"),
        )
        with self.assertRaises(PolicyError):
            other_actor.submit_verified_evidence(
                project_id="default", verification_token=checked["verification_token"]
            )
        with self.assertRaises(PolicyError):
            self.agent.submit_verified_evidence(
                project_id="project-two", verification_token=checked["verification_token"]
            )

        short_settings = replace(self.settings, limits=Limits(verification_token_ttl_seconds=0))
        expired = ResearchService(short_settings, self.agent_actor).verify_quote(
            project_id="default",
            passage_id=checked["passage_id"],
            quote="Machine-learning models support multilingual retrieval",
        )
        with self.assertRaises(PolicyError):
            self.agent.submit_verified_evidence(
                project_id="default", verification_token=expired["verification_token"]
            )

        changed = self.agent.verify_quote(
            project_id="default",
            passage_id=checked["passage_id"],
            quote="Machine-learning models support multilingual retrieval",
        )
        self.admin.metadata_update(
            project_id="default",
            document_id=ingested["document_id"],
            updates={"source_version": "v2"},
            reason="source version correction",
        )
        with self.assertRaises(PolicyError):
            self.agent.submit_verified_evidence(
                project_id="default", verification_token=changed["verification_token"]
            )

        valid = self.agent.verify_quote(
            project_id="default",
            passage_id=checked["passage_id"],
            quote="Machine-learning models support multilingual retrieval",
        )
        evidence = self.agent.submit_verified_evidence(
            project_id="default", verification_token=valid["verification_token"]
        )
        self.assertEqual(evidence["status"], "candidate")
        with self.assertRaises(PolicyError):
            self.agent.submit_verified_evidence(
                project_id="default", verification_token=valid["verification_token"]
            )

    def test_evidence_candidate_acceptance_and_approval_targets(self) -> None:
        ingested = self._ingest()
        passage_id = self._passage_id(ingested["document_id"])
        checked = self.agent.verify_quote(
            project_id="default", passage_id=passage_id,
            quote="Machine-learning models support multilingual retrieval",
        )
        evidence = self.agent.submit_verified_evidence(
            project_id="default", verification_token=checked["verification_token"]
        )
        request = self.agent.request_user_approval(
            project_id="default",
            target_type="evidence",
            verified_evidence_id=evidence["verified_evidence_id"],
            rationale="Accept source-consistent evidence",
        )
        decision = self.admin.decide_approval(request_id=request["request_id"], approve=True, note="Reviewed")
        self.assertEqual(decision["target_type"], "evidence")
        with connect(self.settings, read_only=True) as connection:
            status = connection.execute(
                """
                SELECT status FROM evidence_status_history
                WHERE verified_evidence_id = ? ORDER BY status_event_id DESC LIMIT 1
                """,
                (evidence["verified_evidence_id"],),
            ).fetchone()[0]
        self.assertEqual(status, "accepted")

        with self.assertRaises(sqlite3.IntegrityError):
            with connect(self.settings) as connection:
                connection.execute(
                    """
                    INSERT INTO approval_requests_v2(
                        request_id, project_id, target_type, item_id, verified_evidence_id,
                        requested_by, requested_status, status, rationale, created_at
                    ) VALUES ('dangling', 'default', 'evidence', NULL, 'missing',
                              'agent', 'accepted', 'pending', '', datetime('now'))
                    """
                )
                connection.commit()

    def test_metadata_audit_and_active_project_guards(self) -> None:
        ingested = self._ingest()
        before_hash = self.agent.get_document_metadata(
            project_id="default", document_id=ingested["document_id"]
        )["content_hash"]
        result = self.admin.metadata_update(
            project_id="default",
            document_id=ingested["document_id"],
            updates={"title": "Corrected title", "reliability_status": "reviewed"},
            reason="human source review",
        )
        self.assertTrue(result["changed"])
        with connect(self.settings, read_only=True) as connection:
            row = connection.execute(
                "SELECT old_values_json, new_values_json, reason, actor_id, created_at FROM source_metadata_audit WHERE document_id = ?",
                (ingested["document_id"],),
            ).fetchone()
        after_hash = self.agent.get_document_metadata(
            project_id="default", document_id=ingested["document_id"]
        )["content_hash"]
        self.assertEqual(before_hash, after_hash)
        self.assertEqual(json.loads(row["old_values_json"])["title"], "Explicit title")
        self.assertEqual(json.loads(row["new_values_json"])["title"], "Corrected title")
        self.assertEqual(row["reason"], "human source review")
        self.assertEqual(row["actor_id"], "admin")

        self.admin.archive_project(project_id="project-two")
        with self.assertRaises(PolicyError):
            self.agent.get_research_context(project_id="project-two")
        with self.assertRaises(PolicyError):
            self.agent.get_search_history(project_id="project-two")
        with self.assertRaises(PolicyError):
            self.agent.search_corpus(project_id="project-two", query="中文")

    def test_chinese_mixed_search_original_excerpt_isolation_and_rebuild(self) -> None:
        first = self._ingest()
        second = self._ingest(project_id="project-two", name="other.txt", text="中文检索测试。另一个项目的同词内容。")
        first_result = self.agent.search_corpus(project_id="default", query="中文")
        self.assertEqual(first_result["count"], 1)
        self.assertEqual(first_result["results"][0]["document_id"], first["document_id"])
        self.assertIn("中文检索测试", first_result["results"][0]["excerpt"])
        self.assertEqual(self.agent.search_corpus(project_id="default", query="中文检索测试")["count"], 1)
        self.assertEqual(self.agent.search_corpus(project_id="default", query="长中文短语")["count"], 1)
        mixed = self.agent.search_corpus(project_id="default", query="machine-learning")
        self.assertEqual(mixed["count"], 1)
        self.assertIn("Machine-learning", mixed["results"][0]["excerpt"])
        self.assertEqual(self.agent.search_corpus(project_id="default", query="multilingual retrieval")["count"], 1)
        self.assertNotEqual(first["document_id"], second["document_id"])
        self.assertEqual(self.agent.search_corpus(project_id="default", query="另一个项目")["count"], 0)
        rebuild = self.admin.reindex()
        self.assertEqual(rebuild["passages"], rebuild["indexed"])
        self.assertEqual(self.agent.search_corpus(project_id="default", query="中文")["count"], 1)

    def test_manifest_dry_run_execute_unknown_defaults_and_escape(self) -> None:
        source = self._write("manifest-source.md", "manifest 中文内容 and machine-learning")
        manifest = self.root / "manifest.json"
        manifest.write_text(
            json.dumps({"files": [{
                "path": source.name,
                "title": "Manifest title",
                "creator": "Manifest creator",
                "source_type": "report",
                "language": "zh-en",
                "source_date": "2026-02-02",
                "source_version": "edition-1",
                "source_name": "Manifest source",
                "reliability_status": "unverified",
            }]}, ensure_ascii=False),
            encoding="utf-8",
        )
        dry = ingest_manifest(self.settings, self.admin_actor, manifest, project_id="default", dry_run=True)
        self.assertTrue(dry["dry_run"])
        self.assertEqual(dry["files"][0]["title"], "Manifest title")
        with connect(self.settings, read_only=True) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0], 0)
        executed = ingest_manifest(self.settings, self.admin_actor, manifest, project_id="default")
        metadata = self.agent.get_document_metadata(project_id="default", document_id=executed["files"][0]["document_id"])
        self.assertEqual(metadata["title"], "Manifest title")
        self.assertEqual(metadata["source_name"], "Manifest source")
        duplicate = ingest_manifest(self.settings, self.admin_actor, manifest, project_id="default")
        self.assertTrue(duplicate["files"][0]["deduplicated"])

        missing = self._write("missing-fields.txt", "missing metadata")
        missing_manifest = self.root / "missing.json"
        missing_manifest.write_text(json.dumps({"files": [{"path": missing.name}]}), encoding="utf-8")
        missing_result = ingest_manifest(self.settings, self.admin_actor, missing_manifest, project_id="default")
        missing_meta = self.agent.get_document_metadata(project_id="default", document_id=missing_result["files"][0]["document_id"])
        self.assertEqual(missing_meta["title"], "unknown")
        self.assertEqual(missing_meta["source_name"], "unknown")
        self.assertEqual(missing_meta["reliability_status"], "unverified")

        empty = self._write("empty.txt", "")
        empty_manifest = self.root / "empty.json"
        empty_manifest.write_text(json.dumps({"files": [{"path": empty.name}]}), encoding="utf-8")
        with self.assertRaises(PolicyError):
            ingest_manifest(self.settings, self.admin_actor, empty_manifest, project_id="default", dry_run=True)

        corrupt = self._write("corrupt.docx", "not a zip")
        corrupt_manifest = self.root / "corrupt.json"
        corrupt_manifest.write_text(json.dumps({"files": [{"path": corrupt.name}]}), encoding="utf-8")
        with self.assertRaises(PolicyError):
            ingest_manifest(self.settings, self.admin_actor, corrupt_manifest, project_id="default", dry_run=True)

        outside = self.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        escape_manifest = self.root / "escape.json"
        escape_manifest.write_text(json.dumps({"files": [{"path": str(outside)}]}), encoding="utf-8")
        with self.assertRaises(PolicyError):
            ingest_manifest(self.settings, self.admin_actor, escape_manifest, project_id="default", dry_run=True)
        link = self.settings.corpus_roots[0] / "outside-link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pass
        else:
            link_manifest = self.root / "link.json"
            link_manifest.write_text(json.dumps({"files": [{"path": link.name}]}), encoding="utf-8")
            with self.assertRaises(PolicyError):
                ingest_manifest(self.settings, self.admin_actor, link_manifest, project_id="default", dry_run=True)

    def test_extract_supported_container_formats(self) -> None:
        html_path = self._write("sample.html", "<html><body>HTML 中文</body></html>")
        self.assertIn("HTML 中文", extract_sections(html_path)[0][1])
        docx_path = self.settings.corpus_roots[0] / "sample.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr(
                "word/document.xml",
                "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body><w:p><w:r><w:t>DOCX text</w:t></w:r></w:p></w:body></w:document>",
            )
        self.assertIn("DOCX text", extract_sections(docx_path)[0][1])
        epub_path = self.settings.corpus_roots[0] / "sample.epub"
        with zipfile.ZipFile(epub_path, "w") as archive:
            archive.writestr("chapter.xhtml", "<html><body>EPUB text</body></html>")
        self.assertIn("EPUB text", extract_sections(epub_path)[0][1])

    def test_cli_all_phase1_commands(self) -> None:
        config = self.root / "config.toml"
        root_text = self.root.as_posix()
        config.write_text(
            f"[paths]\ndatabase = \"{root_text}/cli-data/research.db\"\ncorpus_roots = [\"{root_text}/cli-corpus\"]\nworkspace = \"{root_text}/cli-workspace\"\n\n[limits]\nmax_top_k = 20\nmax_context_passages = 3\nmax_query_chars = 1000\nmax_return_chars = 16000\nmax_searches_per_session = 100\nmax_writes_per_session = 50\nverification_token_ttl_seconds = 900\n\n[retrieval]\ndefault_mode = \"lexical\"\nsemantic_enabled = false\n",
            encoding="utf-8",
        )
        cli_corpus = self.root / "cli-corpus"
        cli_corpus.mkdir()
        cli_source = cli_corpus / "cli.txt"
        cli_source.write_text("CLI 中文内容", encoding="utf-8")
        manifest = self.root / "cli-manifest.json"
        manifest.write_text(json.dumps({"files": [{"path": "cli.txt", "title": "CLI title", "source_type": "note"}]}), encoding="utf-8")

        def run_cli(*args: str) -> dict:
            output = io.StringIO()
            with patch.object(sys, "argv", ["research-kb", "--config", str(config), *args]), redirect_stdout(output):
                cli_main()
            return json.loads(output.getvalue())

        self.assertTrue(run_cli("init")["ok"])
        self.assertEqual(run_cli("project", "create", "--project-id", "cli-project", "--title", "CLI", "--objective", "Test")["status"], "active")
        self.assertGreaterEqual(len(run_cli("project", "list")["projects"]), 2)
        dry = run_cli("ingest", "--project", "cli-project", "--manifest", str(manifest), "--dry-run")
        self.assertTrue(dry["dry_run"])
        executed = run_cli("ingest", "--project", "cli-project", "--manifest", str(manifest))
        document_id = executed["files"][0]["document_id"]
        self.assertEqual(run_cli("metadata", "show", "--project", "cli-project", "--document", document_id)["title"], "CLI title")
        self.assertTrue(run_cli("metadata", "update", "--project", "cli-project", "--document", document_id, "--reason", "test correction", "--set", "title=CLI corrected")["changed"])
        self.assertEqual(run_cli("approval", "list")["approvals"], [])
        self.assertEqual(run_cli("reindex")["passages"], 1)
        self.assertEqual(run_cli("status")["integrity"], ["ok"])
        backup = run_cli("backup", "--output", str(self.root / "backup.db"))
        self.assertEqual(backup["quick_check"], "ok")
        self.assertTrue(Path(backup["backup"]).exists())

    def _passage_id(self, document_id: str) -> str:
        with connect(self.settings, read_only=True) as connection:
            return connection.execute(
                "SELECT passage_id FROM passages WHERE document_id = ? ORDER BY ordinal LIMIT 1",
                (document_id,),
            ).fetchone()[0]

    @staticmethod
    def _token_hash(value: str) -> str:
        import hashlib
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    unittest.main()