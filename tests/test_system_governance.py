from __future__ import annotations

import hashlib
import asyncio
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from research_kb.config import Settings
from research_kb.db import connect, migrate
from research_kb.doctor import SKILL_SCAN_MAX_DEPTH, run_doctor
from research_kb import __version__
from research_kb.system_manifest import (
    EXPECTED_MCP_TOOLS,
    ManifestError,
    load_manifest,
    redact_path,
    resolve_manifest_path,
    sha256_file,
)


BASE_MANIFEST = f"""
manifest_format_version = 1

[engine]
package = "research-kb"
version = "{__version__}"

[schema]
version = 5

[protocol]
name = "research-kb/v1"

[config]
path = "config.toml"

[components.database]
path = "data/research.db"
boundary = "runtime_root"
required = true

[components.corpus]
paths = ["corpus"]
boundary = "runtime_root"
required = true

[components.workspace]
path = "workspace"
boundary = "runtime_root"
required = true

[components.catalog]
path = "catalog"
boundary = "runtime_root"
required = false

[components.backup]
path = "workspace/backups"
boundary = "runtime_root"
required = false

[components.skills]
path = "workspace/.agents/skills"
boundary = "runtime_root"
required = false

[mcp]
server_name = "research-kb"
tools = [
  "search_corpus", "get_passage", "get_document_metadata", "get_research_context",
  "submit_hypothesis", "submit_objection", "save_research_note",
  "verify_quote_or_claim", "submit_verified_evidence", "get_search_history",
  "submit_research_report", "request_user_approval",
]

[project_registry]
projects = []

[skills]
items = []

[catalog]
lifecycle = ["cataloged", "reviewed", "ready", "ingested", "indexed", "available", "retired"]
summary_files = ["summary.json"]

[capabilities]
lexical = true
semantic = false
hybrid = false
local_model = false
remote_deployment = false
""".strip() + "\n"


class SystemGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "corpus").mkdir()
        (self.root / "workspace").mkdir()
        (self.root / "data").mkdir()
        self.config_path = self.root / "config.toml"
        self.config_path.write_text(
            """
[paths]
database = "data/research.db"
corpus_roots = ["corpus"]
workspace = "workspace"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        self.settings = Settings.load(self.config_path)
        migrate(self.settings)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(self, text: str = BASE_MANIFEST) -> Path:
        path = self.root / "system-manifest.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def _insert_item(
        self,
        item_id: str,
        *,
        kind: str = "note",
        payload: str = '{"schema":"legacy"}',
        project_id: str = "default",
        status: str = "candidate",
        supersedes_item_id: str | None = None,
    ) -> None:
        with connect(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO research_items(
                    item_id, project_id, kind, status, created_by,
                    supersedes_item_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'test', ?, '2026-08-08 00:00:00', '2026-08-08 00:00:00')
                """,
                (item_id, project_id, kind, status, supersedes_item_id),
            )
            connection.execute(
                """
                INSERT INTO research_item_versions(
                    version_id, item_id, version_no, payload_json,
                    content_hash, created_by, created_at
                ) VALUES (?, ?, 1, ?, 'test-hash', 'test', '2026-08-08 00:00:00')
                """,
                (f"{item_id}_v1", item_id, payload),
            )

    @staticmethod
    def _all_strings(value: object) -> list[str]:
        if isinstance(value, dict):
            return [item for key in value for item in [str(key), *SystemGovernanceTests._all_strings(value[key])]]
        if isinstance(value, (list, tuple)):
            return [item for child in value for item in SystemGovernanceTests._all_strings(child)]
        return [value] if isinstance(value, str) else []

    def test_valid_manifest_parses_and_normalizes(self) -> None:
        manifest = load_manifest(self._write_manifest())
        self.assertEqual(manifest.schema_version, 5)
        self.assertEqual(manifest.protocol, "research-kb/v1")
        self.assertEqual(len(manifest.mcp_tools), 12)
        self.assertEqual(manifest.to_dict()["components"]["database"]["path"], "data/research.db")

    def test_manifest_report_redacts_nested_paths_before_json_encoding(self) -> None:
        windows_path = r"C:\Users\Alice\secret\research.db"
        posix_path = "/Users/alice/secret/corpus"
        unc_path = r"\\server\share\secret\workspace"
        file_uri = "file:///Users/alice/secret/catalog.json"
        http_url = "https://example.invalid/catalog.json"
        manifest_text = f"""
manifest_format_version = 1
[engine]
package = "research-kb"
version = "0.1.0"
[schema]
version = 5
[protocol]
name = "research-kb/v1"
[config]
path = '{windows_path}'
[components.database]
path = '{windows_path}'
boundary = "runtime_root"
required = true
[components.corpus]
paths = ['{posix_path}']
boundary = "runtime_root"
required = true
[components.workspace]
path = '{unc_path}'
boundary = "runtime_root"
required = true
[components.catalog]
path = '{file_uri}'
boundary = "external"
required = false
[components.backup]
path = '{posix_path}'
boundary = "runtime_root"
required = false
[components.skills]
path = '{windows_path}'
boundary = "runtime_root"
required = false
[mcp]
server_name = "research-kb"
tools = [
  "search_corpus", "get_passage", "get_document_metadata", "get_research_context",
  "submit_hypothesis", "submit_objection", "save_research_note",
  "verify_quote_or_claim", "submit_verified_evidence", "get_search_history",
  "submit_research_report", "request_user_approval",
]
[project_registry]
projects = [{{ project_id = "default", workspace = '{unc_path}', corpus_scope = ['{posix_path}'], checkpoint_policy = "one-current" }}]
[skills]
items = [{{ name = "nested", path = '{file_uri}', version = "1" }}]
[catalog]
lifecycle = ["cataloged", "reviewed", "ready", "ingested", "indexed", "available", "retired"]
summary_files = ['{file_uri}', '{http_url}']
[capabilities]
lexical = true
semantic = false
hybrid = false
local_model = false
remote_deployment = false
""".strip() + "\n"
        manifest_path = self._write_manifest(manifest_text)
        report = run_doctor(self.config_path, manifest_path=manifest_path, show_paths=False)
        manifest = report["manifest"]
        self.assertEqual(report["redaction"]["paths"], "redacted")
        self.assertEqual(manifest["config"]["path"], "<local-path>")
        self.assertEqual(manifest["components"]["database"]["path"], "<local-path>")
        self.assertEqual(manifest["components"]["corpus"]["paths"], ["<local-path>"])
        self.assertEqual(manifest["components"]["workspace"]["path"], "<unc-path>")
        self.assertEqual(manifest["components"]["catalog"]["path"], "<file-uri>")
        self.assertEqual(manifest["project_registry"]["projects"][0]["workspace"], "<unc-path>")
        self.assertEqual(manifest["project_registry"]["projects"][0]["corpus_scope"], ["<local-path>"])
        self.assertEqual(manifest["skills"]["items"][0]["path"], "<file-uri>")
        self.assertEqual(manifest["catalog"]["summary_files"], ["<file-uri>", http_url])
        self.assertNotIn("source_path", manifest)
        strings = self._all_strings(report)
        self.assertNotIn(windows_path, strings)
        self.assertNotIn(posix_path, strings)
        self.assertNotIn(unc_path, strings)
        self.assertIn(http_url, strings)

        shown = run_doctor(self.config_path, manifest_path=manifest_path, show_paths=True)
        shown_manifest = shown["manifest"]
        self.assertEqual(shown["redaction"]["paths"], "shown")
        self.assertEqual(shown_manifest["config"]["path"], windows_path)
        self.assertEqual(shown_manifest["components"]["workspace"]["path"], unc_path)
        self.assertEqual(shown_manifest["components"]["catalog"]["path"], file_uri)
        self.assertEqual(shown_manifest["catalog"]["summary_files"], [file_uri, http_url])

    def test_manifest_semantics_are_strict_and_catalog_summary_has_one_authority(self) -> None:
        wrong_server = BASE_MANIFEST.replace('server_name = "research-kb"', 'server_name = "other-server"')
        with self.assertRaises(ManifestError):
            load_manifest(self._write_manifest(wrong_server))

        wrong_policy = BASE_MANIFEST.replace(
            "projects = []",
            'projects = [{ project_id = "default", workspace = ".", corpus_scope = ["."], checkpoint_policy = "any" }]',
        )
        with self.assertRaises(ManifestError):
            load_manifest(self._write_manifest(wrong_policy))

        component_summary = BASE_MANIFEST.replace(
            '[components.catalog]\npath = "catalog"\nboundary = "runtime_root"\nrequired = false',
            '[components.catalog]\npath = "catalog"\nboundary = "runtime_root"\nrequired = false\nsummary_files = ["wrong.json"]',
        )
        with self.assertRaises(ManifestError):
            load_manifest(self._write_manifest(component_summary))
        manifest = load_manifest(self._write_manifest())
        self.assertNotIn("summary_files", manifest.to_dict()["components"]["catalog"])
        self.assertEqual(manifest.to_dict()["catalog"]["summary_files"], ["summary.json"])

    def test_manifest_missing_unknown_type_and_version_are_explicit(self) -> None:
        missing = BASE_MANIFEST.replace("[schema]\nversion = 5\n\n", "")
        with self.assertRaises(ManifestError):
            load_manifest(self._write_manifest(missing))

        unknown = BASE_MANIFEST + "\nunexpected_control_field = true\n"
        with self.assertRaises(ManifestError):
            load_manifest(self._write_manifest(unknown))

        wrong_type = BASE_MANIFEST.replace("version = 5", 'version = "5"')
        with self.assertRaises(ManifestError):
            load_manifest(self._write_manifest(wrong_type))

        unsupported = BASE_MANIFEST.replace("manifest_format_version = 1", "manifest_format_version = 9")
        with self.assertRaises(ManifestError):
            load_manifest(self._write_manifest(unsupported))

    def test_path_resolution_redaction_supports_windows_posix_unc_and_utf8(self) -> None:
        self.assertEqual(redact_path(r"C:\Users\Alice\secret\research.db"), "<local-path>")
        self.assertEqual(redact_path(r"\\server\share\secret"), "<unc-path>")
        self.assertEqual(redact_path("/Users/alice/secret/research.db"), "<local-path>")
        self.assertEqual(redact_path("https://example.invalid/source"), "https://example.invalid/source")
        self.assertEqual(redact_path("资料/中文路径.txt"), "资料/中文路径.txt")
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(resolve_manifest_path("${SG1A_NOT_SET}/data.db", self.root))
        self.assertEqual(
            resolve_manifest_path("资料/中文路径", self.root),
            (self.root / "资料" / "中文路径").resolve(),
        )

    def test_missing_config_and_database_fail_closed_without_creating_files(self) -> None:
        missing_root = self.root / "missing-runtime"
        missing_config = missing_root / "config.toml"
        report = run_doctor(missing_config, manifest_path=None)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["exit_code"], 2)
        self.assertFalse(missing_root.exists())

        config = missing_root / "config.toml"
        missing_root.mkdir()
        config.write_text(
            "[paths]\ndatabase = \"data/research.db\"\ncorpus_roots = [\"corpus\"]\nworkspace = \"workspace\"\n",
            encoding="utf-8",
        )
        report = run_doctor(config)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(missing_root.joinpath("data").exists())

    def test_doctor_json_is_deterministic_and_read_only(self) -> None:
        manifest_path = self._write_manifest()
        database = self.settings.database
        before_mtime = database.stat().st_mtime_ns
        with connect(self.settings, read_only=True) as connection:
            before_schema = connection.execute("PRAGMA schema_version").fetchone()[0]
            before_fts = connection.execute("SELECT COUNT(*) FROM passages_search_fts").fetchone()[0]
            before_audit = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        fixed_now = datetime(2026, 8, 8, tzinfo=timezone.utc)
        first = run_doctor(self.config_path, manifest_path=manifest_path, now=fixed_now)
        second = run_doctor(self.config_path, manifest_path=manifest_path, now=fixed_now)
        self.assertEqual(
            json.dumps(first, ensure_ascii=False, sort_keys=True),
            json.dumps(second, ensure_ascii=False, sort_keys=True),
        )
        with connect(self.settings, read_only=True) as connection:
            after_schema = connection.execute("PRAGMA schema_version").fetchone()[0]
            after_fts = connection.execute("SELECT COUNT(*) FROM passages_search_fts").fetchone()[0]
            after_audit = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        self.assertEqual(database.stat().st_mtime_ns, before_mtime)
        self.assertEqual(after_schema, before_schema)
        self.assertEqual(after_fts, before_fts)
        self.assertEqual(after_audit, before_audit)
        serialized = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("SELECT ", serialized)
        self.assertNotIn("Traceback", serialized)
        self.assertNotIn("C:\\Users\\", serialized)

    def test_manifest_schema_and_protocol_mismatch_are_p0(self) -> None:
        schema_bad = self._write_manifest(BASE_MANIFEST.replace("version = 5", "version = 4"))
        report = run_doctor(self.config_path, manifest_path=schema_bad)
        self.assertEqual(report["status"], "failed")
        self.assertIn("manifest_schema_mismatch", {item["id"] for item in report["checks"]})

        protocol_bad = self._write_manifest(BASE_MANIFEST.replace('name = "research-kb/v1"', 'name = "research-kb/v9"'))
        report = run_doctor(self.config_path, manifest_path=protocol_bad)
        self.assertEqual(report["status"], "failed")
        self.assertIn("manifest_protocol_mismatch", {item["id"] for item in report["checks"]})

    def test_skill_hash_drift_is_reported_without_emitting_skill_content(self) -> None:
        skill = self.root / "workspace" / ".agents" / "skills" / "example" / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text("# Example skill\n", encoding="utf-8")
        digest = hashlib.sha256(skill.read_bytes()).hexdigest()
        skill_manifest = BASE_MANIFEST.replace(
            "[skills]\nitems = []",
            f'[skills]\nitems = [{{ name = "example", path = "workspace/.agents/skills/example/SKILL.md", version = "1", content_sha256 = "{digest}" }}]',
        )
        report = run_doctor(self.config_path, manifest_path=self._write_manifest(skill_manifest))
        self.assertIn("skill_hash_ok", {item["id"] for item in report["checks"]})
        skill.write_text("# Changed skill\n", encoding="utf-8")
        report = run_doctor(self.config_path, manifest_path=self._write_manifest(skill_manifest))
        self.assertIn("skill_hash_drift", {item["id"] for item in report["checks"]})
        self.assertNotIn("Changed skill", json.dumps(report, ensure_ascii=False))

    def test_deep_skill_scan_rejects_external_and_out_of_boundary_roots(self) -> None:
        external_root = self.root / "external-skills"
        external_root.mkdir()
        (external_root / "SKILL.md").write_text("external", encoding="utf-8")
        external_manifest = BASE_MANIFEST.replace(
            '[components.skills]\npath = "workspace/.agents/skills"\nboundary = "runtime_root"',
            '[components.skills]\npath = "external-skills"\nboundary = "external"',
        )
        external_report = run_doctor(
            self.config_path,
            manifest_path=self._write_manifest(external_manifest),
            deep=True,
        )
        external_ids = {item["id"] for item in external_report["checks"]}
        self.assertIn("skill_inventory_external_boundary", external_ids)
        self.assertNotIn("skill_inventory_incomplete", external_ids)

        outside_manifest = BASE_MANIFEST.replace(
            'path = "workspace/.agents/skills"\nboundary = "runtime_root"',
            'path = "../outside-skills"\nboundary = "runtime_root"',
        )
        outside_report = run_doctor(
            self.config_path,
            manifest_path=self._write_manifest(outside_manifest),
            deep=True,
        )
        self.assertIn(
            "skill_inventory_boundary",
            {item["id"] for item in outside_report["checks"]},
        )

    def test_deep_skill_scan_is_bounded_and_deterministic(self) -> None:
        root = self.settings.workspace / ".agents" / "skills"
        root.mkdir(parents=True)
        current = root
        for index in range(SKILL_SCAN_MAX_DEPTH + 1):
            current = current / f"depth-{index}"
            current.mkdir()
        (current / "SKILL.md").write_text("undeclared", encoding="utf-8")
        manifest_path = self._write_manifest()
        before = {path.relative_to(self.root).as_posix(): path.stat().st_mtime_ns for path in self.root.rglob("*")}
        first = run_doctor(self.config_path, manifest_path=manifest_path, deep=True)
        second = run_doctor(self.config_path, manifest_path=manifest_path, deep=True)
        self.assertEqual(
            json.dumps(first, ensure_ascii=False, sort_keys=True),
            json.dumps(second, ensure_ascii=False, sort_keys=True),
        )
        limited = next(item for item in first["checks"] if item["id"] == "skill_inventory_scan_limited")
        self.assertEqual(limited["details"]["limit"], "depth")
        self.assertEqual(
            before,
            {path.relative_to(self.root).as_posix(): path.stat().st_mtime_ns for path in self.root.rglob("*")},
        )

    def test_deep_skill_scan_stops_at_directory_and_file_limits(self) -> None:
        from research_kb import doctor as doctor_module

        root = self.settings.workspace / ".agents" / "skills"
        root.mkdir(parents=True)
        for name in ("a", "b", "c"):
            (root / name).mkdir()
        with patch.object(doctor_module, "SKILL_SCAN_MAX_DIRECTORIES", 2):
            report = run_doctor(self.config_path, manifest_path=self._write_manifest(), deep=True)
        directory_limit = next(item for item in report["checks"] if item["id"] == "skill_inventory_scan_limited")
        self.assertEqual(directory_limit["details"]["limit"], "directory_count")

        for name in ("a", "b", "c"):
            (root / name).rmdir()
        for name in ("a.txt", "b.txt", "c.txt"):
            (root / name).write_text("x", encoding="utf-8")
        with patch.object(doctor_module, "SKILL_SCAN_MAX_FILES", 2):
            report = run_doctor(self.config_path, manifest_path=self._write_manifest(), deep=True)
        file_limit = next(item for item in report["checks"] if item["id"] == "skill_inventory_scan_limited")
        self.assertEqual(file_limit["details"]["limit"], "file_count")

    def test_deep_skill_scan_skips_symlink_without_traversing_it(self) -> None:
        from research_kb import doctor as doctor_module

        root = self.settings.workspace / ".agents" / "skills"
        target = self.settings.workspace / "symlink-target"
        root.mkdir(parents=True)
        target.mkdir()
        (target / "SKILL.md").write_text("outside target", encoding="utf-8")
        link = root / "linked"
        simulated_reparse = False
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            simulated_reparse = True
            link.mkdir()
            (link / "SKILL.md").write_text("simulated reparse target", encoding="utf-8")
            self.assertTrue(str(exc))
        if simulated_reparse:
            real_check = doctor_module._is_reparse_entry

            def simulated_check(entry):
                return getattr(entry, "name", "") == "linked" or real_check(entry)

            with patch.object(doctor_module, "_is_reparse_entry", side_effect=simulated_check):
                report = run_doctor(self.config_path, manifest_path=self._write_manifest(), deep=True)
        else:
            report = run_doctor(self.config_path, manifest_path=self._write_manifest(), deep=True)
        ids = {item["id"] for item in report["checks"]}
        self.assertIn("skill_inventory_reparse_skipped", ids)
        self.assertNotIn("skill_inventory_incomplete", ids)

    def test_catalog_missing_corrupt_and_ready_summary_are_distinguished(self) -> None:
        manifest_path = self._write_manifest()
        catalog = self.root / "catalog"
        catalog.mkdir()
        (catalog / "summary.json").write_text(
            json.dumps({"catalog_version": 2, "ready_for_manifest": 3, "duplicate_status_counts": {"none": 2}}),
            encoding="utf-8",
        )
        report = run_doctor(self.config_path, manifest_path=manifest_path)
        readable = next(item for item in report["checks"] if item["id"] == "catalog_summary_readable")
        self.assertEqual(readable["details"]["stage"], "ready")
        (catalog / "summary.json").write_text("not json", encoding="utf-8")
        report = run_doctor(self.config_path, manifest_path=manifest_path)
        self.assertIn("catalog_summary_invalid", {item["id"] for item in report["checks"]})
        (catalog / "summary.json").unlink()
        report = run_doctor(self.config_path, manifest_path=manifest_path)
        self.assertIn("catalog_summary_missing", {item["id"] for item in report["checks"]})

    def test_multiple_current_checkpoints_are_reported_not_modified(self) -> None:
        with connect(self.settings) as connection:
            for item_id in ("checkpoint_one", "checkpoint_two"):
                connection.execute(
                    """
                    INSERT INTO research_items(item_id, project_id, kind, status, created_by, created_at, updated_at)
                    VALUES (?, 'default', 'note', 'candidate', 'test', datetime('now'), datetime('now'))
                    """,
                    (item_id,),
                )
                connection.execute(
                    """
                    INSERT INTO research_item_versions(version_id, item_id, version_no, payload_json, content_hash, created_by, created_at)
                    VALUES (?, ?, 1, '{"schema":"research-checkpoint/v1"}', 'hash', 'test', datetime('now'))
                    """,
                    (f"{item_id}_v1", item_id),
                )
        report = run_doctor(self.config_path)
        finding = next(item for item in report["checks"] if item["id"] == "checkpoint_multiple_current")
        self.assertEqual(finding["details"]["current_checkpoint_count"], 2)
        self.assertEqual(finding["details"]["project_status"], "active")
        self.assertEqual(finding["details"]["research_item_count"], 2)
        self.assertEqual(finding["details"]["standard_checkpoint_count"], 2)
        self.assertEqual(finding["details"]["legacy_candidate_count"], 0)
        with connect(self.settings, read_only=True) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM research_items WHERE kind = 'note'").fetchone()[0], 2)

    def test_checkpoint_diagnostics_separate_archived_and_empty_active_projects(self) -> None:
        with connect(self.settings) as connection:
            connection.execute("UPDATE projects SET status = 'archived' WHERE project_id = 'default'")
        archived = run_doctor(self.config_path)
        archived_finding = next(
            item for item in archived["checks"] if item["id"] == "checkpoint_not_required_archived"
        )
        self.assertEqual(archived_finding["details"]["project_status"], "archived")
        self.assertEqual(archived_finding["details"]["research_item_count"], 0)
        self.assertNotIn("checkpoint_zero_current", {item["id"] for item in archived["checks"]})

        with connect(self.settings) as connection:
            connection.execute("UPDATE projects SET status = 'active' WHERE project_id = 'default'")
        empty = run_doctor(self.config_path)
        empty_finding = next(item for item in empty["checks"] if item["id"] == "checkpoint_not_required_empty")
        self.assertEqual(empty_finding["details"]["project_status"], "active")
        self.assertEqual(empty_finding["details"]["research_item_count"], 0)
        self.assertEqual(empty_finding["details"]["standard_checkpoint_count"], 0)
        self.assertEqual(empty_finding["details"]["legacy_candidate_count"], 0)

    def test_checkpoint_diagnostics_classify_standard_legacy_and_zero_activity(self) -> None:
        database = self.settings.database
        self._insert_item("standard_checkpoint", payload='{"schema":"research-checkpoint/v1","private":"hidden"}')
        before_mtime = database.stat().st_mtime_ns
        standard = run_doctor(self.config_path)
        standard_finding = next(item for item in standard["checks"] if item["id"] == "checkpoint_one_current")
        self.assertEqual(standard_finding["details"]["standard_checkpoint_count"], 1)
        self.assertEqual(standard_finding["details"]["legacy_candidate_count"], 0)
        self.assertNotIn("hidden", json.dumps(standard, ensure_ascii=False))
        self.assertEqual(database.stat().st_mtime_ns, before_mtime)


    def test_checkpoint_diagnostics_classify_legacy_note(self) -> None:
        self._insert_item("legacy_note", payload='{"old_handoff":"hidden"}')
        before_mtime = self.settings.database.stat().st_mtime_ns
        legacy = run_doctor(self.config_path)
        legacy_finding = next(item for item in legacy["checks"] if item["id"] == "checkpoint_legacy_unrecognized")
        self.assertEqual(legacy_finding["details"]["standard_checkpoint_count"], 0)
        self.assertEqual(legacy_finding["details"]["legacy_candidate_count"], 1)
        self.assertNotIn("hidden", json.dumps(legacy, ensure_ascii=False))
        self.assertEqual(self.settings.database.stat().st_mtime_ns, before_mtime)

    def test_checkpoint_diagnostics_classify_active_research_without_checkpoint(self) -> None:
        self._insert_item("activity_without_checkpoint", kind="hypothesis", payload='{"claim":"hidden"}')
        before_mtime = self.settings.database.stat().st_mtime_ns
        zero = run_doctor(self.config_path)
        zero_finding = next(item for item in zero["checks"] if item["id"] == "checkpoint_zero_current")
        self.assertEqual(zero_finding["details"]["research_item_count"], 1)
        self.assertEqual(zero_finding["details"]["standard_checkpoint_count"], 0)
        self.assertEqual(zero_finding["details"]["legacy_candidate_count"], 0)
        self.assertNotIn("hidden", json.dumps(zero, ensure_ascii=False))
        self.assertEqual(self.settings.database.stat().st_mtime_ns, before_mtime)

    def test_checkpoint_uses_only_latest_note_version(self) -> None:
        self._insert_item("versioned_note", payload='{"old_handoff":true}')
        with connect(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO research_item_versions(
                    version_id, item_id, version_no, payload_json,
                    content_hash, created_by, created_at
                ) VALUES ('versioned_note_v2', 'versioned_note', 2, '{"schema":"research-checkpoint/v1"}', 'test-hash-2', 'test', '2026-08-08 00:00:00')
                """
            )
        report = run_doctor(self.config_path)
        finding = next(item for item in report["checks"] if item["id"] == "checkpoint_one_current")
        self.assertEqual(finding["details"]["standard_checkpoint_count"], 1)
        self.assertEqual(finding["details"]["legacy_candidate_count"], 0)

    def test_orphan_registry_mapping_is_reported_without_creation_or_deletion(self) -> None:
        registry = BASE_MANIFEST.replace(
            "projects = []",
            'projects = [{ project_id = "ghost", workspace = "ghost", corpus_scope = ["corpus"], checkpoint_policy = "one-current" }]',
        )
        before = {path.name for path in self.root.iterdir()}
        report = run_doctor(self.config_path, manifest_path=self._write_manifest(registry))
        ids = {item["id"] for item in report["checks"]}
        self.assertIn("project_registry_mapping_orphan", ids)
        self.assertIn("project_workspace_mapping_orphan", ids)
        self.assertEqual(before | {"system-manifest.toml"}, {path.name for path in self.root.iterdir()})

    def test_registry_workspace_and_corpus_scope_semantics_are_observed(self) -> None:
        project_workspace = self.settings.workspace / "default"
        project_scope = self.settings.corpus_roots[0] / "topic"
        project_workspace.mkdir()
        project_scope.mkdir()
        registry = BASE_MANIFEST.replace(
            "projects = []",
            'projects = [{ project_id = "default", workspace = "default", corpus_scope = ["topic"], checkpoint_policy = "one-current" }]',
        )
        report = run_doctor(self.config_path, manifest_path=self._write_manifest(registry))
        ids = {item["id"] for item in report["checks"]}
        self.assertIn("project_registry_mapping_ok", ids)
        self.assertNotIn("project_workspace_mapping_orphan", ids)
        self.assertIn("project_corpus_scope_mapped", ids)

        invalid = BASE_MANIFEST.replace(
            "projects = []",
            'projects = [{ project_id = "default", workspace = "../outside", corpus_scope = ["../outside"], checkpoint_policy = "one-current" }]',
        )
        before = {path.relative_to(self.root).as_posix() for path in self.root.rglob("*")}
        invalid_report = run_doctor(self.config_path, manifest_path=self._write_manifest(invalid))
        invalid_ids = {item["id"] for item in invalid_report["checks"]}
        self.assertIn("project_workspace_not_relative", invalid_ids)
        self.assertIn("project_corpus_scope_invalid", invalid_ids)
        self.assertEqual(before | {"system-manifest.toml"}, {path.relative_to(self.root).as_posix() for path in self.root.rglob("*")})

    def test_corpus_scope_ambiguity_is_reported_without_guessing(self) -> None:
        second_root = self.root / "corpus-second"
        second_root.mkdir()
        (self.settings.corpus_roots[0] / "topic").mkdir()
        (second_root / "topic").mkdir()
        self.config_path.write_text(
            "[paths]\ndatabase = \"data/research.db\"\ncorpus_roots = [\"corpus\", \"corpus-second\"]\nworkspace = \"workspace\"\n",
            encoding="utf-8",
        )
        self.settings = Settings.load(self.config_path)
        registry = BASE_MANIFEST.replace(
            "projects = []",
            'projects = [{ project_id = "default", workspace = ".", corpus_scope = ["topic"], checkpoint_policy = "one-current" }]',
        )
        report = run_doctor(self.config_path, manifest_path=self._write_manifest(registry))
        finding = next(item for item in report["checks"] if item["id"] == "project_corpus_scope_ambiguous")
        self.assertEqual(finding["severity"], "P1")

    def test_stale_and_duplicate_pending_approvals_are_reported(self) -> None:
        with connect(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO research_items(item_id, project_id, kind, status, created_by, created_at, updated_at)
                VALUES ('approval_item', 'default', 'note', 'candidate', 'test', datetime('now'), datetime('now'))
                """
            )
            for request_id in ("approval_one", "approval_two"):
                connection.execute(
                    """
                    INSERT INTO approval_requests_v2(
                        request_id, project_id, target_type, item_id, requested_by,
                        requested_status, status, rationale, created_at
                    ) VALUES (?, 'default', 'research_item', 'approval_item', 'test', 'accepted', 'pending', '', '2000-01-01 00:00:00')
                    """,
                    (request_id,),
                )
        report = run_doctor(self.config_path, now=datetime(2026, 8, 8, tzinfo=timezone.utc))
        finding = next(item for item in report["checks"] if item["id"] == "approval_pending_risk")
        self.assertEqual(finding["details"]["duplicate_groups"], 1)
        self.assertEqual(finding["details"]["stale"], 2)

    def test_archived_project_is_only_observed(self) -> None:
        with connect(self.settings) as connection:
            connection.execute("UPDATE projects SET status = 'archived' WHERE project_id = 'default'")
        report = run_doctor(self.config_path)
        self.assertIn("checkpoint_not_required_archived", {item["id"] for item in report["checks"]})
        with connect(self.settings, read_only=True) as connection:
            self.assertEqual(
                connection.execute("SELECT status FROM projects WHERE project_id = 'default'").fetchone()[0],
                "archived",
            )

    def test_mcp_contract_remains_exactly_twelve_names(self) -> None:
        self.assertEqual(len(EXPECTED_MCP_TOOLS), 12)
        self.assertEqual(len(set(EXPECTED_MCP_TOOLS)), 12)
        self.assertEqual(EXPECTED_MCP_TOOLS[-1], "request_user_approval")

    def test_doctor_distinguishes_declared_mcp_contract_from_live_check(self) -> None:
        report = run_doctor(self.config_path)
        declared = next(item for item in report["checks"] if item["id"] == "mcp_tool_contract_declared")
        self.assertIn("declared", declared["message"])
        self.assertNotIn("mcp_live_tools_ok", {item["id"] for item in report["checks"]})

    def test_deep_doctor_reads_actual_fastmcp_registration(self) -> None:
        try:
            from research_kb.mcp_server import create_mcp_server
        except SystemExit as exc:
            self.skipTest(str(exc))
        server = create_mcp_server(self.settings)
        actual = asyncio.run(server.list_tools())
        actual_names = [tool.name for tool in actual]
        self.assertEqual(set(actual_names), set(EXPECTED_MCP_TOOLS))
        report = run_doctor(self.config_path, deep=True)
        live = next(item for item in report["checks"] if item["id"] == "mcp_live_tools_ok")
        self.assertEqual(live["details"]["count"], 12)

    def test_deep_mcp_live_mismatch_is_p0_and_unavailable_is_safe_p2(self) -> None:
        from research_kb import mcp_server

        class FakeTool:
            def __init__(self, name: str) -> None:
                self.name = name

        class FakeServer:
            async def list_tools(self):
                return [FakeTool("search_corpus")]

        with patch.object(mcp_server, "create_mcp_server", return_value=FakeServer()):
            mismatch = run_doctor(self.config_path, deep=True)
        mismatch_finding = next(item for item in mismatch["checks"] if item["id"] == "mcp_live_tools_mismatch")
        self.assertEqual(mismatch_finding["severity"], "P0")
        self.assertEqual(mismatch["exit_code"], 2)

        with patch.object(mcp_server, "create_mcp_server", side_effect=SystemExit("missing extra")):
            unavailable = run_doctor(self.config_path, deep=True)
        unavailable_finding = next(item for item in unavailable["checks"] if item["id"] == "mcp_live_check_unavailable")
        self.assertEqual(unavailable_finding["severity"], "P2")
        self.assertNotIn("Traceback", json.dumps(unavailable, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
