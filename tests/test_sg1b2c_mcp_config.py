from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research_kb.doctor import run_doctor
from research_kb.system_manifest import EXPECTED_MCP_TOOLS


class CodexMCPAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.runtime = self.root / "runtime"
        self.codex = self.root / "codex"
        self.runtime.mkdir()
        (self.runtime / "workspace").mkdir()
        (self.runtime / "corpus").mkdir()
        self.runtime_config = self.runtime / "config.toml"
        self.codex_config = self.codex / "config.toml"
        self.codex.mkdir()
        self.manifest = self.runtime / "system-manifest.toml"
        self.env = patch.dict(
            os.environ,
            {"SG1B2C_CODEX_ROOT": str(self.codex)},
            clear=False,
        )
        self.env.start()
        self.manifest.write_text(self._manifest_text(), encoding="utf-8")
        self.runtime_config.write_text(
            '[paths]\n'
            'database = "data/research.db"\n'
            'corpus_roots = ["corpus"]\n'
            'workspace = "workspace"\n\n'
            '[limits]\n'
            'max_query_chars = 1000\n'
            'max_return_chars = 4000\n'
            'max_searches_per_session = 100\n'
            'max_writes_per_session = 100\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.env.stop()
        self.tempdir.cleanup()

    @staticmethod
    def _toml_array(values: list[str]) -> str:
        return json.dumps(values, ensure_ascii=False)

    def _config_text(self) -> str:
        tools = self._toml_array(list(EXPECTED_MCP_TOOLS))
        return (
            'model = "baseline"\n\n'
            '[mcp_servers.research-kb-pilot]\n'
            'command = "python"\n'
            'args = ["-m", "research_kb.mcp_server", "--config", "pilot-config.toml"]\n'
            'cwd = "workspace"\n'
            'enabled = true\n'
            'required = false\n'
            'startup_timeout_sec = 30\n'
            'tool_timeout_sec = 60\n'
            f'enabled_tools = {tools}\n\n'
            '[mcp_servers.node_repl]\n'
            'command = "node"\n'
            'args = []\n'
        )

    def _manifest_text(self, *, config_path: str | None = None) -> str:
        config_path = config_path or "${SG1B2C_CODEX_ROOT}/config.toml"
        return (
            'manifest_format_version = 1\n\n'
            '[engine]\npackage = "research-kb"\nversion = "0.1.0"\n\n'
            '[schema]\nversion = 5\n\n'
            '[protocol]\nname = "research-kb/v1"\n\n'
            '[config]\npath = "config.toml"\n\n'
            '[components.database]\npath = "data/research.db"\nboundary = "runtime_root"\nrequired = false\n\n'
            '[components.corpus]\npaths = ["corpus"]\nboundary = "runtime_root"\nrequired = false\n\n'
            '[components.workspace]\npath = "workspace"\nboundary = "runtime_root"\nrequired = false\n\n'
            '[components.catalog]\npath = "catalog"\nboundary = "runtime_root"\nrequired = false\n\n'
            '[components.backup]\npath = "backups"\nboundary = "runtime_root"\nrequired = false\n\n'
            '[components.skills]\npath = "skills"\nboundary = "runtime_root"\nrequired = false\n\n'
            '[mcp]\nserver_name = "research-kb"\n'
            f'tools = {self._toml_array(list(EXPECTED_MCP_TOOLS))}\n\n'
            '[project_registry]\nprojects = []\n\n'
            '[skills]\nitems = []\n\n'
            '[mcp_authority]\nauthority = "manifest"\n\n'
            '[[mcp_authority.installations]]\n'
            'name = "codex-research-kb-pilot"\n'
            'platform = "codex"\n'
            f'config_path = {json.dumps(config_path)}\n'
            'config_boundary = "external"\n'
            'server_name = "research-kb-pilot"\n'
            'transport = "stdio"\n'
            'command = "python"\n'
            'args = ["-m", "research_kb.mcp_server", "--config", "pilot-config.toml"]\n'
            'cwd = "workspace"\n'
            'enabled = true\n'
            'required = false\n'
            'startup_timeout_sec = 30\n'
            'tool_timeout_sec = 60\n'
            f'enabled_tools = {self._toml_array(list(EXPECTED_MCP_TOOLS))}\n\n'
            '[catalog]\nlifecycle = ["cataloged", "reviewed", "ready", "ingested", "indexed", "available", "retired"]\n'
            'summary_files = ["summary.json"]\n\n'
            '[capabilities]\nlexical = true\nsemantic = false\nhybrid = false\nlocal_model = false\nremote_deployment = false\n'
        )

    def _write_config(self, text: str | None = None) -> None:
        self.codex_config.write_text(text or self._config_text(), encoding="utf-8")

    def _report(self, config_text: str | None = None, *, manifest_text: str | None = None) -> dict:
        self._write_config(config_text)
        if manifest_text is not None:
            self.manifest.write_text(manifest_text, encoding="utf-8")
        return run_doctor(self.runtime_config, manifest_path=self.manifest, deep=False)

    @staticmethod
    def _ids(report: dict) -> set[str]:
        return {item["id"] for item in report["checks"]}

    def test_correct_stdio_configuration_passes(self) -> None:
        report = self._report()
        self.assertIn("codex_mcp_config_ok", self._ids(report))
        self.assertNotIn("codex_mcp_config_drift", self._ids(report))

    def test_same_name_server_missing(self) -> None:
        report = self._report(self._config_text().replace("research-kb-pilot", "other-server"))
        self.assertIn("codex_mcp_server_missing", self._ids(report))

    def test_command_args_and_cwd_drift_are_detected(self) -> None:
        cases = (
            ('command = "python"', 'command = "other-python"', "command"),
            (
                'args = ["-m", "research_kb.mcp_server", "--config", "pilot-config.toml"]',
                'args = ["--config", "pilot-config.toml", "-m", "research_kb.mcp_server"]',
                "args",
            ),
            ('cwd = "workspace"', 'cwd = "other-workspace"', "cwd"),
        )
        for old, new, field in cases:
            with self.subTest(field=field):
                report = self._report(self._config_text().replace(old, new))
                drift = next(item for item in report["checks"] if item["id"] == "codex_mcp_config_drift")
                self.assertIn(field, drift["details"]["fields"])

    def test_enabled_and_timeout_drift_are_detected(self) -> None:
        for old, new, field in (
            ("enabled = true", "enabled = false", "enabled"),
            ("required = false", "required = true", "required"),
            ("startup_timeout_sec = 30", "startup_timeout_sec = 31", "startup_timeout_sec"),
            ("tool_timeout_sec = 60", "tool_timeout_sec = 61", "tool_timeout_sec"),
        ):
            with self.subTest(field=field):
                report = self._report(self._config_text().replace(old, new))
                drift = next(item for item in report["checks"] if item["id"] == "codex_mcp_config_drift")
                self.assertIn(field, drift["details"]["fields"])

    def test_exact_twelve_allowlist_missing_duplicate_and_extra_are_detected(self) -> None:
        cases = (
            ([], "missing"),
            (list(EXPECTED_MCP_TOOLS[:-1]) + [EXPECTED_MCP_TOOLS[0]], "duplicate"),
            (list(EXPECTED_MCP_TOOLS) + ["unexpected_tool"], "extra"),
        )
        for tools, label in cases:
            with self.subTest(label=label):
                replacement = f"enabled_tools = {self._toml_array(tools)}"
                report = self._report(
                    re.sub(
                        r"enabled_tools = \[[^\]]*\]",
                        replacement,
                        self._config_text(),
                        count=1,
                        flags=re.DOTALL,
                    )
                )
                drift = next(item for item in report["checks"] if item["id"] == "codex_mcp_config_drift")
                self.assertIn("enabled_tools", drift["details"]["fields"])

    def test_forbidden_url_headers_auth_disabled_tools_and_dangerous_env(self) -> None:
        config = self._config_text().replace(
            'enabled_tools = ',
            'url = "https://example.invalid/mcp"\n'
            'headers = { Authorization = "Bearer secret" }\n'
            'disabled_tools = ["search_corpus"]\n'
            'env = { PYTHONPATH = "secret", BEARER_TOKEN = "secret" }\n'
            'enabled_tools = ',
            1,
        )
        report = self._report(config)
        ids = self._ids(report)
        self.assertIn("codex_mcp_forbidden_field", ids)
        self.assertIn("codex_mcp_dangerous_env", ids)

    def test_unrelated_codex_settings_and_node_repl_do_not_drift_target(self) -> None:
        config = self._config_text().replace('model = "baseline"', 'model = "unrelated-change"')
        report = self._report(config)
        self.assertIn("codex_mcp_config_ok", self._ids(report))
        self.assertNotIn("codex_mcp_config_drift", self._ids(report))

    def test_default_doctor_output_redacts_external_config_path(self) -> None:
        report = self._report()
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertNotIn(str(self.codex), serialized)
        self.assertEqual(report["manifest"]["mcp_authority"]["installations"][0]["config_path"], "<env-path>")

    def test_unc_device_file_uri_and_unresolved_paths_fail_closed(self) -> None:
        cases = (
            (r"\\server\share\config.toml", "unc"),
            (r"\\?\C:\config.toml", "device"),
            ("file:///tmp/config.toml", "file_uri"),
            ("${SG1B2C_MISSING}/config.toml", "unresolved"),
        )
        for value, label in cases:
            with self.subTest(label=label):
                manifest = self._manifest_text(config_path=value)
                report = self._report(manifest_text=manifest)
                self.assertIn("codex_mcp_config_path_invalid", self._ids(report))


if __name__ == "__main__":
    unittest.main()
