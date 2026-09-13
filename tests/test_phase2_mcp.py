from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from research_kb.admin import AdminService
from research_kb.config import Limits, Settings
from research_kb.db import SCHEMA_VERSION, connect, migrate
from research_kb.ingest import ingest_file
from research_kb.mcp_server import (
    MCPRuntime, PROTOCOL, ServerIdentity, TOOL_NAMES, _classify_error,
    _readiness_check, create_mcp_server,
)
from research_kb.policy import Actor, PolicyError


class MCPPhase2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(dir=os.environ.get("RESEARCH_KB_TEST_TMP")))
        self.settings = Settings(
            config_path=self.root / "config.toml",
            root=self.root,
            database=self.root / "data" / "research.db",
            corpus_roots=(self.root / "corpus",),
            workspace=self.root / "workspace",
            limits=Limits(max_return_chars=4000),
        )
        self.settings.config_path.write_text(
            "[paths]\ndatabase = \"data/research.db\"\ncorpus_roots = [\"corpus\"]\nworkspace = \"workspace\"\n\n"
            "[limits]\nmax_return_chars = 4000\n",
            encoding="utf-8",
        )
        migrate(self.settings)
        self.admin_actor = Actor("admin", "admin-session", "user", "admin", "unittest")
        self.admin = AdminService(self.settings, self.admin_actor)
        self.admin.create_project(project_id="project-two", title="Second", objective="Isolation")
        corpus = self.settings.corpus_roots[0]
        corpus.mkdir(parents=True, exist_ok=True)
        source = corpus / "source.txt"
        source.write_text(
            "中文检索测试。这个长中文短语用于验证本地研究知识库。"
            "Machine-learning models support multilingual retrieval.",
            encoding="utf-8",
        )
        self.ingested = ingest_file(
            self.settings,
            self.admin_actor,
            source,
            project_id="default",
            title="Explicit title",
            creator="Explicit creator",
            source_type="article",
            language="zh-en",
            source_date="2026-01-01",
            source_version="v1",
            source_name="Explicit source name",
            reliability_status="unverified",
        )
        with connect(self.settings, read_only=True) as connection:
            self.passage_id = connection.execute(
                "SELECT passage_id FROM passages WHERE document_id = ? ORDER BY ordinal LIMIT 1",
                (self.ingested["document_id"],),
            ).fetchone()[0]

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _params(self) -> StdioServerParameters:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return StdioServerParameters(
            command=sys.executable,
            args=["-m", "research_kb.mcp_server", "--config", str(self.settings.config_path)],
            env=env,
            cwd=str(Path(__file__).parents[1]),
        )

    @staticmethod
    async def _payload(result) -> dict:
        structured = getattr(result, "structuredContent", None)
        if structured:
            return structured
        text_blocks = [item.text for item in result.content if hasattr(item, "text")]
        if not text_blocks:
            raise AssertionError("MCP result contained no JSON content")
        return json.loads(text_blocks[0])

    async def _flow(self, calls: list[tuple[str, dict]]) -> tuple[list[str], list[dict], str]:
        log_path = self.root / "stderr.log"
        names: list[str] = []
        results: list[dict] = []
        with log_path.open("w+", encoding="utf-8") as errlog:
            async with stdio_client(self._params(), errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    names = [tool.name for tool in listed.tools]
                    for name, arguments in calls:
                        results.append(await self._payload(await session.call_tool(name, arguments=arguments)))
            errlog.flush()
        return names, results, log_path.read_text(encoding="utf-8")

    def test_real_official_client_lists_exactly_twelve_tools_and_schemas(self) -> None:
        names, _, _ = asyncio.run(self._flow([]))
        self.assertEqual(set(names), set(TOOL_NAMES))
        self.assertEqual(len(names), 12)

    def test_real_client_complete_research_flow_and_sanitized_transcript(self) -> None:
        async def complete_flow() -> tuple[list[str], list[dict], str, str]:
            log_path = self.root / "stderr-flow.log"
            names: list[str] = []
            results: list[dict] = []
            token = ""
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        names.extend(tool.name for tool in listed.tools)

                        async def call(name: str, arguments: dict) -> dict:
                            result = await self._payload(await session.call_tool(name, arguments=arguments))
                            results.append(result)
                            return result

                        await call("search_corpus", {
                            "project_id": "default", "query": "\u4e2d\u6587", "search_mode": "auto",
                        })
                        await call("get_passage", {
                            "project_id": "default", "passage_id": self.passage_id, "context": 1,
                        })
                        await call("get_document_metadata", {
                            "project_id": "default", "document_id": self.ingested["document_id"],
                        })
                        await call("get_research_context", {"project_id": "default", "detail": "brief"})
                        await call("save_research_note", {
                            "project_id": "default", "title": "Scratch note", "body": "A bounded research note.",
                        })
                        await call("get_search_history", {"project_id": "default", "limit": 20})
                        hypothesis = await call("submit_hypothesis", {
                            "project_id": "default", "title": "Working hypothesis",
                            "claim": "The local index can retrieve mixed-language evidence.",
                            "epistemic_status": "exploratory_hypothesis",
                            "supporting_passage_ids": [self.passage_id],
                        })
                        await call("submit_objection", {
                            "project_id": "default", "target_item_id": hypothesis["data"]["item_id"],
                            "objection_type": "coverage", "text": "The sample is narrow.",
                        })
                        checked = await call("verify_quote_or_claim", {
                            "project_id": "default", "passage_id": self.passage_id,
                            "quote_text": "Machine-learning models support multilingual retrieval",
                            "verification_type": "exact_quote",
                        })
                        token = checked["data"]["verification_token"]
                        await call("submit_verified_evidence", {
                            "project_id": "project-two", "verification_token": token,
                        })
                        evidence = await call("submit_verified_evidence", {
                            "project_id": "default", "verification_token": token,
                        })
                        report = await call("submit_research_report", {
                            "project_id": "default", "question": "Can retrieval support the hypothesis?",
                            "summary": "The lexical index found the cited passage.",
                            "claims": [{
                                "claim_id": "C001", "text": "The quote occurs in the source.",
                                "epistemic_status": "source_fact",
                                "verified_evidence_ids": [evidence["data"]["verified_evidence_id"]],
                            }],
                            "strongest_objection": "The corpus is small.",
                            "alternative_explanations": ["The match may be incidental."],
                            "unresolved_questions": ["Would more sources change the result?"],
                            "evidence_limits": ["One local source."],
                            "next_steps": ["Ingest another source."],
                        })
                        await call("request_user_approval", {
                            "project_id": "default", "target_type": "research_item",
                            "target_id": report["data"]["item_id"], "rationale": "Review candidate report.",
                        })
                        await call("request_user_approval", {
                            "project_id": "default", "target_type": "evidence",
                            "target_id": evidence["data"]["verified_evidence_id"],
                            "rationale": "Review candidate evidence.",
                        })
                        await call("submit_verified_evidence", {
                            "project_id": "default", "verification_token": token,
                        })
                errlog.flush()
            return names, results, token, log_path.read_text(encoding="utf-8")

        names, results, token, logs = asyncio.run(complete_flow())
        self.assertEqual(set(names), set(TOOL_NAMES))
        self.assertEqual(len(names), 12)
        for result in results:
            self.assertEqual(result["protocol"], PROTOCOL)
            self.assertEqual(result["schema_version"], SCHEMA_VERSION)
            self.assertIn("trace_id", result)
        self.assertTrue(results[0]["ok"], results[0])
        self.assertEqual(results[0]["data"]["search_mode"], "lexical")
        self.assertIn("\u4e2d\u6587\u68c0\u7d22\u6d4b\u8bd5", results[0]["data"]["results"][0]["excerpt"])
        self.assertFalse(results[9]["ok"])
        self.assertEqual(results[9]["error"]["code"], "OUT_OF_SCOPE")
        self.assertTrue(results[10]["ok"])
        self.assertEqual(results[12]["data"]["status"], "pending")
        self.assertEqual(results[13]["data"]["status"], "pending")
        self.assertFalse(results[14]["ok"])
        self.assertEqual(results[14]["error"]["code"], "TOKEN_CONSUMED")
        self.assertNotIn(token, logs)
        self.assertNotIn("Traceback", logs)

        async def second_process_consume() -> tuple[dict, str]:
            log_path = self.root / "stderr-second-process.log"
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        result = await self._payload(await session.call_tool(
                            "submit_verified_evidence",
                            arguments={"project_id": "default", "verification_token": token},
                        ))
                errlog.flush()
            return result, log_path.read_text(encoding="utf-8")

        foreign_result, foreign_logs = asyncio.run(second_process_consume())
        self.assertFalse(foreign_result["ok"])
        self.assertEqual(foreign_result["error"]["code"], "FORBIDDEN")
        self.assertNotIn(token, foreign_logs)
        with connect(self.settings, read_only=True) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM approval_requests_v2 WHERE status = 'pending'"
                ).fetchone()[0],
                2,
            )

    def test_search_modes_and_cross_project_ids_fail_closed(self) -> None:
        _, results, _ = asyncio.run(self._flow([
            ("search_corpus", {"project_id": "default", "query": "中文", "search_mode": "semantic"}),
            ("search_corpus", {"project_id": "default", "query": "中文", "search_mode": "hybrid"}),
            ("get_passage", {"project_id": "project-two", "passage_id": self.passage_id}),
            ("get_document_metadata", {"project_id": "project-two", "document_id": self.ingested["document_id"]}),
            ("request_user_approval", {
                "project_id": "project-two", "target_type": "research_item",
                "target_id": "item_missing", "rationale": "cross project",
            }),
            ("verify_quote_or_claim", {
                "project_id": "default", "passage_id": self.passage_id,
                "quote_text": "Machine-learning models support multilingual retrieval",
                "verification_type": "fact_truth",
            }),
        ]))
        self.assertEqual(results[0]["error"]["code"], "UNSUPPORTED_MODE")
        self.assertEqual(results[1]["error"]["code"], "UNSUPPORTED_MODE")
        self.assertFalse(results[2]["ok"])
        self.assertFalse(results[3]["ok"])
        self.assertEqual(results[4]["error"]["code"], "OUT_OF_SCOPE")
        self.assertEqual(results[5]["error"]["code"], "UNSUPPORTED_MODE")

    def test_identity_fields_are_not_in_any_schema(self) -> None:
        log_path = self.root / "stderr-schema.log"

        async def inspect_tools() -> list[dict]:
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        return [tool.inputSchema for tool in listed.tools]

        schemas = asyncio.run(inspect_tools())
        self.assertEqual(len(schemas), 12)
        for schema in schemas:
            self.assertEqual(schema.get("type"), "object")
            self.assertTrue(schema.get("properties"))
        forbidden = {"actor_id", "session_id", "role", "admin", "actor_kind"}
        for schema in schemas:
            self.assertTrue(forbidden.isdisjoint(schema.get("properties", {})))

    def test_stable_error_mapping_and_output_bound(self) -> None:
        expected = {
            "invalid argument": "INVALID_ARGUMENT",
            "active project not found": "OUT_OF_SCOPE",
            "verification token was issued to another actor": "FORBIDDEN",
            "session quota exceeded": "QUOTA_EXCEEDED",
            "semantic retrieval is disabled": "UNSUPPORTED_MODE",
            "verification token has expired": "TOKEN_EXPIRED",
            "verification token has already been consumed": "TOKEN_CONSUMED",
            "source content or version changed": "CONFLICT",
            "unexpected": "INTERNAL",
        }
        for message, code in expected.items():
            exc = RuntimeError(message)
            if message == "invalid argument":
                exc = PolicyError(message)
            self.assertEqual(_classify_error(exc), code)
        self.assertEqual(_classify_error(KeyError("missing")), "NOT_FOUND")
        self.assertEqual(_classify_error(PolicyError("invalid verification token")), "OUT_OF_SCOPE")
        runtime = MCPRuntime(self.settings, ServerIdentity("mcp-agent", "bound-session"))
        response = runtime.invoke("bounded", lambda: {"results": [{"text": "x" * 10000}]})
        self.assertLessEqual(len(json.dumps(response, ensure_ascii=False)), self.settings.limits.max_return_chars)
        self.assertIn("RETURN_TRUNCATED", response["warnings"])
        actor = ServerIdentity("attacker", "stable", framework="test", model="model").actor()
        self.assertEqual((actor.actor_kind, actor.role, actor.is_admin), ("agent", "researcher", False))
        source = Path(__file__).parents[1] / "src" / "research_kb" / "mcp_server.py"
        adapter_source = source.read_text(encoding="utf-8")
        self.assertNotIn("AdminService", adapter_source)
        self.assertNotIn("decide_approval", adapter_source)

    def test_module_import_and_stdio_have_no_debug_stdout(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        # The official client context above is the protocol-level startup and
        # shutdown check. Import is separately checked in a child interpreter.
        import subprocess
        completed = subprocess.run(
            [sys.executable, "-c", "import research_kb.mcp_server"],
            cwd=str(Path(__file__).parents[1]),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")


    def test_official_client_cancellation_and_shutdown(self) -> None:
        log_path = self.root / "stderr-cancel.log"

        async def cancel_client() -> str:
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        pending = asyncio.create_task(session.list_tools())
                        pending.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await pending
                errlog.flush()
            return log_path.read_text(encoding="utf-8")

        logs = asyncio.run(cancel_client())
        self.assertNotIn("Traceback", logs)
    def test_missing_database_mcp_start_fails_without_creating_database(self) -> None:
        root = Path(tempfile.mkdtemp())
        try:
            config = root / "config.toml"
            config.write_text(
                "[paths]\ndatabase = \\\"data/research.db\\\"\n"
                "corpus_roots = [\\\"corpus\\\"]\nworkspace = \\\"workspace\\\"\n",
                encoding="utf-8",
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            database = root / "data" / "research.db"
            completed = subprocess.run(
                [sys.executable, "-m", "research_kb.mcp_server", "--config", str(config)],
                cwd=str(Path(__file__).parents[1]), env=env,
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(database.exists())
            self.assertFalse((root / "data").exists())
            self.assertIn("Admin CLI", completed.stderr)
            self.assertNotIn(str(database), completed.stderr)
            self.assertEqual(completed.stdout, "")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_mcp_readiness_does_not_change_schema_fts_or_database_mtime(self) -> None:
        before_mtime = self.settings.database.stat().st_mtime_ns
        with connect(self.settings, read_only=True) as connection:
            before_schema = connection.execute("PRAGMA schema_version").fetchone()[0]
            before_fts = connection.execute("SELECT COUNT(*) FROM passages_search_fts").fetchone()[0]
        server = create_mcp_server(self.settings, ServerIdentity("test-agent", "ready-session"))
        self.assertEqual(len(server._tool_manager.list_tools()), 12)
        with connect(self.settings, read_only=True) as connection:
            after_schema = connection.execute("PRAGMA schema_version").fetchone()[0]
            after_fts = connection.execute("SELECT COUNT(*) FROM passages_search_fts").fetchone()[0]
        self.assertEqual(self.settings.database.stat().st_mtime_ns, before_mtime)
        self.assertEqual(after_schema, before_schema)
        self.assertEqual(after_fts, before_fts)

    def test_large_fts_database_startup_does_not_reindex(self) -> None:
        with connect(self.settings) as connection:
            connection.executemany(
                "INSERT INTO passages_search_fts(passage_id, title, body) VALUES (?, ?, ?)",
                ((f"large-{index}", "large", "startup sentinel fragment") for index in range(100000)),
            )
            connection.execute(
                "INSERT INTO passages_search_fts(passage_id, title, body) VALUES (?, ?, ?)",
                ("startup-sentinel", "sentinel", "must survive read-only startup"),
            )
        before_mtime = self.settings.database.stat().st_mtime_ns
        with connect(self.settings, read_only=True) as connection:
            before_count = connection.execute("SELECT COUNT(*) FROM passages_search_fts").fetchone()[0]
        _readiness_check(self.settings)
        create_mcp_server(self.settings, ServerIdentity("large-agent", "large-session"))
        with connect(self.settings, read_only=True) as connection:
            after_count = connection.execute("SELECT COUNT(*) FROM passages_search_fts").fetchone()[0]
            sentinel = connection.execute(
                "SELECT COUNT(*) FROM passages_search_fts WHERE passage_id = 'startup-sentinel'"
            ).fetchone()[0]
        self.assertEqual(after_count, before_count)
        self.assertEqual(sentinel, 1)
        self.assertEqual(self.settings.database.stat().st_mtime_ns, before_mtime)

    def test_second_mcp_process_cannot_consume_unconsumed_token(self) -> None:
        _, issued, first_logs = asyncio.run(self._flow([(
            "verify_quote_or_claim",
            {
                "project_id": "default", "passage_id": self.passage_id,
                "quote_text": "Machine-learning models support multilingual retrieval",
                "verification_type": "exact_quote",
            },
        )]))
        token = issued[0]["data"]["verification_token"]
        self.assertNotIn(token, first_logs)
        _, foreign, foreign_logs = asyncio.run(self._flow([(
            "submit_verified_evidence",
            {"project_id": "default", "verification_token": token},
        )]))
        self.assertFalse(foreign[0]["ok"])
        self.assertEqual(foreign[0]["error"]["code"], "FORBIDDEN")
        self.assertNotIn(token, foreign_logs)
        with connect(self.settings, read_only=True) as connection:
            self.assertIsNone(connection.execute(
                "SELECT consumed_at FROM verification_tokens WHERE token_hash = ?",
                (hashlib.sha256(token.encode("utf-8")).hexdigest(),),
            ).fetchone()[0])

    def test_official_client_recursively_redacts_local_metadata_paths(self) -> None:
        metadata = {
            "origin": r"C:\Secret\notes.txt",
            "comment": r"/home/user/private.md",
            "unc_value": r"\\server\share\file.txt",
            "device_value": r"\\.\PhysicalDrive0",
            "uri_value": "file:///home/user/private.md",
            "nested": [{"arbitrary": r"C:\nested\secret.txt"}],
            "web": "https://example.com/source.pdf",
        }
        self.admin.metadata_update(
            project_id="default", document_id=self.ingested["document_id"],
            updates={"metadata_json": metadata}, reason="path redaction regression",
        )
        _, results, logs = asyncio.run(self._flow([(
            "get_document_metadata",
            {"project_id": "default", "document_id": self.ingested["document_id"]},
        )]))
        self.assertTrue(results[0]["ok"])
        returned = results[0]["data"]["metadata"]
        for key in ("origin", "comment", "unc_value", "device_value", "uri_value"):
            self.assertEqual(returned[key], "[redacted-local-path]")
        self.assertEqual(returned["nested"][0]["arbitrary"], "[redacted-local-path]")
        self.assertEqual(returned["web"], "https://example.com/source.pdf")
        self.assertNotIn("Secret", logs)
        self.assertNotIn("private.md", logs)

    def test_official_client_invalid_schema_arguments_use_safe_invalid_argument_envelope(self) -> None:
        calls = [
            ("search_corpus", {"project_id": "default", "query": "Machine-learning", "top_k": 999}),
            ("search_corpus", {"query": "Machine-learning"}),
            ("search_corpus", {"project_id": 123, "query": "Machine-learning"}),
        ]
        _, results, logs = asyncio.run(self._flow(calls))
        for result in results:
            self.assertFalse(result["ok"])
            self.assertEqual(result["protocol"], PROTOCOL)
            self.assertEqual(result["schema_version"], SCHEMA_VERSION)
            self.assertEqual(result["error"]["code"], "INVALID_ARGUMENT")
            self.assertEqual(result["error"]["message"], "The supplied arguments are invalid.")
            self.assertNotIn("traceback", json.dumps(result).casefold())
            self.assertNotIn("pydantic", json.dumps(result).casefold())
        self.assertNotIn("Traceback", logs)
        self.assertNotIn("research.db", logs)

if __name__ == "__main__":
    unittest.main()




















