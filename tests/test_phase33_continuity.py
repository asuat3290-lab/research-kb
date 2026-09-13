from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from research_kb.admin import AdminService
from research_kb.config import Limits, Settings
from research_kb.db import connect, migrate
from research_kb.ingest import ingest_file
from research_kb.mcp_server import TOOL_NAMES
from research_kb.policy import Actor
from research_kb.service import ResearchService


class Phase33ContinuityTests(unittest.TestCase):
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
            "[paths]\n"
            "database = \"data/research.db\"\n"
            "corpus_roots = [\"corpus\"]\n"
            "workspace = \"workspace\"\n\n"
            "[limits]\nmax_return_chars = 4000\n",
            encoding="utf-8",
        )
        migrate(self.settings)
        self.admin_actor = Actor("admin", "phase33-admin", "user", "admin", "phase33")
        self.admin = AdminService(self.settings, self.admin_actor)
        self.admin.create_project(project_id="project-two", title="Second", objective="Isolation")
        self.agent = ResearchService(
            self.settings, Actor("fixture-agent", "fixture-session", "agent", "researcher", "phase33")
        )

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
        blocks = [item.text for item in result.content if hasattr(item, "text")]
        if not blocks:
            raise AssertionError("MCP result contained no JSON content")
        return json.loads(blocks[0])

    def _assert_bounded(self, response: dict) -> None:
        self.assertLessEqual(
            len(json.dumps(response, ensure_ascii=False)), 4000,
            response,
        )
        self.assertIn("ok", response)
        self.assertEqual(response.get("protocol"), "research-kb/v1")

    async def _read_section(self, session: ClientSession, item_id: str, section: str) -> tuple[str, str]:
        offset = 0
        chunks: list[str] = []
        content_type = ""
        while True:
            response = await self._payload(await session.call_tool(
                "get_research_context",
                arguments={
                    "project_id": "default",
                    "item_id": item_id,
                    "section": section,
                    "offset": offset,
                    "chunk_size": 1400,
                },
            ))
            self._assert_bounded(response)
            self.assertTrue(response["ok"], response)
            item = response["data"]["items"][0]
            section_data = item["section"]
            self.assertEqual(section_data["name"], section)
            content_type = section_data["content_type"]
            chunks.append(section_data["content"])
            next_offset = section_data["next_offset"]
            if next_offset is None:
                break
            self.assertGreater(next_offset, offset)
            offset = next_offset
        return "".join(chunks), content_type

    def test_two_process_client_recovers_long_checkpoint_and_report_at_4000(self) -> None:
        note_body = "NOTE-CHECKPOINT-" + ("N" * 6980)
        report_summary = "REPORT-SUMMARY-" + ("S" * 7580)
        unresolved = [
            "UNRESOLVED-CONTINUITY-QUESTION-" + ("Q" * 880),
            "BOUNDARY-QUESTION-" + ("B" * 880),
            "COUNTEREVIDENCE-QUESTION-" + ("C" * 880),
        ]
        self.assertGreater(len(note_body), 6000)
        self.assertGreater(len(report_summary) + sum(len(value) for value in unresolved), 10000)
        lead = {
            "idea": "A lead connecting persistent state to the next mechanism test.",
            "source_bridges": ["checkpoint", "report"],
            "supporting_passage_ids": [],
            "why_not_literature_summary": "It links unresolved state to a new test.",
            "possible_counterevidence": ["A later source may reject the mechanism."],
            "missing_evidence": ["A boundary case"],
            "next_search": ["Search the boundary case"],
            "epistemic_status": "analytical_inference",
            "confidence": "low",
        }

        leads = [dict(lead, idea=lead["idea"] + f" ({index})") for index in range(3)]
        expected_claims = [{
            "claim_id": "C001",
            "text": "The report records a stateful checkpoint.",
            "epistemic_status": "source_interpretation",
            "verified_evidence_ids": [],
        }]

        async def session_a() -> tuple[list[str], dict, dict, str]:
            log_path = self.root / "session-a.stderr"
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        names = [tool.name for tool in tools.tools]
                        note = await self._payload(await session.call_tool(
                            "save_research_note",
                            arguments={"project_id": "default", "title": "Long checkpoint", "body": note_body},
                        ))
                        self._assert_bounded(note)
                        self.assertTrue(note["ok"], note)
                        report = await self._payload(await session.call_tool(
                            "submit_research_report",
                            arguments={
                                "project_id": "default",
                                "question": "How does the next round recover state?",
                                "summary": report_summary,
                                "claims": expected_claims,
                                "strongest_objection": "The checkpoint may omit context.",
                                "alternative_explanations": ["The next agent may reconstruct the question."],
                                "unresolved_questions": unresolved,
                                "evidence_limits": ["This is a continuity fixture."],
                                "next_steps": ["Read the unresolved questions first."],
                                "research_leads": leads,
                                "status": "candidate",
                            },
                        ))
                        self._assert_bounded(report)
                        self.assertTrue(report["ok"], report)
            return names, note, report, log_path.read_text(encoding="utf-8")

        names_a, note_result, report_result, logs_a = asyncio.run(session_a())
        self.assertEqual(set(names_a), set(TOOL_NAMES))
        self.assertEqual(len(names_a), 12)
        self.assertNotIn("Traceback", logs_a)
        self.assertNotIn(str(self.root), logs_a)
        note_id = note_result["data"]["item_id"]
        report_id = report_result["data"]["item_id"]
        self.assertNotEqual(note_id, report_id)

        foreign = self.agent.save_research_note(
            project_id="project-two", title="Foreign checkpoint", body="foreign project state"
        )
        foreign_id = foreign["item_id"]

        async def session_b() -> tuple[dict, dict, dict, dict, dict, list[str], str]:
            log_path = self.root / "session-b.stderr"
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        names = [tool.name for tool in listed.tools]
                        index = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "default", "detail": "brief", "limit": 1},
                        ))
                        self._assert_bounded(index)
                        self.assertTrue(index["ok"], index)
                        self.assertGreaterEqual(index["data"]["total_items"], 2)
                        records = index["data"]["items"]
                        self.assertTrue(all(
                            {"status", "kind", "supersedes_item_id", "has_successor", "available_sections"}
                            .issubset(item) for item in records
                        ))
                        next_cursor = index["data"]["next_cursor"]
                        self.assertTrue(next_cursor)
                        paged_ids = [item["item_id"] for item in records]
                        page_cursor = next_cursor
                        page_count = 0
                        while page_cursor is not None:
                            page_count += 1
                            self.assertLessEqual(page_count, 20)
                            page = await self._payload(await session.call_tool(
                                "get_research_context",
                                arguments={"project_id": "default", "cursor": page_cursor, "limit": 10},
                            ))
                            self._assert_bounded(page)
                            self.assertTrue(page["ok"], page)
                            paged_ids.extend(item["item_id"] for item in page["data"]["items"])
                            page_cursor = page["data"]["next_cursor"]
                        self.assertIn(note_id, paged_ids)
                        self.assertIn(report_id, paged_ids)

                        note_index = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "default", "item_id": note_id},
                        ))
                        self._assert_bounded(note_index)
                        self.assertTrue(note_index["ok"], note_index)
                        note_record = note_index["data"]["items"][0]
                        self.assertEqual(note_record["kind"], "note")
                        self.assertFalse(note_record["payload_complete"])
                        note_text, note_type = await self._read_section(session, note_id, "body")
                        self.assertEqual(note_type, "text")
                        self.assertEqual(note_text, note_body)

                        recovered_sections: dict[str, tuple[str, str]] = {}
                        for section in ("summary", "claims", "research_leads", "unresolved_questions"):
                            recovered_sections[section] = await self._read_section(session, report_id, section)
                        self.assertEqual(recovered_sections["summary"], (report_summary, "text"))
                        self.assertEqual(json.loads(recovered_sections["claims"][0]), expected_claims)
                        recovered_unresolved = json.loads(recovered_sections["unresolved_questions"][0])
                        self.assertEqual(recovered_unresolved, unresolved)
                        self.assertEqual(json.loads(recovered_sections["research_leads"][0])[0]["idea"], leads[0]["idea"])

                        first_question = recovered_unresolved[0]
                        hypothesis = await self._payload(await session.call_tool(
                            "submit_hypothesis",
                            arguments={
                                "project_id": "default",
                                "title": "Continuity mechanism hypothesis",
                                "claim": "The next mechanism test must address: " + first_question,
                                "epistemic_status": "exploratory_hypothesis",
                                "open_questions": [first_question],
                                "confidence": "low",
                                "status": "candidate",
                            },
                        ))
                        self._assert_bounded(hypothesis)
                        self.assertTrue(hypothesis["ok"], hypothesis)
                        hypothesis_id = hypothesis["data"]["item_id"]
                        hypothesis_text, hypothesis_type = await self._read_section(session, hypothesis_id, "claim")
                        self.assertEqual(hypothesis_type, "text")
                        self.assertIn(first_question, hypothesis_text)

                        cross_item = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "project-two", "item_id": note_id},
                        ))
                        self._assert_bounded(cross_item)
                        malformed = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "default", "cursor": "not-a-valid-cursor"},
                        ))
                        self._assert_bounded(malformed)
                        cross_cursor = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "default", "limit": 1},
                        ))
                        self._assert_bounded(cross_cursor)
                        cursor_result = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "project-two", "cursor": cross_cursor["data"]["next_cursor"]},
                        ))
                        self._assert_bounded(cursor_result)
            return index, note_index, cross_item, malformed, cursor_result, names, log_path.read_text(encoding="utf-8")

        index, note_index, cross_item, malformed, cursor_result, names_b, logs_b = asyncio.run(session_b())
        self.assertEqual(set(names_b), set(TOOL_NAMES))
        self.assertEqual(len(names_b), 12)
        self.assertEqual(note_index["data"]["items"][0]["item_id"], note_id)
        self.assertFalse(cross_item["ok"])
        self.assertIn(cross_item["error"]["code"], {"NOT_FOUND", "OUT_OF_SCOPE"})
        self.assertNotIn(foreign_id, json.dumps(cross_item))
        self.assertFalse(malformed["ok"])
        self.assertEqual(malformed["error"]["code"], "INVALID_ARGUMENT")
        self.assertFalse(cursor_result["ok"])
        self.assertEqual(cursor_result["error"]["code"], "OUT_OF_SCOPE")
        self.assertNotIn("Traceback", logs_b)
        self.assertNotIn(str(self.root), logs_b)

        self.admin.archive_project(project_id="project-two")
        async def archived_context() -> dict:
            with (self.root / "archived.stderr").open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        result = await self._payload(await session.call_tool(
                            "get_research_context", arguments={"project_id": "project-two"}
                        ))
                        self._assert_bounded(result)
                        return result
        archived = asyncio.run(archived_context())
        self.assertFalse(archived["ok"])
        self.assertEqual(archived["error"]["code"], "OUT_OF_SCOPE")

    def test_lexical_all_any_auto_and_session_event_are_explicit(self) -> None:
        source = self.settings.corpus_roots[0] / "strategy.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("alpha marker only", encoding="utf-8")
        ingest_file(
            self.settings,
            self.admin_actor,
            source,
            project_id="default",
            title="Strategy source",
            creator="Fixture",
            source_type="article",
            language="en",
            source_date="2026",
            source_version="v1",
            source_name="strategy",
        )

        async def search_flow() -> list[dict]:
            with (self.root / "search.stderr").open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        results = []
                        for strategy in ("all", "any", "auto"):
                            result = await self._payload(await session.call_tool(
                                "search_corpus",
                                arguments={
                                    "project_id": "default",
                                    "query": "alpha absent-term",
                                    "match_strategy": strategy,
                                    "top_k": 20,
                                },
                            ))
                            self._assert_bounded(result)
                            results.append(result)
                        history = await self._payload(await session.call_tool(
                            "get_search_history", arguments={"project_id": "default", "limit": 20}
                        ))
                        self._assert_bounded(history)
                        results.append(history)
                        return results

        results = asyncio.run(search_flow())
        self.assertTrue(results[0]["ok"])
        self.assertEqual(results[0]["data"]["match_strategy"], "all")
        self.assertFalse(results[0]["data"]["query_relaxed"])
        self.assertEqual(results[0]["data"]["count"], 0)
        self.assertEqual(results[1]["data"]["match_strategy"], "any")
        self.assertFalse(results[1]["data"]["query_relaxed"])
        self.assertGreaterEqual(results[1]["data"]["count"], 1)
        self.assertEqual(results[2]["data"]["match_strategy"], "any")
        self.assertTrue(results[2]["data"]["query_relaxed"])
        self.assertGreaterEqual(results[2]["data"]["count"], 1)
        events = results[3]["data"]["events"]
        self.assertTrue(any(event["parameters"]["query_relaxed"] for event in events))
        self.assertTrue(any(event["parameters"]["match_strategy"] == "any" for event in events))

    def test_context_tool_schema_exposes_only_optional_continuity_parameters(self) -> None:
        async def inspect() -> tuple[dict, dict]:
            with (self.root / "schema.stderr").open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        by_name = {tool.name: tool.inputSchema for tool in listed.tools}
                        return by_name["get_research_context"], by_name["search_corpus"]
        context_schema, search_schema = asyncio.run(inspect())
        self.assertEqual(len(context_schema.get("properties", {})), 8)
        self.assertTrue({"item_id", "section", "offset", "limit", "cursor", "chunk_size"}.issubset(context_schema["properties"]))
        self.assertIn("match_strategy", search_schema["properties"])
        self.assertEqual(len(TOOL_NAMES), 12)


if __name__ == "__main__":
    unittest.main()
