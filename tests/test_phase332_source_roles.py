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


class Phase332SourceRoleTests(unittest.TestCase):
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
        self.admin_actor = Actor("admin", "phase332-admin", "user", "admin", "phase332")
        self.admin = AdminService(self.settings, self.admin_actor)
        self.admin.create_project(project_id="project-two", title="Second", objective="Isolation")
        corpus = self.settings.corpus_roots[0]
        corpus.mkdir(parents=True, exist_ok=True)
        source = corpus / "primary.txt"
        source.write_text("Primary source passage for dynamic role testing.", encoding="utf-8")
        ingested = ingest_file(
            self.settings,
            self.admin_actor,
            source,
            project_id="default",
            title="Primary source",
            creator="Explicit Creator",
            source_type="article",
            language="en",
            source_date="2026",
            source_version="v1",
            source_name="primary-source",
            metadata={"bibliographic_profile": {
                "type": "journal_article",
                "authors": ["Explicit Creator"],
                "title": "Primary source",
                "container_title": "Fixture Journal",
                "year": 2026,
                "page_range": "1-2",
                "doi": "unknown",
            }},
        )
        self.document_id = ingested["document_id"]
        with connect(self.settings, read_only=True) as connection:
            self.passage_id = connection.execute(
                "SELECT passage_id FROM passages WHERE document_id = ? ORDER BY ordinal LIMIT 1",
                (self.document_id,),
            ).fetchone()[0]
        foreign_source = corpus / "foreign.txt"
        foreign_source.write_text("Foreign project passage.", encoding="utf-8")
        foreign = ingest_file(
            self.settings,
            self.admin_actor,
            foreign_source,
            project_id="project-two",
            title="Foreign source",
            creator="Foreign Creator",
            source_type="article",
            language="en",
            source_date="2026",
            source_version="v1",
            source_name="foreign-source",
        )
        self.foreign_document_id = foreign["document_id"]
        with connect(self.settings, read_only=True) as connection:
            self.foreign_passage_id = connection.execute(
                "SELECT passage_id FROM passages WHERE document_id = ? ORDER BY ordinal LIMIT 1",
                (self.foreign_document_id,),
            ).fetchone()[0]
        self.direct_agent = ResearchService(
            self.settings, Actor("fixture-agent", "fixture-session", "agent", "researcher", "phase332")
        )
        self.baseline_metadata = self.direct_agent.get_document_metadata(
            project_id="default", document_id=self.document_id
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

    @staticmethod
    def _assert_bounded(response: dict) -> None:
        assert response.get("protocol") == "research-kb/v1", response
        assert len(json.dumps(response, ensure_ascii=False)) <= 4000, response

    async def _read_body_json(self, session: ClientSession, item_id: str) -> dict:
        offset = 0
        chunks: list[str] = []
        while True:
            response = await self._payload(await session.call_tool(
                "get_research_context",
                arguments={
                    "project_id": "default",
                    "item_id": item_id,
                    "section": "body",
                    "offset": offset,
                    "chunk_size": 900,
                },
            ))
            self._assert_bounded(response)
            self.assertTrue(response["ok"], response)
            self.assertEqual(response["warnings"], [], response)
            section = response["data"]["items"][0]["section"]
            self.assertEqual(section["name"], "body")
            self.assertEqual(section["offset"], offset)
            chunks.append(section["content"])
            next_offset = section["next_offset"]
            if next_offset is None:
                break
            self.assertEqual(next_offset, offset + len(section["content"]))
            self.assertGreater(next_offset, offset)
            offset = next_offset
        return json.loads("".join(chunks))

    def _build_role_map(self) -> dict:
        assignments = []
        role_variants = [
            ("question-A", "primary-text", "core_research_object", "supports", "direct"),
            ("question-A", "reception-history", "historical_background", "contextualizes", "contextual"),
            ("question-B", "target-analysis", "competing_ideas", "competing_explanation", "indirect"),
            ("question-B", "transmission-test", "discovery-only", "identifies_transmission", "indirect"),
            ("question-C", "countercase", "counterevidence", "counters", "contextual"),
            ("question-C", "source-audit", "excluded", "discovery_only", "indirect"),
        ]
        for index, (question, subtask, role, function, directness) in enumerate(role_variants):
            assignments.append({
                "research_question": question,
                "subtask": subtask,
                "document_id": self.document_id,
                "citation_identity": {
                    "document_id": self.document_id,
                    "title": self.baseline_metadata["title"],
                    "authors": [self.baseline_metadata["creator"]],
                },
                "untrusted_client_hint": {
                    "author": "Forged Author",
                    "page": 999,
                    "doi": "10/forged",
                },
                "role_type": role,
                "evidential_function": function,
                "rationale": f"Role rationale {index}: " + ("This is task-specific reasoning. " * 14),
                "can_support": ["the bounded subtask claim"],
                "cannot_support": ["a universal claim outside this question"],
                "directness": directness,
                "confidence": "medium",
                "provisional": True,
                "supporting_passage_ids": [self.passage_id],
                "competing_or_alternative_sources": [self.foreign_document_id],
            })
        return {
            "schema": "source-role-map/v1",
            "research_scope": {
                "research_object": "dynamic role assignment",
                "core_question": "How does the same document function in different tasks?",
                "time_or_text_scope": "current fixture source",
                "current_subtasks": [item[1] for item in role_variants],
            },
            "assignments": assignments,
            "role_changes": [{
                "previous_role": "core_research_object",
                "new_role": "historical_background",
                "reason_for_change": "The active subtask changed from source analysis to reception history.",
                "affected_subtask_or_claim": "question-A/reception-history",
            }],
            "limitations": [
                "Conceptual similarity is not transmission evidence.",
                "Role assignment does not change document integrity metadata.",
            ],
        }

    def test_phase332_text_encoding_static_regression(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        pilot_root = Path(
            os.environ.get("RESEARCH_KB_PILOT_ROOT", str(repo_root.parent / "research-kb-pilot"))
        )
        skill_path = pilot_root / "workspace" / ".agents" / "skills" / "source-based-research" / "SKILL.md"
        role_test_path = repo_root / "tests" / "test_phase332_source_roles.py"
        files = [
            skill_path,
            role_test_path,
            repo_root / "docs" / "report-template.md",
            repo_root / "docs" / "tool-contract.md",
        ]
        texts = {}
        for path in files:
            if not path.exists():
                self.skipTest(f"pilot documentation path unavailable: {path}")
            text = path.read_text(encoding="utf-8")
            self.assertEqual(text.encode("utf-8").decode("utf-8"), text)
            self.assertNotIn("\ufffd", text)
            texts[path] = text
        self.assertNotIn("?" * 2, texts[role_test_path])
        self.assertIn(
            "Treat `project state recovered` and `research content recovered` as separate checks.",
            texts[skill_path],
        )

    def test_two_process_client_recovers_dynamic_source_role_map(self) -> None:
        role_map = self._build_role_map()
        role_map_text = json.dumps(role_map, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertGreater(len(role_map_text), 6000)
        self.assertLess(len(role_map_text), 8000)

        async def session_a() -> tuple[list[str], dict, dict, dict, str]:
            log_path = self.root / "session-a.stderr"
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        names = [tool.name for tool in listed.tools]
                        role_note = await self._payload(await session.call_tool(
                            "save_research_note",
                            arguments={
                                "project_id": "default",
                                "title": "Source Role Map checkpoint",
                                "body": role_map_text,
                            },
                        ))
                        self._assert_bounded(role_note)
                        self.assertTrue(role_note["ok"], role_note)
                        checkpoint = {
                            "schema": "research-checkpoint/v1",
                            "research_question": "How does the same document function in different tasks?",
                            "subtasks": ["primary-text", "reception-history"],
                            "source_role_map_item_id": role_note["data"]["item_id"],
                            "read_item_ids": [role_note["data"]["item_id"]],
                            "key_findings": ["Role is task-relative, not a global document rank."],
                            "unresolved_questions": ["Does the transmission claim have direct evidence?"],
                            "next_first_step": "Switch to transmission-test and re-evaluate the role.",
                        }
                        checkpoint_note = await self._payload(await session.call_tool(
                            "save_research_note",
                            arguments={
                                "project_id": "default",
                                "title": "Role Map checkpoint",
                                "body": json.dumps(checkpoint, ensure_ascii=False, separators=(",", ":")),
                            },
                        ))
                        self._assert_bounded(checkpoint_note)
                        self.assertTrue(checkpoint_note["ok"], checkpoint_note)
                        metadata_before = await self._payload(await session.call_tool(
                            "get_document_metadata",
                            arguments={"project_id": "default", "document_id": self.document_id},
                        ))
                        self._assert_bounded(metadata_before)
            return names, role_note, checkpoint_note, metadata_before, log_path.read_text(encoding="utf-8")

        names_a, role_note, checkpoint_note, metadata_before, logs_a = asyncio.run(session_a())
        self.assertEqual(set(names_a), set(TOOL_NAMES))
        self.assertEqual(len(names_a), 12)
        self.assertTrue(metadata_before["ok"])
        self.assertNotIn("Traceback", logs_a)
        role_map_id = role_note["data"]["item_id"]
        checkpoint_id = checkpoint_note["data"]["item_id"]

        updated_map = {
            "schema": "source-role-map/v1",
            "research_scope": {
                "research_object": "transmission test",
                "core_question": "Is there direct evidence of transmission?",
                "current_subtasks": ["transmission-test"],
            },
            "assignments": [{
                "research_question": "question-B",
                "subtask": "transmission-test",
                "document_id": self.document_id,
                "citation_identity": {"document_id": self.document_id},
                "role_type": "discovery-only",
                "evidential_function": "identifies_transmission",
                "rationale": "The role is narrowed because the current task requires contact evidence.",
                "can_support": ["a search direction"],
                "cannot_support": ["direct transmission by itself"],
                "directness": "indirect",
                "confidence": "low",
                "provisional": True,
                "supporting_passage_ids": [self.passage_id],
                "competing_or_alternative_sources": [self.foreign_document_id],
            }],
            "role_changes": [{
                "previous_role": "core_research_object",
                "new_role": "discovery-only",
                "reason_for_change": "Session B changed to a transmission subtask and the source lacks direct contact evidence.",
                "affected_subtask_or_claim": "question-B/transmission-test",
            }],
        }

        async def session_b() -> tuple[dict, dict, dict, dict, dict, dict, list[str], str]:
            log_path = self.root / "session-b.stderr"
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        names = [tool.name for tool in listed.tools]
                        index = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "default", "detail": "brief", "limit": 20},
                        ))
                        self._assert_bounded(index)
                        self.assertTrue(index["ok"], index)
                        role_index = next(item for item in index["data"]["items"] if item["item_id"] == role_map_id)
                        checkpoint_index = next(item for item in index["data"]["items"] if item["item_id"] == checkpoint_id)
                        self.assertEqual(role_index["kind"], "note")
                        self.assertEqual(checkpoint_index["kind"], "note")
                        self.assertIn("body", role_index["available_sections"])
                        recovered_map = await self._read_body_json(session, role_map_id)
                        recovered_checkpoint = await self._read_body_json(session, checkpoint_id)
                        self.assertEqual(recovered_checkpoint["source_role_map_item_id"], role_map_id)
                        self.assertEqual(recovered_map, role_map)
                        assignments = recovered_map["assignments"]
                        self.assertEqual(
                            assignments[0]["document_id"], assignments[1]["document_id"]
                        )
                        self.assertNotEqual(
                            assignments[0]["research_question"], assignments[2]["research_question"]
                        )
                        self.assertNotEqual(
                            assignments[0]["subtask"], assignments[1]["subtask"]
                        )
                        self.assertNotEqual(
                            assignments[0]["evidential_function"], assignments[1]["evidential_function"]
                        )

                        updated_note = await self._payload(await session.call_tool(
                            "save_research_note",
                            arguments={
                                "project_id": "default",
                                "title": "Source Role Map after task switch",
                                "body": json.dumps(updated_map, ensure_ascii=False, separators=(",", ":")),
                            },
                        ))
                        self._assert_bounded(updated_note)
                        self.assertTrue(updated_note["ok"], updated_note)
                        recovered_updated_map = await self._read_body_json(
                            session, updated_note["data"]["item_id"]
                        )
                        self.assertEqual(recovered_updated_map, updated_map)
                        self.assertEqual(
                            recovered_updated_map["role_changes"][0]["previous_role"],
                            "core_research_object",
                        )
                        self.assertEqual(
                            recovered_updated_map["role_changes"][0]["new_role"],
                            "discovery-only",
                        )
                        self.assertTrue(recovered_updated_map["role_changes"][0]["reason_for_change"])
                        hypothesis = await self._payload(await session.call_tool(
                            "submit_hypothesis",
                            arguments={
                                "project_id": "default",
                                "title": "Role-aware candidate",
                                "claim": "The source is currently discovery-only for a transmission claim.",
                                "epistemic_status": "exploratory_hypothesis",
                                "supporting_passage_ids": [self.passage_id],
                                "confidence": "low",
                                "status": "candidate",
                            },
                        ))
                        self._assert_bounded(hypothesis)
                        self.assertTrue(hypothesis["ok"], hypothesis)
                        hypothesis_context = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={
                                "project_id": "default",
                                "item_id": hypothesis["data"]["item_id"],
                                "section": "source_links",
                            },
                        ))
                        self._assert_bounded(hypothesis_context)
                        self.assertTrue(hypothesis_context["ok"], hypothesis_context)
                        cross_item = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "project-two", "item_id": role_map_id},
                        ))
                        self._assert_bounded(cross_item)
                        cross_document = await self._payload(await session.call_tool(
                            "get_document_metadata",
                            arguments={"project_id": "default", "document_id": self.foreign_document_id},
                        ))
                        self._assert_bounded(cross_document)
                        cross_passage = await self._payload(await session.call_tool(
                            "get_passage",
                            arguments={"project_id": "default", "passage_id": self.foreign_passage_id},
                        ))
                        self._assert_bounded(cross_passage)
                        metadata_after = await self._payload(await session.call_tool(
                            "get_document_metadata",
                            arguments={"project_id": "default", "document_id": self.document_id},
                        ))
                        self._assert_bounded(metadata_after)
            return (
                updated_note, hypothesis, hypothesis_context, cross_item,
                cross_document, cross_passage, metadata_after, names, log_path.read_text(encoding="utf-8")
            )

        (
            updated_note, hypothesis, hypothesis_context, cross_item,
            cross_document, cross_passage, metadata_after, names_b, logs_b
        ) = asyncio.run(session_b())
        self.assertEqual(set(names_b), set(TOOL_NAMES))
        self.assertEqual(len(names_b), 12)
        self.assertTrue(updated_note["ok"])
        self.assertTrue(hypothesis["ok"])
        self.assertTrue(hypothesis_context["ok"])
        generated_link = json.loads(hypothesis_context["data"]["items"][0]["section"]["content"])[0]
        self.assertEqual(generated_link["passage_id"], self.passage_id)
        self.assertNotEqual(generated_link["passage_id"], self.foreign_passage_id)
        self.assertFalse(cross_item["ok"])
        self.assertEqual(cross_item["error"]["code"], "NOT_FOUND")
        self.assertFalse(cross_document["ok"])
        self.assertEqual(cross_document["error"]["code"], "NOT_FOUND")
        self.assertFalse(cross_passage["ok"])
        self.assertEqual(cross_passage["error"]["code"], "NOT_FOUND")
        self.assertEqual(metadata_after["data"]["reliability_status"], self.baseline_metadata["reliability_status"])
        self.assertEqual(metadata_after["data"]["verification_status"], self.baseline_metadata["verification_status"])
        self.assertEqual(metadata_after["data"]["metadata"], self.baseline_metadata["metadata"])
        self.assertEqual(metadata_after["data"]["citation_record"], self.baseline_metadata["citation_record"])
        self.assertNotIn("Forged Author", json.dumps(metadata_after, ensure_ascii=False))
        self.assertNotIn("10/forged", json.dumps(metadata_after, ensure_ascii=False))
        self.assertNotIn("Traceback", logs_b)


if __name__ == "__main__":
    unittest.main()
