from __future__ import annotations

import asyncio
import hashlib
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
from research_kb.db import connect, migrate, transaction
from research_kb.ingest import ingest_file
from research_kb.mcp_server import TOOL_NAMES
from research_kb.policy import Actor
from research_kb.service import ResearchService


class Phase331SourceLinksTests(unittest.TestCase):
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
        self.admin_actor = Actor("admin", "phase331-admin", "user", "admin", "phase331")
        self.admin = AdminService(self.settings, self.admin_actor)
        self.admin.create_project(project_id="project-two", title="Second", objective="Isolation")
        self.corpus = self.settings.corpus_roots[0]
        self.corpus.mkdir(parents=True, exist_ok=True)
        self.passage_ids: list[str] = []
        self.document_ids: list[str] = []
        for index in range(12):
            source = self.corpus / f"source-{index}.txt"
            source.write_text(f"Source passage {index} for structured relation recovery.", encoding="utf-8")
            result = ingest_file(
                self.settings,
                self.admin_actor,
                source,
                project_id="default",
                title=f"Source {index}",
                creator="Fixture",
                source_type="article",
                language="en",
                source_date="2026",
                source_version="v1",
                source_name=f"source-{index}",
            )
            self.document_ids.append(result["document_id"])
            with connect(self.settings, read_only=True) as connection:
                self.passage_ids.append(connection.execute(
                    "SELECT passage_id FROM passages WHERE document_id = ? ORDER BY ordinal LIMIT 1",
                    (result["document_id"],),
                ).fetchone()[0])
        foreign_source = self.corpus / "foreign.txt"
        foreign_source.write_text("Foreign project passage.", encoding="utf-8")
        foreign_result = ingest_file(
            self.settings,
            self.admin_actor,
            foreign_source,
            project_id="project-two",
            title="Foreign source",
            creator="Fixture",
            source_type="article",
            language="en",
            source_date="2026",
            source_version="v1",
            source_name="foreign",
        )
        self.foreign_document_id = foreign_result["document_id"]
        with connect(self.settings, read_only=True) as connection:
            self.foreign_passage_id = connection.execute(
                "SELECT passage_id FROM passages WHERE document_id = ? ORDER BY ordinal LIMIT 1",
                (self.foreign_document_id,),
            ).fetchone()[0]
        self.direct_agent = ResearchService(
            self.settings, Actor("fixture-agent", "fixture-session", "agent", "researcher", "phase331")
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
    def _assert_envelope(response: dict) -> None:
        assert response.get("protocol") == "research-kb/v1", response
        assert len(json.dumps(response, ensure_ascii=False)) <= 4000, response

    async def _read_source_links(
        self, session: ClientSession, item_id: str, version_id: str
    ) -> list[dict]:
        offset = 0
        chunks: list[str] = []
        seen_offsets: list[int] = []
        while True:
            response = await self._payload(await session.call_tool(
                "get_research_context",
                arguments={
                    "project_id": "default",
                    "item_id": item_id,
                    "section": "source_links",
                    "offset": offset,
                    "chunk_size": 256,
                },
            ))
            self._assert_envelope(response)
            self.assertTrue(response["ok"], response)
            self.assertEqual(response["warnings"], [], response)
            item = response["data"]["items"][0]
            self.assertEqual(item["version_id"], version_id)
            section = item["section"]
            self.assertEqual(section["name"], "source_links")
            self.assertEqual(section["offset"], offset)
            seen_offsets.append(offset)
            chunks.append(section["content"])
            next_offset = section["next_offset"]
            if next_offset is None:
                break
            self.assertEqual(next_offset, offset + len(section["content"]))
            self.assertGreater(next_offset, offset)
            offset = next_offset
        self.assertGreater(len(seen_offsets), 1)
        return json.loads("".join(chunks))

    def test_two_process_client_recovers_server_owned_source_links(self) -> None:
        supports = self.passage_ids[:6]
        counters = self.passage_ids[6:]

        async def session_a() -> tuple[list[str], dict, dict, str]:
            log_path = self.root / "session-a.stderr"
            with log_path.open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        names = [tool.name for tool in listed.tools]
                        hypothesis = await self._payload(await session.call_tool(
                            "submit_hypothesis",
                            arguments={
                                "project_id": "default",
                                "title": "Structured relation hypothesis",
                                "claim": "A mechanism claim without embedded passage identifiers.",
                                "epistemic_status": "exploratory_hypothesis",
                                "supporting_passage_ids": supports,
                                "counter_passage_ids": counters,
                                "confidence": "low",
                                "status": "candidate",
                            },
                        ))
                        self._assert_envelope(hypothesis)
                        self.assertTrue(hypothesis["ok"], hypothesis)
                        objection = await self._payload(await session.call_tool(
                            "submit_objection",
                            arguments={
                                "project_id": "default",
                                "target_item_id": hypothesis["data"]["item_id"],
                                "objection_type": "boundary",
                                "text": "A counter-argument without embedded passage identifiers.",
                                "passage_ids": supports,
                                "status": "candidate",
                            },
                        ))
                        self._assert_envelope(objection)
                        self.assertTrue(objection["ok"], objection)
            return names, hypothesis, objection, log_path.read_text(encoding="utf-8")

        names_a, hypothesis, objection, logs_a = asyncio.run(session_a())
        self.assertEqual(set(names_a), set(TOOL_NAMES))
        self.assertEqual(len(names_a), 12)
        self.assertNotIn("Traceback", logs_a)
        hypothesis_id = hypothesis["data"]["item_id"]
        objection_id = objection["data"]["item_id"]
        hypothesis_version = hypothesis["data"]["version_id"]
        objection_version = objection["data"]["version_id"]

        async def session_b() -> tuple[dict, dict, dict, dict, dict, list[dict], list[dict], list[str], str]:
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
                        self._assert_envelope(index)
                        self.assertTrue(index["ok"], index)
                        by_id = {item["item_id"]: item for item in index["data"]["items"]}
                        self.assertIn(hypothesis_id, by_id)
                        self.assertIn(objection_id, by_id)
                        self.assertEqual(by_id[hypothesis_id]["source_link_count"], 12)
                        self.assertEqual(by_id[hypothesis_id]["source_link_relations"], {"supports": 6, "counters": 6})
                        self.assertEqual(by_id[objection_id]["source_link_count"], 6)
                        self.assertEqual(by_id[objection_id]["source_link_relations"], {"counters": 6})
                        self.assertIn("source_links", by_id[hypothesis_id]["available_sections"])
                        self.assertIn("source_links", by_id[objection_id]["available_sections"])

                        hypothesis_item = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "default", "item_id": hypothesis_id},
                        ))
                        self._assert_envelope(hypothesis_item)
                        self.assertTrue(hypothesis_item["ok"], hypothesis_item)
                        self.assertEqual(hypothesis_item["data"]["items"][0]["version_id"], hypothesis_version)
                        self.assertNotIn("source_links", hypothesis_item["data"]["items"][0].get("payload", {}))
                        hypothesis_links = await self._read_source_links(session, hypothesis_id, hypothesis_version)
                        objection_links = await self._read_source_links(session, objection_id, objection_version)

                        cross_item = await self._payload(await session.call_tool(
                            "get_research_context",
                            arguments={"project_id": "project-two", "item_id": hypothesis_id},
                        ))
                        self._assert_envelope(cross_item)
                        cross_passage = await self._payload(await session.call_tool(
                            "get_passage",
                            arguments={"project_id": "default", "passage_id": self.foreign_passage_id},
                        ))
                        self._assert_envelope(cross_passage)
                        cross_document = await self._payload(await session.call_tool(
                            "get_document_metadata",
                            arguments={"project_id": "default", "document_id": self.foreign_document_id},
                        ))
                        self._assert_envelope(cross_document)
            return (
                index, hypothesis_item, cross_item, cross_passage, cross_document,
                hypothesis_links, objection_links, names, log_path.read_text(encoding="utf-8")
            )

        (
            index, hypothesis_item, cross_item, cross_passage, cross_document,
            hypothesis_links, objection_links, names_b, logs_b
        ) = asyncio.run(session_b())
        self.assertEqual(set(names_b), set(TOOL_NAMES))
        self.assertEqual(len(names_b), 12)
        self.assertTrue(hypothesis_item["ok"])
        self.assertEqual(hypothesis_item["data"]["items"][0]["version_id"], hypothesis_version)

        expected = [("supports", passage_id, None) for passage_id in supports]
        expected += [("counters", passage_id, None) for passage_id in counters]
        actual = [
            (link["relation"], link["passage_id"], link["verified_evidence_id"])
            for link in hypothesis_links
        ]
        self.assertEqual(sorted(actual), sorted(expected))
        self.assertEqual(len(actual), len(set(actual)))
        self.assertEqual(
            sorted((link["relation"], link["passage_id"], link["verified_evidence_id"]) for link in objection_links),
            sorted(("counters", passage_id, None) for passage_id in supports),
        )
        for link in hypothesis_links:
            self.assertEqual(link["version_id"], hypothesis_version)
        for link in objection_links:
            self.assertEqual(link["version_id"], objection_version)
        for link in hypothesis_links + objection_links:
            self.assertIn("document_id", link)
            self.assertEqual(link["citation_locator"]["document_id"], link["document_id"])
            self.assertNotIn("path", json.dumps(link, ensure_ascii=False).casefold())
        self.assertFalse(cross_item["ok"])
        self.assertEqual(cross_item["error"]["code"], "NOT_FOUND")
        self.assertFalse(cross_passage["ok"])
        self.assertEqual(cross_passage["error"]["code"], "NOT_FOUND")
        self.assertFalse(cross_document["ok"])
        self.assertEqual(cross_document["error"]["code"], "NOT_FOUND")
        self.assertNotIn("Traceback", logs_b)

    def test_source_links_are_bound_to_latest_version_only(self) -> None:
        with transaction(self.settings) as connection:
            result = self.direct_agent._create_item(
                connection,
                project_id="default",
                kind="hypothesis",
                status="candidate",
                payload={
                    "title": "Version-bound links",
                    "claim": "Latest version only.",
                    "epistemic_status": "exploratory_hypothesis",
                },
                passage_links=[("supports", self.passage_ids[0])],
            )
            first_payload = connection.execute(
                "SELECT payload_json FROM research_item_versions WHERE version_id = ?",
                (result["version_id"],),
            ).fetchone()[0]
            latest_version = "ver_latest_source_links"
            connection.execute(
                """
                INSERT INTO research_item_versions(
                    version_id, item_id, version_no, payload_json, content_hash,
                    created_by, created_at
                ) VALUES (?, ?, 2, ?, ?, ?, datetime('now'))
                """,
                (
                    latest_version, result["item_id"], first_payload,
                    hashlib.sha256(first_payload.encode("utf-8")).hexdigest(),
                    self.direct_agent.actor.actor_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO evidence_links(
                    link_id, version_id, relation, passage_id, verified_evidence_id, created_at
                ) VALUES (?, ?, 'counters', ?, NULL, datetime('now'))
                """,
                ("lnk_latest_source_links", latest_version, self.passage_ids[1]),
            )
        context = self.direct_agent.get_research_context(
            project_id="default", item_id=result["item_id"], section="source_links", chunk_size=1000
        )
        item = context["items"][0]
        links = json.loads(item["section"]["content"])
        self.assertEqual(item["version_id"], latest_version)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["version_id"], latest_version)
        self.assertEqual(links[0]["relation"], "counters")
        self.assertEqual(links[0]["passage_id"], self.passage_ids[1])

    def test_client_named_source_links_cannot_override_synthetic_section(self) -> None:
        with transaction(self.settings) as connection:
            result = self.direct_agent._create_item(
                connection,
                project_id="default",
                kind="hypothesis",
                status="candidate",
                payload={
                    "title": "Payload collision",
                    "claim": "No source identifier in free text.",
                    "epistemic_status": "exploratory_hypothesis",
                    "source_links": [{"relation": "counters", "passage_id": "forged"}],
                },
                passage_links=[("supports", self.passage_ids[0])],
            )
        context = self.direct_agent.get_research_context(
            project_id="default", item_id=result["item_id"], section="source_links", chunk_size=1000
        )
        links = json.loads(context["items"][0]["section"]["content"])
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["relation"], "supports")
        self.assertEqual(links[0]["passage_id"], self.passage_ids[0])
        self.assertNotEqual(links[0]["passage_id"], "forged")
        self.assertEqual(context["items"][0]["version_id"], result["version_id"])


if __name__ == "__main__":
    unittest.main()
