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
from research_kb.policy import Actor, PolicyError
from research_kb.service import ResearchService


class Phase325FeedbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
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
        self.admin_actor = Actor("admin", "admin-session", "user", "admin", "feedback-tests")
        self.agent = ResearchService(
            self.settings, Actor("agent", "agent-session", "agent", "researcher", "feedback-tests")
        )
        self.admin = AdminService(self.settings, self.admin_actor)
        self.admin.create_project(project_id="pilot", title="Pilot", objective="Feedback")
        self.corpus = self.settings.corpus_roots[0]
        self.corpus.mkdir(parents=True, exist_ok=True)
        self.source = self.corpus / "explicit-source.txt"
        self.source.write_text("A passage about cooperative self-determination and non-alienated labor.", encoding="utf-8")
        self.ingested = ingest_file(
            self.settings, self.admin_actor, self.source, project_id="pilot",
            title="Explicit source title", creator="Explicit Author",
            source_type="journal_article", language="en", source_date="2025",
            source_version="publisher-pdf", source_name="Explicit Journal",
            metadata={"bibliographic_profile": {
                "type": "journal_article", "authors": ["Explicit Author"],
                "title": "Explicit source title", "container_title": "Explicit Journal",
                "year": 2025, "volume": 12, "issue": 2,
                "page_range": "10-25", "doi": "unknown", "publisher": "unknown",
            }},
        )
        with connect(self.settings, read_only=True) as connection:
            self.passage_id = connection.execute(
                "SELECT passage_id FROM passages WHERE document_id = ? ORDER BY ordinal LIMIT 1",
                (self.ingested["document_id"],),
            ).fetchone()[0]

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_citation_profile_locator_and_unknowns_are_backward_compatible(self) -> None:
        metadata = self.agent.get_document_metadata(project_id="pilot", document_id=self.ingested["document_id"])
        self.assertEqual(metadata["title"], "Explicit source title")
        self.assertEqual(metadata["citation_record"]["authors"], ["Explicit Author"])
        self.assertEqual(metadata["citation_record"]["page_range"], "10-25")
        self.assertEqual(metadata["citation_locator"]["passage_id"], "unknown")
        self.assertEqual(metadata["citation_locator"]["document_id"], self.ingested["document_id"])
        passage = self.agent.get_passage(project_id="pilot", passage_id=self.passage_id, context=0)
        self.assertEqual(passage["citation_record"], metadata["citation_record"])
        self.assertEqual(passage["citation_locator"]["passage_id"], self.passage_id)
        self.assertEqual(passage["citation_locator"]["source_version"], "publisher-pdf")
        self.assertNotIn("source_uri", passage["citation_record"])

        no_profile = self.corpus / "missing-profile.txt"
        no_profile.write_text("No explicit bibliography here.", encoding="utf-8")
        ingested = ingest_file(
            self.settings, self.admin_actor, no_profile, project_id="pilot",
            title="Explicit second title", creator="unknown", source_type="journal_article",
            language="en", source_version="v1", source_name="unknown",
        )
        result = self.agent.get_document_metadata(project_id="pilot", document_id=ingested["document_id"])
        self.assertEqual(result["citation_record"]["authors"], "unknown")
        self.assertEqual(result["citation_record"]["container_title"], "unknown")
        self.assertNotIn("missing-profile", json.dumps(result, ensure_ascii=False))

    def test_admin_metadata_profile_is_audited_and_book_fields_are_supported(self) -> None:
        self.admin.metadata_update(
            project_id="pilot", document_id=self.ingested["document_id"],
            updates={"source_type": "book", "metadata_json": {
                "bibliographic_profile": {
                    "type": "book", "authors": ["Book Author"], "editors": "unknown",
                    "translators": "unknown", "title": "Book title", "edition": "2nd",
                    "place": "unknown", "publisher": "Explicit Publisher", "year": 2024,
                    "isbn": "unknown",
                }
            }},
            reason="Test explicit book profile correction",
        )
        result = self.agent.get_document_metadata(project_id="pilot", document_id=self.ingested["document_id"])
        self.assertEqual(result["citation_record"]["source_type"], "book")
        self.assertEqual(result["citation_record"]["edition"], "2nd")
        self.assertEqual(result["citation_record"]["isbn"], "unknown")
        with connect(self.settings, read_only=True) as connection:
            row = connection.execute(
                "SELECT old_values_json, new_values_json, reason, actor_id, created_at FROM source_metadata_audit WHERE document_id = ? ORDER BY audit_id DESC LIMIT 1",
                (self.ingested["document_id"],),
            ).fetchone()
        self.assertEqual(row["reason"], "Test explicit book profile correction")
        self.assertEqual(row["actor_id"], "admin")
        self.assertIn("journal_article", row["old_values_json"])
        self.assertIn("book", row["new_values_json"])
        self.assertTrue(row["created_at"])

    def test_discovery_report_has_three_to_six_leads_and_passage_links(self) -> None:
        record = self.agent.get_document_metadata(project_id="pilot", document_id=self.ingested["document_id"])
        leads = []
        for i in range(3):
            leads.append({
                "idea": f"Lead {i}",
                "source_bridges": ["source A", "source B"],
                "supporting_passage_ids": [self.passage_id],
                "why_not_literature_summary": "It proposes a cross-source mechanism.",
                "possible_counterevidence": ["A source with the opposite premise"],
                "missing_evidence": ["A comparative case"],
                "next_search": ["Search for a boundary condition"],
                "epistemic_status": "exploratory_hypothesis",
                "confidence": "low",
            })
        result = self.agent.submit_research_report(
            project_id="pilot", question="How do sources differ?", summary="A candidate synthesis.",
            claims=[{"text": "The sources share a concern.", "epistemic_status": "source_interpretation"}],
            strongest_objection="The corpus may be too small.", alternative_explanations=["Different terminology"],
            unresolved_questions=["What is the boundary?"], evidence_limits=["No external sources"],
            next_steps=["Search for a counterexample"], research_leads=leads,
            source_table=[{"document_id": self.ingested["document_id"], "citation_record": record["citation_record"]}],
        )
        self.assertEqual(result["status"], "candidate")
        context = self.agent.get_research_context(project_id="pilot", detail="full")
        item = next(item for item in context["items"] if item["item_id"] == result["item_id"])
        self.assertEqual(len(item["payload"]["research_leads"]), 3)
        self.assertEqual(item["payload"]["source_table"][0]["document_id"], self.ingested["document_id"])
        with connect(self.settings, read_only=True) as connection:
            links = connection.execute(
                "SELECT COUNT(*) FROM evidence_links WHERE version_id = ? AND passage_id = ?",
                (result["version_id"], self.passage_id),
            ).fetchone()[0]
        self.assertEqual(links, 1)

    def test_report_citations_are_server_canonical(self) -> None:
        checked = self.agent.verify_quote(
            project_id="pilot", passage_id=self.passage_id,
            quote="A passage about cooperative",
        )
        evidence = self.agent.submit_verified_evidence(
            project_id="pilot", verification_token=checked["verification_token"]
        )
        metadata = self.agent.get_document_metadata(
            project_id="pilot", document_id=self.ingested["document_id"]
        )
        passage = self.agent.get_passage(
            project_id="pilot", passage_id=self.passage_id, context=0
        )
        forged_record = dict(metadata["citation_record"])
        forged_record.update({"authors": ["Forged Author"], "year": 1900, "doi": "10/forged"})
        forged_locator = dict(passage["citation_locator"])
        forged_locator.update({"page": 999, "source_version": "forged-version"})
        result = self.agent.submit_research_report(
            project_id="pilot", question="Canonical citation test", summary="Server-owned citations.",
            claims=[{
                "text": "A source interpretation.", "epistemic_status": "source_interpretation",
                "verified_evidence_ids": [evidence["verified_evidence_id"]],
            }],
            strongest_objection="Client citation fields are untrusted.", alternative_explanations=[],
            unresolved_questions=[], evidence_limits=[], next_steps=[],
            source_table=[{"document_id": self.ingested["document_id"], "citation_record": forged_record}],
            evidence_citation_map=[{
                "evidence_id": evidence["verified_evidence_id"],
                "passage_id": self.passage_id,
                "document_id": self.ingested["document_id"],
                "citation_record": forged_record,
                "citation_locator": forged_locator,
            }],
        )
        context = self.agent.get_research_context(project_id="pilot", detail="full")
        item = next(item for item in context["items"] if item["item_id"] == result["item_id"])
        payload = item["payload"]
        self.assertEqual(payload["source_table"][0]["citation_record"], metadata["citation_record"])
        self.assertEqual(payload["evidence_citation_map"][0]["citation_record"], passage["citation_record"])
        self.assertEqual(payload["evidence_citation_map"][0]["citation_locator"], passage["citation_locator"])
        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("Forged Author", serialized)
        self.assertNotIn("forged-version", serialized)
        self.assertNotIn("10/forged", serialized)

    def test_successor_blocks_approval_but_allows_explicit_rejection(self) -> None:
        old = self.agent.submit_hypothesis(
            project_id="pilot", title="old candidate", claim="old", epistemic_status="exploratory_hypothesis"
        )
        request = self.agent.request_user_approval(
            project_id="pilot", item_id=old["item_id"], target_type="research_item"
        )
        successor = self.agent.submit_hypothesis(
            project_id="pilot", title="successor candidate", claim="corrected", 
            epistemic_status="exploratory_hypothesis", supersedes_item_id=old["item_id"]
        )
        self.assertEqual(successor["status"], "candidate")
        with self.assertRaises(PolicyError):
            self.admin.decide_approval(request_id=request["request_id"], approve=True, note="must not approve old item")
        rejected = self.admin.decide_approval(
            request_id=request["request_id"], approve=False, note="old item superseded"
        )
        self.assertEqual(rejected["decision"], "rejected")

    @unittest.skipUnless(os.environ.get("RESEARCH_KB_PILOT_CONFIG"), "pilot config not provided")
    def test_pilot_ascii_profile_and_official_client_round_trip(self) -> None:
        from research_kb.config import Settings

        settings = Settings.load(os.environ["RESEARCH_KB_PILOT_CONFIG"])
        admin = AdminService(
            settings, Actor("readonly-audit", "readonly-audit-session", "user", "admin", "feedback-tests")
        )
        expected = {
            "doc_d422da2065a322182708": {"page_range": "417-433"},
            "doc_93312e7e3120fd60f1be": {
                "title": "'Alienation' and critique in Marx's manuscripts of 1857-58 ('Grundrisse')"
            },
            "doc_044461d912b34cd4916b": {
                "title": "Rahel Jaeggi's theory of alienation", "page_range": "126-143"
            },
            "doc_6102ba2b793e3983c38e": {"page_range": "29-55"},
        }
        records = {}
        for document_id, fields in expected.items():
            record = admin.metadata_show(project_id="pilot", document_id=document_id)["citation_record"]
            records[document_id] = record
            for field, value in fields.items():
                self.assertEqual(record[field], value)
            encoded = json.dumps(record, ensure_ascii=False).encode("utf-8")
            self.assertEqual(json.loads(encoded.decode("utf-8")), record)

        async def flow() -> None:
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "research_kb.mcp_server", "--config", str(settings.config_path)],
                env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
                cwd=str(Path(__file__).parents[1]),
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    for document_id, expected_record in records.items():
                        result = await session.call_tool(
                            "get_document_metadata", {"project_id": "pilot", "document_id": document_id}
                        )
                        structured = getattr(result, "structuredContent", None)
                        if not structured:
                            structured = json.loads("".join(item.text for item in result.content if hasattr(item, "text")))
                        self.assertTrue(structured["ok"])
                        self.assertEqual(structured["data"]["citation_record"], expected_record)

        asyncio.run(flow())

    def test_official_client_sees_citation_fields_and_report_schema(self) -> None:
        async def flow() -> None:
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "research_kb.mcp_server", "--config", str(self.settings.config_path)],
                env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
                cwd=str(Path(__file__).parents[1]),
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    self.assertEqual(len(listed.tools), 12)
                    report_tool = next(tool for tool in listed.tools if tool.name == "submit_research_report")
                    properties = report_tool.inputSchema["properties"]
                    self.assertIn("research_leads", properties)
                    self.assertIn("source_table", properties)
                    result = await session.call_tool("get_passage", {
                        "project_id": "pilot", "passage_id": self.passage_id, "context": 0,
                    })
                    structured = getattr(result, "structuredContent", None)
                    if not structured:
                        structured = json.loads("".join(item.text for item in result.content if hasattr(item, "text")))
                    self.assertTrue(structured["ok"])
                    self.assertIn("citation_record", structured["data"])
                    self.assertIn("citation_locator", structured["data"])
                    metadata_result = await session.call_tool("get_document_metadata", {
                        "project_id": "pilot", "document_id": self.ingested["document_id"]
                    })
                    metadata = getattr(metadata_result, "structuredContent", None)
                    if not metadata:
                        metadata = json.loads("".join(item.text for item in metadata_result.content if hasattr(item, "text")))
                    forged_report = await session.call_tool("submit_research_report", {
                        "project_id": "pilot",
                        "question": "official client canonical citation",
                        "summary": "The client citation is untrusted.",
                        "claims": [{"text": "A source interpretation.", "epistemic_status": "source_interpretation"}],
                        "strongest_objection": "The client can forge metadata.",
                        "alternative_explanations": [], "unresolved_questions": [],
                        "evidence_limits": [], "next_steps": [],
                        "source_table": [{"document_id": self.ingested["document_id"], "citation_record": {
                            "document_id": self.ingested["document_id"], "content_hash": "forged-hash",
                            "source_version": "forged-version", "authors": ["Forged Author"],
                            "title": "Forged title", "year": 1900, "doi": "10/forged"
                        }}],
                    })
                    forged_payload = getattr(forged_report, "structuredContent", None)
                    if not forged_payload:
                        forged_payload = json.loads("".join(item.text for item in forged_report.content if hasattr(item, "text")))
                    self.assertTrue(forged_payload["ok"])
                    context_result = await session.call_tool("get_research_context", {
                        "project_id": "pilot", "detail": "full"
                    })
                    context = getattr(context_result, "structuredContent", None)
                    if not context:
                        context = json.loads("".join(item.text for item in context_result.content if hasattr(item, "text")))
                    item = next(item for item in context["data"]["items"] if item["item_id"] == forged_payload["data"]["item_id"])
                    canonical = item["payload"]["source_table"][0]["citation_record"]
                    self.assertEqual(canonical, metadata["data"]["citation_record"])
                    self.assertNotIn("Forged Author", json.dumps(item["payload"], ensure_ascii=False))
                    self.assertNotIn("forged-version", json.dumps(item["payload"], ensure_ascii=False))

        asyncio.run(flow())


if __name__ == "__main__":
    unittest.main()
