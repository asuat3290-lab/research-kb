from __future__ import annotations

import sqlite3
import os
import tempfile
import unittest
from pathlib import Path

from research_kb.config import Limits, Settings
from research_kb.db import SCHEMA_VERSION, connect, migrate
from research_kb.policy import Actor, PolicyError, resolve_corpus_file
from research_kb.service import ResearchService


class FrameworkSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch_root = os.environ.get("RESEARCH_KB_TEST_TMP")
        self.temporary = tempfile.TemporaryDirectory(dir=scratch_root)
        root = Path(self.temporary.name)
        self.settings = Settings(
            config_path=root / "config.toml",
            root=root,
            database=root / "data" / "research.db",
            corpus_roots=(root / "corpus",),
            workspace=root / "workspace",
            limits=Limits(),
        )
        migrate(self.settings)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _insert_document(self) -> None:
        with connect(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO documents(
                    document_id, content_hash, title, creator, source_type, language,
                    source_date, source_version, source_name, source_uri,
                    reliability_status, verification_status, ingestion_method,
                    metadata_json, created_at
                ) VALUES (
                    'doc_one', 'hash_one', 'Research methods', 'Author', 'book', 'en',
                    '2025', '1', 'Local source', 'corpus/source.txt',
                    'unverified', 'unverified', 'test', '{}', datetime('now')
                )
                """
            )
            connection.execute(
                """
                INSERT INTO project_sources(project_id, document_id, added_at)
                VALUES ('default', 'doc_one', datetime('now'))
                """
            )
            connection.execute(
                """
                INSERT INTO passages(
                    passage_id, document_id, ordinal, location_json, text,
                    text_hash, char_start, char_end, created_at
                ) VALUES (
                    'passage_one', 'doc_one', 1, '{"section":1}',
                    'Research needs evidence and objections.', 'text_hash',
                    0, 39, datetime('now')
                )
                """
            )
            connection.commit()

    def test_database_initializes_with_integrity(self) -> None:
        with connect(self.settings) as connection:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0],
                SCHEMA_VERSION,
            )

    def test_document_identity_is_immutable_but_metadata_can_change(self) -> None:
        self._insert_document()
        with connect(self.settings) as connection:
            connection.execute(
                """
                UPDATE documents
                SET title = 'Corrected title', reliability_status = 'reviewed'
                WHERE document_id = 'doc_one'
                """
            )
            connection.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE documents SET content_hash = 'changed' WHERE document_id = 'doc_one'"
                )

    def test_passages_and_accepted_items_are_immutable(self) -> None:
        self._insert_document()
        with connect(self.settings) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE passages SET text = 'changed' WHERE passage_id = 'passage_one'"
                )
            connection.execute(
                """
                INSERT INTO research_items(
                    item_id, project_id, kind, status, created_by, created_at, updated_at
                ) VALUES (
                    'item_one', 'default', 'report', 'accepted', 'admin',
                    datetime('now'), datetime('now')
                )
                """
            )
            connection.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE research_items SET status = 'archived' WHERE item_id = 'item_one'"
                )

    def test_fts_and_service_status_work(self) -> None:
        self._insert_document()
        with connect(self.settings) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM passages_fts WHERE passages_fts MATCH 'evidence'"
                ).fetchone()[0],
                1,
            )
        actor = Actor(
            actor_id="tester",
            session_id="session",
            actor_kind="user",
            role="admin",
            framework="unittest",
        )
        result = ResearchService(self.settings, actor).status()
        self.assertTrue(result["ok"])
        self.assertEqual(result["integrity"], ["ok"])
        self.assertEqual(result["counts"]["passages"], 1)

    def test_corpus_path_policy(self) -> None:
        allowed = self.settings.corpus_roots[0] / "allowed.txt"
        allowed.write_text("source", encoding="utf-8")
        self.assertEqual(resolve_corpus_file(self.settings, allowed), allowed.resolve())

        outside = self.settings.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        with self.assertRaises(PolicyError):
            resolve_corpus_file(self.settings, outside)


    def test_agent_to_human_research_flow(self) -> None:
        self._insert_document()
        agent = Actor(
            actor_id="agent_one",
            session_id="agent_session",
            actor_kind="agent",
            role="researcher",
            framework="unittest",
            model="external-test-model",
        )
        service = ResearchService(self.settings, agent)

        search = service.search_corpus(project_id="default", query="evidence")
        self.assertEqual(search["count"], 1)
        self.assertEqual(search["results"][0]["passage_id"], "passage_one")

        hypothesis = service.submit_hypothesis(
            project_id="default",
            title="Evidence discipline",
            claim="Explicit evidence improves research discipline.",
            epistemic_status="analytical_inference",
            supporting_passage_ids=["passage_one"],
            alternative_explanations=["Workflow effects may explain part of the result."],
            open_questions=["How large is the effect?"],
            confidence="low",
        )
        objection = service.submit_objection(
            project_id="default",
            target_item_id=hypothesis["item_id"],
            objection_type="alternative_explanation",
            text="The source alone does not establish a causal effect.",
            passage_ids=["passage_one"],
        )
        self.assertEqual(objection["status"], "candidate")

        checked = service.verify_quote(
            project_id="default",
            passage_id="passage_one",
            quote="Research needs evidence",
        )
        evidence = service.submit_verified_evidence(
            project_id="default",
            verification_token=checked["verification_token"],
        )
        report = service.submit_research_report(
            project_id="default",
            question="What supports research discipline?",
            summary="Evidence and explicit objections are useful controls.",
            claims=[{
                "text": "The source states that research needs evidence.",
                "epistemic_status": "source_fact",
                "verified_evidence_ids": [evidence["verified_evidence_id"]],
            }],
            strongest_objection="A source statement is not proof of effectiveness.",
            alternative_explanations=["The process may matter more than the stored evidence."],
            unresolved_questions=["How should quality be measured?"],
            evidence_limits=["Single synthetic source."],
            next_steps=["Test with multiple source types."],
        )
        approval = service.request_user_approval(
            project_id="default", item_id=report["item_id"], rationale="Review the report"
        )
        with self.assertRaises(PolicyError):
            service.decide_approval(request_id=approval["request_id"], approve=True)

        admin = Actor("admin", "admin_session", "user", "admin", "unittest")
        decision = ResearchService(self.settings, admin).decide_approval(
            request_id=approval["request_id"], approve=True, note="Accepted in smoke test"
        )
        self.assertEqual(decision["decision"], "approved")


if __name__ == "__main__":
    unittest.main()
