from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from research_kb.admin import AdminService
from research_kb.config import Limits, Settings
from research_kb.db import connect, migrate
from research_kb.doctor import run_doctor
from research_kb.mcp_server import create_mcp_server
from research_kb.policy import Actor, PolicyError
from research_kb.service import ResearchService
from research_kb.system_manifest import EXPECTED_MCP_TOOLS
import research_kb.service as service_module


class SG1B1CheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
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
        self.actor = Actor("sg1b1-agent", "sg1b1-session", "agent", "researcher", "test")
        self.service = ResearchService(self.settings, self.actor)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _payload(self, item_id: str) -> dict:
        with connect(self.settings, read_only=True) as connection:
            row = connection.execute(
                """
                SELECT riv.payload_json
                FROM research_item_versions riv
                WHERE riv.item_id = ?
                  AND riv.version_no = (
                      SELECT MAX(latest.version_no)
                      FROM research_item_versions latest
                      WHERE latest.item_id = riv.item_id
                  )
                """,
                (item_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return json.loads(row["payload_json"])

    def _count_items(self) -> int:
        with connect(self.settings, read_only=True) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM research_items").fetchone()[0])

    def _write_counts(self) -> tuple[int, int, int, int]:
        with connect(self.settings, read_only=True) as connection:
            return tuple(
                int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("research_items", "research_item_versions", "audit_log", "evidence_links")
            )

    def _current_checkpoint_ids(self) -> list[str]:
        with connect(self.settings, read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT ri.item_id
                FROM research_items ri
                JOIN research_item_versions riv ON riv.item_id = ri.item_id
                WHERE ri.project_id = 'default'
                  AND ri.kind = 'note'
                  AND ri.status NOT IN ('archived', 'rejected')
                  AND riv.version_no = (
                      SELECT MAX(latest.version_no)
                      FROM research_item_versions latest
                      WHERE latest.item_id = ri.item_id
                  )
                  AND json_extract(riv.payload_json, '$.schema') = 'research-checkpoint/v1'
                  AND NOT EXISTS (
                      SELECT 1 FROM research_items successor
                      WHERE successor.supersedes_item_id = ri.item_id
                  )
                ORDER BY ri.item_id
                """
            ).fetchall()
        return [str(row["item_id"]) for row in rows]

    def _empty_report(self, *, supersedes_item_id: str | None = None) -> dict:
        return self.service.submit_research_report(
            project_id="default",
            question="What is the bounded report question?",
            summary="A candidate report used only for successor validation.",
            claims=[
                {
                    "claim_id": "C001",
                    "text": "This is an exploratory test claim.",
                    "epistemic_status": "exploratory_hypothesis",
                    "verified_evidence_ids": [],
                }
            ],
            strongest_objection="The fixture is intentionally small.",
            alternative_explanations=[],
            unresolved_questions=[],
            evidence_limits=[],
            next_steps=[],
            supersedes_item_id=supersedes_item_id,
        )

    def _stdio_params(self) -> StdioServerParameters:
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
    async def _mcp_payload(result) -> dict:
        structured = getattr(result, "structuredContent", None)
        if structured:
            return structured
        text_blocks = [item.text for item in result.content if hasattr(item, "text")]
        if not text_blocks:
            raise AssertionError("MCP result contained no JSON content")
        return json.loads(text_blocks[0])

    def _insert_item(
        self,
        item_id: str,
        *,
        project_id: str = "default",
        kind: str = "note",
        status: str = "candidate",
        payload: dict | None = None,
        supersedes_item_id: str | None = None,
    ) -> None:
        data = payload or {"schema": "research-checkpoint/v1"}
        serialized = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        with connect(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO research_items(
                    item_id, project_id, kind, status, created_by,
                    supersedes_item_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'fixture', ?, datetime('now'), datetime('now'))
                """,
                (item_id, project_id, kind, status, supersedes_item_id),
            )
            connection.execute(
                """
                INSERT INTO research_item_versions(
                    version_id, item_id, version_no, payload_json,
                    content_hash, created_by, created_at
                ) VALUES (?, ?, 1, ?, 'fixture-hash', 'fixture', datetime('now'))
                """,
                (f"{item_id}-v1", item_id, serialized),
            )

    def test_old_three_argument_call_and_default_note_are_unchanged(self) -> None:
        result = self.service.save_research_note(
            project_id="default", title="  ordinary note  ", body="  ordinary body  "
        )
        payload = self._payload(result["item_id"])
        self.assertEqual(result["kind"], "note")
        self.assertEqual(result["status"], "draft")
        self.assertEqual(payload, {
            "body": "ordinary body",
            "epistemic_status": "unresolved",
            "title": "ordinary note",
        })
        self.assertNotIn("schema", payload)

    def test_first_checkpoint_payload_is_server_generated_and_recoverable(self) -> None:
        result = self.service.save_research_note(
            project_id="default",
            title="Round checkpoint",
            body="Question and next step",
            note_purpose="checkpoint",
        )
        payload = self._payload(result["item_id"])
        self.assertEqual(payload["schema"], "research-checkpoint/v1")
        self.assertEqual(payload["checkpoint_version"], 1)
        self.assertEqual(payload["title"], "Round checkpoint")
        self.assertEqual(payload["body"], "Question and next step")
        metadata = payload["checkpoint_metadata"]
        self.assertEqual(metadata["project_id"], "default")
        self.assertEqual(metadata["created_by"], self.actor.actor_id)
        self.assertEqual(metadata["session_id"], self.actor.session_id)
        self.assertIsInstance(metadata["created_at"], str)

        other = ResearchService(
            self.settings,
            Actor("other-agent", "other-session", "agent", "researcher", "test"),
        )
        recovered = other.get_research_context(
            project_id="default", item_id=result["item_id"], section="body", chunk_size=256
        )
        self.assertEqual(recovered["items"][0]["section"]["content"], "Question and next step")

    def test_client_body_cannot_override_checkpoint_metadata(self) -> None:
        body = json.dumps({
            "schema": "attacker/schema",
            "checkpoint_version": 999,
            "checkpoint_metadata": {"project_id": "attacker", "created_by": "attacker"},
        })
        result = self.service.save_research_note(
            project_id="default", title="safe", body=body, note_purpose="checkpoint"
        )
        payload = self._payload(result["item_id"])
        self.assertEqual(payload["schema"], "research-checkpoint/v1")
        self.assertEqual(payload["checkpoint_version"], 1)
        self.assertEqual(payload["checkpoint_metadata"]["project_id"], "default")
        self.assertEqual(payload["checkpoint_metadata"]["created_by"], self.actor.actor_id)
        self.assertEqual(payload["body"], body)

    def test_doctor_recognizes_a_service_created_standard_current(self) -> None:
        self.service.save_research_note(
            project_id="default", title="doctor checkpoint", body="body", note_purpose="checkpoint"
        )
        report = run_doctor(self.settings.config_path)
        finding = next(item for item in report["checks"] if item["id"] == "checkpoint_one_current")
        self.assertEqual(finding["details"]["standard_checkpoint_count"], 1)
        self.assertEqual(finding["details"]["legacy_candidate_count"], 0)

    def test_checkpoint_requires_current_successor_and_allows_ordinary_note(self) -> None:
        first = self.service.save_research_note(
            project_id="default", title="first", body="first", note_purpose="checkpoint"
        )
        ordinary = self.service.save_research_note(
            project_id="default", title="ordinary", body="ordinary", note_purpose="research_note"
        )
        self.assertNotIn("schema", self._payload(ordinary["item_id"]))
        with self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
            self.service.save_research_note(
                project_id="default", title="missing successor", body="body", note_purpose="checkpoint"
            )
        second = self.service.save_research_note(
            project_id="default",
            title="second",
            body="second",
            note_purpose="checkpoint",
            supersedes_item_id=first["item_id"],
        )
        self.assertEqual(self._payload(second["item_id"])["checkpoint_version"], 1)
        with self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
            self.service.save_research_note(
                project_id="default",
                title="replay",
                body="replay",
                note_purpose="checkpoint",
                supersedes_item_id=first["item_id"],
            )

    def test_invalid_checkpoint_targets_fail_closed(self) -> None:
        ordinary = self.service.save_research_note(
            project_id="default", title="ordinary", body="ordinary"
        )
        hypothesis = self.service.submit_hypothesis(
            project_id="default",
            title="hypothesis",
            claim="claim",
            epistemic_status="exploratory_hypothesis",
        )
        for target in (ordinary["item_id"], hypothesis["item_id"], "foreign-item"):
            with self.subTest(target=target), self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
                self.service.save_research_note(
                    project_id="default",
                    title="invalid target",
                    body="body",
                    note_purpose="checkpoint",
                    supersedes_item_id=target,
                )
        with self.assertRaisesRegex(PolicyError, "only valid"):
            self.service.save_research_note(
                project_id="default",
                title="ordinary target",
                body="body",
                supersedes_item_id=ordinary["item_id"],
            )

    def test_hypothesis_report_and_ordinary_note_cannot_supersede_checkpoint(self) -> None:
        first = self.service.save_research_note(
            project_id="default", title="first", body="first", note_purpose="checkpoint"
        )
        before = self._write_counts()
        with self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
            self.service.submit_hypothesis(
                project_id="default",
                title="bad hypothesis successor",
                claim="This must not break the checkpoint chain.",
                epistemic_status="exploratory_hypothesis",
                supersedes_item_id=first["item_id"],
            )
        self.assertEqual(self._write_counts(), before)
        self.assertEqual(self._current_checkpoint_ids(), [first["item_id"]])

        with self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
            self._empty_report(supersedes_item_id=first["item_id"])
        self.assertEqual(self._write_counts(), before)
        self.assertEqual(self._current_checkpoint_ids(), [first["item_id"]])

        with self.assertRaisesRegex(PolicyError, "only valid"):
            self.service.save_research_note(
                project_id="default",
                title="ordinary cannot supersede",
                body="ordinary body",
                note_purpose="research_note",
                supersedes_item_id=first["item_id"],
            )
        self.assertEqual(self._write_counts(), before)
        self.assertEqual(self._current_checkpoint_ids(), [first["item_id"]])

    def test_checkpoint_bypass_sequence_is_closed_and_correct_successor_still_works(self) -> None:
        first = self.service.save_research_note(
            project_id="default", title="first", body="first", note_purpose="checkpoint"
        )
        for attempt in ("hypothesis", "report"):
            with self.subTest(attempt=attempt), self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
                if attempt == "hypothesis":
                    self.service.submit_hypothesis(
                        project_id="default",
                        title="blocked",
                        claim="blocked",
                        epistemic_status="exploratory_hypothesis",
                        supersedes_item_id=first["item_id"],
                    )
                else:
                    self._empty_report(supersedes_item_id=first["item_id"])
        with self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
            self.service.save_research_note(
                project_id="default", title="new root", body="new root", note_purpose="checkpoint"
            )
        second = self.service.save_research_note(
            project_id="default",
            title="successor",
            body="successor",
            note_purpose="checkpoint",
            supersedes_item_id=first["item_id"],
        )
        self.assertEqual(self._current_checkpoint_ids(), [second["item_id"]])

    def test_non_checkpoint_hypothesis_and_report_successors_remain_legal(self) -> None:
        hypothesis = self.service.submit_hypothesis(
            project_id="default",
            title="hypothesis one",
            claim="first",
            epistemic_status="exploratory_hypothesis",
        )
        hypothesis_successor = self.service.submit_hypothesis(
            project_id="default",
            title="hypothesis two",
            claim="second",
            epistemic_status="exploratory_hypothesis",
            supersedes_item_id=hypothesis["item_id"],
        )
        self.assertEqual(hypothesis_successor["kind"], "hypothesis")

        report = self._empty_report()
        report_successor = self._empty_report(supersedes_item_id=report["item_id"])
        self.assertEqual(report_successor["kind"], "report")

    def test_doctor_reports_historical_cross_kind_checkpoint_successor_without_content(self) -> None:
        self._insert_item(
            "checkpoint-root",
            payload={"schema": "research-checkpoint/v1", "checkpoint_version": 1},
        )
        self._insert_item(
            "hypothesis-breaker",
            kind="hypothesis",
            payload={"claim": "SECRET_RESEARCH_BODY"},
            supersedes_item_id="checkpoint-root",
        )
        report = run_doctor(self.settings.config_path)
        findings = [
            item for item in report["checks"]
            if item["id"] == "checkpoint_cross_kind_successor"
        ]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["severity"], "P1")
        self.assertEqual(finding["details"]["project_id"], "default")
        self.assertEqual(finding["details"]["checkpoint_item_id"], "checkpoint-root")
        self.assertEqual(finding["details"]["successor_item_id"], "hypothesis-breaker")
        self.assertEqual(finding["details"]["successor_kind"], "hypothesis")
        self.assertEqual(finding["details"]["anomaly_count"], 1)
        self.assertNotIn("SECRET_RESEARCH_BODY", json.dumps(report, ensure_ascii=False))

    def test_official_mcp_client_rejects_hypothesis_and_report_checkpoint_bypass(self) -> None:
        first = self.service.save_research_note(
            project_id="default", title="first", body="first", note_purpose="checkpoint"
        )

        async def flow() -> tuple[list[str], list[dict]]:
            with (self.root / "mcp-stderr.log").open("w+", encoding="utf-8") as errlog:
                async with stdio_client(self._stdio_params(), errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        hypothesis = await session.call_tool(
                            "submit_hypothesis",
                            arguments={
                                "project_id": "default",
                                "title": "blocked hypothesis",
                                "claim": "blocked",
                                "epistemic_status": "exploratory_hypothesis",
                                "supersedes_item_id": first["item_id"],
                            },
                        )
                        report = await session.call_tool(
                            "submit_research_report",
                            arguments={
                                "project_id": "default",
                                "question": "blocked report",
                                "summary": "blocked",
                                "claims": [{
                                    "claim_id": "C001",
                                    "text": "blocked",
                                    "epistemic_status": "exploratory_hypothesis",
                                    "verified_evidence_ids": [],
                                }],
                                "strongest_objection": "blocked",
                                "supersedes_item_id": first["item_id"],
                            },
                        )
                        return (
                            [tool.name for tool in listed.tools],
                            [await self._mcp_payload(hypothesis), await self._mcp_payload(report)],
                        )

        names, failures = asyncio.run(flow())
        self.assertEqual(len(names), 12)
        self.assertEqual(len(set(names)), 12)
        for failure in failures:
            self.assertEqual(
                set(failure), {"ok", "protocol", "schema_version", "error", "warnings", "trace_id"}
            )
            self.assertFalse(failure["ok"])
            self.assertEqual(failure["error"]["code"], "CONFLICT")
            self.assertEqual(failure["error"]["message"], "The source or research state conflicts with this operation.")
            self.assertEqual(failure["warnings"], [])
            self.assertNotIn(first["item_id"], json.dumps(failure, ensure_ascii=False))

    def test_cross_project_and_rejected_archived_targets_fail(self) -> None:
        AdminService(
            self.settings,
            Actor("admin", "admin-session", "user", "admin", "test"),
        ).create_project(project_id="project-two", title="Two", objective="Isolation")
        foreign = ResearchService(
            self.settings,
            Actor("foreign-agent", "foreign-session", "agent", "researcher", "test"),
        ).save_research_note(
            project_id="project-two", title="foreign", body="foreign", note_purpose="checkpoint"
        )
        with self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
            self.service.save_research_note(
                project_id="default",
                title="cross project",
                body="body",
                note_purpose="checkpoint",
                supersedes_item_id=foreign["item_id"],
            )

        for status in ("rejected", "archived"):
            item_id = f"{status}-checkpoint"
            self._insert_item(item_id, status=status)
            with self.subTest(status=status), self.assertRaisesRegex(PolicyError, "checkpoint conflict"):
                self.service.save_research_note(
                    project_id="default",
                    title="inactive target",
                    body="body",
                    note_purpose="checkpoint",
                    supersedes_item_id=item_id,
                )

    def test_multiple_current_checkpoints_fail_closed_without_insertion(self) -> None:
        self._insert_item("current-a")
        self._insert_item("current-b")
        before = self._count_items()
        with self.assertRaisesRegex(PolicyError, "multiple current checkpoints"):
            self.service.save_research_note(
                project_id="default", title="blocked", body="blocked", note_purpose="checkpoint"
            )
        self.assertEqual(self._count_items(), before)

    def test_successor_chain_is_acyclic_and_old_versions_are_preserved(self) -> None:
        first = self.service.save_research_note(
            project_id="default", title="one", body="one", note_purpose="checkpoint"
        )
        second = self.service.save_research_note(
            project_id="default",
            title="two",
            body="two",
            note_purpose="checkpoint",
            supersedes_item_id=first["item_id"],
        )
        with connect(self.settings, read_only=True) as connection:
            rows = connection.execute(
                "SELECT item_id, supersedes_item_id FROM research_items WHERE kind = 'note' ORDER BY item_id"
            ).fetchall()
        mapping = {row["item_id"]: row["supersedes_item_id"] for row in rows}
        self.assertEqual(mapping[second["item_id"]], first["item_id"])
        self.assertIsNone(mapping[first["item_id"]])
        for item_id in mapping:
            seen: set[str] = set()
            cursor = item_id
            while cursor is not None:
                self.assertNotIn(cursor, seen)
                seen.add(cursor)
                cursor = mapping.get(cursor)

    def test_self_successor_cycle_is_rejected_before_insert(self) -> None:
        first = self.service.save_research_note(
            project_id="default", title="one", body="one", note_purpose="checkpoint"
        )
        before = self._count_items()
        with patch.object(service_module, "_id", return_value=first["item_id"]):
            with self.assertRaisesRegex(PolicyError, "successor cycle"):
                self.service.save_research_note(
                    project_id="default",
                    title="cycle",
                    body="cycle",
                    note_purpose="checkpoint",
                    supersedes_item_id=first["item_id"],
                )
        self.assertEqual(self._count_items(), before)

    def test_concurrent_supersede_allows_at_most_one_success_for_twenty_rounds(self) -> None:
        current: str | None = None
        for round_no in range(20):
            def attempt(slot: int) -> object:
                actor = Actor(
                    f"concurrent-{round_no}-{slot}",
                    f"concurrent-session-{round_no}-{slot}",
                    "agent",
                    "researcher",
                    "test",
                )
                service = ResearchService(self.settings, actor)
                try:
                    return service.save_research_note(
                        project_id="default",
                        title=f"round {round_no} slot {slot}",
                        body="bounded checkpoint",
                        note_purpose="checkpoint",
                        supersedes_item_id=current,
                    )
                except Exception as exc:  # the loser is expected to be a conflict
                    return exc

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(attempt, (0, 1)))
            successes = [item for item in outcomes if isinstance(item, dict)]
            failures = [item for item in outcomes if isinstance(item, Exception)]
            self.assertEqual(len(successes), 1, outcomes)
            self.assertEqual(len(failures), 1, outcomes)
            self.assertIsInstance(failures[0], PolicyError)
            current = successes[0]["item_id"]

        with connect(self.settings, read_only=True) as connection:
            current_rows = connection.execute(
                """
                SELECT ri.item_id
                FROM research_items ri
                JOIN research_item_versions riv ON riv.item_id = ri.item_id
                WHERE ri.kind = 'note'
                  AND riv.version_no = 1
                  AND json_extract(riv.payload_json, '$.schema') = 'research-checkpoint/v1'
                  AND NOT EXISTS (
                      SELECT 1 FROM research_items successor
                      WHERE successor.supersedes_item_id = ri.item_id
                  )
                """
            ).fetchall()
        self.assertEqual([row["item_id"] for row in current_rows], [current])

    def test_mcp_schema_adds_optional_fields_without_changing_twelve_tools(self) -> None:
        server = create_mcp_server(self.settings)
        listed = asyncio.run(server.list_tools())
        self.assertEqual(tuple(tool.name for tool in listed), EXPECTED_MCP_TOOLS)
        save_tool = next(tool for tool in listed if tool.name == "save_research_note")
        properties = save_tool.inputSchema["properties"]
        self.assertIn("note_purpose", properties)
        self.assertIn("supersedes_item_id", properties)
        self.assertEqual(properties["note_purpose"]["enum"], ["research_note", "checkpoint"])


if __name__ == "__main__":
    unittest.main()
