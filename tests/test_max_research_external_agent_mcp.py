from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from research_kb.max_research.external_agent import ExternalAgentService
from research_kb.max_research.external_agent_mcp_server import MAX_CONTROL_MCP_TOOLS
from research_kb.max_research.persistence import MaxControlRepository
from research_kb.policy import Actor


class _ServerSourceResolver:
    """Server-owned source binding used only to seed the disposable control DB."""

    def resolve_reference(self, *, project_id: str, reference: dict[str, object]):
        if reference.get("passage_id") == "mr1:passage:source-a":
            return {
                "project_id": project_id,
                "document_id": "mr1:document:source-a",
                "passage_id": "mr1:passage:source-a",
            }
        return None


class ExternalAgentMCPTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mr-external-agent-mcp-")
        self.root = Path(self.temp.name)
        self.database = self.root / "control.db"
        self.project_id = "external-agent-mcp-project"
        self.admin = Actor("admin", "admin-session", "user", "admin", "test")
        repository = MaxControlRepository(self.database)
        repository.initialize()
        charter = {
            "question": "Which bounded source observations can an external Agent submit?",
            "scope": "MCP transport fixture",
            "invariants": ["server-owned source references", "candidate-only results"],
            "non_goals": ["provider execution", "automatic acceptance"],
            "deliverables": ["two transport rounds"],
            "model_identity": "external-agent-transport-test",
            "budget": {"iteration_count": 2, "input_tokens": 500, "output_tokens": 300, "cost_units": 0},
            "source_policy": {"mode": "server-resolved"},
            "quality_gates": {"require_human_approval": True},
        }
        proposed = repository.propose(project_id=self.project_id, charter=charter, actor=self.admin)
        repository.approve(
            run_id=proposed["run_id"],
            charter_hash_value=proposed["charter_hash"],
            reason="transport fixture start",
            actor=self.admin,
        )
        started = repository.start(run_id=proposed["run_id"], actor=self.admin)
        iteration = repository.begin_iteration(
            run_id=proposed["run_id"],
            round_type="exploration",
            actor=self.admin,
            fencing_token=started["lease"]["fencing_token"],
        )
        self.run_id = proposed["run_id"]
        self.iteration_id = iteration["iteration_id"]
        self.control = ExternalAgentService(
            repository,
            self.admin,
            source_resolver=_ServerSourceResolver(),
        )
        self.packet = self.control.issue_work_packet(
            project_id=self.project_id,
            run_id=self.run_id,
            iteration_id=self.iteration_id,
            question="Which bounded observation is directly supported?",
            role="evidence-mapper",
            source_refs=[{"passage_id": "mr1:passage:source-a"}],
            round_no=1,
        )["packet"]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _params(self, *, actor_id: str, actor_session: str) -> StdioServerParameters:
        env = dict(os.environ)
        if os.environ.get("RESEARCH_KB_USE_SOURCE") == "1":
            env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        elif os.environ.get("RESEARCH_KB_USE_INSTALLED") == "1":
            env["PYTHONPATH"] = os.environ.get("PYTHONPATH", "")
        else:
            env.pop("PYTHONPATH", None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "research_kb.max_research.external_agent_mcp_server",
                "--database",
                str(self.database),
                "--actor-id",
                actor_id,
                "--actor-session",
                actor_session,
                "--allowed-project",
                self.project_id,
            ],
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

    @staticmethod
    def _candidate(text: str = "The permitted passage supports one bounded observation.") -> dict[str, object]:
        return {
            "candidate_claims": [
                {
                    "text": text,
                    "epistemic_status": "candidate",
                    "source_refs": ["mr1:passage:source-a"],
                    "rationale": "The claim is limited to the server-bound passage.",
                }
            ],
            "evidence_links": [{"source_ref": "mr1:passage:source-a", "relation": "supports"}],
            "objections": [{"text": "The passage does not establish a general law.", "source_refs": ["mr1:passage:source-a"]}],
            "unresolved_questions": ["What additional source would test the limitation?"],
            "next_steps": ["Read the next permitted context segment."],
            "usage": {"status": "unknown"},
        }

    async def _session_a(self) -> tuple[dict, list[dict], str]:
        transcript: list[dict] = []
        log_path = self.root / "session-a.stderr"
        with log_path.open("w+", encoding="utf-8") as errlog:
            async with stdio_client(self._params(actor_id="agent-a", actor_session="connection-a"), errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    transcript.append({"process": "A", "operation": "list_tools", "count": len(listed.tools), "names": sorted(tool.name for tool in listed.tools)})

                    async def call(name: str, arguments: dict) -> dict:
                        value = await self._payload(await session.call_tool(name, arguments=arguments))
                        transcript.append({"process": "A", "operation": name, "ok": value.get("ok"), "error": (value.get("error") or {}).get("code")})
                        return value

                    discovery = await call("max_discover", {})
                    self.assertTrue(discovery["ok"])
                    self.assertEqual(discovery["data"]["transport"], "research-kb/max-control-mcp/v1")

                    forged_identity = await call("max_open_session", {
                        "project_id": self.project_id,
                        "claimed_agent_id": "agent-a",
                        "claimed_model": "model-a",
                        "admin": True,
                        "authenticated_identity": "forged",
                    })
                    self.assertFalse(forged_identity["ok"])

                    cross_project = await call("max_open_session", {
                        "project_id": "other-project",
                        "claimed_agent_id": "agent-a",
                    })
                    self.assertFalse(cross_project["ok"])

                    opened = await call("max_open_session", {
                        "project_id": self.project_id,
                        "claimed_agent_id": "luna-desktop",
                        "claimed_model": "gpt-5.6-luna",
                    })
                    self.assertTrue(opened["ok"])
                    session_id = opened["data"]["session_id"]

                    packet = await call("max_get_work_packet", {"session_id": session_id, "work_packet_id": self.packet["work_packet_id"]})
                    self.assertTrue(packet["ok"])
                    claim = await call("max_claim_work", {"session_id": session_id, "work_packet_id": self.packet["work_packet_id"]})
                    self.assertTrue(claim["ok"])
                    claim_data = claim["data"]
                    packet_data = claim_data["packet"]
                    base = {
                        "session_id": session_id,
                        "work_packet_id": self.packet["work_packet_id"],
                        "claim_id": claim_data["claim"]["claim_id"],
                        "expected_state_version": packet_data["state_version"],
                        "expected_state_hash": packet_data["state_hash"],
                        "idempotency_key": "transport-round-1",
                        "result": self._candidate(),
                    }

                    accepted_status = self._candidate()
                    accepted_status["candidate_claims"][0]["epistemic_status"] = "accepted"
                    invalid_status = await call("max_submit_candidate", {**base, "result": accepted_status})
                    self.assertFalse(invalid_status["ok"])

                    unauthorized_source = self._candidate()
                    unauthorized_source["candidate_claims"][0]["source_refs"] = ["mr1:passage:not-allowed"]
                    invalid_source = await call("max_submit_candidate", {**base, "result": unauthorized_source, "idempotency_key": "unauthorized-source"})
                    self.assertFalse(invalid_source["ok"])

                    extra_field = {**self._candidate(), "accepted": True}
                    invalid_shape = await call("max_submit_candidate", {**base, "result": extra_field, "idempotency_key": "unknown-field"})
                    self.assertFalse(invalid_shape["ok"])

                    first = await call("max_submit_candidate", base)
                    self.assertTrue(first["ok"])
                    replay = await call("max_submit_candidate", base)
                    self.assertTrue(replay["ok"])
                    self.assertTrue(replay["data"]["idempotent"])
                    conflict = await call("max_submit_candidate", {**base, "result": self._candidate("A conflicting replay must be rejected.")})
                    self.assertFalse(conflict["ok"])

                    status = await call("max_get_submission_status", {
                        "session_id": session_id,
                        "work_packet_id": self.packet["work_packet_id"],
                        "idempotency_key": "transport-round-1",
                    })
                    self.assertTrue(status["ok"])
                    self.assertEqual(status["data"]["status"], "candidate")
                    await call("max_close_session", {"session_id": session_id})
        return first["data"], transcript, log_path.read_text(encoding="utf-8")

    async def _session_b(self, *, second_packet_id: str, first_result_id: str) -> tuple[list[dict], str]:
        transcript: list[dict] = []
        log_path = self.root / "session-b.stderr"
        with log_path.open("w+", encoding="utf-8") as errlog:
            async with stdio_client(self._params(actor_id="agent-b", actor_session="connection-b"), errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    transcript.append({"process": "B", "operation": "list_tools", "count": len(listed.tools), "names": sorted(tool.name for tool in listed.tools)})

                    async def call(name: str, arguments: dict) -> dict:
                        value = await self._payload(await session.call_tool(name, arguments=arguments))
                        transcript.append({"process": "B", "operation": name, "ok": value.get("ok"), "error": (value.get("error") or {}).get("code")})
                        return value

                    opened = await call("max_open_session", {
                        "project_id": self.project_id,
                        "claimed_agent_id": "hermes-worker",
                        "claimed_model": "other-model",
                    })
                    self.assertTrue(opened["ok"])
                    session_id = opened["data"]["session_id"]
                    first_status = await call("max_get_submission_status", {
                        "session_id": session_id,
                        "work_packet_id": self.packet["work_packet_id"],
                        "idempotency_key": "transport-round-1",
                    })
                    self.assertTrue(first_status["ok"])
                    self.assertEqual(first_status["data"]["result_id"], first_result_id)
                    recovered = await call("max_recover_work", {"session_id": session_id})
                    self.assertTrue(recovered["ok"])
                    self.assertEqual(recovered["data"]["count"], 1)
                    packet = await call("max_get_work_packet", {"session_id": session_id, "work_packet_id": second_packet_id})
                    self.assertTrue(packet["ok"])
                    claim = await call("max_claim_work", {"session_id": session_id, "work_packet_id": second_packet_id})
                    self.assertTrue(claim["ok"])
                    claim_data = claim["data"]
                    packet_data = claim_data["packet"]
                    second = await call("max_submit_candidate", {
                        "session_id": session_id,
                        "work_packet_id": second_packet_id,
                        "claim_id": claim_data["claim"]["claim_id"],
                        "expected_state_version": packet_data["state_version"],
                        "expected_state_hash": packet_data["state_hash"],
                        "idempotency_key": "transport-round-2",
                        "result": self._candidate("The second Agent preserves the bounded candidate and adds a limitation."),
                    })
                    self.assertTrue(second["ok"])
                    status = await call("max_get_submission_status", {
                        "session_id": session_id,
                        "work_packet_id": second_packet_id,
                        "idempotency_key": "transport-round-2",
                    })
                    self.assertTrue(status["ok"])
                    stale_claim = await call("max_claim_work", {"session_id": session_id, "work_packet_id": self.packet["work_packet_id"]})
                    self.assertFalse(stale_claim["ok"])
                    verified = await call("max_verify", {"session_id": session_id, "run_id": self.run_id})
                    self.assertTrue(verified["ok"])
                    self.assertTrue(verified["data"]["ok"])
                    await call("max_close_session", {"session_id": session_id})
        return transcript, log_path.read_text(encoding="utf-8")

    def test_official_mcp_client_cross_process_two_round_recovery(self) -> None:
        first_result, transcript_a, stderr_a = asyncio.run(self._session_a())
        second_packet = self.control.issue_next_round(
            prior_result_id=first_result["result_id"],
            question="Which limitation most threatens the first candidate?",
            role="adversarial-reviewer",
        )["packet"]
        transcript_b, stderr_b = asyncio.run(
            self._session_b(second_packet_id=second_packet["work_packet_id"], first_result_id=first_result["result_id"])
        )
        self.assertEqual(transcript_a[0]["count"], len(MAX_CONTROL_MCP_TOOLS))
        self.assertEqual(transcript_b[0]["count"], len(MAX_CONTROL_MCP_TOOLS))
        self.assertEqual(transcript_a[0]["names"], sorted(MAX_CONTROL_MCP_TOOLS))
        self.assertEqual(transcript_b[0]["names"], sorted(MAX_CONTROL_MCP_TOOLS))
        self.assertNotIn("Traceback", stderr_a + stderr_b)
        verification = self.control.verify(run_id=self.run_id)
        self.assertTrue(verification["ok"], verification)
        self.assertEqual(verification["counts"]["results"], 2)


if __name__ == "__main__":
    unittest.main()
