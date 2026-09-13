from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from research_kb.max_research.external_agent import ExternalAgentService
from research_kb.max_research.persistence import MaxControlError, MaxControlRepository
from research_kb.policy import Actor


class _ServerSourceResolver:
    """Small server-owned reference resolver; it never returns source text."""

    def resolve_reference(self, *, project_id: str, reference: dict[str, object]):
        passage_id = reference.get("passage_id")
        if passage_id == "mr1:passage:source-a":
            return {
                "project_id": project_id,
                "document_id": "mr1:document:document-a",
                "passage_id": passage_id,
            }
        if passage_id == "mr1:passage:source-b":
            return {
                "project_id": project_id,
                "document_id": "mr1:document:document-b",
                "passage_id": passage_id,
            }
        return None


class ExternalAgentProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "external-agent.db"
        self.admin = Actor("admin", "admin-session", "user", "admin", "test")
        self.repository = MaxControlRepository(self.database)
        self.repository.initialize()
        charter = {
            "question": "How can an external Agent preserve source-grounded research state?",
            "scope": "external Agent protocol",
            "invariants": ["candidate-only submissions", "project-scoped references"],
            "non_goals": ["provider execution", "automatic acceptance"],
            "deliverables": ["bounded candidate result"],
            "model_identity": "external-agent-test-model",
            "budget": {
                "iteration_count": 2,
                "input_tokens": 2000,
                "output_tokens": 1000,
                "cost_units": 0,
                "acquisition_requests": 0,
                "acquisition_bytes": 0,
            },
            "source_policy": {"mode": "server-resolved"},
            "quality_gates": {"require_human_approval": True},
        }
        proposed = self.repository.propose(project_id="external-agent-test", charter=charter, actor=self.admin)
        self.run_id = proposed["run_id"]
        self.repository.approve(
            run_id=self.run_id,
            charter_hash_value=proposed["charter_hash"],
            reason="test start approval",
            actor=self.admin,
        )
        started = self.repository.start(run_id=self.run_id, actor=self.admin)
        self.fencing_token = started["lease"]["fencing_token"]
        iteration = self.repository.begin_iteration(
            run_id=self.run_id,
            round_type="targeted_retrieval",
            actor=self.admin,
            fencing_token=self.fencing_token,
        )
        self.iteration_id = iteration["iteration_id"]
        self.resolver = _ServerSourceResolver()
        self.service = ExternalAgentService(
            self.repository,
            self.admin,
            source_resolver=self.resolver,
        )
        self.agent_one = Actor("agent-one", "agent-session-one", "agent", "researcher", "codex", "gpt-5.6-luna")
        self.agent_two = Actor("agent-two", "agent-session-two", "agent", "researcher", "hermes", "other-model")
        self.session_one = self.service.open_session(
            project_id="external-agent-test",
            authenticated_actor=self.agent_one,
            claimed_agent_id="luna-desktop",
            claimed_model="gpt-5.6-luna",
        )
        self.session_two = self.service.open_session(
            project_id="external-agent-test",
            authenticated_actor=self.agent_two,
            claimed_agent_id="hermes-worker",
            claimed_model="other-model",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _packet(self, *, round_no: int | None = None):
        return self.service.issue_work_packet(
            project_id="external-agent-test",
            run_id=self.run_id,
            iteration_id=self.iteration_id,
            question="Which bounded observations can this source support?",
            role="evidence-mapper",
            source_refs=[{"passage_id": "mr1:passage:source-a"}],
            round_no=round_no,
        )

    @staticmethod
    def _candidate(*, text: str = "The passage supports a bounded candidate observation.") -> dict[str, object]:
        return {
            "candidate_claims": [
                {
                    "text": text,
                    "epistemic_status": "candidate",
                    "source_refs": ["mr1:passage:source-a"],
                    "rationale": "The claim does not exceed the referenced passage.",
                }
            ],
            "evidence_links": [
                {"source_ref": "mr1:passage:source-a", "relation": "supports"}
            ],
            "objections": [
                {"text": "The source does not establish a general causal law.", "source_refs": ["mr1:passage:source-a"]}
            ],
            "unresolved_questions": ["What additional material would test the mechanism?"],
            "next_steps": ["Read the permitted surrounding context."],
            "usage": {"status": "unknown"},
        }

    def _claim(self, session: dict[str, object], packet_id: str):
        claimed = self.service.claim_work(session_id=session["session_id"], work_packet_id=packet_id)
        return claimed, claimed["packet"]["state_version"], claimed["packet"]["state_hash"]

    def _submit(self, session: dict[str, object], claimed: dict[str, object], result: dict[str, object], key: str):
        packet = claimed["packet"]
        return self.service.submit_candidate(
            session_id=session["session_id"],
            work_packet_id=packet["work_packet_id"],
            claim_id=claimed["claim"]["claim_id"],
            expected_state_version=packet["state_version"],
            expected_state_hash=packet["state_hash"],
            idempotency_key=key,
            result=result,
        )

    def test_discovery_separates_authenticated_and_claimed_identity(self) -> None:
        value = ExternalAgentService.discover()
        self.assertEqual(value["protocol"], "research-kb/external-agent/v1")
        self.assertEqual(value["identity"]["authenticated_connection"], "server_injected_actor_identity")
        self.assertEqual(value["identity"]["claimed_agent_and_model"], "self_reported_metadata")
        self.assertEqual(value["external_actions"], {"provider": 0, "network": 0, "credential_reads": 0})
        self.assertEqual(self.session_one["authenticated_identity"]["actor_id"], "agent-one")
        self.assertEqual(self.session_one["claimed_identity"]["agent_id"], "luna-desktop")

    def test_candidate_submit_replay_and_stale_or_forged_inputs_fail_closed(self) -> None:
        packet = self._packet()["packet"]
        claimed, _, _ = self._claim(self.session_one, packet["work_packet_id"])
        result = self._candidate()
        first = self._submit(self.session_one, claimed, result, "round-1")
        replay = self._submit(self.session_one, claimed, result, "round-1")
        self.assertFalse(first["idempotent"])
        self.assertTrue(replay["idempotent"])
        self.assertEqual(first["result_id"], replay["result_id"])
        conflicting = self._candidate(text="A different candidate must not replace the first one.")
        with self.assertRaises(MaxControlError):
            self._submit(self.session_one, claimed, conflicting, "round-1")
        hash_as_citation = self._candidate()
        hash_as_citation["candidate_claims"] = [
            {**hash_as_citation["candidate_claims"][0], "source_refs": [packet["source_refs"][0]["reference_hash"]]}
        ]
        with self.assertRaises(MaxControlError):
            self._submit(self.session_one, claimed, hash_as_citation, "hash-citation")

        stale_packet = self._packet(round_no=2)["packet"]
        stale_claimed, _, _ = self._claim(self.session_one, stale_packet["work_packet_id"])
        with self.assertRaises(MaxControlError):
            self.service.submit_candidate(
                session_id=self.session_one["session_id"],
                work_packet_id=stale_packet["work_packet_id"],
                claim_id=stale_claimed["claim"]["claim_id"],
                expected_state_version=stale_packet["state_version"] + 1,
                expected_state_hash=stale_packet["state_hash"],
                idempotency_key="stale-state",
                result=result,
            )
        self.service.release_work(
            session_id=self.session_one["session_id"],
            work_packet_id=stale_packet["work_packet_id"],
            claim_id=stale_claimed["claim"]["claim_id"],
            reason="stale input test cleanup",
        )

        forged = dict(result)
        forged["authenticated_actor_id"] = "forged"
        packet_three = self._packet(round_no=3)["packet"]
        claimed_three, _, _ = self._claim(self.session_one, packet_three["work_packet_id"])
        with self.assertRaises(MaxControlError):
            self._submit(self.session_one, claimed_three, forged, "forged-result")
        self.service.release_work(
            session_id=self.session_one["session_id"],
            work_packet_id=packet_three["work_packet_id"],
            claim_id=claimed_three["claim"]["claim_id"],
            reason="forged input test cleanup",
        )

    def test_project_boundary_interruption_recovery_and_second_round(self) -> None:
        packet = self._packet()["packet"]
        other_project = self.service.open_session(
            project_id="other-project",
            authenticated_actor=Actor("other", "other-session", "agent", "researcher", "qoder"),
            claimed_agent_id="other-agent",
        )
        with self.assertRaises(MaxControlError):
            self.service.get_work_packet(session_id=other_project["session_id"], work_packet_id=packet["work_packet_id"])

        claimed, _, _ = self._claim(self.session_one, packet["work_packet_id"])
        with self.assertRaises(MaxControlError):
            self._submit(self.session_two, claimed, self._candidate(), "wrong-owner")
        self.service.release_work(
            session_id=self.session_one["session_id"],
            work_packet_id=packet["work_packet_id"],
            claim_id=claimed["claim"]["claim_id"],
            reason="simulated disconnect",
        )
        recovered = self.service.recover_work(session_id=self.session_two["session_id"], work_packet_id=packet["work_packet_id"])
        self.assertEqual(recovered["count"], 1)
        resumed, _, _ = self._claim(self.session_two, packet["work_packet_id"])
        first = self._submit(self.session_two, resumed, self._candidate(), "recovered-round-1")
        self.assertEqual(first["status"], "candidate")

        next_packet = self.service.issue_next_round(
            prior_result_id=first["result_id"],
            question="Which limitation most threatens the first candidate?",
            role="adversarial-reviewer",
        )["packet"]
        second_claimed, _, _ = self._claim(self.session_one, next_packet["work_packet_id"])
        second_result = self._submit(
            self.session_one,
            second_claimed,
            self._candidate(text="The candidate remains bounded and should not be generalized beyond the source."),
            "round-2",
        )
        self.assertEqual(second_result["status"], "candidate")
        self.assertEqual(self.service.verify(run_id=self.run_id)["ok"], True)
        database_verification = self.repository.verify_database()
        self.assertTrue(database_verification["ok"], database_verification)
        self.assertTrue(database_verification["external_agent"]["ok"], database_verification["external_agent"])

    def test_twenty_concurrent_claimers_create_one_active_claim(self) -> None:
        packet = self.service.issue_work_packet(
            project_id="external-agent-test",
            run_id=self.run_id,
            iteration_id=self.iteration_id,
            question="Which agent may claim this work packet?",
            role="concurrency-checker",
            source_refs=[{"passage_id": "mr1:passage:source-b"}],
            round_no=4,
        )["packet"]
        sessions = [self.session_one, self.session_two]
        for index in range(18):
            sessions.append(
                self.service.open_session(
                    project_id="external-agent-test",
                    authenticated_actor=Actor(f"agent-{index + 3}", f"session-{index + 3}", "agent", "researcher", "generic"),
                    claimed_agent_id=f"agent-{index + 3}",
                )
            )

        def attempt(session: dict[str, object]):
            try:
                return self.service.claim_work(session_id=session["session_id"], work_packet_id=packet["work_packet_id"])
            except MaxControlError:
                return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(attempt, sessions))
        winners = [item for item in outcomes if item is not None]
        self.assertEqual(len(winners), 1)
        connection = sqlite3.connect(self.database)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM max_external_agent_work_claim_current WHERE work_packet_id=? AND state='active'",
                    (packet["work_packet_id"],),
                ).fetchone()[0],
                1,
            )
        finally:
            connection.close()
        winner = winners[0]
        winner_session = next(
            session for session, outcome in zip(sessions, outcomes) if outcome is winner
        )
        self.service.release_work(
            session_id=winner_session["session_id"],
            work_packet_id=packet["work_packet_id"],
            claim_id=winner["claim"]["claim_id"],
            reason="concurrency test cleanup",
        )

    def test_repository_verifier_includes_external_agent_protocol(self) -> None:
        result = self.repository.verify_database()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["external_agent"]["ok"], result["external_agent"])
        self.assertEqual(result["external_agent"]["counts"]["packets"], 0)


if __name__ == "__main__":
    unittest.main()
