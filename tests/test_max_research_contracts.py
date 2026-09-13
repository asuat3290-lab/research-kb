from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from research_kb.max_research import (
    Adjudication,
    AdjudicationValue,
    AcquisitionRequest,
    ApprovalConsumption,
    AttackRecord,
    CanonicalObject,
    CanonicalRelation,
    Checkpoint,
    ClaimSnapshot,
    ColdReviewPacket,
    ColdReviewResult,
    CompletionEvaluationInput,
    CompletionGateResult,
    CompletionResult,
    CoverageLedger,
    CrossExamination,
    DiscussionSession,
    EvidenceSnapshot,
    FormalCompletionEvidence,
    MaxResearchCharter,
    MaxRunState,
    MinorityReport,
    RehydrationInput,
    RehydrationPolicy,
    RolePacket,
    RolePosition,
    RunStatus,
    SearchStrategy,
    StartApproval,
    ValidityAudit,
    WorkingState,
    canonical_sha256,
    charter_hash,
    evaluate_completion_gate,
    evaluate_completion_result,
    evaluate_saturation,
    make_claim_snapshot,
    make_evidence_snapshot,
    make_stable_id,
    make_version_id,
    project_report,
    rebuild_research_state,
    rehydrate,
    transition_run_state,
    validate_claim_evidence_trace,
    validate_acquisition_request,
    validate_checkpoint,
    validate_checkpoint_lineage,
    validate_cold_review_packet,
    validate_cold_review_result,
    validate_completion_result,
    validate_discussion_session,
    validate_report_projection,
    validate_run_state,
    validate_start_approval,
    should_rehydrate,
    validate_speculative_idea,
    validate_speculative_transition,
    ContractValidationError,
    SpeculativeIdea,
)


FIXED_TIME = "2026-08-10T08:00:00+00:00"


class MaxResearchContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_id = "project-one"
        self.run_id = "run-one"
        kinds = (
            "document_version", "passage", "verification_record", "evidence_link",
            "evidence", "claim", "hypothesis", "iteration", "objection",
        )
        self.ids = {kind: make_stable_id(kind, f"{kind}-one") for kind in kinds}
        document = CanonicalObject(self.ids["document_version"], "document_version", self.project_id, payload={"title": "source"})
        passage = CanonicalObject(self.ids["passage"], "passage", self.project_id, payload={"text": "passage"})
        verification = CanonicalObject(self.ids["verification_record"], "verification_record", self.project_id, payload={"method": "server-exact-quote"})
        evidence = CanonicalObject(
            self.ids["evidence"], "evidence", self.project_id,
            payload={
                "status": "verified", "quote": "evidence",
                "verification_record_id": self.ids["verification_record"],
                "verified_source_version_id": document.version_id,
            },
        )
        evidence_link = CanonicalObject(self.ids["evidence_link"], "evidence_link", self.project_id, payload={"purpose": "claim_support"})
        claim = CanonicalObject(self.ids["claim"], "claim", self.project_id, payload={"status": "final", "text": "A traceable claim", "evidence_link_ids": [self.ids["evidence_link"]]})
        hypothesis = CanonicalObject(self.ids["hypothesis"], "hypothesis", self.project_id, payload={"status": "active", "is_leading": True})
        iteration = CanonicalObject(self.ids["iteration"], "iteration", self.project_id, payload={"status": "completed", "sequence": 1})
        objection = CanonicalObject(self.ids["objection"], "objection", self.project_id, payload={"status": "open"})
        self.objects = (document, passage, verification, evidence, evidence_link, claim, hypothesis, iteration, objection)
        self.by_id = {obj.stable_id: obj for obj in self.objects}
        self.by_kind = {obj.kind: obj for obj in self.objects}
        self.relations = (
            self.rel("claim", "evidence_link", "has_evidence_link"),
            self.rel("evidence_link", "evidence", "links_evidence"),
            self.rel("evidence", "passage", "derived_from"),
            self.rel("passage", "document_version", "located_in"),
        )

    def rel(self, source: str, target: str, relation: str) -> CanonicalRelation:
        source_obj = self.by_kind[source]
        target_obj = self.by_kind[target]
        return CanonicalRelation(source_obj.stable_id, target_obj.stable_id, relation, self.project_id, source_version_id=source_obj.version_id, target_version_id=target_obj.version_id)

    def charter(self, *, question: str = "How does the protocol preserve evidence?") -> MaxResearchCharter:
        return MaxResearchCharter(
            question=question,
            scope=["research-kb contract"],
            invariants=["canonical evidence is append-only"],
            non_goals=["no runner in MR-0"],
            deliverables=["contract package", "deterministic tests"],
            model_identity="fixture-model/v1",
            budget={"max_iterations": 12, "max_candidates": 20},
            source_policy={"network_allowed": False, "roles": ["primary", "counterevidence"]},
            quality_gates={"cold_review": True, "exact_trace": True, "required_strategy_families": ["direct", "counterevidence"]},
        )

    def checkpoint(self, *, iteration: int = 0, canonical_ids: tuple[str, ...] | None = None, supersedes: str | None = None) -> Checkpoint:
        ids = canonical_ids or tuple(obj.stable_id for obj in self.objects)
        working = WorkingState(
            project_id=self.project_id, run_id=self.run_id, iteration_index=iteration,
            budget_remaining={"max_iterations": 12 - iteration}, canonical_object_ids=ids,
            claim_ids=(self.ids["claim"],), evidence_ids=(self.ids["evidence"],),
            active_leading_hypothesis_id=self.ids["hypothesis"],
        )
        return Checkpoint(self.project_id, self.run_id, working, {"max_iterations": 12 - iteration}, iteration, ids, supersedes_item_id=supersedes)

    def state(self, objects=None, relations=None):
        return rebuild_research_state(objects or self.objects, relations or self.relations, project_id=self.project_id, run_id=self.run_id)

    def approval(self) -> StartApproval:
        charter = self.charter()
        now = datetime.now(timezone.utc)
        return StartApproval(
            run_id=self.run_id, project_id=self.project_id, charter_hash=charter_hash(charter),
            model_identity=charter.model_identity, budget=charter.budget,
            source_policy_hash=canonical_sha256(charter.source_policy),
            approval_id=make_stable_id("start_approval", "approval-one"), decision="approved",
            approved_by="human-reviewer", approved_at=now.isoformat(), decision_authority="human",
            expires_at=(now + timedelta(minutes=10)).isoformat(),
        )

    def awaiting(self) -> MaxRunState:
        charter = self.charter()
        return MaxRunState(
            self.run_id, self.project_id, RunStatus.AWAITING_START_APPROVAL,
            charter_hash(charter), charter.model_identity, charter.budget,
            canonical_sha256(charter.source_policy),
        )

    def running(self):
        state = self.state()
        approved = transition_run_state(self.awaiting(), RunStatus.APPROVED, approval=self.approval(), consumption_ledger=())
        return transition_run_state(approved, RunStatus.RUNNING, research_state=state)

    def role_session(self, *, state=None) -> DiscussionSession:
        state = state or self.state()
        positions = (
            RolePosition("lead", "retain", (self.ids["claim"],), (self.ids["evidence"],), "trace supports"),
            RolePosition("rival", "weaken", (self.ids["claim"],), (self.ids["evidence"],), "boundary remains"),
        )
        allowed = (self.ids["hypothesis"], self.ids["claim"], self.ids["evidence"])
        packets = tuple(RolePacket(self.project_id, self.run_id, state.state_hash, self.ids["hypothesis"], role, allowed, "fixture-model/v1", "inference/v1") for role in ("lead", "rival"))
        minority = MinorityReport("rival", "retain objection", "preserved for review", (self.ids["claim"],))
        return DiscussionSession(
            project_id=self.project_id, run_id=self.run_id, target_id=self.ids["hypothesis"],
            independent_positions=positions,
            cross_examinations=(CrossExamination("rival", "lead", "What would falsify this?", "The primary evidence boundary.", (self.ids["claim"],)),),
            validity_audits=(ValidityAudit("validity-auditor", True, ("all dimensions checked",), (self.ids["claim"],), True, True, True, True, "all dimensions checked"),),
            adjudication=Adjudication(AdjudicationValue.REASONED_DISSENSUS, "Evidence supports a qualified disagreement.", (self.ids["objection"],), (self.ids["evidence"],), (minority.report_id,), "adjudicator"),
            minority_reports=(minority,), state_hash=state.state_hash, model_identity="fixture-model/v1",
            inference_profile_hash="inference/v1", role_packets=packets,
        )

    def attack(self, *, state=None) -> AttackRecord:
        state = state or self.state()
        return AttackRecord(
            self.project_id, self.run_id, charter_hash(self.charter()), state.state_hash,
            self.by_kind["iteration"].stable_id, self.ids["hypothesis"], self.by_kind["hypothesis"].version_id,
            (self.ids["objection"],), (self.ids["evidence"],), "bounded", "counterexample boundary was recorded",
        )

    def report_bundle(self, *, state=None):
        state = state or self.state()
        report = project_report(state, claim_ids=(self.ids["claim"],))
        packet = ColdReviewPacket(self.project_id, self.run_id, state.state_hash, charter_hash(self.charter()), report.claim_ids, report.evidence_ids, report.source_links, report.report_id)
        review = ColdReviewResult(
            packet.packet_id, packet.packet_hash, self.project_id, self.run_id, charter_hash(self.charter()), state.state_hash,
            report.report_id, "fixture-model/v1", "inference/v1", True, (),
            {"passed": True, "claim_ids": report.claim_ids}, {"passed": True, "evidence_ids": report.evidence_ids},
            {"passed": True, "source_links": report.source_links}, FIXED_TIME,
        )
        formal = FormalCompletionEvidence(
            self.project_id, self.run_id, state.state_hash, report.report_id, report.claim_ids,
            report.evidence_ids, report.source_links,
            canonical_sha256({"claim_ids": report.claim_ids, "evidence_ids": report.evidence_ids, "source_links": report.source_links}),
        )
        return report, packet, review, formal

    def completion_input(self, *, state=None, running=None, **changes) -> CompletionEvaluationInput:
        state = state or self.state()
        running = running or self.running()
        report, packet, review, formal = self.report_bundle(state=state)
        clean = rehydrate(RehydrationInput(self.project_id, self.run_id, self.checkpoint(), self.objects, self.relations, prior_state=state))
        ledger = CoverageLedger((SearchStrategy(self.project_id, "direct", "mechanism"), SearchStrategy(self.project_id, "counterevidence", "boundary")), ("direct", "counterevidence"))
        claim_snapshot = make_claim_snapshot(self.by_kind["claim"])
        evidence_snapshot = make_evidence_snapshot(self.by_kind["evidence"])
        values = dict(
            project_id=self.project_id, run_id=self.run_id, charter_hash=charter_hash(self.charter()), state_hash=state.state_hash,
            charter=self.charter(), run_state=running, research_state=state, strategy_ledger=ledger,
            attack_records=(self.attack(state=state),), discussion_sessions=(self.role_session(state=state),),
            rehydration_output=clean, cold_review_packet=packet, cold_review_result=review, final_report=report,
            formal_completion_evidence=formal, claim_snapshots=(claim_snapshot, claim_snapshot),
            evidence_snapshots=(evidence_snapshot,), counterevidence_snapshots=(evidence_snapshot,),
            budget_snapshot=self.charter().budget, source_policy_snapshot=self.charter().source_policy,
            model_identity=self.charter().model_identity, evaluated_at=FIXED_TIME,
        )
        values.update(changes)
        return CompletionEvaluationInput(**values)

    def test_mr0a_ids_versions_relations_and_deterministic_rehydration_still_hold(self) -> None:
        first = self.state(); second = self.state(tuple(reversed(self.objects)), tuple(reversed(self.relations)))
        self.assertEqual(first.state_hash, second.state_hash)
        forged = replace(self.by_kind["claim"], version_id=self.by_kind["evidence"].version_id)
        with self.assertRaises(ContractValidationError): rebuild_research_state((forged,) + tuple(obj for obj in self.objects if obj.stable_id != forged.stable_id), self.relations, project_id=self.project_id, run_id=self.run_id)

    def test_strict_mapping_deep_freeze_and_utf8_safe_value_models(self) -> None:
        payload = {"nested": {"items": ["a"]}}
        obj = CanonicalObject(self.ids["claim"], "claim", self.project_id, payload=payload)
        payload["nested"]["items"].append("mutated")
        self.assertEqual(obj.payload["nested"]["items"], ("a",))

    def test_four_p1_fake_completion_result_is_fail_closed(self) -> None:
        value = self.completion_input()
        fake_gate = CompletionGateResult(passed=True, checks={"fabricated": True}, gate_hash="")
        fake = CompletionResult(self.project_id, self.run_id, value.charter_hash, "attacker-state", fake_gate, FIXED_TIME)
        self.assertFalse(validate_completion_result(fake, evaluation_input=value))
        with self.assertRaises(ContractValidationError): transition_run_state(value.run_state, RunStatus.COMPLETED, completion_result=fake, completion_input=value)

    def test_missing_evidence_status_cannot_rebuild_or_report(self) -> None:
        evidence = replace(self.by_kind["evidence"], payload={"quote": "evidence"})
        objects = tuple(evidence if item.stable_id == evidence.stable_id else item for item in self.objects)
        self.assertFalse(validate_claim_evidence_trace(self.by_kind["claim"], objects, self.relations))
        with self.assertRaises(ContractValidationError): rebuild_research_state(objects, self.relations, project_id=self.project_id, run_id=self.run_id)

    def test_approval_consumption_is_immutable_and_ledger_bound(self) -> None:
        approval = self.approval(); before = approval.to_dict()
        result = transition_run_state(self.awaiting(), RunStatus.APPROVED, approval=approval, consumption_ledger=())
        self.assertEqual(before, approval.to_dict()); self.assertIsNone(approval.consumed_at)
        consumption = result.approval_consumption
        self.assertIsInstance(consumption, ApprovalConsumption)
        mapping = approval.to_dict(); mapping["consumed_at"] = None
        rebuilt = StartApproval.from_mapping(mapping)
        with self.assertRaises(ContractValidationError): transition_run_state(self.awaiting(), RunStatus.APPROVED, approval=rebuilt, consumption_ledger=(consumption,))

    def test_attack_record_is_typed_state_bound_and_placeholder_orphans_fail(self) -> None:
        value = self.completion_input()
        for bad in (
            replace(value.attack_records[0], attack_id="placeholder"),
            replace(value.attack_records[0], target_id=make_stable_id("hypothesis", "orphan")),
            replace(value.attack_records[0], target_version_id=self.by_kind["evidence"].version_id),
        ):
            bad_value = replace(value, attack_records=(bad,))
            self.assertFalse(evaluate_completion_gate(bad_value).passed)

    def test_cold_review_requires_result_and_exact_bindings(self) -> None:
        value = self.completion_input()
        self.assertFalse(evaluate_completion_gate(replace(value, cold_review_result=replace(value.cold_review_result, passed=False))).passed)
        self.assertFalse(validate_cold_review_result(replace(value.cold_review_result, packet_id=make_stable_id("cold_review", "other")), value.cold_review_packet, value.research_state, report=value.final_report))
        self.assertFalse(validate_cold_review_packet(replace(value.cold_review_packet, excluded_sections=("working_summary",)), value.research_state, expected_charter_hash=value.charter_hash))

    def test_validity_audit_passed_mismatch_fails(self) -> None:
        bad_session = replace(self.role_session(), validity_audits=(ValidityAudit("auditor", True, ("bad",), (), False, True, True, True, "bad"),))
        self.assertFalse(validate_discussion_session(bad_session))

    def test_completion_discussion_requires_ids_from_supplied_state(self) -> None:
        value = self.completion_input()
        bad = replace(value.discussion_sessions[0], target_id=make_stable_id("hypothesis", "not-in-state"))
        self.assertFalse(evaluate_completion_gate(replace(value, discussion_sessions=(bad,))).passed)

    def test_empty_ledger_and_each_saturation_dimension_blocks_completion(self) -> None:
        value = self.completion_input()
        missing_ledger = replace(value, strategy_ledger=CoverageLedger((), ("direct", "counterevidence")))
        self.assertFalse(evaluate_completion_gate(missing_ledger).passed)
        self.assertFalse(evaluate_completion_gate(replace(value, evidence_snapshots=())).passed)
        self.assertFalse(evaluate_completion_gate(replace(value, counterevidence_snapshots=())).passed)
        changed = ClaimSnapshot(value.claim_snapshots[0].claim_id, value.claim_snapshots[0].version_id, "changed", "changed-semantic-hash")
        self.assertFalse(evaluate_completion_gate(replace(value, claim_snapshots=(changed, changed))).passed)

    def test_formal_completion_evidence_is_typed_not_arbitrary_mapping(self) -> None:
        with self.assertRaises(ContractValidationError): self.completion_input(formal_completion_evidence={"placeholder": True})
        self.assertFalse(evaluate_completion_gate({"passed": True, "formal_completion_evidence": {"placeholder": True}}).passed)

    def test_empty_shell_completion_context_cannot_pass_gate(self) -> None:
        value = self.completion_input()
        shell = replace(value, strategy_ledger=CoverageLedger((), ()), counterevidence_snapshots=())
        self.assertFalse(evaluate_completion_gate(shell).passed)

    def test_source_links_are_one_record_per_evidence_path(self) -> None:
        document2 = CanonicalObject(make_stable_id("document_version", "two"), "document_version", self.project_id, payload={"title": "source-two"})
        passage2 = CanonicalObject(make_stable_id("passage", "two"), "passage", self.project_id, payload={"text": "passage-two"})
        verification2 = CanonicalObject(make_stable_id("verification_record", "two"), "verification_record", self.project_id, payload={"method": "server-exact-quote"})
        evidence2 = CanonicalObject(make_stable_id("evidence", "two"), "evidence", self.project_id, payload={"status": "verified", "verification_record_id": verification2.stable_id, "verified_source_version_id": document2.version_id, "quote": "two"})
        link2 = CanonicalObject(make_stable_id("evidence_link", "two"), "evidence_link", self.project_id, payload={"purpose": "counter"})
        claim2 = replace(self.by_kind["claim"], payload={"status": "final", "text": "two traces", "evidence_link_ids": [self.ids["evidence_link"], link2.stable_id]})
        objects = tuple(claim2 if item.stable_id == claim2.stable_id else item for item in self.objects) + (document2, passage2, verification2, evidence2, link2)
        relations = self.relations + (
            CanonicalRelation(claim2.stable_id, link2.stable_id, "has_evidence_link", self.project_id, source_version_id=claim2.version_id, target_version_id=link2.version_id),
            CanonicalRelation(link2.stable_id, evidence2.stable_id, "links_evidence", self.project_id, source_version_id=link2.version_id, target_version_id=evidence2.version_id),
            CanonicalRelation(evidence2.stable_id, passage2.stable_id, "derived_from", self.project_id, source_version_id=evidence2.version_id, target_version_id=passage2.version_id),
            CanonicalRelation(passage2.stable_id, document2.stable_id, "located_in", self.project_id, source_version_id=passage2.version_id, target_version_id=document2.version_id),
        )
        state = self.state(objects, relations); report = project_report(state, claim_ids=(claim2.stable_id,))
        self.assertEqual(len(report.source_links), 2)
        self.assertTrue(all("passage_ids" not in link and "document_version_ids" not in link for link in report.source_links))
        self.assertNotEqual(report.source_links[0]["passage_id"], report.source_links[1]["passage_id"])
        forged = replace(report, source_links=(dict(report.source_links[0], passage_id=report.source_links[1]["passage_id"]), report.source_links[1]))
        self.assertFalse(validate_report_projection(forged, state))

    def test_completion_evaluator_is_deterministic_and_reacts_to_knowledge_change(self) -> None:
        value = self.completion_input(); first = evaluate_completion_result(value); second = evaluate_completion_result(value)
        self.assertEqual(first.to_dict(), second.to_dict())
        changed = replace(value.attack_records[0], outcome="different")
        changed_value = replace(value, attack_records=(changed,))
        changed_result = evaluate_completion_result(changed_value)
        self.assertNotEqual(first.gate_input_hash, changed_result.gate_input_hash)
        self.assertNotEqual(first.result_id, changed_result.result_id)

    def test_completion_requires_bound_budget_source_policy_model_and_state(self) -> None:
        value = self.completion_input()
        self.assertFalse(evaluate_completion_gate(replace(value, model_identity="attacker-model")).passed)
        self.assertFalse(evaluate_completion_gate(replace(value, budget_snapshot={"max_iterations": 999})).passed)
        self.assertFalse(evaluate_completion_gate(replace(value, source_policy_snapshot={"network_allowed": True})).passed)
        self.assertFalse(evaluate_completion_gate(replace(value, state_hash="stale-state")).passed)

    def test_completed_transition_requires_recomputed_result_and_current_state(self) -> None:
        value = self.completion_input(); result = evaluate_completion_result(value)
        completed = transition_run_state(value.run_state, RunStatus.COMPLETED, completion_input=value, completion_result=result)
        self.assertEqual(completed.completion_result_id, result.result_id)
        self.assertTrue(validate_run_state(completed))
        with self.assertRaises(ContractValidationError): transition_run_state(value.run_state, RunStatus.COMPLETED, completion_result=result)

    def test_mr0a_rehydration_detects_deletion_and_100_round_drift(self) -> None:
        checkpoint = self.checkpoint(); prior = self.state(); clean = 0
        for round_index in range(1, 101):
            objects = self.objects; relations = self.relations; summary = None
            if round_index == 12:
                changed = replace(self.by_kind["hypothesis"], payload={"status": "weakened", "is_leading": True})
                objects = tuple(changed if item.stable_id == changed.stable_id else item for item in objects)
            elif round_index == 24:
                relations = self.relations[:-1]
            elif round_index == 36:
                objects = objects + (CanonicalObject(make_stable_id("objection", "round-36"), "objection", self.project_id, payload={"text": "new"}),)
            elif round_index == 48:
                summary = {"active_leading_hypothesis_id": make_stable_id("hypothesis", "different")}
            result = rehydrate(RehydrationInput(self.project_id, self.run_id, checkpoint, objects, relations, summary, prior))
            if round_index in {12, 24, 36, 48}:
                self.assertFalse(result.accepted); self.assertTrue(result.drift_flags)
            else: self.assertTrue(result.accepted); clean += 1
        self.assertEqual(clean, 96)

    def test_evidence_status_matrix_and_provisional_projection(self) -> None:
        for status in ("candidate", "unverified", "rejected"):
            evidence = replace(self.by_kind["evidence"], payload={"status": status})
            objects = tuple(evidence if item.stable_id == evidence.stable_id else item for item in self.objects)
            self.assertFalse(validate_claim_evidence_trace(self.by_kind["claim"], objects, self.relations))
        provisional = replace(self.by_kind["claim"], payload={"status": "provisional", "evidence_link_ids": [self.ids["evidence_link"]]})
        objects = tuple(provisional if item.stable_id == provisional.stable_id else item for item in self.objects)
        state = self.state(objects, self.relations)
        with self.assertRaises(ContractValidationError): project_report(state, claim_ids=(provisional.stable_id,))

    def test_cold_review_packet_is_not_a_cold_review_result(self) -> None:
        value = self.completion_input()
        self.assertFalse(validate_cold_review_result(value.cold_review_packet.to_dict(), value.cold_review_packet, value.research_state, report=value.final_report))
        self.assertFalse(evaluate_completion_gate(replace(value, cold_review_result=ColdReviewResult(value.cold_review_packet.packet_id, value.cold_review_packet.packet_hash, self.project_id, self.run_id, value.charter_hash, value.state_hash, value.final_report.report_id, "fixture-model/v1", "inference/v1", False, ("blocking",), {"passed": False}, {"passed": False}, {"passed": False}, FIXED_TIME))).passed)

    def test_checkpoint_lineage_acquisition_and_rehydration_policy_regressions(self) -> None:
        first = self.checkpoint(iteration=0)
        second = self.checkpoint(iteration=1, supersedes=first.checkpoint_id)
        self.assertTrue(validate_checkpoint(first, project_id=self.project_id, run_id=self.run_id, canonical_objects=self.objects))
        self.assertTrue(validate_checkpoint_lineage((first, second)))
        branch = self.checkpoint(iteration=2, supersedes=first.checkpoint_id)
        self.assertFalse(validate_checkpoint_lineage((first, second, branch)))
        request = AcquisitionRequest(self.project_id, "missing counterexample", (self.ids["hypothesis"],), "boundary test", 0.7, ("find contradiction",), "counterevidence", run_id=self.run_id, source_policy_hash=canonical_sha256(self.charter().source_policy))
        self.assertTrue(validate_acquisition_request(request))
        self.assertTrue(should_rehydrate(RehydrationPolicy(interval_iterations=12, triggers=("recovery",)), iteration_index=12))

    def test_speculation_cannot_skip_candidate_and_completion_gate_rejects_legacy_gate(self) -> None:
        idea = SpeculativeIdea(self.project_id, "possible mechanism", run_id=self.run_id, source_policy_hash=canonical_sha256(self.charter().source_policy))
        self.assertTrue(validate_speculative_idea(idea))
        self.assertFalse(validate_speculative_transition("speculative", "supported"))
        self.assertFalse(evaluate_completion_gate({"passed": True, "checks": {"fabricated": True}}).passed)


if __name__ == "__main__":
    unittest.main()
