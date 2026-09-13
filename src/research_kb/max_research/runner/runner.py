"""The MR-2A bounded, single-model runner.

The runner is intentionally small and boring at its boundary: it owns one
bounded adapter call, while the repository owns every durable mutation.  No
SQLite transaction is held while ``adapter.dispatch`` or a gateway call is in
flight.  A fixture adapter is the only implementation shipped in this phase.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from typing import Any, Callable, Mapping, Sequence

from ..contract import (
    Adjudication,
    AttackRecord,
    CanonicalObject,
    CanonicalObjectKind,
    ClaimSnapshot,
    CoverageLedger,
    ContractValidationError,
    CorrectionPosition,
    CrossExamination,
    DiscussionSession,
    EvidenceSnapshot,
    MaxResearchCharter,
    MaxRunState,
    MinorityReport,
    RehydrationPolicy,
    ResearchState,
    RolePosition,
    RunStatus,
    SearchStrategy,
    ValidityAudit,
    canonical_json,
    canonical_sha256,
    charter_hash,
    is_stable_id,
    make_claim_snapshot,
    make_evidence_snapshot,
    model_to_dict,
    rebuild_research_state,
    validate_discussion_session,
    validate_run_state,
)
from ...policy import Actor
from ..persistence.control_models import CanonicalChangeSet, UsageReceipt
from ..persistence.db import MaxControlError
from ..persistence.repository import MaxControlRepository, _reject_untrusted_payload
from ..persistence.runner import RunnerPersistence
from .adapter import FixtureResearchGateway, FixtureUsageAuthority
from .contracts import (
    DispatchUnknown,
    ModelCallIntent,
    ModelCallResult,
    ModelCallStatus,
    ModelRequestEnvelope,
    ModelResponseEnvelope,
    RecoveryDisposition,
    ResearchGateway,
    RunnerPlan,
    RunnerProfile,
    RunnerProposal,
)
from .planner import build_plan


_FORBIDDEN_MODEL_KINDS = {
    CanonicalObjectKind.START_APPROVAL.value,
    CanonicalObjectKind.APPROVAL_CONSUMPTION.value,
    CanonicalObjectKind.CHECKPOINT.value,
    CanonicalObjectKind.WORKING_STATE.value,
    CanonicalObjectKind.RESEARCH_STATE.value,
    CanonicalObjectKind.COMPLETION_GATE.value,
    CanonicalObjectKind.REPORT.value,
    CanonicalObjectKind.COLD_REVIEW_RESULT.value,
    CanonicalObjectKind.FORMAL_COMPLETION_EVIDENCE.value,
    CanonicalObjectKind.ITERATION.value,
}
_FORBIDDEN_STATUS_VALUES = {"final", "verified", "accepted", "approved", "completed", "complete", "published"}
_SENSITIVE_KEYS = {
    "full_text", "source_text", "passage_text", "pdf_text", "raw_document", "api_key",
    "secret", "password", "access_token", "refresh_token", "token", "model_key",
    "absolute_path", "path", "source", "source_ref", "source_reference", "source_reference_id",
    "source_version", "document_id", "document_version_id", "passage_id", "verified_evidence_id",
    "source_link", "citation", "citation_metadata", "citation_key", "citation_locator", "locator",
    "doi", "page", "pages", "page_number", "author", "authors",
}
_ABSOLUTE_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/|file:)")


class InjectedRunnerCrash(RuntimeError):
    """Test-only crash seam; the message never contains model data."""


class UsageDispute(MaxControlError):
    """A provider call happened, but its usage fact is not authoritative.

    The reservation must remain controlled until an administrator resolves the
    dispute.  This is deliberately distinct from a rejected model proposal:
    the latter may release unused budget, while the former represents an
    external billing fact that the control plane cannot safely forget.
    """

    def __init__(self, logical_call_id: str, message: str = "provider usage requires an administrative dispute decision") -> None:
        super().__init__(message)
        self.logical_call_id = logical_call_id


class BoundedRunner:
    """Advance at most one persisted iteration for one explicitly handed-off Run."""

    def __init__(
        self,
        repository: MaxControlRepository,
        actor: Actor,
        profile: RunnerProfile | Mapping[str, Any],
        adapter: Any,
        *,
        gateway: ResearchGateway | None = None,
        usage_authority: Any | None = None,
        fixture: bool = False,
        lease_ttl: int = 60,
        failure_injection: str | Callable[[str], bool] | None = None,
        plan_builder: Callable[..., RunnerPlan] | None = None,
        plan_validator: Callable[[RunnerPlan], None] | None = None,
    ) -> None:
        self.repository = repository
        self.persistence = RunnerPersistence(repository)
        self.actor = actor
        self.profile = profile if isinstance(profile, RunnerProfile) else RunnerProfile.from_mapping(profile)
        self.adapter = adapter
        self.gateway = gateway
        self.fixture = bool(fixture)
        self.lease_ttl = lease_ttl
        self._failure = failure_injection
        self._plan_builder = plan_builder or build_plan
        self._plan_validator = plan_validator
        if self.adapter is None:
            raise MaxControlError("ADAPTER_NOT_CONFIGURED")
        if self.gateway is None:
            raise MaxControlError("GATEWAY_NOT_CONFIGURED")
        if usage_authority is not None:
            if self.repository.usage_authority is not None and self.repository.usage_authority is not usage_authority:
                raise MaxControlError("USAGE_AUTHORITY_CONFLICT")
            self.repository.usage_authority = usage_authority
        if self.repository.usage_authority is None:
            raise MaxControlError("USAGE_AUTHORITY_NOT_CONFIGURED")
        if self.fixture:
            if not self.repository.is_fixture_database():
                raise MaxControlError("FIXTURE_DATABASE_REQUIRED")
            if not getattr(self.adapter, "fixture_only", False) or not getattr(self.gateway, "fixture_only", False) or not getattr(self.repository.usage_authority, "fixture_only", False):
                raise MaxControlError("FIXTURE_DEPENDENCY_REQUIRED")
        elif getattr(self.adapter, "fixture_only", False) or getattr(self.gateway, "fixture_only", False) or getattr(self.repository.usage_authority, "fixture_only", False):
            raise MaxControlError("FIXTURE_EXECUTION_REQUIRES_SIMULATE_NEXT")

    def inject_failure(self, stage: str) -> None:
        if not isinstance(stage, str) or not stage.strip():
            raise ValueError("runner failure stage is required")
        self._failure = stage.strip()

    def _should_fail(self, stage: str) -> bool:
        current = self._failure
        if current is None:
            return False
        if callable(current):
            return bool(current(stage))
        if current == stage:
            self._failure = None
            return True
        return False

    def _crash_if(self, stage: str) -> None:
        if self._should_fail(stage):
            raise InjectedRunnerCrash(f"injected runner interruption at {stage}")

    def _read_context(self, run_id: str) -> tuple[MaxRunState, MaxResearchCharter, ResearchState, dict[str, Any], int]:
        connection = self.repository._connect(read_only=True)
        try:
            row = self.repository._run_row(connection, run_id)
            state = self.repository._run_state(row)
            charter = self.repository._charter(row)
            approval_count = int(connection.execute("SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?", (run_id,)).fetchone()[0])
        finally:
            connection.close()
        if state.status != RunStatus.RUNNING:
            raise MaxControlError("bounded runner requires a RUNNING Run")
        validate_run_state(state).raise_if_invalid()
        if charter_hash(charter) != state.charter_hash or charter.model_identity != state.model_identity:
            raise MaxControlError("stored Charter/model binding is invalid")
        if approval_count != 1:
            raise MaxControlError("bounded runner requires exactly one consumed human approval")
        try:
            state_value = ResearchState.from_mapping(self.repository.get_state(run_id=run_id))
        except Exception as exc:
            raise MaxControlError("Research State is not readable") from exc
        if state_value.state_hash != state.current_state_hash or state_value.run_id != run_id or state_value.project_id != state.project_id:
            raise MaxControlError("Research State is stale or outside the Run boundary")
        budget = self.repository.reconstruct_budget(run_id=run_id)
        if not budget.get("ok", True):
            raise MaxControlError("budget ledger cannot be reconstructed")
        return state, charter, state_value, budget, approval_count

    @staticmethod
    def _redacted_summary(**values: Any) -> dict[str, Any]:
        allowed = {
            "run_id", "project_id", "status", "iteration_id", "iteration_number", "round_type",
            "cognitive_kind", "plan_hash", "intent_hash", "logical_call_id", "result_hash",
            "change_set_id", "output_state_hash", "iteration_outcome_id", "usage_entry_id",
            "recovery_disposition", "reason", "idempotent", "model_call_status", "profile_hash",
        }
        return {key: values[key] for key in sorted(values) if key in allowed and values[key] is not None}

    @staticmethod
    def _walk_untrusted(value: Any, path: str = "$") -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                key_text = str(key)
                lowered = key_text.casefold()
                if lowered in _SENSITIVE_KEYS:
                    raise MaxControlError("model output contains a forbidden field")
                BoundedRunner._walk_untrusted(item, f"{path}.{key_text}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                BoundedRunner._walk_untrusted(item, f"{path}[{index}]")
        elif isinstance(value, str):
            if _ABSOLUTE_PATH.match(value.strip()):
                raise MaxControlError("model output contains an absolute path")

    @staticmethod
    def _walk_gateway_context(value: Any, path: str = "$") -> None:
        """Reject secrets/source bodies while allowing trusted stable IDs."""

        allowed_identifier_keys = {"source_id", "document_id", "document_version_id", "passage_id", "verified_evidence_id", "version_id", "stable_id", "source_reference_ids"}
        forbidden = {"full_text", "source_text", "passage_text", "pdf_text", "raw_document", "api_key", "secret", "password", "access_token", "refresh_token", "token", "model_key", "absolute_path", "path", "prompt", "raw_response", "response_text"}
        if isinstance(value, Mapping):
            for key, item in value.items():
                key_text = str(key); lowered = key_text.casefold()
                if lowered in forbidden or (lowered in _SENSITIVE_KEYS and key_text not in allowed_identifier_keys):
                    raise MaxControlError("GATEWAY_CONTEXT_REJECTED")
                BoundedRunner._walk_gateway_context(item, f"{path}.{key_text}")
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                BoundedRunner._walk_gateway_context(item, f"{path}[{index}]")
        elif isinstance(value, str) and _ABSOLUTE_PATH.match(value.strip()):
            raise MaxControlError("GATEWAY_CONTEXT_REJECTED")

    @classmethod
    def _reject_model_statuses(cls, value: Any) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if str(key).casefold() in {"status", "decision", "verification_status"} and isinstance(item, str) and item.casefold() in _FORBIDDEN_STATUS_VALUES:
                    raise MaxControlError("model output cannot assert a final or verified status")
                cls._reject_model_statuses(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                cls._reject_model_statuses(item)

    def _normalize_proposal(
        self,
        *,
        proposal_value: Mapping[str, Any],
        state: ResearchState,
        run_state: MaxRunState,
        charter: MaxResearchCharter,
        plan: RunnerPlan,
        authoritative_discussion: DiscussionSession | None = None,
    ) -> tuple[RunnerProposal, CanonicalChangeSet, CoverageLedger, tuple[dict[str, Any], ...], tuple[str, ...]]:
        try:
            self._walk_untrusted(proposal_value)
            self._reject_model_statuses(proposal_value)
            proposal = RunnerProposal.from_mapping(proposal_value)
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("model proposal failed strict validation") from exc

        known_ids = set(state.latest_by_id)
        proposed_ids: set[str] = set()
        objects: list[CanonicalObject] = []
        for item in proposal.objects:
            kind = str(getattr(item.kind, "value", item.kind))
            if item.project_id != run_state.project_id or kind in _FORBIDDEN_MODEL_KINDS:
                raise MaxControlError("model proposal contains a forbidden or cross-project canonical object")
            if not is_stable_id(item.stable_id) or item.stable_id in proposed_ids:
                raise MaxControlError("model proposal contains an invalid or duplicate canonical ID")
            if item.version != 1 or item.supersedes_version_id is not None:
                raise MaxControlError("model proposal cannot self-assert a canonical predecessor")
            if item.version_id in {obj.version_id for obj in state.objects}:
                raise MaxControlError("model proposal attempts to reuse an existing canonical version")
            proposed_ids.add(item.stable_id)
            self._walk_untrusted(item.payload)
            self._reject_model_statuses(item.payload)
            objects.append(item)

        relations = []
        endpoint_ids = known_ids | proposed_ids
        endpoint_versions = {obj.version_id for obj in state.objects} | {obj.version_id for obj in objects}
        for relation in proposal.relations:
            if relation.project_id != run_state.project_id or not is_stable_id(relation.relation_id):
                raise MaxControlError("model proposal contains an invalid relation")
            if relation.source_id not in endpoint_ids or relation.target_id not in endpoint_ids:
                raise MaxControlError("model relation endpoint is outside the canonical frontier")
            if relation.source_version_id not in endpoint_versions or relation.target_version_id not in endpoint_versions:
                raise MaxControlError("model relation endpoint version is not exact")
            self._walk_untrusted(relation.metadata)
            relations.append(relation)

        record_refs = []
        for reference in proposal.record_refs:
            if not is_stable_id(reference) or reference not in endpoint_ids:
                raise MaxControlError("model record reference is outside the canonical frontier")
            record_refs.append(reference)

        strategy: SearchStrategy | None = None
        if proposal.strategy is not None:
            try:
                raw_strategy = dict(proposal.strategy)
                raw_strategy.pop("strategy_id", None)
                raw_strategy["project_id"] = run_state.project_id
                raw_strategy["run_id"] = run_state.run_id
                raw_strategy["target_ids"] = tuple(item for item in raw_strategy.get("target_ids", ()) if item in endpoint_ids)
                raw_strategy["result_ids"] = tuple(item for item in raw_strategy.get("result_ids", ()) if item in endpoint_ids)
                raw_strategy["new_evidence_ids"] = tuple(item for item in raw_strategy.get("new_evidence_ids", ()) if item in proposed_ids)
                strategy = SearchStrategy.from_mapping(raw_strategy)
            except Exception as exc:
                raise MaxControlError("model search strategy is invalid") from exc
            if any(not is_stable_id(item) for item in (*strategy.target_ids, *strategy.result_ids, *strategy.new_evidence_ids)):
                raise MaxControlError("model search strategy contains an invalid canonical ID")
        if strategy is None:
            # A round without a provider search result still has a server-owned
            # ledger entry, so completion history cannot be faked by a payload.
            strategy = SearchStrategy(
                project_id=run_state.project_id,
                run_id=run_state.run_id,
                family="bounded_review",
                query=f"fixture:{plan.cognitive_kind}",
                target_ids=tuple(sorted(endpoint_ids))[:8],
                filters={"server_generated": True},
                coverage_keys=(plan.cognitive_kind,),
            )
        required = charter.quality_gates.get("required_strategy_families", ())
        if not isinstance(required, (list, tuple)):
            raise MaxControlError("Charter strategy family policy is invalid")
        ledger = CoverageLedger(strategies=(strategy,), required_families=tuple(str(item) for item in required))
        artifacts: list[dict[str, Any]] = []
        allowed_artifact_types = {"search_strategy", "attack_record", "attack", "discussion_session", "adjudication", "rehydration_output", "rehydration_review", "acquisition_request", "validity_audit", "minority_report", "speculative_idea", "cold_review_packet", "cold_review_result", "final_report", "formal_completion_evidence"}
        server_owned_artifact_types = {"attack_record", "attack", "discussion_session", "adjudication", "rehydration_output", "rehydration_review", "validity_audit", "minority_report", "cold_review_packet", "cold_review_result", "final_report", "formal_completion_evidence"}
        for item in proposal.artifact_links:
            allowed = {"artifact_type", "artifact_id", "artifact", "artifact_json", "artifact_hash"}
            if set(item) - allowed or not isinstance(item.get("artifact_type"), str) or not item.get("artifact_type"):
                raise MaxControlError("model artifact link is invalid")
            if item["artifact_type"] not in allowed_artifact_types:
                raise MaxControlError("model artifact type is unknown")
            artifact = item.get("artifact", item.get("artifact_json"))
            if not isinstance(artifact, Mapping):
                raise MaxControlError("model artifact must be a typed object")
            self._walk_untrusted(artifact)
            artifact_type = item["artifact_type"]
            if artifact_type == "search_strategy":
                # The authoritative typed SearchStrategy is reconstructed from
                # proposal.strategy below; a model-provided artifact link is
                # only an untrusted duplicate.
                continue
            if artifact_type in server_owned_artifact_types:
                expected_server_round = (
                    (artifact_type in {"attack_record", "attack"} and plan.round_type == "attack")
                    or (artifact_type in {"discussion_session", "adjudication", "validity_audit", "minority_report"} and plan.round_type == "adjudication")
                    or (artifact_type == "rehydration_review" and plan.round_type == "rehydration")
                )
                if expected_server_round:
                    # Server normalization below or repository rehydration owns
                    # these records; the model never gets to assert them.
                    continue
                raise MaxControlError("model cognitive artifact is outside its round authority")
            raise MaxControlError("model cognitive artifact type is not supported by the bounded runner")
        artifacts.append({"artifact_type": "search_strategy", "artifact": model_to_dict(strategy)})
        if plan.round_type == "attack":
            target = state.latest_by_id.get(plan.role_packets[0].target_id)
            if target is None:
                raise MaxControlError("attack target is outside the canonical frontier")
            objection_ids = tuple(item.stable_id for item in objects if str(getattr(item.kind, "value", item.kind)) == CanonicalObjectKind.OBJECTION.value)
            counter_ids = tuple(sorted({endpoint for relation in relations if str(getattr(relation.relation, "value", relation.relation)) == "counters" for endpoint in (relation.source_id, relation.target_id) if endpoint in known_ids | proposed_ids}))
            attack = AttackRecord(project_id=run_state.project_id, run_id=run_state.run_id, charter_hash=charter_hash(charter), state_hash=state.state_hash, iteration_id=plan.iteration_id, target_id=target.stable_id, target_version_id=target.version_id, objection_ids=objection_ids, counterevidence_ids=counter_ids, outcome="needs_review", rationale="server-normalized bounded adversarial attack")
            artifacts = [item for item in artifacts if item["artifact_type"] not in {"attack_record", "attack"}]
            artifacts.append({"artifact_type": "attack_record", "artifact": model_to_dict(attack)})
        if plan.round_type == "adjudication":
            if authoritative_discussion is None:
                raise MaxControlError("adjudication requires the persisted five-call typed discussion output")
            discussion = authoritative_discussion
            try:
                validate_discussion_session(discussion, state=state).raise_if_invalid()
            except (ContractValidationError, KeyError, TypeError, ValueError) as exc:
                # The provider owns the nested values, but never the error
                # boundary.  In particular, a nested Adjudication,
                # ValidityAudit, or MinorityReport failure must become a
                # stable control-plane failure before any canonical write.
                raise MaxControlError("INVALID_ADJUDICATION") from exc
            artifacts = [item for item in artifacts if item["artifact_type"] not in {"discussion_session", "adjudication"}]
            artifacts.append({"artifact_type": "discussion_session", "artifact": model_to_dict(discussion)})
            # Keep the adjudicator's typed sub-results independently linked to
            # the adjudicator call as well as embedded in the aggregate
            # DiscussionSession.  This makes it impossible for a later
            # projection to claim that an audit or minority report came from
            # an unrelated role call.
            for audit in discussion.validity_audits:
                artifacts.append({"artifact_type": "validity_audit", "artifact": model_to_dict(audit)})
            for minority in discussion.minority_reports:
                artifacts.append({"artifact_type": "minority_report", "artifact": model_to_dict(minority)})
        change_set = CanonicalChangeSet(
            project_id=run_state.project_id,
            run_id=run_state.run_id,
            iteration_id=plan.iteration_id,
            input_state_hash=state.state_hash,
            objects=tuple(objects),
            relations=tuple(relations),
            source_reference_results=(),
        )
        return proposal, change_set, ledger, tuple(artifacts), tuple(record_refs)

    def _choose_reservation_amount(self, budget: Mapping[str, Any]) -> dict[str, int | float]:
        available = budget.get("available", {})
        if not isinstance(available, Mapping):
            raise MaxControlError("budget availability is invalid")
        requested: dict[str, int | float] = {}
        for unit, value in self.profile.call_budget.items():
            available_value = available.get(unit)
            if available_value is None:
                continue
            if isinstance(available_value, bool) or not isinstance(available_value, (int, float)) or available_value < value:
                raise MaxControlError("Max Run budget is below the frozen per-call reservation upper bound")
            requested[str(unit)] = value
        if not requested:
            raise MaxControlError("Max Run has no declared model-call budget units")
        return requested

    def _ensure_reservation(self, *, run_id: str, iteration_id: str, logical_call_id: str, budget: Mapping[str, Any], fencing_token: int) -> tuple[str, dict[str, Any]]:
        key = f"mr2a:reserve:{logical_call_id}"
        existing = self.persistence.budget_reservation(run_id=run_id, idempotency_key=key)
        amount = existing["amount"] if existing is not None else self._choose_reservation_amount(budget)
        self._crash_if("reserve_before")
        result = self.repository.reserve_budget(run_id=run_id, amount=amount, idempotency_key=key, actor=self.actor, fencing_token=fencing_token, iteration_id=iteration_id)
        self._crash_if("reserve_after")
        reservation_id = result.get("reservation_id") or result.get("entry_id")
        if not isinstance(reservation_id, str) or not reservation_id:
            raise MaxControlError("budget reservation did not return a server ID")
        return reservation_id, result

    def _build_intent(
        self,
        *,
        run_state: MaxRunState,
        state: ResearchState,
        charter: MaxResearchCharter,
        plan: RunnerPlan,
        budget: Mapping[str, Any],
        role_index: int = 0,
        request_state_hash: str | None = None,
        frontier_hash: str | None = None,
        upstream_public: Mapping[str, Any] | None = None,
    ) -> ModelCallIntent:
        if isinstance(role_index, bool) or role_index < 0 or role_index >= len(plan.role_packets):
            raise MaxControlError("runner role index is invalid")
        packet = plan.role_packets[role_index]
        spec = plan.call_specs[role_index]
        cold = bool(plan.metadata.get("cold_context", False))
        effective_state_hash = request_state_hash or state.state_hash
        context = dict(self.gateway.context(project_id=run_state.project_id, run_id=run_state.run_id, state_hash=effective_state_hash, allowed_ids=packet.allowed_canonical_ids, cold=cold))
        try:
            self._walk_gateway_context(context)
        except MaxControlError as exc:
            raise MaxControlError("GATEWAY_CONTEXT_REJECTED") from exc
        # Available balance changes after reserve/release.  It is not part of
        # the frozen model request; recovery binds the request to the Charter
        # limits and reconstructs the live balance separately.
        context["budget_limits"] = dict(charter.budget)
        context["call_budget_limits"] = dict(self.profile.call_budget)
        context["frontier_hash"] = frontier_hash or canonical_sha256(sorted(state.latest_by_id))
        context["canonical_claim_ids"] = sorted(obj.stable_id for obj in state.latest_by_id.values() if str(getattr(obj.kind, "value", obj.kind)) == CanonicalObjectKind.CLAIM.value)
        context["canonical_evidence_ids"] = sorted(obj.stable_id for obj in state.latest_by_id.values() if str(getattr(obj.kind, "value", obj.kind)) == CanonicalObjectKind.EVIDENCE.value)
        gateway_name = str(getattr(self.gateway, "gateway_name", self.profile.gateway_name))
        gateway_identity = str(getattr(self.gateway, "gateway_identity", gateway_name))
        gateway_config_hash = str(getattr(self.gateway, "config_hash", canonical_sha256({"gateway_identity": gateway_identity, "profile_hash": self.profile.profile_hash})))
        source_reference_ids: list[str] = []
        raw_references = context.get("source_references", ())
        if isinstance(raw_references, (list, tuple)):
            for reference in raw_references:
                if isinstance(reference, Mapping):
                    for key in ("source_id", "document_id", "document_version_id", "passage_id", "verified_evidence_id", "version_id", "stable_id"):
                        candidate = reference.get(key)
                        if isinstance(candidate, str) and candidate.strip():
                            source_reference_ids.append(candidate.strip())
                elif isinstance(reference, str) and reference.strip():
                    source_reference_ids.append(reference.strip())
        context["gateway_name"] = gateway_name
        context["gateway_identity"] = gateway_identity
        context["gateway_config_hash"] = gateway_config_hash
        context["contract_version"] = "research-kb/v1"
        context["source_reference_ids"] = sorted(set(source_reference_ids))
        public_value = dict(upstream_public or {})
        if spec.upstream_call_ids and not public_value:
            raise MaxControlError("required public upstream deliberation artifacts are missing")
        if not spec.upstream_call_ids and public_value:
            raise MaxControlError("independent deliberation call received upstream output")
        context["public_upstream_artifacts"] = [
            {"call_id": key, "artifact_hash": canonical_sha256(value), "artifact_type": value.get("kind", "public") if isinstance(value, Mapping) else "public"}
            for key, value in sorted(public_value.items())
        ]
        context["fragment_count"] = len(public_value)
        context["request_char_count"] = len(canonical_json({"context": context, "upstream": public_value}))
        context["context_hash"] = canonical_sha256({key: context[key] for key in sorted(context) if key not in {"source_references", "public_upstream_artifacts", "trusted_source_data"}})
        idempotency_key = f"mr2a:call:{run_state.run_id}:{plan.iteration_id}:{role_index}:{spec.call_id}:{plan.plan_hash[:24]}"
        logical_call_id = canonical_sha256({"run_id": run_state.run_id, "iteration_id": plan.iteration_id, "idempotency_key": idempotency_key})[:48]
        request = ModelRequestEnvelope(
            project_id=run_state.project_id,
            run_id=run_state.run_id,
            iteration_id=plan.iteration_id,
            role_packet=packet,
            model_identity=run_state.model_identity,
            inference_profile=self.profile.inference_profile,
            context=context,
            request_payload={
                "round_type": plan.round_type,
                "cognitive_kind": plan.cognitive_kind,
                "plan_hash": plan.plan_hash,
                "sequence": plan.sequence,
                "target_id": packet.target_id,
                "logical_call_id": logical_call_id,
                "phase": spec.phase,
                "call_spec_id": spec.call_id,
                "upstream_call_ids": list(spec.upstream_call_ids),
                "public_upstream": public_value,
            },
        )
        return ModelCallIntent(
            project_id=run_state.project_id,
            run_id=run_state.run_id,
            iteration_id=plan.iteration_id,
            input_state_hash=effective_state_hash,
            role_packet_id=packet.packet_id,
            round_type=plan.round_type,
            model_identity=run_state.model_identity,
            inference_profile_hash=self.profile.inference_profile.inference_profile_hash,
            request_hash=request.request_hash,
            idempotency_key=idempotency_key,
            request=request,
            phase=spec.phase,
            call_spec_id=spec.call_id,
            upstream_call_ids=spec.upstream_call_ids,
        )

    def _load_intent(self, row: Mapping[str, Any], *, run_state: MaxRunState, state: ResearchState, charter: MaxResearchCharter, plan: RunnerPlan, budget: Mapping[str, Any]) -> ModelCallIntent:
        try:
            manifest = json.loads(str(row["intent_json"]))
            call_spec_id = str(manifest.get("call_spec_id", ""))
            role = str(manifest.get("role", ""))
            role_index = next((index for index, spec in enumerate(plan.call_specs) if (call_spec_id and spec.call_id == call_spec_id) or (not call_spec_id and plan.role_packets[index].role == role and plan.role_packets[index].packet_id == manifest.get("role_packet_id"))), -1)
            if role_index < 0:
                raise ValueError("stored intent role packet is not in the frozen plan")
            spec = plan.call_specs[role_index]
            upstream_public: dict[str, Any] = {}
            group_id = row.get("group_id") if isinstance(row, Mapping) else None
            if spec.upstream_call_ids and isinstance(group_id, str):
                for index, upstream_spec in enumerate(plan.call_specs):
                    if upstream_spec.call_id not in spec.upstream_call_ids:
                        continue
                    binding = self.persistence.group_binding(run_id=run_state.run_id, group_id=group_id, call_index=index)
                    if binding is None or not binding.get("result_json"):
                        raise ValueError("stored public upstream result is missing")
                    upstream_result = self._load_result(binding)
                    upstream_public[upstream_spec.call_id] = self._public_call_artifact(upstream_result, upstream_spec.call_id)
            intent = self._build_intent(run_state=run_state, state=state, charter=charter, plan=plan, budget=budget, role_index=role_index, request_state_hash=str(manifest.get("input_state_hash")), frontier_hash=manifest.get("frontier_hash"), upstream_public=upstream_public)
            if intent.intent_hash != row["intent_hash"] or intent.logical_call_id != row["logical_call_id"] or intent.intent_id != row["intent_id"]:
                raise ValueError("stored intent manifest binding mismatch")
            if manifest.get("request_hash") != intent.request_hash or manifest.get("packet_hash") != canonical_sha256(intent.request.role_packet):
                raise ValueError("stored intent manifest request mismatch")
            if manifest.get("phase", intent.phase) != intent.phase or manifest.get("call_spec_id", intent.call_spec_id) != intent.call_spec_id:
                raise ValueError("stored intent phase binding mismatch")
            return intent
        except Exception as exc:
            raise MaxControlError("stored model intent is invalid") from exc

    def _load_result(self, row: Mapping[str, Any]) -> ModelCallResult:
        try:
            durable = json.loads(str(row["result_json"]))
            response = {
                "logical_call_id": durable["logical_call_id"],
                "intent_hash": durable["intent_hash"],
                "model_identity": durable["model_identity"],
                "inference_profile_hash": durable["inference_profile_hash"],
                "status": durable["status"],
                "proposal": durable.get("proposal", {}),
                "usage_receipt": durable.get("usage_receipt", {}),
                "provider_call_id": durable.get("provider_call_id", "fixture-call"),
                "dispatch_known": durable.get("dispatch_known", True),
                "error_code": durable.get("error_code"),
                "response_hash": durable.get("response_hash", ""),
            }
            return ModelCallResult.from_mapping({"logical_call_id": durable["logical_call_id"], "intent_hash": durable["intent_hash"], "status": durable["status"], "response": response, "authoritative": durable.get("authoritative", True), "result_hash": durable.get("result_hash", "")})
        except Exception as exc:
            raise MaxControlError("stored model result is invalid") from exc

    @staticmethod
    def _public_call_artifact(result: ModelCallResult, call_spec_id: str) -> Mapping[str, Any]:
        """Return only the typed public artifact allowed downstream."""

        proposal = result.response.proposal
        value = proposal.get("deliberation") if isinstance(proposal, Mapping) else None
        if not isinstance(value, Mapping):
            raise MaxControlError("deliberation call did not return a typed public artifact")
        expected_kind = {
            "lead_position": "position", "rival_position": "position",
            "rival_cross_examination": "cross_examination",
            "lead_cross_examination_response": "correction",
            "adjudicator": "adjudication",
        }.get(call_spec_id)
        if expected_kind is not None and value.get("kind") != expected_kind:
            raise MaxControlError("deliberation call returned the wrong artifact kind")
        # Keep the public object bounded and deterministic.  The request
        # manifest stores its hash and IDs; the typed result stores the
        # corresponding public value for crash recovery.
        if len(canonical_json(value)) > 20_000:
            raise MaxControlError("public deliberation artifact exceeds the bound")
        BoundedRunner._walk_untrusted(value)
        return {str(key): value[key] for key in sorted(value)}

    def _settle_call_usage(self, *, run_id: str, intent: ModelCallIntent, result: ModelCallResult, fencing_token: int) -> str | None:
        # A failed provider call may still be billable.  An empty receipt on a
        # failed call means that no authoritative usage fact was supplied and
        # the reservation is handled by the group abort path; a non-empty
        # receipt follows the same exact binding/settlement path as success.
        if result.status != ModelCallStatus.SUCCEEDED.value and not result.response.usage_receipt:
            return None
        # ``_record_response`` settles a fresh provider result before it is
        # returned.  Group execution may see the same result again (and
        # recovery may resume after the result/usage seam), so the immutable
        # binding is the authoritative idempotency boundary.  Checking it
        # first also avoids replaying a commit after its reservation has
        # already been released.
        existing_binding = self.persistence.usage_binding(run_id=run_id, logical_call_id=intent.logical_call_id)
        if existing_binding is not None:
            return str(existing_binding["usage_entry_id"])
        try:
            receipt = UsageReceipt.from_mapping(result.response.usage_receipt)
        except Exception as exc:
            raise MaxControlError("successful call usage receipt is invalid") from exc
        reservation = self.persistence.budget_reservation(run_id=run_id, idempotency_key=f"mr2a:reserve:{intent.logical_call_id}")
        if reservation is None:
            raise MaxControlError("successful call has no durable budget reservation")
        reservation_id = reservation["reservation_id"] or reservation["entry_id"]
        usage = self.repository.record_authoritative_usage(
            run_id=run_id,
            amount=dict(receipt.amount),
            receipt=receipt,
            provenance={"runner": "mr-2a.2", "logical_call_id": intent.logical_call_id},
            idempotency_key=f"mr2a.2:usage:{intent.logical_call_id}",
            actor=self.actor,
            fencing_token=fencing_token,
            iteration_id=intent.iteration_id,
            logical_call_id=intent.logical_call_id,
            intent_hash=intent.intent_hash,
            request_hash=intent.request_hash,
            provider_call_id=result.response.provider_call_id,
            inference_profile_hash=intent.inference_profile_hash,
        )
        usage_entry_id = str(usage.get("entry_id"))
        self.repository.commit_budget(
            run_id=run_id,
            reservation_id=reservation_id,
            amount=dict(receipt.amount),
            idempotency_key=f"mr2a.2:commit:{intent.logical_call_id}",
            actor=self.actor,
            fencing_token=fencing_token,
            iteration_id=intent.iteration_id,
        )
        self.repository.release_budget(
            run_id=run_id,
            reservation_id=reservation_id,
            amount=None,
            idempotency_key=f"mr2a.2:release:{intent.logical_call_id}",
            actor=self.actor,
            fencing_token=fencing_token,
            iteration_id=intent.iteration_id,
        )
        stored = self.persistence.stored_result(run_id=run_id, logical_call_id=intent.logical_call_id)
        if stored is None:
            raise MaxControlError("settled usage result disappeared")
        self.persistence.record_usage_binding(run_id=run_id, result_id=str(stored["result_id"]), receipt=receipt, usage_entry_id=usage_entry_id, actor=self.actor, fencing_token=fencing_token)
        return usage_entry_id

    def _charge_iteration(self, *, run_id: str, iteration_id: str, fencing_token: int) -> str:
        result = self.repository.record_server_usage(
            run_id=run_id,
            amount={"iteration_count": 1},
            idempotency_key=f"mr2a.2:iteration:{iteration_id}",
            actor=self.actor,
            fencing_token=fencing_token,
            iteration_id=iteration_id,
            charge_kind="iteration",
        )
        return str(result["entry_id"])

    def _parse_plan(self, row: Mapping[str, Any]) -> RunnerPlan:
        try:
            plan = RunnerPlan.from_mapping(json.loads(str(row["plan_json"])))
        except Exception as exc:
            raise MaxControlError("stored runner plan is invalid") from exc
        if plan.plan_hash != row["plan_hash"] or plan.plan_id != row["plan_id"] or str(row.get("profile_hash", self.profile.profile_hash)) != self.profile.profile_hash:
            raise MaxControlError("stored runner plan/profile binding is invalid")
        return plan

    def _persist_plan_and_iteration(self, *, run_state: MaxRunState, charter: MaxResearchCharter, state: ResearchState, budget: Mapping[str, Any], fencing_token: int) -> tuple[RunnerPlan, dict[str, Any]]:
        current = self.persistence.current_work(run_id=run_state.run_id)
        latest_plan_row = self.persistence.latest_plan(run_id=run_state.run_id)
        existing_iteration = self.persistence.open_iteration(run_id=run_state.run_id)
        history = self.persistence.list_history(run_id=run_state.run_id)
        next_sequence = max((int(item.get("sequence_no", 0)) for item in history), default=0) + 1
        if current is not None:
            plan = self._parse_plan(current)
        elif latest_plan_row is not None and latest_plan_row["input_state_hash"] == state.state_hash and (
            int(latest_plan_row["sequence_no"]) == next_sequence
            or (existing_iteration is not None and latest_plan_row["iteration_id"] == existing_iteration["iteration_id"])
        ):
            plan = self._parse_plan(latest_plan_row)
        else:
            self._crash_if("plan_before")
            policy_triggers = self.persistence.server_policy_triggers(run_id=run_state.run_id, state_hash=state.state_hash)
            plan = self._plan_builder(
                project_id=run_state.project_id,
                run_id=run_state.run_id,
                sequence=next_sequence,
                state=model_to_dict(state),
                history=history,
                profile=self.profile,
                rehydration_policy=RehydrationPolicy(),
                recovery_required=False,
                policy_triggers=policy_triggers,
                budget_snapshot=budget,
            )
            if self._plan_validator is not None:
                self._plan_validator(plan)
            self.persistence.record_plan(run_id=run_state.run_id, plan=plan, profile=self.profile, actor=self.actor, fencing_token=fencing_token)
            self._crash_if("plan_after")

        open_iteration = existing_iteration or self.persistence.open_iteration(run_id=run_state.run_id)
        if open_iteration is None:
            self._crash_if("begin_before")
            begun = self.repository.begin_iteration(
                run_id=run_state.run_id,
                round_type=plan.round_type,
                actor=self.actor,
                fencing_token=fencing_token,
                input_state_hash=plan.input_state_hash,
                iteration_id=plan.iteration_id,
                requested_sequence=plan.sequence,
            )
            self._crash_if("begin_after")
            open_iteration = begun
        if open_iteration["iteration_id"] != plan.iteration_id:
            raise MaxControlError("stored runner plan is not bound to the current iteration")
        if self._plan_validator is not None:
            self._plan_validator(plan)
        self.persistence.bind_plan(run_id=run_state.run_id, plan_id=plan.plan_id, iteration_id=plan.iteration_id, actor=self.actor, fencing_token=fencing_token)
        self.persistence.record_call_group(run_id=run_state.run_id, plan=plan, actor=self.actor, fencing_token=fencing_token)
        return plan, dict(open_iteration)

    def _record_response(self, *, run_id: str, intent: ModelCallIntent, response: ModelResponseEnvelope, fencing_token: int) -> ModelCallResult:
        if response.logical_call_id != intent.logical_call_id or response.intent_hash != intent.intent_hash:
            raise MaxControlError("model response is not bound to the persisted intent")
        if response.model_identity != intent.model_identity or response.inference_profile_hash != intent.inference_profile_hash:
            raise MaxControlError("model response model/profile binding is invalid")
        if response.status not in {ModelCallStatus.SUCCEEDED.value, ModelCallStatus.FAILED.value} or not response.dispatch_known:
            raise MaxControlError("model response is not an authoritative bounded result")
        self._crash_if("result_before")
        result = ModelCallResult(intent.logical_call_id, intent.intent_hash, response.status, response)
        usage_candidate = bool(response.usage_receipt) or response.status == ModelCallStatus.SUCCEEDED.value
        try:
            self.persistence.record_result(run_id=run_id, result=result, actor=self.actor, fencing_token=fencing_token)
        except MaxControlError as exc:
            message = str(exc).casefold()
            if usage_candidate and ("usage" in message or "receipt" in message or "authority" in message):
                self._record_usage_dispute(run_id=run_id, intent=intent, response=response, fencing_token=fencing_token)
                raise UsageDispute(intent.logical_call_id) from exc
            raise
        self._crash_if("usage_before")
        try:
            self._settle_call_usage(run_id=run_id, intent=intent, result=result, fencing_token=fencing_token)
        except MaxControlError:
            if usage_candidate:
                self._record_usage_dispute(run_id=run_id, intent=intent, response=response, fencing_token=fencing_token)
                raise UsageDispute(intent.logical_call_id)
            raise
        self._crash_if("usage_after")
        self._crash_if("result_after")
        return result

    def _record_usage_dispute(
        self,
        *,
        run_id: str,
        intent: ModelCallIntent,
        response: ModelResponseEnvelope,
        fencing_token: int,
    ) -> None:
        """Persist only a redacted recovery marker before pausing the Run."""

        self.persistence.record_recovery(
            run_id=run_id,
            logical_call_id=intent.logical_call_id,
            disposition=RecoveryDisposition.ADMIN_DECISION_REQUIRED,
            decision={
                "reason": "usage_dispute",
                "provider_call_id_hash": canonical_sha256(response.provider_call_id),
                "receipt_hash": canonical_sha256(response.usage_receipt),
                "reservation_retained": True,
            },
            actor=self.actor,
            fencing_token=fencing_token,
        )

    def _dispatch_or_recover(self, *, run_state: MaxRunState, intent: ModelCallIntent, unfinished: Mapping[str, Any] | None, fencing_token: int) -> ModelCallResult | None:
        capabilities = self.adapter.capabilities
        consumed = self.persistence.recovery_consumption(run_id=run_state.run_id, logical_call_id=intent.logical_call_id)
        if consumed is not None and consumed.get("decision") == "retry":
            # The administrator has explicitly accepted the duplicate-risk
            # branch.  Reuse the exact persisted intent/idempotency key; never
            # invent a new logical call during recovery.
            self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=RecoveryDisposition.REUSE_INTENT, decision={"admin_consumption_id": consumed["consumption_id"], "duplicate_risk_explicitly_confirmed": True}, actor=self.actor, fencing_token=fencing_token)
            self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="dispatching", detail={"recovery": True, "admin_retry": True}, actor=self.actor, fencing_token=fencing_token)
            self._crash_if("dispatch_before")
            try:
                response = self.adapter.dispatch(intent.request, idempotency_key=intent.idempotency_key)
            except Exception as exc:
                self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="failed", detail={"error_code": "adapter_failure", "admin_retry": True}, actor=self.actor, fencing_token=fencing_token)
                raise MaxControlError("admin retry adapter failed") from exc
            if response is None:
                raise MaxControlError("admin retry did not return an authoritative result")
            self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="dispatched", detail={"provider_call": True, "admin_retry": True}, actor=self.actor, fencing_token=fencing_token)
            self.persistence.record_dispatch_ack(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, status="dispatched", dispatch_known=True, provider_call_id=response.provider_call_id, actor=self.actor, fencing_token=fencing_token, preserve_existing=True)
            return self._record_response(run_id=run_state.run_id, intent=intent, response=response, fencing_token=fencing_token)
        dispatch_status = str(unfinished.get("dispatch_status")) if unfinished and unfinished.get("dispatch_status") else None
        latest_attempt = self.persistence.latest_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id)
        attempt_stage = str(latest_attempt.get("stage")) if latest_attempt else None

        def query() -> ModelResponseEnvelope | None:
            if not capabilities.supports_result_query:
                return None
            try:
                value = self.adapter.query(idempotency_key=intent.idempotency_key)
            except Exception as exc:
                raise MaxControlError("provider result query failed") from exc
            return value if isinstance(value, ModelResponseEnvelope) else (ModelResponseEnvelope.from_mapping(value) if isinstance(value, Mapping) else None)

        response: ModelResponseEnvelope | None = None
        recovery_disposition: RecoveryDisposition | None = None
        recovery_decision: dict[str, Any] = {}
        if dispatch_status in {"unknown", "dispatched"} or attempt_stage in {"unknown", "dispatched"}:
            response = query()
            if response is not None:
                recovery_disposition = RecoveryDisposition.QUERY_PROVIDER_RESULT
                recovery_decision = {"provider_result": True}
            if response is None and capabilities.supports_provider_idempotency:
                # The same server idempotency key is the only retry allowed.
                self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=RecoveryDisposition.REUSE_INTENT, decision={"reason": "provider result was not queryable; reusing the persisted idempotency key"}, actor=self.actor, fencing_token=fencing_token)
                self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="dispatching", detail={"recovery": True}, actor=self.actor, fencing_token=fencing_token)
                response = self.adapter.dispatch(intent.request, idempotency_key=intent.idempotency_key)
                if response is not None:
                    recovery_disposition = RecoveryDisposition.IDEMPOTENT_SUCCESS
                    recovery_decision = {"provider_idempotency": True}
            if response is None:
                self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=RecoveryDisposition.AMBIGUOUS_PAUSE, decision={"reason": "provider outcome remains unknown", "provider_idempotency": bool(capabilities.supports_provider_idempotency), "result_query": bool(capabilities.supports_result_query)}, actor=self.actor, fencing_token=fencing_token)
                self.repository.pause(run_id=run_state.run_id, actor=self.actor, fencing_token=fencing_token)
                return None
        elif attempt_stage == "dispatching" and not capabilities.supports_provider_idempotency and not capabilities.supports_result_query:
            self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=RecoveryDisposition.AMBIGUOUS_PAUSE, decision={"reason": "dispatch started before process recovery and provider has no safe recovery primitive"}, actor=self.actor, fencing_token=fencing_token)
            self.repository.pause(run_id=run_state.run_id, actor=self.actor, fencing_token=fencing_token)
            return None
        else:
            self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="dispatching", detail={"recovery": False}, actor=self.actor, fencing_token=fencing_token)
            self._crash_if("dispatch_before")
            try:
                response = self.adapter.dispatch(intent.request, idempotency_key=intent.idempotency_key)
            except DispatchUnknown as exc:
                self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="unknown", detail={"sent": bool(exc.sent)}, actor=self.actor, fencing_token=fencing_token)
                self.persistence.record_dispatch_ack(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, status="unknown", dispatch_known=False, provider_call_id=None, actor=self.actor, fencing_token=fencing_token)
                if not exc.sent:
                    self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=RecoveryDisposition.REUSE_INTENT, decision={"reason": "adapter proved dispatch did not start"}, actor=self.actor, fencing_token=fencing_token)
                    return None
                if capabilities.supports_result_query:
                    response = query()
                    if response is not None:
                        recovery_disposition = RecoveryDisposition.QUERY_PROVIDER_RESULT
                        recovery_decision = {"provider_result": True}
                if response is None and capabilities.supports_provider_idempotency:
                    self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=RecoveryDisposition.REUSE_INTENT, decision={"reason": "dispatch outcome remains unknown; the persisted idempotency key is retained"}, actor=self.actor, fencing_token=fencing_token)
                    return None
                if response is None:
                    self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=RecoveryDisposition.AMBIGUOUS_PAUSE, decision={"reason": "sent dispatch is unknown and provider cannot query or idempotently retry"}, actor=self.actor, fencing_token=fencing_token)
                    self.repository.pause(run_id=run_state.run_id, actor=self.actor, fencing_token=fencing_token)
                    return None
            except Exception as exc:
                self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="failed", detail={"error_code": "adapter_failure"}, actor=self.actor, fencing_token=fencing_token)
                raise MaxControlError("bounded model adapter failed") from exc
            if response is not None:
                if recovery_disposition is not None:
                    self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=recovery_disposition, decision=recovery_decision, actor=self.actor, fencing_token=fencing_token)
                if self._should_fail("dispatch_after_unknown"):
                    self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="unknown", detail={"sent": True, "injected": True}, actor=self.actor, fencing_token=fencing_token)
                    self.persistence.record_dispatch_ack(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, status="unknown", dispatch_known=False, provider_call_id=None, actor=self.actor, fencing_token=fencing_token)
                    raise InjectedRunnerCrash("injected runner interruption at dispatch_after_unknown")
                self.persistence.record_attempt(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, stage="dispatched", detail={"provider_call": True}, actor=self.actor, fencing_token=fencing_token)
                self.persistence.record_dispatch_ack(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, status="dispatched", dispatch_known=True, provider_call_id=response.provider_call_id, actor=self.actor, fencing_token=fencing_token, preserve_existing=True)
        if response is None:
            return None
        return self._record_response(run_id=run_state.run_id, intent=intent, response=response, fencing_token=fencing_token)

    def _finish_aborted(self, *, run_state: MaxRunState, plan: RunnerPlan, intent: ModelCallIntent | None, reason: str, fencing_token: int) -> dict[str, Any]:
        if intent is not None:
            self.persistence.record_recovery(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, disposition=RecoveryDisposition.ADMIN_DECISION_REQUIRED, decision={"reason": reason}, actor=self.actor, fencing_token=fencing_token)
        open_iteration = self.persistence.open_iteration(run_id=run_state.run_id)
        bindings: list[dict[str, Any]] = []
        group = self.persistence.current_group(run_id=run_state.run_id)
        if group is not None and group.get("iteration_id") == plan.iteration_id:
            for call_index in range(int(group["call_count"])):
                binding = self.persistence.group_binding(run_id=run_state.run_id, group_id=group["group_id"], call_index=call_index)
                if binding is not None:
                    bindings.append(binding)
        elif intent is not None:
            bindings.append({"logical_call_id": intent.logical_call_id, "result_id": None})
        existing_iteration_outcome = self.persistence.iteration_outcome(run_id=run_state.run_id, iteration_id=plan.iteration_id)
        if open_iteration is not None and open_iteration["iteration_id"] == plan.iteration_id:
            for binding in bindings:
                logical_call_id = str(binding["logical_call_id"])
                reservation = self.persistence.budget_reservation(run_id=run_state.run_id, idempotency_key=f"mr2a:reserve:{logical_call_id}")
                if reservation is not None:
                    self.repository.release_budget(run_id=run_state.run_id, reservation_id=reservation["reservation_id"] or reservation["entry_id"], amount=None, idempotency_key=f"mr2a.2:release:{logical_call_id}", actor=self.actor, fencing_token=fencing_token, iteration_id=plan.iteration_id)
            try:
                self._charge_iteration(run_id=run_state.run_id, iteration_id=plan.iteration_id, fencing_token=fencing_token)
            except MaxControlError:
                # The original failure remains fail-closed; finish_iteration
                # will expose the missing/invalid charge rather than hiding it.
                raise
            delta = self.persistence.iteration_budget_delta(run_id=run_state.run_id, iteration_id=plan.iteration_id)
            self._crash_if("iteration_finish_before")
            finished = self.repository.finish_iteration(run_id=run_state.run_id, iteration_id=plan.iteration_id, actor=self.actor, fencing_token=fencing_token, status="aborted", output_state_hash=run_state.current_state_hash, budget_delta=delta)
            self._crash_if("iteration_finish_after")
        elif existing_iteration_outcome is not None and existing_iteration_outcome["status"] == "aborted":
            # Recovery after the immutable iteration outcome was appended but
            # before the group/conflict boundary completed must reuse the
            # stored identity and hash.  Reconstructing a placeholder here
            # would change every per-call outcome hash and make retry fail.
            finished = {
                "iteration_id": plan.iteration_id,
                "outcome_id": existing_iteration_outcome["outcome_id"],
                "outcome_hash": existing_iteration_outcome["outcome_hash"],
                "status": existing_iteration_outcome["status"],
            }
        else:
            finished = {"iteration_id": plan.iteration_id, "outcome_id": None, "status": "aborted"}
        for binding in bindings:
            logical_call_id = str(binding["logical_call_id"])
            result_hash = None
            result_id = binding.get("result_id")
            if result_id:
                stored = self.persistence.stored_result(run_id=run_state.run_id, logical_call_id=logical_call_id)
                if stored is not None:
                    result_hash = stored.get("result_hash")
            usage_entry_id = None
            check = self.repository._connect(read_only=True)
            try:
                usage_row = check.execute("SELECT usage_entry_id FROM max_runner_usage_bindings WHERE logical_call_id=?", (logical_call_id,)).fetchone()
                usage_entry_id = usage_row["usage_entry_id"] if usage_row is not None else None
            finally:
                check.close()
            outcome = {"reason": reason, "group_id": group.get("group_id") if group else None, "result_hash": result_hash, "usage_entry_id": usage_entry_id, "iteration_outcome_id": finished.get("outcome_id")}
            links = ({"link_type": "iteration_outcome", "target_id": finished["outcome_id"], "target_hash": finished.get("outcome_hash", canonical_sha256(finished))},) if finished.get("outcome_id") else ()
            if usage_entry_id:
                links += ({"link_type": "budget_entry", "target_id": usage_entry_id, "target_hash": canonical_sha256({"entry_id": usage_entry_id, "logical_call_id": logical_call_id})},)
            self.persistence.record_outcome(run_id=run_state.run_id, logical_call_id=logical_call_id, status="aborted", iteration_id=plan.iteration_id, outcome=outcome, actor=self.actor, fencing_token=fencing_token, links=links)
        if reason in {"proposal_rejected", "invalid_adjudication", "dispatch_or_result_rejected"} and intent is not None:
            stored_result = self.persistence.stored_result(run_id=run_state.run_id, logical_call_id=intent.logical_call_id)
            proposal_hash = canonical_sha256({"reason": reason, "logical_call_id": intent.logical_call_id})
            if stored_result is not None:
                try:
                    proposal_hash = canonical_sha256(json.loads(str(stored_result["result_json"])).get("proposal", {}))
                except Exception:
                    pass
            try:
                canonical_state = ResearchState.from_mapping(self.repository.get_state(run_id=run_state.run_id))
                version_hashes = tuple(sorted(canonical_sha256(model_to_dict(obj)) for obj in canonical_state.objects))
            except Exception:
                version_hashes = ()
            conflict_type = {
                "proposal_rejected": "repeated_invalid_proposal",
                "invalid_adjudication": "invalid_adjudication",
                "dispatch_or_result_rejected": "receipt_authority_conflict",
            }[reason]
            self._crash_if("conflict_before")
            conflict = self.persistence.record_epistemic_conflict(
                run_id=run_state.run_id,
                iteration_id=plan.iteration_id,
                logical_call_id=intent.logical_call_id,
                intent_hash=intent.intent_hash,
                request_hash=intent.request_hash,
                proposal_hash=proposal_hash,
                validator_hash=canonical_sha256({"validator": "mr-2a.2", "reason": reason, "phase": intent.phase}),
                canonical_state_hash=run_state.current_state_hash or "unknown-state",
                canonical_version_hashes=version_hashes,
                issue_codes=(reason,),
                conflict_type=conflict_type,
                canonical_basis={"reason": reason, "iteration_id": plan.iteration_id, "state_hash": run_state.current_state_hash or "unknown-state"},
                # The semantic fingerprint is stable across deterministic
                # retries and later round labels.  The exact intent/request
                # hashes remain stored separately, so a changed proposal is
                # still distinguishable while the escalation ladder can
                # recognize the same class of epistemic conflict.
                fingerprint=canonical_sha256({"run_id": run_state.run_id, "conflict_type": conflict_type, "reason": reason}),
                actor=self.actor,
                fencing_token=fencing_token,
            )
            self._crash_if("conflict_after")
            # The persisted resolution is the control-plane escalation point;
            # changing Run state is left to the explicit admin transition so
            # the group can still be finalized with the current fencing token.
            if conflict.get("resolution") == "paused":
                return self._redacted_summary(run_id=run_state.run_id, project_id=run_state.project_id, status="aborted", iteration_id=plan.iteration_id, round_type=plan.round_type, cognitive_kind=plan.cognitive_kind, plan_hash=plan.plan_hash, logical_call_id=intent.logical_call_id, reason="epistemic_conflict_paused")
        return self._redacted_summary(run_id=run_state.run_id, project_id=run_state.project_id, status="aborted", iteration_id=plan.iteration_id, round_type=plan.round_type, cognitive_kind=plan.cognitive_kind, plan_hash=plan.plan_hash, logical_call_id=intent.logical_call_id if intent else None, reason=reason)

    def _finalize_call_group(self, *, run_id: str, group_id: str, status: str, fencing_token: int) -> dict[str, Any]:
        """Finalize a group with explicit crash seams around the durable write."""

        self._crash_if("group_finalize_before")
        result = self.persistence.finalize_call_group(run_id=run_id, group_id=group_id, status=status, actor=self.actor, fencing_token=fencing_token)
        self._crash_if("group_finalize_after")
        return result

    def _build_adjudication_session(
        self,
        *,
        state: ResearchState,
        run_state: MaxRunState,
        plan: RunnerPlan,
        results_by_call: Mapping[str, ModelCallResult],
    ) -> DiscussionSession:
        required = {"lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response", "adjudicator"}
        if set(results_by_call) != required:
            raise MaxControlError("adjudication group does not contain the exact five logical calls")

        def typed(call_id: str, kind: str, allowed: set[str]) -> Mapping[str, Any]:
            proposal = results_by_call[call_id].response.proposal
            value = proposal.get("deliberation") if isinstance(proposal, Mapping) else None
            if not isinstance(value, Mapping) or value.get("kind") != kind or set(value) - allowed:
                raise MaxControlError("deliberation output is missing or contains unknown fields")
            for key in allowed & {"position", "question", "correction", "rationale"}:
                if key in value and (not isinstance(value[key], str) or not value[key].strip()):
                    raise MaxControlError("deliberation text is empty")
            return value

        lead = typed("lead_position", "position", {"kind", "role", "position", "canonical_claim_ids", "canonical_evidence_ids", "rationale"})
        rival = typed("rival_position", "position", {"kind", "role", "position", "canonical_claim_ids", "canonical_evidence_ids", "rationale"})
        cross = typed("rival_cross_examination", "cross_examination", {"kind", "examiner_role", "respondent_role", "question", "challenged_claim_ids"})
        response = typed("lead_cross_examination_response", "correction", {"kind", "role", "correction", "corrected_claim_ids"})
        final = results_by_call["adjudicator"].response.proposal.get("deliberation")
        if not isinstance(final, Mapping) or final.get("kind") != "adjudication" or set(final) - {"kind", "validity_audit", "adjudication", "minority_reports"}:
            raise MaxControlError("adjudicator did not return the exact typed adjudication output")
        try:
            positions = (
                RolePosition(role=lead["role"], position=lead["position"], canonical_claim_ids=tuple(lead.get("canonical_claim_ids", ())), canonical_evidence_ids=tuple(lead.get("canonical_evidence_ids", ())), rationale=lead["rationale"]),
                RolePosition(role=rival["role"], position=rival["position"], canonical_claim_ids=tuple(rival.get("canonical_claim_ids", ())), canonical_evidence_ids=tuple(rival.get("canonical_evidence_ids", ())), rationale=rival["rationale"]),
            )
            correction = CorrectionPosition(role=response["role"], correction=response["correction"], corrected_claim_ids=tuple(response.get("corrected_claim_ids", ())))
            examination = CrossExamination(examiner_role=cross["examiner_role"], respondent_role=cross["respondent_role"], question=cross["question"], answer=correction.correction, challenged_claim_ids=tuple(cross.get("challenged_claim_ids", ())))
            audit = ValidityAudit.from_mapping(final["validity_audit"])
            adjudication = Adjudication.from_mapping(final["adjudication"])
            minorities = tuple(MinorityReport.from_mapping(item) for item in final.get("minority_reports", ()))
            discussion = DiscussionSession(
                project_id=run_state.project_id,
                run_id=run_state.run_id,
                target_id=plan.role_packets[0].target_id,
                independent_positions=positions,
                cross_examinations=(examination,),
                corrections=(correction,),
                validity_audits=(audit,),
                adjudication=adjudication,
                minority_reports=minorities,
                state_hash=state.state_hash,
                model_identity=run_state.model_identity,
                inference_profile_hash=self.profile.inference_profile.inference_profile_hash,
                # The public DiscussionSession contains only the two isolated
                # position packets.  Cross/response/adjudicator packets remain
                # durable in the call-spec/binding tables and are linked by
                # the artifact binding below.
                role_packets=tuple(plan.role_packets[:2]),
            )
        except Exception as exc:
            if isinstance(exc, MaxControlError):
                raise
            raise MaxControlError("typed adjudication output is invalid") from exc
        try:
            self._crash_if("validation_before")
            validate_discussion_session(discussion, state=state).raise_if_invalid()
            self._crash_if("validation_after")
        except (ContractValidationError, KeyError, TypeError, ValueError) as exc:
            # Do not let provider-shaped ContractValidationError escape the
            # runner trust boundary.  The caller will close the group and
            # iteration through the normal controlled-abort path.
            raise MaxControlError("INVALID_ADJUDICATION") from exc
        return discussion

    def _finish_success(
        self,
        *,
        run_state: MaxRunState,
        state: ResearchState,
        charter: MaxResearchCharter,
        plan: RunnerPlan,
        intent: ModelCallIntent,
        result: ModelCallResult,
        budget: Mapping[str, Any],
        fencing_token: int,
        role_results: Sequence[ModelCallResult] = (),
    ) -> dict[str, Any]:
        if result.status != ModelCallStatus.SUCCEEDED.value:
            return self._finish_aborted(run_state=run_state, plan=plan, intent=intent, reason="model_result_failed", fencing_token=fencing_token)
        change_row = self.persistence.find_change_set(run_id=run_state.run_id, iteration_id=plan.iteration_id, input_state_hash=intent.input_state_hash)
        proposal_state = state
        if change_row is not None and state.state_hash != intent.input_state_hash:
            # Recovery after canonical apply must validate the stored result
            # against the pre-change graph.  Validating it against the current
            # graph would mistake the already-adopted version for a forged
            # duplicate and abort an otherwise safe replay.
            try:
                stored_change = CanonicalChangeSet.from_mapping(json.loads(str(change_row["change_set_json"])))
                added_versions = {item.version_id for item in stored_change.objects} | set(stored_change.adopt_object_version_ids)
                added_relations = {item.relation_id for item in stored_change.relations} | set(stored_change.adopt_relation_ids)
                proposal_state = rebuild_research_state(
                    tuple(item for item in state.objects if item.version_id not in added_versions),
                    tuple(item for item in state.relations if item.relation_id not in added_relations),
                    project_id=run_state.project_id,
                    run_id=run_state.run_id,
                )
                if proposal_state.state_hash != intent.input_state_hash:
                    raise ValueError("stored change set predecessor state does not match intent")
            except Exception as exc:
                raise MaxControlError("stored change set predecessor cannot be reconstructed") from exc
        proposal_value = result.response.proposal
        authoritative_discussion: DiscussionSession | None = None
        if plan.round_type == "adjudication":
            try:
                if len(role_results) != len(plan.call_specs):
                    raise MaxControlError("adjudication completion requires all five call results")
                results_by_call = {spec.call_id: item for spec, item in zip(plan.call_specs, role_results)}
                authoritative_discussion = self._build_adjudication_session(state=proposal_state, run_state=run_state, plan=plan, results_by_call=results_by_call)
            except (ContractValidationError, KeyError, TypeError, ValueError, MaxControlError):
                return self._finish_aborted(run_state=run_state, plan=plan, intent=intent, reason="invalid_adjudication", fencing_token=fencing_token)
        try:
            _, change_set, ledger, artifacts, refs = self._normalize_proposal(proposal_value=proposal_value, state=proposal_state, run_state=run_state, charter=charter, plan=plan, authoritative_discussion=authoritative_discussion)
        except (ContractValidationError, KeyError, TypeError, ValueError, MaxControlError):
            if plan.round_type == "adjudication":
                return self._finish_aborted(run_state=run_state, plan=plan, intent=intent, reason="invalid_adjudication", fencing_token=fencing_token)
            return self._finish_aborted(run_state=run_state, plan=plan, intent=intent, reason="proposal_rejected", fencing_token=fencing_token)

        # The iteration charge belongs to the authoritative iteration outcome,
        # not to an in-memory retry.  A crash after ``finish_iteration`` can
        # re-enter this method while the call group is still open; in that
        # case the immutable outcome proves that the service charge already
        # exists and must not be appended again.
        outcome_row = self.persistence.iteration_outcome(run_id=run_state.run_id, iteration_id=plan.iteration_id)
        if outcome_row is None:
            self._charge_iteration(run_id=run_state.run_id, iteration_id=plan.iteration_id, fencing_token=fencing_token)
        if change_row is None:
            self._crash_if("change_set_before")
            applied = self.repository.apply_change_set(run_id=run_state.run_id, change_set=change_set, actor=self.actor, fencing_token=fencing_token)
            self._crash_if("change_set_after")
            change_id = applied["change_set_id"]
            change_hash = applied["change_set_hash"]
            output_hash = applied["output_state_hash"]
        else:
            change_id = str(change_row["change_set_id"])
            change_hash = str(change_row["change_set_hash"])
            output_hash = str(change_row["expected_output_state_hash"])

        current_state = ResearchState.from_mapping(self.repository.get_state(run_id=run_state.run_id))
        claims = tuple(make_claim_snapshot(obj) for obj in current_state.latest_by_id.values() if str(getattr(obj.kind, "value", obj.kind)) == CanonicalObjectKind.CLAIM.value)
        evidence_by_id = {obj.stable_id: make_evidence_snapshot(obj) for obj in current_state.latest_by_id.values() if str(getattr(obj.kind, "value", obj.kind)) == CanonicalObjectKind.EVIDENCE.value}
        counter_ids: set[str] = set()
        for relation in current_state.relations:
            if str(getattr(relation.relation, "value", relation.relation)) != "counters":
                continue
            for endpoint in (relation.source_id, relation.target_id):
                if endpoint in evidence_by_id:
                    counter_ids.add(endpoint)
        evidence = tuple(evidence_by_id[key] for key in sorted(evidence_by_id))
        counterevidence = tuple(evidence_by_id[key] for key in sorted(counter_ids))
        # Usage is settled immediately after each authoritative provider
        # result, before proposal acceptance.  The iteration charge is owned
        # by the service and is appended exactly once for the group.
        usage_entry_id: str | None = None
        if result.status == ModelCallStatus.SUCCEEDED.value:
            usage_row = self.repository._connect(read_only=True)
            try:
                row = usage_row.execute("SELECT usage_entry_id FROM max_runner_usage_bindings WHERE logical_call_id=?", (result.logical_call_id,)).fetchone()
                usage_entry_id = row["usage_entry_id"] if row is not None else None
            finally:
                usage_row.close()

        if outcome_row is None:
            delta = self.persistence.iteration_budget_delta(run_id=run_state.run_id, iteration_id=plan.iteration_id)
            self._crash_if("finish_before")
            self._crash_if("iteration_finish_before")
            finished = self.repository.finish_iteration(run_id=run_state.run_id, iteration_id=plan.iteration_id, actor=self.actor, fencing_token=fencing_token, status="completed", output_state_hash=current_state.state_hash, claim_snapshots=claims, evidence_snapshots=evidence, counterevidence_snapshots=counterevidence, strategy_ledger=ledger, record_refs=refs, artifact_links=artifacts, budget_delta=delta)
            self._crash_if("iteration_finish_after")
            self._crash_if("finish_after")
            iteration_outcome_id = finished.get("outcome_id")
            iteration_outcome_hash = finished.get("outcome_hash") or canonical_sha256(finished)
        else:
            iteration_outcome_id = outcome_row["outcome_id"]
            iteration_outcome_hash = outcome_row["outcome_hash"]

        stored_primary = self.persistence.stored_result(run_id=run_state.run_id, logical_call_id=result.logical_call_id)
        if stored_primary is None:
            raise MaxControlError("authoritative result is missing while binding iteration artifacts")
        for artifact in artifacts:
            artifact_id = artifact.get("artifact_id") or canonical_sha256(artifact["artifact"])[:48]
            self.persistence.record_artifact_binding(
                run_id=run_state.run_id,
                iteration_id=plan.iteration_id,
                artifact_type=str(artifact["artifact_type"]),
                artifact_id=str(artifact_id),
                artifact_hash=canonical_sha256(artifact["artifact"]),
                logical_call_id=result.logical_call_id,
                result_id=str(stored_primary["result_id"]),
                actor=self.actor,
                fencing_token=fencing_token,
            )

        outcome = {"change_set_id": change_id, "iteration_outcome_id": iteration_outcome_id, "usage_entry_id": usage_entry_id, "output_state_hash": current_state.state_hash, "plan_hash": plan.plan_hash, "result_hash": result.result_hash}
        links = (
            {"link_type": "change_set", "target_id": change_id, "target_hash": change_hash},
            {"link_type": "iteration_outcome", "target_id": iteration_outcome_id, "target_hash": iteration_outcome_hash},
        )
        if usage_entry_id:
            links += ({"link_type": "budget_entry", "target_id": usage_entry_id, "target_hash": canonical_sha256({"entry_id": usage_entry_id, "logical_call_id": intent.logical_call_id})},)
        persisted = self.persistence.record_outcome(run_id=run_state.run_id, logical_call_id=intent.logical_call_id, status="completed", iteration_id=plan.iteration_id, outcome=outcome, actor=self.actor, fencing_token=fencing_token, links=links)
        verified = self.persistence.verify_run(run_id=run_state.run_id)
        if not verified.get("ok"):
            raise MaxControlError("runner recovery verification failed after iteration")
        return self._redacted_summary(run_id=run_state.run_id, project_id=run_state.project_id, status="completed", iteration_id=plan.iteration_id, iteration_number=plan.sequence, round_type=plan.round_type, cognitive_kind=plan.cognitive_kind, plan_hash=plan.plan_hash, intent_hash=intent.intent_hash, logical_call_id=intent.logical_call_id, result_hash=result.result_hash, change_set_id=change_id, output_state_hash=current_state.state_hash, iteration_outcome_id=iteration_outcome_id, usage_entry_id=usage_entry_id, profile_hash=self.profile.profile_hash, idempotent=bool(persisted.get("idempotent")))

    def _continue_existing(self, *, run_state: MaxRunState, charter: MaxResearchCharter, state: ResearchState, budget: Mapping[str, Any], plan: RunnerPlan, intent: ModelCallIntent, unfinished: Mapping[str, Any] | None, fencing_token: int) -> dict[str, Any]:
        existing_outcome = self.persistence.stored_outcome(run_id=run_state.run_id, logical_call_id=intent.logical_call_id)
        if existing_outcome is not None:
            if existing_outcome["status"] == "paused":
                raise MaxControlError("ambiguous model call requires an explicit admin decision")
            return self._redacted_summary(run_id=run_state.run_id, project_id=run_state.project_id, status="idempotent_success" if existing_outcome["status"] == "completed" else existing_outcome["status"], iteration_id=intent.iteration_id, logical_call_id=intent.logical_call_id, idempotent=True)
        consumed = self.persistence.recovery_consumption(run_id=run_state.run_id, logical_call_id=intent.logical_call_id)
        if consumed is not None and consumed.get("decision") == "abort":
            return self._finish_aborted(run_state=run_state, plan=plan, intent=intent, reason="admin_abort", fencing_token=fencing_token)
        stored = self.persistence.stored_result(run_id=run_state.run_id, logical_call_id=intent.logical_call_id)
        if stored is not None:
            result = self._load_result(stored)
        else:
            result = self._dispatch_or_recover(run_state=run_state, intent=intent, unfinished=unfinished, fencing_token=fencing_token)
            if result is None:
                status = self.repository.get_run(run_state.run_id)["status"]
                return self._redacted_summary(run_id=run_state.run_id, project_id=run_state.project_id, status="paused" if status == RunStatus.PAUSED.value else "recovery_pending", iteration_id=intent.iteration_id, logical_call_id=intent.logical_call_id, recovery_disposition="ambiguous_pause" if status == RunStatus.PAUSED.value else "reuse_intent")
        return self._finish_success(run_state=run_state, state=state, charter=charter, plan=plan, intent=intent, result=result, budget=budget, fencing_token=fencing_token)

    def _execute_group(self, *, run_id: str, run_state: MaxRunState, charter: MaxResearchCharter, state: ResearchState, budget: Mapping[str, Any], plan: RunnerPlan, fencing_token: int) -> dict[str, Any]:
        group = self.persistence.current_group(run_id=run_id)
        if group is None or group["plan_id"] != plan.plan_id:
            raise MaxControlError("runner call group is missing or not bound to the current plan")
        results: list[ModelCallResult] = []
        public_artifacts: dict[str, Mapping[str, Any]] = {}
        for call_index, _packet in enumerate(plan.role_packets):
            spec = plan.call_specs[call_index]
            binding = self.persistence.group_binding(run_id=run_id, group_id=group["group_id"], call_index=call_index)
            intent: ModelCallIntent | None = None
            intent_persisted = binding is not None
            try:
                if binding is not None:
                    intent = self._load_intent(binding, run_state=run_state, state=state, charter=charter, plan=plan, budget=budget)
                    stored = self.persistence.stored_result(run_id=run_id, logical_call_id=intent.logical_call_id)
                    if stored is not None:
                        result = self._load_result(stored)
                        self._settle_call_usage(run_id=run_id, intent=intent, result=result, fencing_token=fencing_token)
                        if spec.call_id in {"lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response", "adjudicator"}:
                            public_artifacts[spec.call_id] = self._public_call_artifact(result, spec.call_id)
                        results.append(result)
                        continue
                else:
                    upstream = {key: public_artifacts[key] for key in spec.upstream_call_ids if key in public_artifacts}
                    intent = self._build_intent(run_state=run_state, state=state, charter=charter, plan=plan, budget=budget, role_index=call_index, upstream_public=upstream)
                    self._ensure_reservation(run_id=run_id, iteration_id=plan.iteration_id, logical_call_id=intent.logical_call_id, budget=budget, fencing_token=fencing_token)
                    self._crash_if("intent_before")
                    self.persistence.record_intent(run_id=run_id, intent=intent, plan_id=plan.plan_id, actor=self.actor, fencing_token=fencing_token, group_id=group["group_id"], call_index=call_index, phase=spec.phase)
                    intent_persisted = True
                    self._crash_if("intent_after")
                result = self._dispatch_or_recover(run_state=run_state, intent=intent, unfinished=binding, fencing_token=fencing_token)
                if result is None:
                    status = self.repository.get_run(run_id)["status"]
                    return self._redacted_summary(run_id=run_id, project_id=run_state.project_id, status="paused" if status == RunStatus.PAUSED.value else "recovery_pending", iteration_id=plan.iteration_id, round_type=plan.round_type, cognitive_kind=plan.cognitive_kind, plan_hash=plan.plan_hash, logical_call_id=intent.logical_call_id)
                self._settle_call_usage(run_id=run_id, intent=intent, result=result, fencing_token=fencing_token)
                if spec.call_id in {"lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response", "adjudicator"}:
                    public_artifacts[spec.call_id] = self._public_call_artifact(result, spec.call_id)
                results.append(result)
            except InjectedRunnerCrash:
                raise
            except UsageDispute as exc:
                # The provider call is known, but the billing fact is not
                # authoritative.  Close only the call-group pointer as
                # paused, retain its reservation, then pause the Run while
                # the current fence is still valid.  The outer run_next
                # finally block can release its invocation claim after the
                # pause because the persistence boundary explicitly permits
                # owner release for PAUSED Runs.
                self._finalize_call_group(run_id=run_id, group_id=group["group_id"], status="paused", fencing_token=fencing_token)
                self.repository.pause(run_id=run_id, actor=self.actor, fencing_token=fencing_token)
                return self._redacted_summary(
                    run_id=run_id,
                    project_id=run_state.project_id,
                    status="paused",
                    iteration_id=plan.iteration_id,
                    round_type=plan.round_type,
                    cognitive_kind=plan.cognitive_kind,
                    plan_hash=plan.plan_hash,
                    logical_call_id=exc.logical_call_id,
                    reason="usage_dispute",
                )
            except MaxControlError as exc:
                if intent is None and "GATEWAY_CONTEXT_REJECTED" in str(exc):
                    # Gateway material is read before a durable intent is
                    # created.  Reject it visibly after closing the empty
                    # group/iteration; never turn a forbidden source body or
                    # secret into an ordinary model-proposal abort.
                    self._finish_aborted(
                        run_state=run_state,
                        plan=plan,
                        intent=None,
                        reason="gateway_context_rejected",
                        fencing_token=fencing_token,
                    )
                    self._finalize_call_group(run_id=run_id, group_id=group["group_id"], status="aborted", fencing_token=fencing_token)
                    raise
                # A bad reservation, receipt, role artifact, or recovered
                # result is a group-level failure.  Persist the already
                # verified usage, release every remaining reservation, and
                # close the immutable iteration/group before returning.
                if intent is not None and intent_persisted:
                    failure_reason = "invalid_adjudication" if plan.round_type == "adjudication" else "dispatch_or_result_rejected"
                else:
                    failure_reason = "dispatch_or_result_rejected"
                summary = self._finish_aborted(
                    run_state=run_state,
                    plan=plan,
                    intent=intent if intent_persisted else None,
                    reason=failure_reason,
                    fencing_token=fencing_token,
                )
                self._finalize_call_group(run_id=run_id, group_id=group["group_id"], status="aborted", fencing_token=fencing_token)
                if summary.get("reason") == "epistemic_conflict_paused":
                    self.repository.pause(run_id=run_id, actor=self.actor, fencing_token=fencing_token)
                    summary = {**summary, "status": "paused"}
                return summary
        if not results:
            raise MaxControlError("runner call group produced no authoritative result")
        terminal_index = len(results) - 1
        terminal_binding = self.persistence.group_binding(run_id=run_id, group_id=group["group_id"], call_index=terminal_index)
        terminal_intent = self._load_intent(terminal_binding or {}, run_state=run_state, state=state, charter=charter, plan=plan, budget=budget)
        try:
            completed = self._finish_success(run_state=run_state, state=state, charter=charter, plan=plan, intent=terminal_intent, result=results[terminal_index], budget=budget, fencing_token=fencing_token, role_results=tuple(results))
        except InjectedRunnerCrash:
            raise
        except MaxControlError:
            summary = self._finish_aborted(run_state=run_state, plan=plan, intent=terminal_intent, reason="invalid_adjudication" if plan.round_type == "adjudication" else "proposal_rejected", fencing_token=fencing_token)
            self._finalize_call_group(run_id=run_id, group_id=group["group_id"], status="aborted", fencing_token=fencing_token)
            if summary.get("reason") == "epistemic_conflict_paused":
                self.repository.pause(run_id=run_id, actor=self.actor, fencing_token=fencing_token)
                summary = {**summary, "status": "paused"}
            return summary
        if completed.get("status") == "aborted":
            self._finalize_call_group(run_id=run_id, group_id=group["group_id"], status="aborted", fencing_token=fencing_token)
            if completed.get("reason") == "epistemic_conflict_paused":
                self.repository.pause(run_id=run_id, actor=self.actor, fencing_token=fencing_token)
                completed = {**completed, "status": "paused"}
            return completed
        lead_outcome = completed.get("iteration_outcome_id")
        for role_index, role_result in enumerate(results):
            if role_index == terminal_index:
                continue
            binding = self.persistence.group_binding(run_id=run_id, group_id=group["group_id"], call_index=role_index)
            if binding is None:
                raise MaxControlError("runner role binding disappeared during adjudication")
            self.persistence.record_outcome(run_id=run_id, logical_call_id=binding["logical_call_id"], status="completed", iteration_id=plan.iteration_id, outcome={"group_id": group["group_id"], "role_index": role_index, "lead_iteration_outcome_id": lead_outcome, "result_hash": role_result.result_hash}, actor=self.actor, fencing_token=fencing_token)
        # Every public deliberation artifact is bound to the result of the
        # logical call that produced it.  The aggregate DiscussionSession is
        # additionally bound by _finish_success to the adjudicator result.
        for call_index, spec in enumerate(plan.call_specs):
            public = public_artifacts.get(spec.call_id)
            if public is None:
                continue
            binding = self.persistence.group_binding(run_id=run_id, group_id=group["group_id"], call_index=call_index)
            stored_call_result = self.persistence.stored_result(run_id=run_id, logical_call_id=str(binding["logical_call_id"])) if binding is not None else None
            if binding is None or stored_call_result is None:
                raise MaxControlError("deliberation artifact call binding is missing")
            self.persistence.record_artifact_binding(
                run_id=run_id,
                iteration_id=plan.iteration_id,
                artifact_type=f"deliberation_{spec.artifact_type}",
                artifact_id=canonical_sha256({"call_id": spec.call_id, "artifact": public})[:48],
                artifact_hash=canonical_sha256(public),
                logical_call_id=str(binding["logical_call_id"]),
                result_id=str(stored_call_result["result_id"]),
                actor=self.actor,
                fencing_token=fencing_token,
            )
        self._finalize_call_group(run_id=run_id, group_id=group["group_id"], status="completed", fencing_token=fencing_token)
        verified = self.persistence.verify_run(run_id=run_id)
        if not verified.get("ok"):
            raise MaxControlError("runner recovery verification failed after iteration")
        return completed

    def _run_next_claimed(self, *, run_id: str, run_state: MaxRunState, charter: MaxResearchCharter, state: ResearchState, budget: Mapping[str, Any], fencing_token: int) -> dict[str, Any]:
        """Execute one invocation after the database mutex is claimed."""

        open_group = self.persistence.current_group(run_id=run_id)
        if open_group is not None:
            plan_row = self.persistence.latest_plan(run_id=run_id)
            if plan_row is None or plan_row["plan_id"] != open_group["plan_id"]:
                raise MaxControlError("open runner call group has no matching plan")
            return self._execute_group(run_id=run_id, run_state=run_state, charter=charter, state=state, budget=budget, plan=self._parse_plan(plan_row), fencing_token=fencing_token)

        unfinished = self.persistence.latest_unfinished(run_id=run_id)
        if unfinished is not None:
            plan_row = self.persistence.latest_plan(run_id=run_id)
            if plan_row is None or plan_row["plan_id"] != unfinished["plan_id"]:
                raise MaxControlError("unfinished model intent has no matching runner plan")
            plan = self._parse_plan(plan_row)
            intent = self._load_intent(unfinished, run_state=run_state, state=state, charter=charter, plan=plan, budget=budget)
            if intent.intent_hash != unfinished["intent_hash"]:
                raise MaxControlError("stored model intent hash is inconsistent")
            return self._continue_existing(run_state=run_state, charter=charter, state=state, budget=budget, plan=plan, intent=intent, unfinished=unfinished, fencing_token=fencing_token)

        current = self.persistence.current_work(run_id=run_id)
        if current is not None and current.get("intent_json"):
            plan = self._parse_plan(current)
            intent = self._load_intent(current, run_state=run_state, state=state, charter=charter, plan=plan, budget=budget)
            return self._continue_existing(run_state=run_state, charter=charter, state=state, budget=budget, plan=plan, intent=intent, unfinished=current, fencing_token=fencing_token)

        if not any(isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 1 for value in budget.get("available", {}).values()):
            return self._redacted_summary(run_id=run_id, project_id=run_state.project_id, status="budget_exhausted", reason="no declared budget unit remains")

        plan, _ = self._persist_plan_and_iteration(run_state=run_state, charter=charter, state=state, budget=budget, fencing_token=fencing_token)
        if plan.round_type == "rehydration" and not bool(plan.metadata.get("long_run_integrated")):
            try:
                # The canonical repository rebuilds from object versions and
                # exact relations before any model call.  The resulting typed
                # RehydrationOutput is server-owned and is already persisted
                # by rehydrate_run; the model cannot manufacture its verdict.
                self.repository.rehydrate_run(run_id=run_id, actor=self.actor, fencing_token=fencing_token)
            except MaxControlError:
                try:
                    self.repository.pause(run_id=run_id, actor=self.actor, fencing_token=fencing_token)
                except MaxControlError:
                    pass
                return self._redacted_summary(run_id=run_id, project_id=run_state.project_id, status="paused", iteration_id=plan.iteration_id, round_type=plan.round_type, cognitive_kind=plan.cognitive_kind, plan_hash=plan.plan_hash, reason="rehydration_drift")
        # A crash after plan/begin is recovered by the same deterministic plan.
        return self._execute_group(run_id=run_id, run_state=run_state, charter=charter, state=state, budget=budget, plan=plan, fencing_token=fencing_token)

    def run_next(self, *, run_id: str) -> dict[str, Any]:
        run_state, charter, state, budget, _ = self._read_context(run_id)
        if not isinstance(self.actor.actor_id, str) or self.actor.is_admin or self.actor.actor_kind not in {"runner", "agent", "worker"}:
            raise MaxControlError("run-next requires a non-admin runner actor")
        self._crash_if("lease_renew")
        lease = self.persistence.claim_runner_lease(run_id=run_id, profile=self.profile, actor=self.actor, lease_ttl=self.lease_ttl)
        fencing_token = int(lease["fencing_token"])
        claim = self.persistence.claim_invocation(run_id=run_id, actor=self.actor, fencing_token=fencing_token, ttl_seconds=self.lease_ttl)
        try:
            return self._run_next_claimed(run_id=run_id, run_state=run_state, charter=charter, state=state, budget=budget, fencing_token=fencing_token)
        finally:
            try:
                self.persistence.release_invocation(run_id=run_id, claim_id=claim["claim_id"], actor=self.actor, fencing_token=fencing_token)
            except MaxControlError:
                # A stale/expired lease must not mask the provider or runner
                # result.  Public verify will report the broken release link.
                pass

    def admin_decision(self, *, run_id: str, logical_call_id: str, decision: str, admin_actor: Actor) -> dict[str, Any]:
        return self.persistence.consume_admin_decision(run_id=run_id, logical_call_id=logical_call_id, decision=decision, admin_actor=admin_actor)


__all__ = ["BoundedRunner", "InjectedRunnerCrash", "UsageDispute"]
