"""Fail-closed, deterministic MR-0A contract validators.

This module is intentionally pure.  It only validates value objects and
computes deterministic projections/hashes; it never opens a database, starts
an MCP process, calls a model, reads a file, or performs network access.
"""

from __future__ import annotations

import datetime as _datetime
import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .base import ContractValidationError, ValidationResult, canonical_sha256, issue_collector, model_to_dict, require_mapping_fields
from .ids import expected_version_id, is_project_id, is_stable_id, make_event_id, make_relation_id, make_stable_id, normalize_kind, parse_stable_id
from .models import (
    AdjudicationValue, AcquisitionRequest, ApprovalConsumption, AttackRecord,
    CanonicalObject, CanonicalObjectKind, CanonicalRelation, Checkpoint,
    ClaimSnapshot, ColdReviewPacket, ColdReviewResult, CompletionEvaluationInput,
    CompletionGate, CompletionGateResult, CompletionResult, CoverageLedger,
    DiscussionSession, DriftKind, EPISTEMIC_CONFLICT_SCHEMA, EpistemicConflictRecord, EvidenceSnapshot, FINAL_CLAIM_STATUSES,
    FINAL_EVIDENCE_STATUSES, FormalCompletionEvidence, Iteration, IterationKind,
    MaxResearchCharter, MaxRunState, MinorityReport, RehydrationInput,
    RehydrationOutput, RehydrationPolicy, RelationKind, ReportProjection,
    ResearchState, RolePacket, RunStatus, RunTransitionResult, SaturationStatus,
    SearchStrategy, SpeculativeIdea, SpeculativeStatus, StartApproval,
    ValidityAudit, WorkingState, COLD_REVIEW_REQUIRED_EXCLUSIONS,
)


_FORMAL_CONTENT_KEYS = {
    "claim", "claims", "evidence", "evidences", "formal_claim", "formal_claims",
    "formal_evidence", "formal_evidences", "claim_payload", "claim_payloads",
    "evidence_payload", "evidence_payloads", "working_interpretation",
}
_DIRECT_EVIDENCE_KEYS = {"evidence_id", "evidence_ids", "verified_evidence_ids"}
_TRACE_RELATIONS = {"has_evidence_link", "links_evidence", "derived_from", "located_in"}
_TERMINAL_RUN_STATES = frozenset({RunStatus.COMPLETED.value, RunStatus.FAILED.value, RunStatus.CANCELLED.value})
_RUN_TRANSITIONS = {
    RunStatus.AWAITING_START_APPROVAL.value: frozenset({RunStatus.APPROVED.value, RunStatus.CANCELLED.value}),
    RunStatus.APPROVED.value: frozenset({RunStatus.RUNNING.value, RunStatus.CANCELLED.value}),
    RunStatus.RUNNING.value: frozenset({RunStatus.PAUSED.value, RunStatus.COMPLETED.value, RunStatus.FAILED.value, RunStatus.CANCELLED.value}),
    RunStatus.PAUSED.value: frozenset({RunStatus.RUNNING.value, RunStatus.FAILED.value, RunStatus.CANCELLED.value}),
    RunStatus.COMPLETED.value: frozenset(), RunStatus.FAILED.value: frozenset(), RunStatus.CANCELLED.value: frozenset(),
}
_SPECULATION_TRANSITIONS = {
    SpeculativeStatus.SPECULATIVE.value: frozenset({SpeculativeStatus.CANDIDATE.value}),
    SpeculativeStatus.CANDIDATE.value: frozenset({SpeculativeStatus.SUPPORTED.value, SpeculativeStatus.WEAKENED.value, SpeculativeStatus.REJECTED.value}),
    SpeculativeStatus.SUPPORTED.value: frozenset(), SpeculativeStatus.WEAKENED.value: frozenset(), SpeculativeStatus.REJECTED.value: frozenset(),
}


def _as(value: Any, cls: type[Any], *, factory: Any = None) -> Any:
    if isinstance(value, cls):
        return value
    if isinstance(value, Mapping):
        converter = getattr(cls, "from_mapping", None)
        if converter is not None:
            return converter(value)
        return cls(**value)
    if factory is not None:
        return factory(value)
    return value


def _safe_as(value: Any, cls: type[Any]) -> tuple[Any | None, tuple[Any, ...]]:
    try:
        converted = _as(value, cls)
    except (ContractValidationError, ValueError, TypeError, KeyError) as exc:
        issues = getattr(exc, "issues", (exc,))
        normalized = []
        for issue in issues:
            if hasattr(issue, "code"):
                normalized.append(issue)
            else:
                from .base import ValidationIssue
                normalized.append(ValidationIssue("contract.parse", "$", str(issue)))
        return None, tuple(normalized)
    return converted, ()


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _required_text(collector: Any, value: Any, path: str, code: str) -> None:
    if not _text(value):
        collector.add(code, path, f"{path} must be a non-empty string")


def _string_sequence(collector: Any, value: Any, path: str, *, required: bool = False) -> None:
    if not isinstance(value, (list, tuple)):
        collector.add("contract.expected_string_list", path, f"{path} must be a list of strings")
        return
    if required and not value:
        collector.add("contract.empty_string_list", path, f"{path} must not be empty")
    for index, item in enumerate(value):
        if not _text(item):
            collector.add("contract.expected_string", f"{path}[{index}]", f"{path}[{index}] must be a non-empty string")


def _id_sequence(collector: Any, values: Any, path: str, *, expected_kind: str | None = None, required: bool = False) -> None:
    if not isinstance(values, (list, tuple)):
        collector.add("id.list_required", path, f"{path} must be a list of stable IDs")
        return
    if required and not values:
        collector.add("id.list_empty", path, f"{path} must not be empty")
    seen: set[str] = set()
    for index, item in enumerate(values):
        item_path = f"{path}[{index}]"
        if not is_stable_id(item, expected_kind=expected_kind):
            collector.add("id.invalid_stable_id", item_path, f"{item_path} is not a valid MR-1 stable ID")
        elif item in seen:
            collector.add("id.duplicate", item_path, f"{item_path} duplicates another stable ID")
        seen.add(item)


def _parse_time(value: Any) -> _datetime.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_datetime.timezone.utc)
    return parsed.astimezone(_datetime.timezone.utc)


def _add_parse_issues(collector: Any, issues: Sequence[Any]) -> None:
    collector.issues.extend(issues)


def _required_mapping(collector: Any, value: Any, path: str) -> None:
    if not isinstance(value, Mapping) or not value:
        collector.add("contract.mapping_required", path, f"{path} must be a non-empty mapping")


def validate_charter(charter: MaxResearchCharter | Mapping[str, Any]) -> ValidationResult:
    value, parse_issues = _safe_as(charter, MaxResearchCharter)
    collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(value, MaxResearchCharter):
        collector.add("charter.type", "$", "charter must be a MaxResearchCharter or strict mapping")
        return collector.result()
    if value.schema != "max-research-charter/v1":
        collector.add("charter.schema", "$.schema", "unsupported charter schema")
    if value.protocol_version != "max-research/v1":
        collector.add("charter.protocol", "$.protocol_version", "unsupported Max Research protocol")
    _required_text(collector, value.question, "$.question", "charter.question_required")
    if isinstance(value.scope, str): _required_text(collector, value.scope, "$.scope", "charter.scope_required")
    elif isinstance(value.scope, (list, tuple)): _string_sequence(collector, value.scope, "$.scope", required=True)
    elif isinstance(value.scope, Mapping): _required_mapping(collector, value.scope, "$.scope")
    else: collector.add("charter.scope_type", "$.scope", "scope must be text, a list, or an object")
    for name in ("invariants", "non_goals", "deliverables"):
        _string_sequence(collector, getattr(value, name), f"$.{name}", required=True)
    _required_text(collector, value.model_identity, "$.model_identity", "charter.model_identity_required")
    for name in ("budget", "source_policy", "quality_gates"):
        _required_mapping(collector, getattr(value, name), f"$.{name}")
        if isinstance(getattr(value, name), Mapping):
            for key, item in getattr(value, name).items():
                if isinstance(item, (int, float)) and not isinstance(item, bool) and item < 0:
                    collector.add("charter.negative_value", f"$.{name}.{key}", f"{name}.{key} must not be negative")
    return collector.result()


def require_valid_charter(charter: MaxResearchCharter | Mapping[str, Any]) -> MaxResearchCharter:
    value = _as(charter, MaxResearchCharter); validate_charter(value).raise_if_invalid(); return value


def charter_hash(charter: MaxResearchCharter | Mapping[str, Any]) -> str:
    return canonical_sha256(model_to_dict(require_valid_charter(charter)))


def source_policy_hash(source_policy: Mapping[str, Any]) -> str:
    if not isinstance(source_policy, Mapping) or not source_policy:
        raise ContractValidationError("source_policy must be a non-empty mapping")
    return canonical_sha256(source_policy)


def validate_start_approval(
    approval: StartApproval | Mapping[str, Any], *, expected_run_id: str | None = None,
    expected_project_id: str | None = None, expected_charter_hash: str | None = None,
    expected_model_identity: str | None = None, expected_budget: Mapping[str, Any] | None = None,
    expected_source_policy_hash: str | None = None, now: _datetime.datetime | None = None,
    reject_consumed: bool = True,
) -> ValidationResult:
    value, parse_issues = _safe_as(approval, StartApproval)
    collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(value, StartApproval):
        collector.add("approval.type", "$", "approval must be a StartApproval or strict mapping"); return collector.result()
    if value.schema != "max-research-start-approval/v1": collector.add("approval.schema", "$.schema", "unsupported start approval schema")
    for name in ("run_id", "project_id", "charter_hash", "model_identity", "source_policy_hash", "approval_id", "decision", "approved_by", "approved_at", "decision_authority"):
        _required_text(collector, getattr(value, name), f"$.{name}", "approval.field_required")
    if not is_project_id(value.project_id): collector.add("approval.project_id", "$.project_id", "project_id is not valid")
    if not is_stable_id(value.approval_id, expected_kind="start_approval"): collector.add("approval.id", "$.approval_id", "approval_id must be a start_approval stable ID")
    if value.decision != "approved": collector.add("approval.not_approved", "$.decision", "start approval must be explicitly approved")
    if value.decision_authority != "human": collector.add("approval.authority", "$.decision_authority", "start approval authority must be human")
    _required_mapping(collector, value.budget, "$.budget")
    if _parse_time(value.approved_at) is None: collector.add("approval.timestamp", "$.approved_at", "approved_at must be ISO-8601")
    current = now or _datetime.datetime.now(_datetime.timezone.utc)
    if value.expires_at is not None:
        expiry = _parse_time(value.expires_at)
        if expiry is None: collector.add("approval.expiry_timestamp", "$.expires_at", "expires_at must be ISO-8601")
        elif expiry <= current: collector.add("approval.expired", "$.expires_at", "start approval has expired")
    if reject_consumed and value.consumed_at is not None: collector.add("approval.replayed", "$.consumed_at", "start approval has already been consumed")
    for name, expected in (("run_id", expected_run_id), ("project_id", expected_project_id), ("charter_hash", expected_charter_hash), ("model_identity", expected_model_identity), ("source_policy_hash", expected_source_policy_hash)):
        if expected is not None and getattr(value, name) != expected: collector.add(f"approval.binding_{name}", f"$.{name}", f"approval does not bind expected {name}")
    if expected_budget is not None and canonical_sha256(value.budget) != canonical_sha256(expected_budget): collector.add("approval.binding_budget", "$.budget", "approval budget differs from current budget")
    return collector.result()


def approval_is_valid(approval: StartApproval | Mapping[str, Any], *, run_id: str, project_id: str, charter_hash_value: str, model_identity: str, budget: Mapping[str, Any], source_policy_hash_value: str, now: _datetime.datetime | None = None) -> bool:
    return bool(validate_start_approval(approval, expected_run_id=run_id, expected_project_id=project_id, expected_charter_hash=charter_hash_value, expected_model_identity=model_identity, expected_budget=budget, expected_source_policy_hash=source_policy_hash_value, now=now))


def validate_run_state(state: MaxRunState | RunTransitionResult | Mapping[str, Any]) -> ValidationResult:
    if isinstance(state, RunTransitionResult):
        state = state.new_state
    value, parse_issues = _safe_as(state, MaxRunState)
    collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(value, MaxRunState): collector.add("run_state.type", "$", "state must be a MaxRunState or strict mapping"); return collector.result()
    if value.schema != "max-research-run-state/v1": collector.add("run_state.schema", "$.schema", "unsupported run state schema")
    _required_text(collector, value.run_id, "$.run_id", "run_state.run_id_required")
    if not is_project_id(value.project_id): collector.add("run_state.project_id", "$.project_id", "project_id is not valid")
    status = getattr(value.status, "value", value.status)
    if status not in _RUN_TRANSITIONS: collector.add("run_state.status", "$.status", "unknown Max Run status")
    for name in ("charter_hash", "model_identity", "source_policy_hash"): _required_text(collector, getattr(value, name), f"$.{name}", "run_state.binding_required")
    _required_mapping(collector, value.budget, "$.budget")
    if isinstance(value.iteration_index, bool) or not isinstance(value.iteration_index, int) or value.iteration_index < 0: collector.add("run_state.iteration_index", "$.iteration_index", "iteration_index must be non-negative")
    if isinstance(value.state_version, bool) or not isinstance(value.state_version, int) or value.state_version < 1: collector.add("run_state.version", "$.state_version", "state_version must be positive")
    if status in {RunStatus.APPROVED.value, RunStatus.RUNNING.value, RunStatus.PAUSED.value}:
        if not is_stable_id(value.approval_id, expected_kind="start_approval"): collector.add("run_state.approval_required", "$.approval_id", "approved/running/paused state requires a start approval ID")
        if _parse_time(value.approval_consumed_at) is None: collector.add("run_state.approval_consumed", "$.approval_consumed_at", "resumable state requires an approval consumption timestamp")
        if not is_stable_id(value.approval_consumption_id, expected_kind="approval_consumption"):
            collector.add("run_state.approval_consumption", "$.approval_consumption_id", "resumable state requires an immutable approval consumption ID")
        if value.budget_snapshot_hash is not None and value.budget_snapshot_hash != canonical_sha256(value.budget):
            collector.add("run_state.budget_snapshot", "$.budget_snapshot_hash", "budget snapshot hash does not bind the run budget")
    if status in {RunStatus.RUNNING.value, RunStatus.PAUSED.value, RunStatus.COMPLETED.value}:
        if not _text(value.current_state_hash): collector.add("run_state.current_state", "$.current_state_hash", "active and terminal states require the current Research State hash")
        if value.current_checkpoint_id is not None and not is_stable_id(value.current_checkpoint_id, expected_kind="checkpoint"):
            collector.add("run_state.current_checkpoint", "$.current_checkpoint_id", "current checkpoint ID is invalid")
    if status == RunStatus.AWAITING_START_APPROVAL.value and (value.approval_consumed_at is not None or value.completion_result_id is not None): collector.add("run_state.awaiting_binding", "$.approval_consumed_at", "awaiting state cannot carry consumed approval or completion")
    if status == RunStatus.COMPLETED.value:
        if not is_stable_id(value.completion_result_id, expected_kind="completion_result"): collector.add("run_state.completion_result", "$.completion_result_id", "completed state requires a completion result ID")
        _required_text(collector, value.completion_state_hash, "$.completion_state_hash", "run_state.completion_hash")
        if value.current_state_hash != value.completion_state_hash: collector.add("run_state.completion_state_binding", "$.completion_state_hash", "completed state must bind the exact current Research State")
    return collector.result()


def allowed_run_transitions(status: RunStatus | str) -> frozenset[str]:
    return _RUN_TRANSITIONS.get(getattr(status, "value", status), frozenset())


def validate_completion_result(
    result: CompletionResult | Mapping[str, Any], *,
    evaluation_input: CompletionEvaluationInput | Mapping[str, Any] | None = None,
    expected_project_id: str | None = None, expected_run_id: str | None = None,
    expected_charter_hash: str | None = None, expected_state_hash: str | None = None,
    current_run_state: MaxRunState | None = None,
) -> ValidationResult:
    value, parse_issues = _safe_as(result, CompletionResult)
    collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(value, CompletionResult): collector.add("completion_result.type", "$", "completion result is invalid"); return collector.result()
    if evaluation_input is None:
        collector.add("completion_result.evaluation_input_required", "$", "completion result must be verified against a complete CompletionEvaluationInput")
        return collector.result()
    try:
        input_value = evaluation_input if isinstance(evaluation_input, CompletionEvaluationInput) else CompletionEvaluationInput.from_mapping(evaluation_input)
        expected = evaluate_completion_result(input_value)
    except (ContractValidationError, ValueError, TypeError, KeyError) as exc:
        collector.add("completion_result.input_invalid", "$.evaluation_input", f"completion input cannot be recomputed: {exc}")
        return collector.result()
    if model_to_dict(value) != model_to_dict(expected): collector.add("completion_result.recompute_mismatch", "$", "CompletionResult differs from the pure evaluator result")
    for name, expected_value in (("project_id", expected_project_id), ("run_id", expected_run_id), ("charter_hash", expected_charter_hash), ("state_hash", expected_state_hash)):
        if expected_value is not None and getattr(value, name) != expected_value: collector.add("completion_result.binding", f"$.{name}", f"completion result {name} differs from expected context")
    if current_run_state is not None and value.state_hash != current_run_state.current_state_hash: collector.add("completion_result.run_state", "$.state_hash", "completion result does not bind the Run State current state hash")
    if not is_stable_id(value.result_id, expected_kind="completion_result"): collector.add("completion_result.id", "$.result_id", "result_id is not stable")
    if _parse_time(value.evaluated_at) is None: collector.add("completion_result.timestamp", "$.evaluated_at", "evaluated_at must be ISO-8601")
    if not value.gate_result.gate_hash or not value.gate_result.gate_input_hash: collector.add("completion_result.hash_required", "$.gate_result", "gate_hash and gate_input_hash are required")
    if not value.gate_result.passed: collector.add("completion_result.gate", "$.gate_result", "completion gate did not pass")
    return collector.result()


def _coerce_transition_state(value: MaxRunState | RunTransitionResult | Mapping[str, Any]) -> MaxRunState:
    if isinstance(value, RunTransitionResult): return value.new_state
    current, parse_issues = _safe_as(value, MaxRunState)
    if parse_issues or not isinstance(current, MaxRunState): raise ContractValidationError(parse_issues or "state is invalid")
    return current


def _coerce_consumption_ledger(values: Sequence[ApprovalConsumption | Mapping[str, Any]] | None) -> tuple[ApprovalConsumption, ...]:
    if values is None: raise ContractValidationError("approval consumption ledger snapshot is required")
    return tuple(item if isinstance(item, ApprovalConsumption) else ApprovalConsumption.from_mapping(item) for item in values)


def _validate_consumption(value: ApprovalConsumption, *, state: MaxRunState, approval_id: str, collector: Any) -> None:
    if value.approval_id != approval_id or value.project_id != state.project_id or value.run_id != state.run_id or value.charter_hash != state.charter_hash: collector.add("approval_consumption.binding", "$.approval_consumption", "approval consumption is not bound to this run")
    if value.prior_state_version < 1 or value.resulting_state_version != value.prior_state_version + 1: collector.add("approval_consumption.version", "$.approval_consumption", "approval consumption state versions are not adjacent")
    if _parse_time(value.consumed_at) is None: collector.add("approval_consumption.timestamp", "$.approval_consumption.consumed_at", "consumed_at must be ISO-8601")
    if not is_stable_id(value.consumption_id, expected_kind="approval_consumption"): collector.add("approval_consumption.id", "$.approval_consumption.consumption_id", "consumption ID is invalid")


def validate_approval_consumption(value: ApprovalConsumption | Mapping[str, Any], *, expected_project_id: str | None = None, expected_run_id: str | None = None, expected_charter_hash: str | None = None, expected_approval_id: str | None = None) -> ValidationResult:
    consumption, parse_issues = _safe_as(value, ApprovalConsumption); collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(consumption, ApprovalConsumption): collector.add("approval_consumption.type", "$", "approval consumption is invalid"); return collector.result()
    if not is_stable_id(consumption.approval_id, expected_kind="start_approval"): collector.add("approval_consumption.approval_id", "$.approval_id", "approval ID is invalid")
    if not is_stable_id(consumption.consumption_id, expected_kind="approval_consumption"): collector.add("approval_consumption.id", "$.consumption_id", "consumption ID is invalid")
    if not is_project_id(consumption.project_id): collector.add("approval_consumption.project_id", "$.project_id", "project ID is invalid")
    for name, expected in (("project_id", expected_project_id), ("run_id", expected_run_id), ("charter_hash", expected_charter_hash), ("approval_id", expected_approval_id)):
        if expected is not None and getattr(consumption, name) != expected: collector.add("approval_consumption.binding", f"$.{name}", f"consumption does not bind expected {name}")
    if isinstance(consumption.prior_state_version, bool) or not isinstance(consumption.prior_state_version, int) or consumption.prior_state_version < 1: collector.add("approval_consumption.prior_version", "$.prior_state_version", "prior state version must be positive")
    if consumption.resulting_state_version != consumption.prior_state_version + 1: collector.add("approval_consumption.resulting_version", "$.resulting_state_version", "resulting state version must immediately follow prior state version")
    if _parse_time(consumption.consumed_at) is None: collector.add("approval_consumption.timestamp", "$.consumed_at", "consumed_at must be ISO-8601")
    return collector.result()


def transition_run_state(
    state: MaxRunState | RunTransitionResult | Mapping[str, Any], target: RunStatus | str, *,
    approval: StartApproval | Mapping[str, Any] | None = None,
    now: _datetime.datetime | None = None,
    completion_result: CompletionResult | Mapping[str, Any] | None = None,
    completion_input: CompletionEvaluationInput | Mapping[str, Any] | None = None,
    research_state: ResearchState | Mapping[str, Any] | None = None,
    consumption_ledger: Sequence[ApprovalConsumption | Mapping[str, Any]] | None = None,
) -> RunTransitionResult:
    current = _coerce_transition_state(state)
    validate_run_state(current).raise_if_invalid()
    target_value = getattr(target, "value", target); current_value = getattr(current.status, "value", current.status)
    if target_value not in allowed_run_transitions(current_value): raise ContractValidationError(f"illegal Max Run transition {current_value!r} -> {target_value!r}")
    approval_id = current.approval_id; consumed_at = current.approval_consumed_at; consumption_id = current.approval_consumption_id; completion_id = current.completion_result_id; completion_hash = current.completion_state_hash; current_state_hash = current.current_state_hash; current_checkpoint_id = current.current_checkpoint_id; budget_hash = current.budget_snapshot_hash; new_consumption: ApprovalConsumption | None = None
    if target_value == RunStatus.APPROVED.value:
        if approval is None: raise ContractValidationError("human start approval is required before APPROVED")
        ledger = _coerce_consumption_ledger(consumption_ledger)
        approval_value = _as(approval, StartApproval)
        validate_start_approval(approval_value, expected_run_id=current.run_id, expected_project_id=current.project_id, expected_charter_hash=current.charter_hash, expected_model_identity=current.model_identity, expected_budget=current.budget, expected_source_policy_hash=current.source_policy_hash, now=now).raise_if_invalid()
        if any(item.approval_id == approval_value.approval_id for item in ledger): raise ContractValidationError("start approval has already appeared in the consumption ledger")
        approval_id = approval_value.approval_id; consumed_at = (now or _datetime.datetime.now(_datetime.timezone.utc)).isoformat(); budget_hash = canonical_sha256(current.budget)
        new_consumption = ApprovalConsumption(approval_id, current.project_id, current.run_id, current.charter_hash, current.state_version, consumed_at, current.state_version + 1)
        consumption_id = new_consumption.consumption_id
    elif target_value == RunStatus.RUNNING.value and current_value == RunStatus.AWAITING_START_APPROVAL.value:
        raise ContractValidationError("AWAITING_START_APPROVAL cannot transition directly to RUNNING")
    elif target_value == RunStatus.RUNNING.value and current_value == RunStatus.APPROVED.value:
        if current.approval_consumption_id is None: raise ContractValidationError("APPROVED state is missing its immutable approval consumption")
    elif target_value == RunStatus.COMPLETED.value:
        if completion_input is None: raise ContractValidationError("a complete CompletionEvaluationInput is required before COMPLETED")
        input_value = completion_input if isinstance(completion_input, CompletionEvaluationInput) else CompletionEvaluationInput.from_mapping(completion_input)
        if input_value.run_state.current_state_hash != current.current_state_hash or input_value.research_state.state_hash != current.current_state_hash: raise ContractValidationError("completion input is stale or does not bind the current Run State")
        expected = evaluate_completion_result(input_value)
        if completion_result is not None and model_to_dict(_as(completion_result, CompletionResult)) != model_to_dict(expected): raise ContractValidationError("submitted CompletionResult differs from recomputed result")
        validate_completion_result(expected, evaluation_input=input_value, current_run_state=current).raise_if_invalid()
        completion_id = expected.result_id; completion_hash = expected.state_hash; current_state_hash = expected.state_hash; current_checkpoint_id = input_value.current_checkpoint_id or current.current_checkpoint_id
    if target_value in {RunStatus.RUNNING.value, RunStatus.PAUSED.value} and research_state is not None:
        bound_state = research_state if isinstance(research_state, ResearchState) else ResearchState.from_mapping(research_state)
        current_state_hash = bound_state.state_hash
    updated = MaxRunState(
        current.run_id, current.project_id, target_value, current.charter_hash, current.model_identity,
        current.budget, current.source_policy_hash, approval_id, current.iteration_index,
        current.state_version + 1, consumed_at, completion_id, completion_hash,
        current.schema, current_state_hash, current_checkpoint_id, consumption_id, budget_hash,
    )
    validate_run_state(updated).raise_if_invalid()
    return RunTransitionResult(updated, new_consumption)


def validate_model_identity_binding(approval: StartApproval | Mapping[str, Any], *, current_model_identity: str, current_budget: Mapping[str, Any], current_source_policy_hash: str, current_charter_hash: str) -> ValidationResult:
    return validate_start_approval(approval, expected_model_identity=current_model_identity, expected_budget=current_budget, expected_source_policy_hash=current_source_policy_hash, expected_charter_hash=current_charter_hash)


def validate_stable_id(value: Any, *, expected_kind: str | None = None) -> ValidationResult:
    collector = issue_collector()
    if not is_stable_id(value, expected_kind=expected_kind): collector.add("id.invalid_stable_id", "$", "value is not a valid MR-1 stable ID")
    return collector.result()


def _object_value(value: CanonicalObject | Mapping[str, Any]) -> CanonicalObject:
    return _as(value, CanonicalObject)


def _cross_project_payload_refs(collector: Any, value: Any, project_id: str, path: str) -> None:
    if isinstance(value, Mapping):
        if "stable_id" in value and "project_id" in value:
            if not is_stable_id(value.get("stable_id")): collector.add("reference.invalid_id", f"{path}.stable_id", "reference stable_id is invalid")
            if value.get("project_id") != project_id: collector.add("reference.cross_project", path, "canonical references may not cross project boundaries")
        for key, item in value.items(): _cross_project_payload_refs(collector, item, project_id, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value): _cross_project_payload_refs(collector, item, project_id, f"{path}[{index}]")


def validate_canonical_object(value: CanonicalObject | Mapping[str, Any]) -> ValidationResult:
    obj, parse_issues = _safe_as(value, CanonicalObject)
    collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(obj, CanonicalObject): collector.add("object.type", "$", "canonical object must be a CanonicalObject or strict mapping"); return collector.result()
    if obj.schema != "max-research-canonical-object/v1": collector.add("object.schema", "$.schema", "unsupported canonical object schema")
    kind = normalize_kind(obj.kind)
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", kind): collector.add("object.kind", "$.kind", "canonical object kind is invalid")
    if not is_stable_id(obj.stable_id, expected_kind=kind): collector.add("object.stable_id", "$.stable_id", "stable_id must encode the object's kind")
    if not is_project_id(obj.project_id): collector.add("object.project_id", "$.project_id", "project_id is not valid")
    if isinstance(obj.version, bool) or not isinstance(obj.version, int) or obj.version < 1: collector.add("object.version", "$.version", "version must be a positive integer")
    try: expected = expected_version_id(kind, obj.project_id, obj.stable_id, obj.version)
    except (ValueError, TypeError): expected = None
    if not is_stable_id(obj.version_id, expected_kind=f"{kind}-version"): collector.add("object.version_id", "$.version_id", "version_id must use the object's version namespace")
    elif expected is not None and obj.version_id != expected: collector.add("object.version_binding", "$.version_id", "version_id is not bound to project, identity, kind and version")
    if not isinstance(obj.payload, Mapping): collector.add("object.payload", "$.payload", "payload must be a mapping")
    if obj.version == 1 and obj.supersedes_version_id is not None: collector.add("object.first_version_supersedes", "$.supersedes_version_id", "version 1 cannot supersede another version")
    if obj.version > 1:
        if not is_stable_id(obj.supersedes_version_id, expected_kind=f"{kind}-version"): collector.add("object.successor_required", "$.supersedes_version_id", "later versions must point to a prior version")
        elif obj.supersedes_version_id == obj.version_id: collector.add("object.self_supersedes", "$.supersedes_version_id", "a version cannot supersede itself")
    _cross_project_payload_refs(collector, obj.payload, obj.project_id, "$.payload")
    return collector.result()


def validate_canonical_relation(value: CanonicalRelation | Mapping[str, Any]) -> ValidationResult:
    relation, parse_issues = _safe_as(value, CanonicalRelation)
    collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(relation, CanonicalRelation): collector.add("relation.type", "$", "relation must be a CanonicalRelation or strict mapping"); return collector.result()
    if relation.schema != "max-research-relation/v1": collector.add("relation.schema", "$.schema", "unsupported relation schema")
    for name in ("source_id", "target_id"):
        if not is_stable_id(getattr(relation, name)): collector.add("relation.invalid_id", f"$.{name}", f"{name} must be a stable ID")
    if relation.relation not in {item.value for item in RelationKind}: collector.add("relation.kind", "$.relation", "relation kind is not in the MR-0A vocabulary")
    if not is_project_id(relation.project_id): collector.add("relation.project_id", "$.project_id", "project_id is not valid")
    for name in ("source_version_id", "target_version_id"):
        if not is_stable_id(getattr(relation, name)): collector.add("relation.version_required", f"$.{name}", f"{name} is required and must be a stable version ID")
    expected = make_relation_id(relation.project_id, relation.source_id, relation.target_id, relation.relation, relation.source_version_id, relation.target_version_id)
    if relation.relation_id != expected: collector.add("relation.id_binding", "$.relation_id", "relation_id is not bound to project, endpoints, relation and endpoint versions")
    if relation.source_id == relation.target_id and relation.relation != RelationKind.SUPERSEDES.value: collector.add("relation.self_reference", "$.target_id", "self-references are not allowed for this relation")
    if not isinstance(relation.metadata, Mapping): collector.add("relation.metadata", "$.metadata", "metadata must be a mapping")
    return collector.result()


def _coerce_objects(values: Iterable[CanonicalObject | Mapping[str, Any]]) -> tuple[CanonicalObject, ...]:
    return tuple(_object_value(value) for value in values)


def _coerce_relations(values: Iterable[CanonicalRelation | Mapping[str, Any]]) -> tuple[CanonicalRelation, ...]:
    return tuple(_as(value, CanonicalRelation) for value in values)


def _index_objects(objects: Sequence[CanonicalObject]) -> tuple[dict[str, CanonicalObject], dict[str, CanonicalObject]]:
    by_identity: dict[str, CanonicalObject] = {}; by_version: dict[str, CanonicalObject] = {}
    for obj in sorted(objects, key=lambda item: (item.stable_id, item.version)):
        if obj.stable_id not in by_identity or obj.version > by_identity[obj.stable_id].version: by_identity[obj.stable_id] = obj
        if obj.version_id is not None: by_version[obj.version_id] = obj
    return by_identity, by_version


def _resolve_object(ref: str, by_identity: Mapping[str, CanonicalObject], by_version: Mapping[str, CanonicalObject]) -> CanonicalObject | None:
    return by_version.get(ref) or by_identity.get(ref)


def _relation_target(relation: CanonicalRelation, by_identity: Mapping[str, CanonicalObject], by_version: Mapping[str, CanonicalObject]) -> CanonicalObject | None:
    """Resolve a relation endpoint by its exact version, never by latest ID."""

    candidate = by_version.get(relation.target_version_id)
    if candidate is None or candidate.stable_id != relation.target_id:
        return None
    return candidate


def _payload_ids(payload: Mapping[str, Any], keys: set[str]) -> set[str]:
    found: set[str] = set()
    for key, value in payload.items():
        if key not in keys: continue
        if isinstance(value, str) and is_stable_id(value): found.add(value)
        elif isinstance(value, (list, tuple)): found.update(item for item in value if isinstance(item, str) and is_stable_id(item))
    return found


def _live_targets(source: CanonicalObject, relations: Sequence[CanonicalRelation], names: set[str]) -> set[str]:
    return {rel.target_id for rel in relations if rel.source_id == source.stable_id and rel.source_version_id == source.version_id and rel.relation in names}


def _live_relations(source: CanonicalObject, relations: Sequence[CanonicalRelation], names: set[str]) -> tuple[CanonicalRelation, ...]:
    return tuple(rel for rel in relations if rel.source_id == source.stable_id and rel.source_version_id == source.version_id and rel.relation in names)


def _latest_objects(objects: Sequence[CanonicalObject]) -> tuple[dict[str, CanonicalObject], list[Any]]:
    collector = issue_collector(); grouped: dict[str, list[CanonicalObject]] = defaultdict(list); seen_versions: dict[str, CanonicalObject] = {}
    for obj in objects:
        if obj.version_id in seen_versions: collector.add("object.duplicate_version_id", "$.objects", f"version ID {obj.version_id} is used by more than one object")
        seen_versions[obj.version_id] = obj; grouped[obj.stable_id].append(obj)
    latest: dict[str, CanonicalObject] = {}
    for stable_id, versions in grouped.items():
        ordered = sorted(versions, key=lambda item: item.version)
        if len({item.version for item in ordered}) != len(ordered): collector.add("object.duplicate_version", f"$.objects[{stable_id}]", "object versions must be unique")
        actual = [item.version for item in ordered]
        if actual != list(range(1, len(ordered) + 1)): collector.add("object.version_gap", f"$.objects[{stable_id}]", "object versions must be contiguous")
        for previous, current in zip(ordered, ordered[1:]):
            if current.supersedes_version_id != previous.version_id: collector.add("object.supersedes_mismatch", f"$.objects[{stable_id}]", "each successor must supersede the immediately prior version")
        latest[stable_id] = ordered[-1]
    return latest, collector.issues


def _relation_endpoint_ok(relation: CanonicalRelation, objects: Sequence[CanonicalObject], collector: Any, path: str) -> None:
    by_identity, by_version = _index_objects(objects)
    for field_name, stable_field, version_field in (("source", "source_id", "source_version_id"), ("target", "target_id", "target_version_id")):
        obj = by_version.get(getattr(relation, version_field))
        if obj is None: collector.add("relation.orphan_version", f"{path}.{version_field}", f"{field_name} version is not canonical")
        elif obj.stable_id != getattr(relation, stable_field): collector.add("relation.version_identity_mismatch", f"{path}.{version_field}", f"{field_name} version does not belong to {stable_field}")
        elif obj.project_id != relation.project_id: collector.add("reference.cross_project", path, "relation endpoint crosses project boundary")
        if getattr(relation, stable_field) not in by_identity: collector.add("relation.orphan_endpoint", f"{path}.{stable_field}", f"{field_name} stable object is not canonical")


def validate_claim_evidence_trace(claim: CanonicalObject | Mapping[str, Any], objects: Sequence[CanonicalObject | Mapping[str, Any]], relations: Sequence[CanonicalRelation | Mapping[str, Any]]) -> ValidationResult:
    claim_obj, claim_issues = _safe_as(claim, CanonicalObject); object_values = _coerce_objects(objects); relation_values = _coerce_relations(relations)
    collector = issue_collector(); _add_parse_issues(collector, claim_issues)
    if not isinstance(claim_obj, CanonicalObject): collector.add("claim.type", "$", "claim must be canonical"); return collector.result()
    if claim_obj.kind != CanonicalObjectKind.CLAIM.value: collector.add("claim.kind", "$.kind", "evidence trace requires a claim object"); return collector.result()
    if claim_obj.payload.get("inherited_from_summary") or claim_obj.payload.get("summary_only"): collector.add("claim.summary_inheritance", "$.payload", "summary-only claims are not formal claims")
    direct = _payload_ids(claim_obj.payload, _DIRECT_EVIDENCE_KEYS)
    if direct or any(key in claim_obj.payload for key in _DIRECT_EVIDENCE_KEYS): collector.add("claim.direct_evidence_bypass", "$.payload", "formal claims may reference evidence only through canonical Evidence Link relations")
    by_identity, by_version = _index_objects(object_values)
    link_ids = _payload_ids(claim_obj.payload, {"evidence_link_id", "evidence_link_ids"})
    claim_link_relations = _live_relations(claim_obj, relation_values, {RelationKind.HAS_EVIDENCE_LINK.value})
    link_ids.update(rel.target_id for rel in claim_link_relations)
    if not link_ids: collector.add("claim.evidence_trace_missing", "$.payload", "formal claim must resolve through an Evidence Link")
    evidence_ids: set[str] = set()
    for link_id in sorted(link_ids):
        link_obj = _resolve_object(link_id, by_identity, by_version)
        if link_obj is None: collector.add("claim.orphan_evidence_link", "$.payload", f"evidence link {link_id} is missing"); continue
        if link_obj.kind != CanonicalObjectKind.EVIDENCE_LINK.value: collector.add("claim.evidence_link_kind", "$.payload", f"{link_id} is not an Evidence Link"); continue
        if any(key in link_obj.payload for key in _DIRECT_EVIDENCE_KEYS): collector.add("claim.link_direct_evidence_bypass", f"$.objects[{link_id}].payload", "Evidence Link must bind evidence with a canonical relation")
        link_relations = _live_relations(link_obj, relation_values, {RelationKind.LINKS_EVIDENCE.value})
        if not link_relations: collector.add("claim.link_evidence_missing", f"$.objects[{link_id}]", "Evidence Link has no version-bound links_evidence relation"); continue
        for rel in link_relations:
            evidence_obj = _relation_target(rel, by_identity, by_version)
            if evidence_obj is None or evidence_obj.kind != CanonicalObjectKind.EVIDENCE.value: collector.add("claim.evidence_kind", f"$.relations[{rel.relation_id}]", "links_evidence target must be canonical Evidence"); continue
            evidence_ids.add(evidence_obj.stable_id)
            raw_status = evidence_obj.payload.get("status")
            status = str(raw_status).lower() if isinstance(raw_status, str) else "unknown"
            if raw_status is None: collector.add("evidence.status_required", f"$.objects[{evidence_obj.stable_id}].payload.status", "Evidence status is missing and therefore cannot be treated as verified")
            if status not in {"candidate", "unverified", "unknown", "verified", "accepted", "rejected", "invalidated", "exact_quote_verified"}:
                collector.add("evidence.status_unknown", f"$.objects[{evidence_obj.stable_id}].payload.status", "Evidence status is outside the closed eligibility vocabulary")
            if status in FINAL_EVIDENCE_STATUSES:
                verification_id = evidence_obj.payload.get("verification_record_id")
                if not is_stable_id(verification_id, expected_kind="verification_record"):
                    collector.add("evidence.verification_record_required", f"$.objects[{evidence_obj.stable_id}].payload.verification_record_id", "verified Evidence must bind a canonical verification record")
                elif verification_id not in by_identity and verification_id not in by_version:
                    collector.add("evidence.verification_record_orphan", f"$.objects[{evidence_obj.stable_id}].payload.verification_record_id", "verification record is not present in canonical state")
                source_version_id = evidence_obj.payload.get("verified_source_version_id")
                if not is_stable_id(source_version_id, expected_kind="document_version-version"):
                    collector.add("evidence.source_version_required", f"$.objects[{evidence_obj.stable_id}].payload.verified_source_version_id", "verified Evidence must bind the exact source Document Version")
            claim_status = str(claim_obj.payload.get("status", "unknown")).lower()
            if status not in FINAL_EVIDENCE_STATUSES and claim_status in FINAL_CLAIM_STATUSES:
                collector.add("claim.evidence_status", f"$.objects[{evidence_obj.stable_id}].payload.status", "final claims cannot use unverified or provisional evidence")
            passage_relations = _live_relations(evidence_obj, relation_values, {RelationKind.DERIVED_FROM.value})
            if not passage_relations: collector.add("claim.evidence_passage_missing", f"$.objects[{evidence_obj.stable_id}]", "Evidence must derive from a Passage"); continue
            for passage_rel in passage_relations:
                passage_obj = _relation_target(passage_rel, by_identity, by_version)
                if passage_obj is None or passage_obj.kind != CanonicalObjectKind.PASSAGE.value: collector.add("claim.passage_kind", f"$.relations[{passage_rel.relation_id}]", "derived_from target must be Passage"); continue
                document_relations = _live_relations(passage_obj, relation_values, {RelationKind.LOCATED_IN.value})
                if not document_relations: collector.add("claim.document_version_missing", f"$.objects[{passage_obj.stable_id}]", "Passage must be located in a Document Version"); continue
                if not any((_relation_target(rel, by_identity, by_version) is not None and _relation_target(rel, by_identity, by_version).kind == CanonicalObjectKind.DOCUMENT_VERSION.value) for rel in document_relations): collector.add("claim.document_version_kind", f"$.objects[{passage_obj.stable_id}]", "Passage location must resolve to Document Version")
                for document_rel in document_relations:
                    document_obj = _relation_target(document_rel, by_identity, by_version)
                    if document_obj is not None and status in FINAL_EVIDENCE_STATUSES and evidence_obj.payload.get("verified_source_version_id") != document_obj.version_id:
                        collector.add("evidence.source_version_binding", f"$.objects[{evidence_obj.stable_id}].payload.verified_source_version_id", "verified Evidence source version differs from the exact trace endpoint")
    if link_ids and not evidence_ids: collector.add("claim.evidence_trace_incomplete", "$.payload", "claim evidence must resolve Evidence Link -> Evidence -> Passage -> Document Version")
    return collector.result()


def rebuild_research_state(objects: Iterable[CanonicalObject | Mapping[str, Any]], relations: Iterable[CanonicalRelation | Mapping[str, Any]], *, project_id: str, run_id: str | None = None) -> ResearchState:
    object_values = _coerce_objects(objects); relation_values = _coerce_relations(relations); collector = issue_collector()
    if not is_project_id(project_id): collector.add("state.project_id", "$.project_id", "project_id is not valid")
    for index, obj in enumerate(object_values):
        collector.issues.extend(validate_canonical_object(obj).issues)
        if obj.project_id != project_id: collector.add("reference.cross_project", f"$.objects[{index}]", "object belongs to another project")
    for index, relation in enumerate(relation_values):
        collector.issues.extend(validate_canonical_relation(relation).issues)
        if relation.project_id != project_id: collector.add("reference.cross_project", f"$.relations[{index}]", "relation belongs to another project")
        _relation_endpoint_ok(relation, object_values, collector, f"$.relations[{index}]")
    latest, version_issues = _latest_objects(object_values); collector.issues.extend(version_issues)
    for stable_id, obj in sorted(latest.items()):
        if obj.kind == CanonicalObjectKind.CLAIM.value: collector.issues.extend(validate_claim_evidence_trace(obj, object_values, relation_values).issues)
    leading = [obj.stable_id for obj in latest.values() if obj.kind == CanonicalObjectKind.HYPOTHESIS.value and bool(obj.payload.get("is_leading") or obj.payload.get("leading")) and obj.payload.get("status", "active") not in {"rejected", "weakened"}]
    if len(leading) > 1: collector.add("state.multiple_leading_hypotheses", "$.objects", "at most one leading hypothesis is allowed")
    collector.result().raise_if_invalid()
    state_payload = {"project_id": project_id, "run_id": run_id, "objects": sorted((model_to_dict(obj) for obj in object_values), key=lambda item: (item["stable_id"], item["version"])), "relations": sorted((model_to_dict(rel) for rel in relation_values), key=lambda item: item["relation_id"])}
    return ResearchState(project_id, run_id, tuple(sorted(object_values, key=lambda item: (item.stable_id, item.version))), tuple(sorted(relation_values, key=lambda item: item.relation_id)), latest, leading[0] if leading else None, canonical_sha256(state_payload))


def _scan_formal_content(value: Any, path: str, collector: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_string = str(key).lower(); item_path = f"{path}.{key}"
            if key_string in _FORMAL_CONTENT_KEYS and isinstance(item, (Mapping, list, tuple)) and item: collector.add("checkpoint.formal_content_embedded", item_path, "checkpoint may contain only canonical IDs, not formal Claim/Evidence payloads")
            _scan_formal_content(item, item_path, collector)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value): _scan_formal_content(item, f"{path}[{index}]", collector)


def validate_checkpoint(checkpoint: Checkpoint | Mapping[str, Any], *, project_id: str | None = None, run_id: str | None = None, canonical_objects: Sequence[CanonicalObject | Mapping[str, Any]] | None = None) -> ValidationResult:
    value, parse_issues = _safe_as(checkpoint, Checkpoint); collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(value, Checkpoint): collector.add("checkpoint.type", "$", "checkpoint must be a Checkpoint or strict mapping"); return collector.result()
    if value.schema != "max-research-checkpoint/v1": collector.add("checkpoint.schema", "$.schema", "unsupported checkpoint schema")
    if value.checkpoint_version != 1: collector.add("checkpoint.version", "$.checkpoint_version", "unsupported checkpoint version")
    if not is_project_id(value.project_id): collector.add("checkpoint.project_id", "$.project_id", "project_id is not valid")
    if not is_stable_id(value.checkpoint_id, expected_kind="checkpoint"): collector.add("checkpoint.id", "$.checkpoint_id", "checkpoint_id must be a checkpoint stable ID")
    if project_id is not None and value.project_id != project_id: collector.add("reference.cross_project", "$.project_id", "checkpoint project differs from expected project")
    if run_id is not None and value.run_id != run_id: collector.add("checkpoint.run_id", "$.run_id", "checkpoint run differs from expected run")
    if isinstance(value.iteration_pointer, bool) or not isinstance(value.iteration_pointer, int) or value.iteration_pointer < 0: collector.add("checkpoint.iteration_pointer", "$.iteration_pointer", "iteration_pointer must be non-negative")
    _required_mapping(collector, value.budget, "$.budget"); _id_sequence(collector, value.canonical_ids, "$.canonical_ids", required=True); _id_sequence(collector, value.frontier_extension_ids, "$.frontier_extension_ids")
    if len(set(value.canonical_ids)) != len(value.canonical_ids): collector.add("checkpoint.frontier_duplicate", "$.canonical_ids", "canonical frontier must be an exact set")
    if not set(value.frontier_extension_ids).issubset(set(value.canonical_ids)): collector.add("checkpoint.frontier_extension", "$.frontier_extension_ids", "frontier extensions must be included in canonical_ids")
    working = value.working_state
    if not isinstance(working, WorkingState): collector.add("checkpoint.working_state", "$.working_state", "working_state is invalid")
    else:
        if working.project_id != value.project_id or working.run_id != value.run_id: collector.add("checkpoint.working_state_binding", "$.working_state", "working state is not bound to checkpoint")
        if working.iteration_index != value.iteration_pointer: collector.add("checkpoint.iteration_binding", "$.working_state.iteration_index", "working state and checkpoint iteration differ")
        if set(working.canonical_object_ids) != set(value.canonical_ids): collector.add("checkpoint.frontier_exact", "$.working_state.canonical_object_ids", "working-state canonical IDs must equal the checkpoint frontier exactly")
        canonical_set = set(value.canonical_ids)
        for path, ids, kind in (("$.working_state.claim_ids", working.claim_ids, "claim"), ("$.working_state.evidence_ids", working.evidence_ids, "evidence"), ("$.working_state.search_strategy_ids", working.search_strategy_ids, "iteration"), ("$.working_state.unresolved_issue_ids", working.unresolved_issue_ids, None)):
            _id_sequence(collector, ids, path, expected_kind=kind)
            for item in ids:
                if item not in canonical_set: collector.add("checkpoint.orphan_reference", path, f"{item} is not in canonical_ids")
        if working.active_leading_hypothesis_id is not None:
            _id_sequence(collector, [working.active_leading_hypothesis_id], "$.working_state.active_leading_hypothesis_id", expected_kind="hypothesis")
            if working.active_leading_hypothesis_id not in canonical_set: collector.add("checkpoint.orphan_reference", "$.working_state.active_leading_hypothesis_id", "leading hypothesis is not in canonical_ids")
    _scan_formal_content(model_to_dict(value), "$.checkpoint", collector)
    if canonical_objects is not None:
        objs = _coerce_objects(canonical_objects); by_identity, by_version = _index_objects(objs)
        if set(value.canonical_ids) != set(by_identity) and not set(value.canonical_ids).issubset(set(by_identity) | set(by_version)):
            collector.add("checkpoint.frontier_object_set", "$.canonical_ids", "checkpoint frontier does not resolve to the supplied canonical object set")
        for index, stable_id in enumerate(value.canonical_ids):
            if stable_id not in by_identity and stable_id not in by_version: collector.add("checkpoint.missing_canonical_object", f"$.canonical_ids[{index}]", f"{stable_id} is unavailable")
            obj = by_identity.get(stable_id) or by_version.get(stable_id)
            if obj is not None and obj.project_id != value.project_id: collector.add("reference.cross_project", f"$.canonical_ids[{index}]", "checkpoint object crosses project boundary")
    return collector.result()


def validate_checkpoint_lineage(checkpoints: Sequence[Checkpoint | Mapping[str, Any]]) -> ValidationResult:
    values: list[Checkpoint] = []; collector = issue_collector()
    for index, item in enumerate(checkpoints):
        value, issues = _safe_as(item, Checkpoint); _add_parse_issues(collector, issues)
        if isinstance(value, Checkpoint): values.append(value)
        else: collector.add("checkpoint.type", f"$[{index}]", "checkpoint is invalid")
    ids: dict[str, Checkpoint] = {}; children: dict[str, list[str]] = defaultdict(list)
    for index, checkpoint in enumerate(values):
        collector.issues.extend(validate_checkpoint(checkpoint).issues)
        if checkpoint.checkpoint_id in ids: collector.add("checkpoint.duplicate_id", f"$[{index}]", "checkpoint IDs must be unique")
        ids[checkpoint.checkpoint_id] = checkpoint
        if checkpoint.supersedes_item_id:
            children[checkpoint.supersedes_item_id].append(checkpoint.checkpoint_id)
            if checkpoint.supersedes_item_id not in ids and checkpoint.supersedes_item_id not in {item.checkpoint_id for item in values}: collector.add("checkpoint.orphan_successor", "$.checkpoints", f"successor points to missing checkpoint {checkpoint.supersedes_item_id}")
            if checkpoint.supersedes_item_id == checkpoint.checkpoint_id: collector.add("checkpoint.lineage_cycle", f"$[{index}]", "checkpoint cannot supersede itself")
    if values:
        ordered = sorted(values, key=lambda item: item.iteration_pointer)
        if any(item.project_id != ordered[0].project_id or item.run_id != ordered[0].run_id for item in ordered[1:]): collector.add("checkpoint.lineage_binding", "$.checkpoints", "checkpoint lineage must remain within one project/run")
        if any(previous.iteration_pointer >= current.iteration_pointer for previous, current in zip(ordered, ordered[1:])): collector.add("checkpoint.iteration_order", "$.checkpoints", "checkpoint iterations must strictly increase")
        for prev, curr in zip(ordered, ordered[1:]):
            if curr.supersedes_item_id != prev.checkpoint_id: collector.add("checkpoint.predecessor_exact", "$.checkpoints", "each checkpoint must name the immediately preceding checkpoint")
            for key, old in prev.budget.items():
                new = curr.budget.get(key)
                if isinstance(old, (int, float)) and isinstance(new, (int, float)) and not isinstance(old, bool) and new > old: collector.add("checkpoint.budget_increase", "$.checkpoints", f"budget key {key} increased along lineage")
        current = [item for item in values if not any(child == item.checkpoint_id for children_list in children.values() for child in children_list)]
        if len(current) != 1: collector.add("checkpoint.one_current", "$.checkpoints", "checkpoint lineage must have exactly one current record")
        for predecessor, child_list in children.items():
            if len(child_list) > 1: collector.add("checkpoint.multiple_successors", "$.checkpoints", f"{predecessor} has multiple successors")
    return collector.result()


def should_rehydrate(policy: RehydrationPolicy | Mapping[str, Any] | None = None, *, iteration_index: int = 0, events: Sequence[str] = ()) -> bool:
    value = policy if isinstance(policy, RehydrationPolicy) else RehydrationPolicy.from_mapping(policy) if isinstance(policy, Mapping) else RehydrationPolicy()
    interval = value.interval_iterations
    if isinstance(interval, bool) or not isinstance(interval, int) or interval < 1: raise ContractValidationError("rehydration interval must be a positive integer")
    if iteration_index > 0 and iteration_index % interval == 0: return True
    return bool(set(events) & set(value.triggers))


def _state_relation_ids(state: ResearchState) -> set[str]: return {relation.relation_id for relation in state.relations}


def rehydrate(value: RehydrationInput | Mapping[str, Any]) -> RehydrationOutput:
    if isinstance(value, RehydrationInput): request = value
    elif isinstance(value, Mapping):
        allowed = {"project_id", "run_id", "checkpoint", "canonical_objects", "relations", "working_summary", "prior_state", "iteration_index", "events", "policy"}
        raw = require_mapping_fields(value, allowed=allowed, required={"project_id", "run_id", "checkpoint", "canonical_objects", "relations"})
        request = RehydrationInput.from_mapping(raw)
    else: raise ContractValidationError("rehydration input is invalid")
    collector = issue_collector(); flags: set[str] = set()
    collector.issues.extend(validate_checkpoint(request.checkpoint, project_id=request.project_id, run_id=request.run_id, canonical_objects=request.canonical_objects).issues)
    checkpoint_ids = set(request.checkpoint.canonical_ids); object_ids = {obj.stable_id for obj in request.canonical_objects}
    missing = checkpoint_ids - object_ids
    if missing: flags.add(DriftKind.MISSING_CANONICAL_OBJECT.value); collector.add("rehydration.missing_object", "$.canonical_objects", "checkpoint references missing canonical objects")
    unexpected = object_ids - (checkpoint_ids | set(request.checkpoint.frontier_extension_ids))
    if unexpected: flags.add(DriftKind.UNEXPECTED_FRONTIER_OBJECT.value); collector.add("rehydration.unexpected_frontier", "$.canonical_objects", "current object set extends the checkpoint without an explicit frontier extension")
    state: ResearchState | None = None
    try: state = rebuild_research_state(request.canonical_objects, request.relations, project_id=request.project_id, run_id=request.run_id)
    except ContractValidationError as exc:
        collector.issues.extend(exc.issues)
        if any(issue.code.startswith("claim.") for issue in exc.issues): flags.add(DriftKind.ORPHAN_CLAIM.value)
        if request.prior_state is not None:
            current_relation_ids = {relation.relation_id for relation in request.relations}
            if _state_relation_ids(request.prior_state) - current_relation_ids:
                flags.add(DriftKind.STALE_RELATION.value)
                collector.add("rehydration.stale_relation", "$.relations", "prior relation is missing while rebuilding the current graph")
    if request.working_summary is not None:
        _scan_formal_content(request.working_summary, "$.working_summary", collector)
        if any(str(key).lower() in _FORMAL_CONTENT_KEYS and isinstance(item, (Mapping, list, tuple)) and item for key, item in request.working_summary.items()): flags.add(DriftKind.SUMMARY_ONLY_INHERITANCE.value)
        if state is not None:
            summary_ids = request.working_summary.get("canonical_object_ids")
            if summary_ids is not None and set(summary_ids) != object_ids: flags.add(DriftKind.SUMMARY_MEANING_DRIFT.value); collector.add("rehydration.summary_ids", "$.working_summary.canonical_object_ids", "working summary cannot redefine canonical membership")
            summary_leading = request.working_summary.get("active_leading_hypothesis_id")
            if summary_leading is not None and summary_leading != state.active_leading_hypothesis_id: flags.add(DriftKind.SUMMARY_MEANING_DRIFT.value); collector.add("rehydration.meaning_drift", "$.working_summary.active_leading_hypothesis_id", "summary disagrees with rebuilt state")
    if request.prior_state is not None and state is not None:
        prior_objects = {(obj.stable_id, obj.version_id): obj for obj in request.prior_state.objects}; current_objects = {(obj.stable_id, obj.version_id): obj for obj in state.objects}
        for key, previous in prior_objects.items():
            candidate = current_objects.get(key)
            if candidate is None:
                flags.add(DriftKind.MISSING_CANONICAL_OBJECT.value); flags.add(DriftKind.VERSION_CHAIN_DRIFT.value); collector.add("rehydration.prior_object_missing", "$.canonical_objects", f"prior canonical object/version {key[0]}:{key[1]} is missing")
            elif canonical_sha256(previous.payload) != canonical_sha256(candidate.payload):
                flags.add(DriftKind.MEANING_DRIFT.value); collector.add("rehydration.same_version_change", f"$.objects[{key[0]}]", "canonical meaning changed without a successor version")
                if previous.payload.get("status") != candidate.payload.get("status"): flags.add(DriftKind.STATUS_DRIFT.value)
        for relation_id in _state_relation_ids(request.prior_state) - _state_relation_ids(state): flags.add(DriftKind.STALE_RELATION.value); collector.add("rehydration.stale_relation", "$.relations", f"prior relation {relation_id} is missing or no longer version-bound")
        prior_chains = {(obj.stable_id, obj.version): obj.supersedes_version_id for obj in request.prior_state.objects}; current_chains = {(obj.stable_id, obj.version): obj.supersedes_version_id for obj in state.objects}
        if any(prior_chains.get(key) != current_chains.get(key) for key in prior_chains if key in current_chains): flags.add(DriftKind.VERSION_CHAIN_DRIFT.value); collector.add("rehydration.version_chain", "$.objects", "version predecessor chain changed")
    return RehydrationOutput(accepted=not collector.issues, state=state, drift_flags=tuple(sorted(flags)), issues=tuple(issue.as_dict() for issue in collector.issues), canonical_object_ids=tuple(sorted(object_ids)))


def validate_iteration(value: Iteration | Mapping[str, Any]) -> ValidationResult:
    iteration, parse_issues = _safe_as(value, Iteration); collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(iteration, Iteration): collector.add("iteration.type", "$", "iteration must be an Iteration or strict mapping"); return collector.result()
    if iteration.kind not in {item.value for item in IterationKind}: collector.add("iteration.kind", "$.kind", "unsupported iteration kind")
    if isinstance(iteration.sequence, bool) or not isinstance(iteration.sequence, int) or iteration.sequence < 0: collector.add("iteration.sequence", "$.sequence", "sequence must be non-negative")
    if not is_project_id(iteration.project_id): collector.add("iteration.project_id", "$.project_id", "project_id is not valid")
    for path, ids in (("$.inputs", iteration.inputs), ("$.outputs", iteration.outputs), ("$.canonical_object_ids", iteration.canonical_object_ids)): _id_sequence(collector, ids, path)
    return collector.result()


def _validity_audit(audit: ValidityAudit, path: str, collector: Any) -> None:
    _required_text(collector, audit.auditor_role, f"{path}.auditor_role", "discussion.auditor_required")
    dimensions: list[bool] = []
    for name in ("facts_evidence_true", "normative_valid", "expression_clear", "role_fidelity"):
        value = getattr(audit, name)
        if not isinstance(value, bool): collector.add("discussion.audit_dimension_required", f"{path}.{name}", "validity audit must record every required dimension")
        else: dimensions.append(value)
    if isinstance(audit.passed, bool) and len(dimensions) == 4 and audit.passed != all(dimensions):
        collector.add("discussion.audit_passed_mismatch", f"{path}.passed", "ValidityAudit.passed must equal the conjunction of all required dimensions")
    if not audit.passed: collector.add("discussion.audit_failed", path, "a failed validity audit blocks adjudication")
    if not audit.findings and not _text(audit.rationale): collector.add("discussion.audit_rationale", path, "validity audit requires findings or rationale")


def validate_discussion_session(value: DiscussionSession | Mapping[str, Any], *, state: ResearchState | None = None) -> ValidationResult:
    session, parse_issues = _safe_as(value, DiscussionSession); collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(session, DiscussionSession): collector.add("discussion.type", "$", "session must be a DiscussionSession or strict mapping"); return collector.result()
    if not is_project_id(session.project_id): collector.add("discussion.project_id", "$.project_id", "project_id is not valid")
    for name, attr in (("run_id", session.run_id), ("state_hash", session.state_hash), ("model_identity", session.model_identity), ("inference_profile_hash", session.inference_profile_hash)): _required_text(collector, attr, f"$.{name}", "discussion.binding_required")
    if not is_stable_id(session.target_id): collector.add("discussion.target_id", "$.target_id", "target_id must be stable")
    roles = [position.role for position in session.independent_positions]
    if len(roles) < 2 or len(set(roles)) < 2: collector.add("discussion.independent_positions", "$.independent_positions", "session requires at least two distinct independent roles")
    if len(session.role_packets) != len(session.independent_positions): collector.add("discussion.role_packet_count", "$.role_packets", "one isolated role packet is required for each position")
    packet_roles = set()
    for index, position in enumerate(session.independent_positions):
        _required_text(collector, position.role, f"$.independent_positions[{index}].role", "discussion.role_required"); _required_text(collector, position.position, f"$.independent_positions[{index}].position", "discussion.position_required")
        _id_sequence(collector, position.canonical_claim_ids, f"$.independent_positions[{index}].canonical_claim_ids", expected_kind="claim"); _id_sequence(collector, position.canonical_evidence_ids, f"$.independent_positions[{index}].canonical_evidence_ids", expected_kind="evidence")
    for index, packet in enumerate(session.role_packets):
        path = f"$.role_packets[{index}]"; packet_roles.add(packet.role)
        for name, expected in (("project_id", session.project_id), ("run_id", session.run_id), ("state_hash", session.state_hash), ("target_id", session.target_id), ("model_identity", session.model_identity), ("inference_profile_hash", session.inference_profile_hash)):
            if getattr(packet, name) != expected: collector.add("discussion.packet_binding", f"{path}.{name}", "role packet is not bound to this session")
        if packet.role not in roles: collector.add("discussion.packet_role", f"{path}.role", "role packet role has no independent position")
        if packet.sees_other_role_outputs: collector.add("discussion.role_contamination", f"{path}.sees_other_role_outputs", "role packet must not see another role's output")
        _id_sequence(collector, packet.allowed_canonical_ids, f"{path}.allowed_canonical_ids"); _id_sequence(collector, packet.forbidden_output_ids, f"{path}.forbidden_output_ids")
        if set(packet.forbidden_output_ids) & set(packet.allowed_canonical_ids): collector.add("discussion.packet_forbidden_overlap", path, "forbidden outputs may not be in the allowed packet")
    if packet_roles != set(roles): collector.add("discussion.packet_roles", "$.role_packets", "role packets must cover the independent roles exactly")
    if not session.cross_examinations: collector.add("discussion.cross_examination_required", "$.cross_examinations", "a real rival must cross-examine the leading position")
    for index, examination in enumerate(session.cross_examinations):
        path = f"$.cross_examinations[{index}]"
        if examination.examiner_role == examination.respondent_role: collector.add("discussion.same_role_cross_exam", path, "cross-examination must involve distinct roles")
        if examination.examiner_role not in roles or examination.respondent_role not in roles: collector.add("discussion.cross_exam_role", path, "cross-examination roles must be independent roles")
        _required_text(collector, examination.question, f"{path}.question", "discussion.question_required"); _required_text(collector, examination.answer, f"{path}.answer", "discussion.answer_required")
        _id_sequence(collector, examination.challenged_claim_ids, f"{path}.challenged_claim_ids", expected_kind="claim")
    if session.adjudication is None: collector.add("discussion.adjudication_required", "$.adjudication", "session requires an adjudication record")
    else:
        if session.adjudication.value not in {item.value for item in AdjudicationValue}: collector.add("discussion.adjudication_value", "$.adjudication.value", "invalid adjudication value")
        _required_text(collector, session.adjudication.rationale, "$.adjudication.rationale", "discussion.rationale_required")
        _id_sequence(collector, session.adjudication.rival_ids, "$.adjudication.rival_ids", required=True); _id_sequence(collector, session.adjudication.canonical_evidence_ids, "$.adjudication.canonical_evidence_ids", expected_kind="evidence", required=True)
        if session.adjudication.value == AdjudicationValue.REASONED_DISSENSUS.value and not session.minority_reports: collector.add("discussion.minority_missing", "$.minority_reports", "reasoned dissensus must preserve a minority report")
        actual_reports = {report.report_id for report in session.minority_reports}; referenced_reports = set(session.adjudication.minority_report_ids)
        if actual_reports != referenced_reports: collector.add("discussion.minority_id_binding", "$.adjudication.minority_report_ids", "adjudication must reference the actual minority report IDs exactly")
    if not session.validity_audits: collector.add("discussion.validity_audit_required", "$.validity_audits", "session requires a validity audit")
    for index, audit in enumerate(session.validity_audits): _validity_audit(audit, f"$.validity_audits[{index}]", collector)
    if state is not None:
        if session.project_id != state.project_id: collector.add("discussion.state_project", "$.project_id", "discussion session is outside the supplied Research State")
        if session.run_id != (state.run_id or ""): collector.add("discussion.state_run", "$.run_id", "discussion session run is outside the supplied Research State")
        if session.state_hash != state.state_hash: collector.add("discussion.state_hash", "$.state_hash", "discussion session must bind the supplied Research State")
        if session.target_id not in state.latest_by_id: collector.add("discussion.state_target", "$.target_id", "discussion target is not in the supplied Research State")
        state_ids = set(state.latest_by_id)
        state_versions = {obj.version_id for obj in state.latest_by_id.values()}
        def check_ids(ids: Sequence[str], path: str) -> None:
            for index, item in enumerate(ids):
                if item not in state_ids and item not in state_versions:
                    collector.add("discussion.state_reference", f"{path}[{index}]", "discussion reference is not a canonical object/version in the supplied Research State")
        for index, position in enumerate(session.independent_positions):
            check_ids(position.canonical_claim_ids, f"$.independent_positions[{index}].canonical_claim_ids")
            check_ids(position.canonical_evidence_ids, f"$.independent_positions[{index}].canonical_evidence_ids")
        for index, packet in enumerate(session.role_packets):
            check_ids(packet.allowed_canonical_ids, f"$.role_packets[{index}].allowed_canonical_ids")
            check_ids(packet.forbidden_output_ids, f"$.role_packets[{index}].forbidden_output_ids")
            if packet.target_id not in state_ids and packet.target_id not in state_versions: collector.add("discussion.packet_target_state", f"$.role_packets[{index}].target_id", "role packet target is not in the supplied Research State")
        for index, examination in enumerate(session.cross_examinations):
            check_ids(examination.challenged_claim_ids, f"$.cross_examinations[{index}].challenged_claim_ids")
        if session.adjudication is not None:
            check_ids(session.adjudication.rival_ids, "$.adjudication.rival_ids")
            check_ids(session.adjudication.canonical_evidence_ids, "$.adjudication.canonical_evidence_ids")
        for index, report in enumerate(session.minority_reports):
            check_ids(report.canonical_claim_ids, f"$.minority_reports[{index}].canonical_claim_ids")
    return collector.result()


def validate_epistemic_conflict_record(value: EpistemicConflictRecord | Mapping[str, Any]) -> ValidationResult:
    record, parse_issues = _safe_as(value, EpistemicConflictRecord)
    collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(record, EpistemicConflictRecord):
        collector.add("epistemic_conflict.type", "$", "conflict record must be typed")
        return collector.result()
    if record.schema != EPISTEMIC_CONFLICT_SCHEMA:
        collector.add("epistemic_conflict.schema", "$.schema", "unsupported epistemic conflict schema")
    for name in ("project_id", "run_id", "iteration_id", "logical_call_id", "intent_hash", "request_hash", "proposal_hash", "validator_hash", "canonical_state_hash", "conflict_type", "fingerprint", "actor_id", "created_at"):
        _required_text(collector, getattr(record, name), f"$.{name}", "epistemic_conflict.binding_required")
    _string_sequence(collector, record.canonical_version_hashes, "$.canonical_version_hashes")
    for index, version_hash in enumerate(record.canonical_version_hashes):
        if not isinstance(version_hash, str) or re.fullmatch(r"[0-9a-f]{64}", version_hash) is None:
            collector.add("epistemic_conflict.version_hash", f"$.canonical_version_hashes[{index}]", "canonical version binding must be a SHA-256 hash")
    _string_sequence(collector, record.issue_codes, "$.issue_codes", required=True)
    if not isinstance(record.canonical_basis, Mapping) or not record.canonical_basis:
        collector.add("epistemic_conflict.canonical_basis", "$.canonical_basis", "canonical basis is required")
    if record.resolution not in {"rejected", "rehydration_required", "paused", "resolved"}:
        collector.add("epistemic_conflict.resolution", "$.resolution", "resolution is not a control-plane resolution")
    if isinstance(record.repeat_count, bool) or not isinstance(record.repeat_count, int) or record.repeat_count < 1:
        collector.add("epistemic_conflict.repeat_count", "$.repeat_count", "repeat_count must be positive")
    expected = make_event_id("epistemic_conflict", record.project_id, {"run_id": record.run_id, "fingerprint": record.fingerprint, "repeat_count": record.repeat_count})
    if record.conflict_id != expected:
        collector.add("epistemic_conflict.id", "$.conflict_id", "conflict_id is not deterministically bound")
    return collector.result()


def validate_cold_review_packet(packet: ColdReviewPacket | Mapping[str, Any], state: ResearchState, *, expected_charter_hash: str | None = None) -> ValidationResult:
    value, parse_issues = _safe_as(packet, ColdReviewPacket); collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(value, ColdReviewPacket): collector.add("cold_review.type", "$", "cold review packet is invalid"); return collector.result()
    if value.project_id != state.project_id: collector.add("cold_review.project", "$.project_id", "cold review packet crosses project")
    if value.run_id != state.run_id: collector.add("cold_review.run", "$.run_id", "cold review packet run differs")
    if value.state_hash != state.state_hash: collector.add("cold_review.state", "$.state_hash", "cold review packet must bind exact Research State")
    if expected_charter_hash is not None and value.charter_hash != expected_charter_hash: collector.add("cold_review.charter", "$.charter_hash", "cold review packet charter differs")
    _id_sequence(collector, value.final_claim_ids, "$.final_claim_ids", expected_kind="claim", required=True); _id_sequence(collector, value.evidence_ids, "$.evidence_ids", expected_kind="evidence")
    if set(value.excluded_sections) != set(COLD_REVIEW_REQUIRED_EXCLUSIONS): collector.add("cold_review.exclusions", "$.excluded_sections", "cold review must exclude the complete mandatory working-context set")
    if len(value.excluded_sections) != len(set(value.excluded_sections)): collector.add("cold_review.exclusion_duplicates", "$.excluded_sections", "cold review exclusions must be unique")
    for claim_id in value.final_claim_ids:
        claim = state.latest_by_id.get(claim_id)
        if claim is None: collector.add("cold_review.claim", "$.final_claim_ids", f"claim {claim_id} is not in state")
        else: collector.issues.extend(validate_claim_evidence_trace(claim, state.objects, state.relations).issues)
    expected_links = _expected_source_links(state, value.final_claim_ids)
    if canonical_sha256(value.source_link_records) != canonical_sha256(expected_links): collector.add("cold_review.source_links", "$.source_link_records", "cold review source links are not a recomputable projection")
    expected_evidence = {item["evidence_id"] for item in expected_links};
    if set(value.evidence_ids) != expected_evidence: collector.add("cold_review.evidence", "$.evidence_ids", "cold review evidence set differs from exact claim trace")
    if not is_stable_id(value.report_id, expected_kind="report"): collector.add("cold_review.report", "$.report_id", "report_id must be stable")
    packet_payload = {
        "project_id": value.project_id, "run_id": value.run_id, "state_hash": value.state_hash,
        "charter_hash": value.charter_hash, "final_claim_ids": sorted(value.final_claim_ids),
        "evidence_ids": sorted(value.evidence_ids), "source_link_records": value.source_link_records,
        "report_id": value.report_id, "excluded_sections": sorted(value.excluded_sections),
    }
    expected_packet_id = make_event_id("cold_review", value.project_id, packet_payload)
    if value.packet_id != expected_packet_id: collector.add("cold_review.packet_id", "$.packet_id", "packet_id is not the canonical packet identity")
    if value.packet_hash != canonical_sha256(packet_payload): collector.add("cold_review.packet_hash", "$.packet_hash", "packet_hash is not the canonical packet input hash")
    return collector.result()


def validate_cold_review_result(
    result: ColdReviewResult | Mapping[str, Any],
    packet: ColdReviewPacket,
    state: ResearchState,
    *,
    report: ReportProjection | None = None,
    expected_model_identity: str | None = None,
    expected_inference_profile_hash: str | None = None,
) -> ValidationResult:
    value, parse_issues = _safe_as(result, ColdReviewResult); collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(value, ColdReviewResult): collector.add("cold_review_result.type", "$", "cold review result is invalid"); return collector.result()
    collector.issues.extend(validate_cold_review_packet(packet, state, expected_charter_hash=packet.charter_hash).issues)
    if report is not None: collector.issues.extend(validate_report_projection(report, state).issues)
    for name, expected in (("packet_id", packet.packet_id), ("packet_hash", packet.packet_hash), ("project_id", state.project_id), ("run_id", state.run_id), ("charter_hash", packet.charter_hash), ("state_hash", state.state_hash), ("report_id", packet.report_id)):
        if getattr(value, name) != expected: collector.add("cold_review_result.binding", f"$.{name}", f"cold review result does not bind {name}")
    if expected_model_identity is not None and value.reviewer_model_identity != expected_model_identity: collector.add("cold_review_result.model", "$.reviewer_model_identity", "cold review result reviewer model differs")
    if expected_inference_profile_hash is not None and value.inference_profile_hash != expected_inference_profile_hash: collector.add("cold_review_result.inference", "$.inference_profile_hash", "cold review result inference profile differs")
    _required_text(collector, value.reviewer_model_identity, "$.reviewer_model_identity", "cold_review_result.model_required")
    _required_text(collector, value.inference_profile_hash, "$.inference_profile_hash", "cold_review_result.inference_required")
    if _parse_time(value.evaluated_at) is None: collector.add("cold_review_result.timestamp", "$.evaluated_at", "evaluated_at must be ISO-8601")
    for name, audit in (("claim_audit", value.claim_audit), ("evidence_audit", value.evidence_audit), ("citation_audit", value.citation_audit)):
        if not isinstance(audit, Mapping) or audit.get("passed") is not True: collector.add("cold_review_result.audit", f"$.{name}", "cold review result requires a passed typed audit")
    if value.blocking_findings: collector.add("cold_review_result.blocking", "$.blocking_findings", "blocking cold-review findings prevent completion")
    expected_id = ColdReviewResult(
        value.packet_id, value.packet_hash, value.project_id, value.run_id, value.charter_hash,
        value.state_hash, value.report_id, value.reviewer_model_identity, value.inference_profile_hash,
        value.passed, value.blocking_findings, value.claim_audit, value.evidence_audit, value.citation_audit,
        value.evaluated_at,
    ).result_id
    if value.result_id != expected_id: collector.add("cold_review_result.id", "$.result_id", "cold review result ID is not bound to all result semantics")
    if value.passed != (not value.blocking_findings and all(isinstance(audit, Mapping) and audit.get("passed") is True for audit in (value.claim_audit, value.evidence_audit, value.citation_audit))):
        collector.add("cold_review_result.passed", "$.passed", "cold review result passed flag must be recomputable from audits and blocking findings")
    return collector.result()


def validate_acquisition_request(value: AcquisitionRequest | Mapping[str, Any]) -> ValidationResult:
    request, parse_issues = _safe_as(value, AcquisitionRequest); collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(request, AcquisitionRequest): collector.add("acquisition.type", "$", "request must be an AcquisitionRequest or strict mapping"); return collector.result()
    if not is_project_id(request.project_id): collector.add("acquisition.project_id", "$.project_id", "project_id is not valid")
    _required_text(collector, request.run_id, "$.run_id", "acquisition.binding_required"); _required_text(collector, request.source_policy_hash, "$.source_policy_hash", "acquisition.binding_required")
    _required_text(collector, request.research_gap, "$.research_gap", "acquisition.field_required"); _required_text(collector, request.why_needed, "$.why_needed", "acquisition.field_required"); _required_text(collector, request.desired_source_role, "$.desired_source_role", "acquisition.field_required")
    _id_sequence(collector, request.target_ids, "$.target_ids", required=True); _string_sequence(collector, request.possible_falsification, "$.possible_falsification", required=True)
    if isinstance(request.expected_information_gain, (int, float)) and (isinstance(request.expected_information_gain, bool) or request.expected_information_gain <= 0): collector.add("acquisition.information_gain", "$.expected_information_gain", "information gain must be positive")
    elif not isinstance(request.expected_information_gain, (int, float)) and not _text(request.expected_information_gain): collector.add("acquisition.information_gain", "$.expected_information_gain", "information gain must be explicit")
    for path, values in (("$.preferred_types", request.preferred_types), ("$.preferred_languages", request.preferred_languages), ("$.exclusions", request.exclusions)): _string_sequence(collector, values, path)
    if not isinstance(request.preferred_date_range, Mapping): collector.add("acquisition.date_range", "$.preferred_date_range", "date range must be an object")
    if isinstance(request.max_candidates, bool) or not isinstance(request.max_candidates, int) or request.max_candidates < 1: collector.add("acquisition.max_candidates", "$.max_candidates", "max_candidates must be positive")
    expected_id = make_event_id("acquisition_request", request.project_id, {"run_id": request.run_id, "gap": request.research_gap, "targets": sorted(request.target_ids), "why": request.why_needed, "gain": request.expected_information_gain, "falsification": request.possible_falsification, "role": request.desired_source_role, "types": request.preferred_types, "languages": request.preferred_languages, "date_range": request.preferred_date_range, "exclusions": request.exclusions, "max_candidates": request.max_candidates})
    if request.request_id != expected_id: collector.add("acquisition.id_binding", "$.request_id", "request_id must bind the complete request semantics")
    return collector.result()


def validate_speculative_transition(current: SpeculativeStatus | str, target: SpeculativeStatus | str, *, history: Sequence[SpeculativeStatus | str] | None = None) -> ValidationResult:
    collector = issue_collector(); current_value = getattr(current, "value", current); target_value = getattr(target, "value", target)
    if current_value not in _SPECULATION_TRANSITIONS: collector.add("speculation.current_status", "$.current_status", "unknown speculative status")
    elif target_value not in _SPECULATION_TRANSITIONS[current_value]: collector.add("speculation.illegal_transition", "$.status", "speculative ideas cannot skip the candidate state or regress")
    if history is not None:
        values = [getattr(item, "value", item) for item in history]
        if len(values) < 2 or values[0] != SpeculativeStatus.SPECULATIVE.value or values[1] != SpeculativeStatus.CANDIDATE.value or values[-1] != target_value: collector.add("speculation.history", "$.history", "status history must explicitly record speculative -> candidate -> target")
        for previous, next_value in zip(values, values[1:]):
            if next_value not in _SPECULATION_TRANSITIONS.get(previous, set()): collector.add("speculation.history_transition", "$.history", "status history contains an illegal transition")
    return collector.result()


def validate_speculative_idea(value: SpeculativeIdea | Mapping[str, Any], *, history: Sequence[SpeculativeStatus | str] | None = None) -> ValidationResult:
    idea, parse_issues = _safe_as(value, SpeculativeIdea); collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(idea, SpeculativeIdea): collector.add("speculation.type", "$", "idea must be a SpeculativeIdea or strict mapping"); return collector.result()
    if not is_project_id(idea.project_id): collector.add("speculation.project_id", "$.project_id", "project_id is not valid")
    _required_text(collector, idea.run_id, "$.run_id", "speculation.binding_required"); _required_text(collector, idea.source_policy_hash, "$.source_policy_hash", "speculation.binding_required"); _required_text(collector, idea.idea, "$.idea", "speculation.idea_required")
    if idea.status not in {item.value for item in SpeculativeStatus}: collector.add("speculation.status", "$.status", "unknown speculative status")
    if idea.version == 1 and idea.status != SpeculativeStatus.SPECULATIVE.value: collector.add("speculation.v1_status", "$.status", "v1 speculative ideas must start in speculative status")
    if not is_stable_id(idea.idea_id, expected_kind="speculative_idea"): collector.add("speculation.idea_id", "$.idea_id", "idea_id must be stable")
    if not is_stable_id(idea.version_id, expected_kind="speculative_idea-version"): collector.add("speculation.version_id", "$.version_id", "version_id must be stable and versioned")
    try: expected = expected_version_id("speculative_idea", idea.project_id, idea.idea_id, idea.version)
    except (ValueError, TypeError): expected = None
    if expected is not None and idea.version_id != expected: collector.add("speculation.version_binding", "$.version_id", "version_id is not bound to idea identity")
    _id_sequence(collector, idea.supporting_ids, "$.supporting_ids", expected_kind="evidence"); _id_sequence(collector, idea.counterevidence_ids, "$.counterevidence_ids", expected_kind="evidence")
    if idea.version > 1 and not is_stable_id(idea.supersedes_version_id, expected_kind="speculative_idea-version"): collector.add("speculation.successor_required", "$.supersedes_version_id", "later idea versions need a predecessor")
    if history is not None: collector.issues.extend(validate_speculative_transition(idea.status, idea.status, history=history).issues)
    return collector.result()


def strategy_fingerprint(strategy: SearchStrategy | Mapping[str, Any]) -> str:
    value = _as(strategy, SearchStrategy)
    if not isinstance(value, SearchStrategy): raise ContractValidationError("strategy must be a SearchStrategy or mapping")
    return canonical_sha256({"family": unicodedata.normalize("NFC", value.family.strip()).casefold(), "query": unicodedata.normalize("NFC", value.query.strip()).casefold(), "target_ids": sorted(value.target_ids), "filters": value.filters})


def make_claim_snapshot(claim: CanonicalObject | Mapping[str, Any]) -> ClaimSnapshot:
    value = _as(claim, CanonicalObject)
    if not isinstance(value, CanonicalObject) or value.kind != CanonicalObjectKind.CLAIM.value:
        raise ContractValidationError("claim snapshot requires a canonical Claim")
    status = value.payload.get("status")
    if not isinstance(status, str) or not status.strip():
        raise ContractValidationError("claim snapshot requires an explicit canonical claim status")
    return ClaimSnapshot(value.stable_id, value.version_id or "", status.lower(), canonical_sha256({"stable_id": value.stable_id, "version_id": value.version_id, "status": status.lower(), "payload": value.payload}))


def make_evidence_snapshot(evidence: CanonicalObject | Mapping[str, Any]) -> EvidenceSnapshot:
    value = _as(evidence, CanonicalObject)
    if not isinstance(value, CanonicalObject) or value.kind != CanonicalObjectKind.EVIDENCE.value:
        raise ContractValidationError("evidence snapshot requires canonical Evidence")
    status = value.payload.get("status")
    if not isinstance(status, str) or not status.strip():
        raise ContractValidationError("evidence snapshot requires an explicit canonical evidence status")
    return EvidenceSnapshot(value.stable_id, value.version_id or "", status.lower(), canonical_sha256({"stable_id": value.stable_id, "version_id": value.version_id, "status": status.lower(), "payload": value.payload}))


def evaluate_saturation(ledger: Any, *, claim_snapshots: Sequence[ClaimSnapshot] = (), evidence_snapshots: Sequence[EvidenceSnapshot] = (), evidence_saturation_window: int = 2, claim_stability_rounds: int = 2, counterevidence_snapshots: Sequence[EvidenceSnapshot] = ()) -> SaturationStatus:
    if isinstance(ledger, Mapping): ledger = CoverageLedger.from_mapping(ledger)
    if not isinstance(ledger, CoverageLedger): raise ContractValidationError("saturation requires a typed CoverageLedger")
    strategies = tuple(item if isinstance(item, SearchStrategy) else SearchStrategy.from_mapping(item) for item in ledger.strategies)
    required = set(ledger.required_families); seen: dict[str, SearchStrategy] = {}; duplicates: list[str] = []
    for strategy in strategies:
        fingerprint = strategy_fingerprint(strategy)
        if fingerprint in seen: duplicates.append(strategy.strategy_id)
        else: seen[fingerprint] = strategy
    unique = tuple(seen.values()); covered = {strategy.family for strategy in unique}
    strategy_saturated = (not required and ledger.allow_empty_strategy_families) or (bool(required) and required.issubset(covered))
    window = max(1, evidence_saturation_window)
    evidence_saturated = len(unique) >= window and all(not strategy.new_evidence_ids for strategy in unique[-window:]) and bool(evidence_snapshots)
    counter = [strategy for strategy in unique if strategy.family.casefold() in {"counterevidence", "adversarial", "counter"}]
    counterevidence_saturated = bool(counter) and all(not strategy.new_evidence_ids for strategy in counter[-window:]) and bool(counterevidence_snapshots)
    typed_claims = tuple(item if isinstance(item, ClaimSnapshot) else ClaimSnapshot.from_mapping(item) for item in claim_snapshots)
    snapshots = [item.semantic_hash for item in typed_claims]
    rounds = max(1, claim_stability_rounds); claim_stable = len(snapshots) >= rounds and len(set(snapshots[-rounds:])) == 1
    reasons: list[str] = []
    if duplicates: reasons.append("duplicate strategies do not count toward strategy saturation")
    if not strategy_saturated: reasons.append("required strategy families are not covered or empty strategy families were not charter-authorized")
    if not evidence_saturated: reasons.append("recent strategy rounds still add evidence or evidence saturation has no canonical snapshot")
    if not counterevidence_saturated: reasons.append("counterevidence is not saturated")
    if not claim_stable: reasons.append("claim meaning/status has not remained stable for the required rounds")
    return SaturationStatus(evidence_saturated, strategy_saturated, claim_stable, counterevidence_saturated, tuple(sorted(covered)), tuple(sorted(duplicates)), tuple(reasons))


def _validate_attack_records(records: Sequence[AttackRecord], state: ResearchState | None, collector: Any, *, project_id: str, run_id: str, charter_hash_value: str, state_hash: str) -> int:
    count = 0
    if not records: collector.add("completion.attack_records_required", "$.attack_records", "at least one typed AttackRecord is required")
    by_identity, by_version = _index_objects(state.objects) if state is not None else ({}, {})
    for index, record in enumerate(records):
        path = f"$.attack_records[{index}]"
        if not isinstance(record, AttackRecord): collector.add("completion.attack_record_type", path, "attack records must be typed AttackRecord values"); continue
        count += 1
        if record.project_id != project_id or record.run_id != run_id or record.charter_hash != charter_hash_value or record.state_hash != state_hash: collector.add("completion.attack_binding", path, "AttackRecord is not bound to the completion context")
        if not is_stable_id(record.attack_id, expected_kind="attack"): collector.add("completion.attack_id", f"{path}.attack_id", "AttackRecord attack_id is not a stable attack ID")
        if not is_stable_id(record.iteration_id, expected_kind="iteration"): collector.add("completion.attack_iteration", f"{path}.iteration_id", "AttackRecord iteration_id is not a stable iteration ID")
        if not is_stable_id(record.target_id): collector.add("completion.attack_target", f"{path}.target_id", "AttackRecord target_id is invalid")
        if not is_stable_id(record.target_version_id): collector.add("completion.attack_target_version", f"{path}.target_version_id", "AttackRecord target_version_id is invalid")
        _required_text(collector, record.outcome, f"{path}.outcome", "completion.attack_outcome")
        _required_text(collector, record.rationale, f"{path}.rationale", "completion.attack_rationale")
        _id_sequence(collector, record.objection_ids, f"{path}.objection_ids")
        _id_sequence(collector, record.counterevidence_ids, f"{path}.counterevidence_ids")
        if state is not None:
            target = by_version.get(record.target_version_id)
            if target is None or target.stable_id != record.target_id: collector.add("completion.attack_target_state", f"{path}.target_version_id", "AttackRecord target/version is not an exact canonical state endpoint")
            elif target.kind not in {CanonicalObjectKind.CLAIM.value, CanonicalObjectKind.HYPOTHESIS.value}: collector.add("completion.attack_target_kind", f"{path}.target_id", "AttackRecord target must be a Claim or Hypothesis")
            for name, ids in (("objection_ids", record.objection_ids), ("counterevidence_ids", record.counterevidence_ids)):
                for item in ids:
                    if item not in by_identity and item not in by_version: collector.add("completion.attack_orphan", f"{path}.{name}", "AttackRecord contains an orphan canonical ID")
    return count


def _validate_formal_completion_evidence(value: FormalCompletionEvidence, state: ResearchState, report: ReportProjection, collector: Any) -> None:
    if value.project_id != state.project_id or value.run_id != (state.run_id or "") or value.state_hash != state.state_hash: collector.add("completion.formal_binding", "$.formal_completion_evidence", "formal completion evidence is not state-bound")
    if value.report_id != report.report_id or tuple(value.claim_ids) != tuple(report.claim_ids) or tuple(value.evidence_ids) != tuple(report.evidence_ids): collector.add("completion.formal_projection", "$.formal_completion_evidence", "formal completion evidence does not bind the exact final report")
    if canonical_sha256(value.source_links) != canonical_sha256(report.source_links): collector.add("completion.formal_links", "$.formal_completion_evidence.source_links", "formal completion evidence source links differ from final report")
    expected_eligibility_hash = canonical_sha256({"claim_ids": report.claim_ids, "evidence_ids": report.evidence_ids, "source_links": report.source_links})
    if value.evidence_eligibility_hash != expected_eligibility_hash: collector.add("completion.formal_eligibility", "$.formal_completion_evidence.evidence_eligibility_hash", "formal evidence eligibility hash is not recomputable")
    if not is_stable_id(value.record_id, expected_kind="formal_completion_evidence"): collector.add("completion.formal_id", "$.formal_completion_evidence.record_id", "formal completion evidence record ID is invalid")


def _validate_completion_input(value: CompletionEvaluationInput, collector: Any) -> tuple[bool, SaturationStatus | None]:
    state = value.research_state
    context_binding = True
    if value.project_id != state.project_id or value.run_id != (state.run_id or "") or value.state_hash != state.state_hash: collector.add("completion.context_binding", "$", "outer completion context differs from Research State"); context_binding = False
    if value.charter_hash != charter_hash(value.charter): collector.add("completion.charter_hash", "$.charter_hash", "charter_hash is not the canonical Charter hash"); context_binding = False
    if value.run_state.project_id != value.project_id or value.run_state.run_id != value.run_id or value.run_state.charter_hash != value.charter_hash: collector.add("completion.run_binding", "$.run_state", "Run State is not bound to project/run/charter"); context_binding = False
    if value.run_state.current_state_hash != value.state_hash: collector.add("completion.run_state_state", "$.run_state.current_state_hash", "Run State does not bind the supplied Research State"); context_binding = False
    if value.current_checkpoint_id is not None and value.run_state.current_checkpoint_id != value.current_checkpoint_id: collector.add("completion.checkpoint_binding", "$.current_checkpoint_id", "completion checkpoint binding differs from Run State")
    try:
        rebuilt = rebuild_research_state(state.objects, state.relations, project_id=state.project_id, run_id=state.run_id)
        if rebuilt.state_hash != state.state_hash: collector.add("completion.state_recompute", "$.research_state.state_hash", "Research State hash is not the canonical rebuild hash"); context_binding = False
    except (ContractValidationError, ValueError, TypeError) as exc:
        collector.add("completion.state_recompute", "$.research_state", f"Research State cannot be recomputed: {exc}"); context_binding = False
    if value.model_identity != value.charter.model_identity or value.model_identity != value.run_state.model_identity: collector.add("completion.model_binding", "$.model_identity", "model identity does not match Charter and Run State")
    if canonical_sha256(value.budget_snapshot) != canonical_sha256(value.charter.budget) or canonical_sha256(value.budget_snapshot) != canonical_sha256(value.run_state.budget): collector.add("completion.budget_binding", "$.budget_snapshot", "budget snapshot does not match Charter and Run State")
    if canonical_sha256(value.source_policy_snapshot) != canonical_sha256(value.charter.source_policy) or canonical_sha256(value.source_policy_snapshot) != value.run_state.source_policy_hash: collector.add("completion.source_policy_binding", "$.source_policy_snapshot", "source policy snapshot does not match Charter and Run State")
    expected_input_hash = model_to_dict(value); expected_input_hash["input_hash"] = ""
    if value.input_hash != canonical_sha256(expected_input_hash): collector.add("completion.input_hash", "$.input_hash", "completion input hash is not canonical")
    if _parse_time(value.evaluated_at) is None: collector.add("completion.evaluated_at", "$.evaluated_at", "completion evaluation time must be ISO-8601")
    attack_count = _validate_attack_records(value.attack_records, state, collector, project_id=value.project_id, run_id=value.run_id, charter_hash_value=value.charter_hash, state_hash=value.state_hash)
    actual_adjudication = False
    for session in value.discussion_sessions:
        result = validate_discussion_session(session, state=state); collector.issues.extend(result.issues); actual_adjudication = actual_adjudication or result.ok
    if not value.discussion_sessions: collector.add("completion.discussion_required", "$.discussion_sessions", "completion requires at least one state-bound discussion session")
    rehydration_ok = value.rehydration_output.accepted and not value.rehydration_output.drift_flags and value.rehydration_output.state is not None and value.rehydration_output.state.state_hash == value.state_hash
    if not rehydration_ok: collector.add("completion.rehydration_context", "$.rehydration_output", "completion requires an accepted, drift-free rehydration result bound to state")
    report_result = validate_report_projection(value.final_report, state); collector.issues.extend(report_result.issues)
    packet_result = validate_cold_review_packet(value.cold_review_packet, state, expected_charter_hash=value.charter_hash); collector.issues.extend(packet_result.issues)
    cold_result = validate_cold_review_result(value.cold_review_result, value.cold_review_packet, state, report=value.final_report, expected_model_identity=value.model_identity); collector.issues.extend(cold_result.issues)
    if value.cold_review_packet.report_id != value.final_report.report_id: collector.add("completion.cold_report", "$.cold_review_packet.report_id", "cold review packet must bind final report")
    _validate_formal_completion_evidence(value.formal_completion_evidence, state, value.final_report, collector)
    expected_claim_snapshots = tuple(make_claim_snapshot(state.latest_by_id[item]) for item in value.final_report.claim_ids if item in state.latest_by_id)
    if not value.claim_snapshots or any(item not in expected_claim_snapshots for item in value.claim_snapshots): collector.add("completion.claim_snapshots", "$.claim_snapshots", "claim snapshots must be canonical Claim-only snapshots")
    expected_evidence_snapshots = tuple(make_evidence_snapshot(state.latest_by_id[item]) for item in value.final_report.evidence_ids if item in state.latest_by_id)
    if not value.evidence_snapshots or any(item not in expected_evidence_snapshots for item in value.evidence_snapshots): collector.add("completion.evidence_snapshots", "$.evidence_snapshots", "evidence snapshots must be canonical Evidence-only snapshots")
    if not value.counterevidence_snapshots: collector.add("completion.counterevidence_snapshots", "$.counterevidence_snapshots", "counterevidence saturation requires canonical snapshots")
    required_families = tuple(value.charter.quality_gates.get("required_strategy_families", value.charter.quality_gates.get("strategy_families", ())))
    allow_empty = value.allow_empty_strategy_families and bool(value.charter.quality_gates.get("allow_empty_strategy_families"))
    if tuple(value.strategy_ledger.required_families) != required_families: collector.add("completion.strategy_charter_binding", "$.strategy_ledger.required_families", "required strategy families must come from the approved Charter")
    if not required_families and not allow_empty: collector.add("completion.strategy_families_required", "$.charter.quality_gates", "Max completion requires Charter-approved strategy families or an explicit hashed exception")
    saturation = evaluate_saturation(value.strategy_ledger, claim_snapshots=value.claim_snapshots, evidence_snapshots=value.evidence_snapshots, counterevidence_snapshots=value.counterevidence_snapshots)
    return context_binding and not collector.issues, saturation


def evaluate_completion_gate(gate: CompletionEvaluationInput | CompletionGate | Mapping[str, Any]) -> CompletionGateResult:
    if not isinstance(gate, CompletionEvaluationInput):
        return CompletionGateResult(False, ("completion.evaluation_input_required",), {"evaluation_input": False})
    value = gate; collector = issue_collector(); valid_input, saturation = _validate_completion_input(value, collector)
    checks = {
        "evaluation_input": valid_input,
        "attack_records": bool(value.attack_records),
        "discussion": bool(value.discussion_sessions),
        "rehydration": value.rehydration_output.accepted and not value.rehydration_output.drift_flags,
        "final_report": bool(validate_report_projection(value.final_report, value.research_state)),
        "cold_review_packet": bool(validate_cold_review_packet(value.cold_review_packet, value.research_state, expected_charter_hash=value.charter_hash)),
        "cold_review_result": bool(value.cold_review_result.passed and not value.cold_review_result.blocking_findings),
        "strategy_saturated": bool(saturation and saturation.strategy_saturated),
        "evidence_saturated": bool(saturation and saturation.evidence_saturated),
        "counterevidence_saturated": bool(saturation and saturation.counterevidence_saturated),
        "claim_stable": bool(saturation and saturation.claim_stable),
        "formal_completion_evidence": isinstance(value.formal_completion_evidence, FormalCompletionEvidence),
    }
    reasons = [name for name, passed in checks.items() if not passed]
    reasons.extend(issue.code for issue in collector.issues if issue.code not in reasons)
    gate_payload = {"input_hash": value.input_hash, "checks": checks, "reasons": reasons, "project_id": value.project_id, "run_id": value.run_id, "charter_hash": value.charter_hash, "state_hash": value.state_hash, "evaluated_at": value.evaluated_at}
    gate_hash = canonical_sha256(gate_payload)
    return CompletionGateResult(not reasons, tuple(reasons), checks, value.project_id, value.run_id, value.charter_hash, value.state_hash, gate_hash, value.input_hash, value.evaluated_at)


def evaluate_completion_result(value: CompletionEvaluationInput | Mapping[str, Any]) -> CompletionResult:
    input_value = value if isinstance(value, CompletionEvaluationInput) else CompletionEvaluationInput.from_mapping(value)
    gate = evaluate_completion_gate(input_value)
    return CompletionResult(input_value.project_id, input_value.run_id, input_value.charter_hash, input_value.state_hash, gate, input_value.evaluated_at)


def _claim_trace(claim: CanonicalObject, objects: Sequence[CanonicalObject], relations: Sequence[CanonicalRelation]) -> tuple[set[str], set[str], set[str], set[str]]:
    by_identity, by_version = _index_objects(objects); evidence_ids: set[str] = set(); link_ids: set[str] = set(); passage_ids: set[str] = set(); document_ids: set[str] = set()
    link_ids.update(_payload_ids(claim.payload, {"evidence_link_id", "evidence_link_ids"})); link_ids.update(rel.target_id for rel in _live_relations(claim, relations, {RelationKind.HAS_EVIDENCE_LINK.value}))
    for link_id in link_ids:
        link = _resolve_object(link_id, by_identity, by_version)
        if link is None: continue
        for rel in _live_relations(link, relations, {RelationKind.LINKS_EVIDENCE.value}):
            evidence = _relation_target(rel, by_identity, by_version)
            if evidence is None: continue
            evidence_ids.add(evidence.stable_id)
            for passage_rel in _live_relations(evidence, relations, {RelationKind.DERIVED_FROM.value}):
                passage = _relation_target(passage_rel, by_identity, by_version)
                if passage is None: continue
                passage_ids.add(passage.stable_id)
                for document_rel in _live_relations(passage, relations, {RelationKind.LOCATED_IN.value}):
                    document = _relation_target(document_rel, by_identity, by_version)
                    if document is not None: document_ids.add(document.stable_id)
    return evidence_ids, link_ids, passage_ids, document_ids


def _expected_source_links(state: ResearchState, claim_ids: Sequence[str]) -> tuple[Mapping[str, Any], ...]:
    records: list[Mapping[str, Any]] = []
    by_identity, by_version = _index_objects(state.objects)
    for claim_id in claim_ids:
        claim = state.latest_by_id.get(claim_id)
        if claim is None: continue
        link_refs = set(_payload_ids(claim.payload, {"evidence_link_id", "evidence_link_ids"}))
        for relation in _live_relations(claim, state.relations, {RelationKind.HAS_EVIDENCE_LINK.value}):
            target = _relation_target(relation, by_identity, by_version)
            if target is not None: link_refs.add(target.stable_id)
        for link_id in sorted(link_refs):
            link = _resolve_object(link_id, by_identity, by_version)
            if link is None or link.kind != CanonicalObjectKind.EVIDENCE_LINK.value: continue
            for evidence_relation in _live_relations(link, state.relations, {RelationKind.LINKS_EVIDENCE.value}):
                evidence = _relation_target(evidence_relation, by_identity, by_version)
                if evidence is None or evidence.kind != CanonicalObjectKind.EVIDENCE.value: continue
                for passage_relation in _live_relations(evidence, state.relations, {RelationKind.DERIVED_FROM.value}):
                    passage = _relation_target(passage_relation, by_identity, by_version)
                    if passage is None or passage.kind != CanonicalObjectKind.PASSAGE.value: continue
                    for document_relation in _live_relations(passage, state.relations, {RelationKind.LOCATED_IN.value}):
                        document = _relation_target(document_relation, by_identity, by_version)
                        if document is None or document.kind != CanonicalObjectKind.DOCUMENT_VERSION.value: continue
                        record: dict[str, Any] = {
                            "claim_id": claim_id,
                            "evidence_link_id": link.stable_id,
                            "evidence_id": evidence.stable_id,
                            "passage_id": passage.stable_id,
                            "document_version_id": document.stable_id,
                            "document_version_version_id": document.version_id,
                            "project_id": state.project_id,
                        }
                        for key in ("citation_id", "citation_locator"):
                            if key in evidence.payload: record[key] = evidence.payload[key]
                        records.append(record)
    return tuple(sorted(records, key=lambda item: (item["claim_id"], item["evidence_link_id"], item["evidence_id"], item["passage_id"], item["document_version_id"])))


def validate_report_projection(projection: ReportProjection | Mapping[str, Any], state: ResearchState) -> ValidationResult:
    if isinstance(projection, ReportProjection): value = projection; parse_issues: tuple[Any, ...] = ()
    elif isinstance(projection, Mapping):
        try:
            raw = require_mapping_fields(projection, allowed={"project_id", "state_hash", "claim_ids", "evidence_ids", "source_links", "summary", "report_id"}, required={"project_id", "state_hash", "claim_ids", "evidence_ids", "source_links"})
            value = ReportProjection(raw["project_id"], raw["state_hash"], raw["claim_ids"], raw["evidence_ids"], raw["source_links"], raw.get("summary", ""), raw.get("report_id", "")); parse_issues = ()
        except ContractValidationError as exc: value = None; parse_issues = exc.issues
    else: value = None; parse_issues = ()
    collector = issue_collector(); _add_parse_issues(collector, parse_issues)
    if not isinstance(value, ReportProjection): collector.add("report.type", "$", "report projection is invalid"); return collector.result()
    if value.project_id != state.project_id: collector.add("report.cross_project", "$.project_id", "report projection is outside state project")
    if value.state_hash != state.state_hash: collector.add("report.state_hash", "$.state_hash", "report projection does not identify this Research State")
    _id_sequence(collector, value.claim_ids, "$.claim_ids", expected_kind="claim", required=True); _id_sequence(collector, value.evidence_ids, "$.evidence_ids", expected_kind="evidence")
    for claim_id in value.claim_ids:
        claim = state.latest_by_id.get(claim_id)
        if claim is None: collector.add("report.unknown_claim", "$.claim_ids", f"claim {claim_id} is not in Research State")
        else:
            claim_status = claim.payload.get("status")
            if not isinstance(claim_status, str) or claim_status.lower() not in FINAL_CLAIM_STATUSES:
                collector.add("report.claim_status", f"$.claim_ids[{claim_id}]", "final report claims require an explicit final/accepted status")
            collector.issues.extend(validate_claim_evidence_trace(claim, state.objects, state.relations).issues)
    expected_links = _expected_source_links(state, value.claim_ids); expected_evidence = {item["evidence_id"] for item in expected_links}
    if set(value.evidence_ids) != expected_evidence: collector.add("report.evidence_projection", "$.evidence_ids", "report evidence set differs from exact canonical claim trace")
    by_identity, by_version = _index_objects(state.objects)
    for index, link in enumerate(expected_links):
        evidence = by_identity.get(link["evidence_id"])
        if evidence is None: continue
        status = evidence.payload.get("status")
        if not isinstance(status, str) or status.lower() not in FINAL_EVIDENCE_STATUSES:
            collector.add("report.evidence_eligibility", f"$.source_links[{index}]", "final report may project only verified, accepted, or exact-quote-verified Evidence")
        if not is_stable_id(evidence.payload.get("verification_record_id"), expected_kind="verification_record"):
            collector.add("report.verification_record", f"$.source_links[{index}]", "final report evidence must bind a canonical verification record")
    if canonical_sha256(value.source_links) != canonical_sha256(expected_links): collector.add("report.source_links", "$.source_links", "report source_links are fabricated, incomplete, or not the exact canonical projection")
    if not is_stable_id(value.report_id, expected_kind="report"): collector.add("report.id", "$.report_id", "report_id must be a stable report ID")
    return collector.result()


def project_report(state: ResearchState, *, claim_ids: Sequence[str] | None = None, summary: str = "") -> ReportProjection:
    selected = tuple(claim_ids) if claim_ids is not None else tuple(sorted(stable_id for stable_id, obj in state.latest_by_id.items() if obj.kind == CanonicalObjectKind.CLAIM.value))
    if not selected: raise ContractValidationError("report must contain at least one canonical claim")
    for claim_id in selected:
        claim = state.latest_by_id.get(claim_id)
        if claim is None: raise ContractValidationError(f"report claim {claim_id} is not in Research State")
        if not isinstance(claim.payload.get("status"), str) or claim.payload.get("status", "").lower() not in FINAL_CLAIM_STATUSES:
            raise ContractValidationError(f"report claim {claim_id} is not final/accepted")
        validate_claim_evidence_trace(claim, state.objects, state.relations).raise_if_invalid()
    links = _expected_source_links(state, selected); evidence = tuple(sorted({item["evidence_id"] for item in links}))
    projection = ReportProjection(state.project_id, state.state_hash, selected, evidence, links, summary)
    validate_report_projection(projection, state).raise_if_invalid(); return projection


__all__ = [
    "allowed_run_transitions", "approval_is_valid", "charter_hash", "evaluate_completion_gate", "evaluate_completion_result", "evaluate_saturation", "make_claim_snapshot", "make_evidence_snapshot", "make_stable_id", "project_report", "rebuild_research_state", "rehydrate", "require_valid_charter", "should_rehydrate", "source_policy_hash", "strategy_fingerprint", "transition_run_state", "validate_acquisition_request", "validate_approval_consumption", "validate_canonical_object", "validate_canonical_relation", "validate_charter", "validate_checkpoint", "validate_checkpoint_lineage", "validate_claim_evidence_trace", "validate_cold_review_packet", "validate_cold_review_result", "validate_completion_result", "validate_discussion_session", "validate_epistemic_conflict_record", "validate_iteration", "validate_model_identity_binding", "validate_report_projection", "validate_run_state", "validate_start_approval", "validate_speculative_idea", "validate_speculative_transition", "validate_stable_id",
]
