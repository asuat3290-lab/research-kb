"""Pure, immutable contract models for Max Research v1 MR-0A.

The dataclasses are value objects only.  They do not persist data, start
processes, call models, or access the network.  Mapping constructors are
strict: an omitted required field or an unknown field is a contract error,
not an invitation to apply a default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from .base import (
    ContractValidationError,
    canonical_sha256,
    deep_freeze,
    model_to_dict,
    require_mapping_fields,
)
from .ids import (
    make_event_id,
    make_relation_id,
    make_stable_id,
    make_version_id,
    normalize_kind,
)


MAX_RESEARCH_PROTOCOL = "max-research/v1"
CHARTER_SCHEMA = "max-research-charter/v1"
RUN_STATE_SCHEMA = "max-research-run-state/v1"
APPROVAL_SCHEMA = "max-research-start-approval/v1"
CANONICAL_OBJECT_SCHEMA = "max-research-canonical-object/v1"
RELATION_SCHEMA = "max-research-relation/v1"
CHECKPOINT_SCHEMA = "max-research-checkpoint/v1"
WORKING_STATE_SCHEMA = "max-research-working-state/v1"
ITERATION_SCHEMA = "max-research-iteration/v1"
DISCUSSION_SCHEMA = "max-research-discussion/v1"
ACQUISITION_SCHEMA = "max-research-acquisition/v1"
SPECULATION_SCHEMA = "max-research-speculation/v1"
REHYDRATION_SCHEMA = "max-research-rehydration/v1"
COLD_REVIEW_SCHEMA = "max-research-cold-review/v1"
COMPLETION_RESULT_SCHEMA = "max-research-completion-result/v1"
ATTACK_SCHEMA = "max-research-attack-record/v1"
APPROVAL_CONSUMPTION_SCHEMA = "max-research-approval-consumption/v1"
COLD_REVIEW_RESULT_SCHEMA = "max-research-cold-review-result/v1"
COMPLETION_INPUT_SCHEMA = "max-research-completion-evaluation-input/v1"
FORMAL_COMPLETION_EVIDENCE_SCHEMA = "max-research-formal-completion-evidence/v1"
CLAIM_SNAPSHOT_SCHEMA = "max-research-claim-snapshot/v1"
EVIDENCE_SNAPSHOT_SCHEMA = "max-research-evidence-snapshot/v1"
EPISTEMIC_CONFLICT_SCHEMA = "max-research-epistemic-conflict/v1"

COLD_REVIEW_REQUIRED_EXCLUSIONS = (
    "working_summary",
    "recent_summaries",
    "working_interpretation",
    "search_history",
    "search_history_narrative",
    "role_discussion_history",
)
EVIDENCE_STATUSES = frozenset(
    {"candidate", "unverified", "unknown", "verified", "accepted", "rejected", "invalidated", "exact_quote_verified"}
)
FINAL_EVIDENCE_STATUSES = frozenset({"verified", "accepted", "exact_quote_verified"})
FINAL_CLAIM_STATUSES = frozenset({"final", "accepted", "reported", "complete", "completed"})


class _StrEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class RunStatus(_StrEnum):
    AWAITING_START_APPROVAL = "AWAITING_START_APPROVAL"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CanonicalObjectKind(_StrEnum):
    SOURCE = "source"
    DOCUMENT = "document"
    DOCUMENT_VERSION = "document_version"
    PASSAGE = "passage"
    QUOTE = "quote"
    EVIDENCE = "evidence"
    VERIFICATION_RECORD = "verification_record"
    EVIDENCE_LINK = "evidence_link"
    CLAIM = "claim"
    HYPOTHESIS = "hypothesis"
    OBJECTION = "objection"
    ATTACK = "attack"
    RESEARCH_QUESTION = "research_question"
    DECISION = "decision"
    CITATION = "citation"
    SOURCE_ROLE = "source_role"
    REPORT = "report"
    ITERATION = "iteration"
    DISCUSSION_SESSION = "discussion_session"
    ACQUISITION_REQUEST = "acquisition_request"
    SPECULATIVE_IDEA = "speculative_idea"
    CHECKPOINT = "checkpoint"
    WORKING_STATE = "working_state"
    RESEARCH_STATE = "research_state"
    COMPLETION_GATE = "completion_gate"
    START_APPROVAL = "start_approval"
    APPROVAL_CONSUMPTION = "approval_consumption"
    COLD_REVIEW_RESULT = "cold_review_result"
    FORMAL_COMPLETION_EVIDENCE = "formal_completion_evidence"


class RelationKind(_StrEnum):
    SUPPORTS = "supports"
    COUNTERS = "counters"
    HAS_EVIDENCE_LINK = "has_evidence_link"
    LINKS_EVIDENCE = "links_evidence"
    DERIVED_FROM = "derived_from"
    LOCATED_IN = "located_in"
    VERSION_OF = "version_of"
    SUPERSEDES = "supersedes"
    CITES = "cites"
    HAS_SOURCE_ROLE = "has_source_role"
    TARGETS = "targets"
    REQUIRES = "requires"
    PRODUCES = "produces"
    DISCUSSES = "discusses"


class IterationKind(_StrEnum):
    SOCRATIC_EXPLORATION = "socratic_exploration"
    TARGETED_RETRIEVAL = "targeted_retrieval"
    ACQUISITION_REQUEST = "acquisition_request"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    HABERMASIAN_ADJUDICATION = "habermasian_adjudication"
    REHYDRATION_REVIEW = "rehydration_review"
    STATE_UPDATE = "state_update"
    SYNTHESIS = "synthesis"
    COLD_REVIEW = "cold_review"


class AdjudicationValue(_StrEnum):
    REASONED_CONSENSUS = "reasoned_consensus"
    QUALIFIED_CONSENSUS = "qualified_consensus"
    REASONED_DISSENSUS = "reasoned_dissensus"
    UNDERDETERMINED = "underdetermined"
    REJECTED = "rejected"


class SpeculativeStatus(_StrEnum):
    SPECULATIVE = "speculative"
    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    REJECTED = "rejected"


class DriftKind(_StrEnum):
    SUMMARY_ONLY_INHERITANCE = "summary_only_inheritance"
    ORPHAN_CLAIM = "orphan_claim"
    MEANING_DRIFT = "meaning_drift"
    STATUS_DRIFT = "status_drift"
    MISSING_CANONICAL_OBJECT = "missing_canonical_object"
    CROSS_PROJECT_REFERENCE = "cross_project_reference"
    CHECKPOINT_CONTRACT = "checkpoint_contract"
    STALE_RELATION = "stale_relation"
    VERSION_CHAIN_DRIFT = "version_chain_drift"
    SUMMARY_MEANING_DRIFT = "summary_meaning_drift"
    UNEXPECTED_FRONTIER_OBJECT = "unexpected_frontier_object"
    COMPLETION_CONTEXT_DRIFT = "completion_context_drift"


class _Model:
    def to_dict(self) -> dict[str, Any]:
        return model_to_dict(self)

    def as_dict(self) -> dict[str, Any]:
        return self.to_dict()


def _tuple(value: Sequence[Any] | None) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ContractValidationError("contract sequence fields must be lists or tuples")
    return tuple(deep_freeze(item) for item in value)


def _dict(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if value is None:
        return deep_freeze({})
    if not isinstance(value, Mapping):
        raise ContractValidationError("contract mapping fields must be objects")
    return deep_freeze(dict(value))


def _strict(value: Mapping[str, Any], allowed: set[str], required: set[str] = frozenset()) -> Mapping[str, Any]:
    return require_mapping_fields(value, allowed=allowed, required=required)


def _nested_tuple(value: Sequence[Any] | None, converter: Any) -> tuple[Any, ...]:
    return tuple(item if isinstance(item, converter) else converter.from_mapping(item) for item in _tuple(value))


@dataclass(frozen=True)
class MaxResearchCharter(_Model):
    question: str
    scope: Any
    invariants: tuple[str, ...]
    non_goals: tuple[str, ...]
    deliverables: tuple[str, ...]
    model_identity: str
    budget: Mapping[str, Any]
    source_policy: Mapping[str, Any]
    quality_gates: Mapping[str, Any]
    protocol_version: str = MAX_RESEARCH_PROTOCOL
    schema: str = CHARTER_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", deep_freeze(self.scope))
        object.__setattr__(self, "invariants", _tuple(self.invariants))
        object.__setattr__(self, "non_goals", _tuple(self.non_goals))
        object.__setattr__(self, "deliverables", _tuple(self.deliverables))
        object.__setattr__(self, "budget", _dict(self.budget))
        object.__setattr__(self, "source_policy", _dict(self.source_policy))
        object.__setattr__(self, "quality_gates", _dict(self.quality_gates))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "MaxResearchCharter":
        raw = _strict(
            value,
            {"question", "scope", "invariants", "non_goals", "deliverables", "model_identity", "budget", "source_policy", "quality_gates", "protocol_version", "schema"},
            {"question", "scope", "invariants", "non_goals", "deliverables", "model_identity", "budget", "source_policy", "quality_gates"},
        )
        return cls(
            question=raw["question"], scope=raw["scope"], invariants=raw["invariants"],
            non_goals=raw["non_goals"], deliverables=raw["deliverables"],
            model_identity=raw["model_identity"], budget=raw["budget"],
            source_policy=raw["source_policy"], quality_gates=raw["quality_gates"],
            protocol_version=raw.get("protocol_version", MAX_RESEARCH_PROTOCOL),
            schema=raw.get("schema", CHARTER_SCHEMA),
        )


@dataclass(frozen=True)
class StartApproval(_Model):
    run_id: str
    project_id: str
    charter_hash: str
    model_identity: str
    budget: Mapping[str, Any]
    source_policy_hash: str
    approval_id: str = ""
    decision: str = ""
    approved_by: str = ""
    approved_at: str = ""
    decision_authority: str = ""
    expires_at: str | None = None
    consumed_at: str | None = None
    schema: str = APPROVAL_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "budget", _dict(self.budget))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "StartApproval":
        raw = _strict(
            value,
            {"run_id", "project_id", "charter_hash", "model_identity", "budget", "source_policy_hash", "approval_id", "decision", "approved_by", "approved_at", "decision_authority", "expires_at", "consumed_at", "schema"},
            {"run_id", "project_id", "charter_hash", "model_identity", "budget", "source_policy_hash", "approval_id", "decision", "approved_by", "approved_at", "decision_authority"},
        )
        return cls(
            run_id=raw["run_id"], project_id=raw["project_id"], charter_hash=raw["charter_hash"],
            model_identity=raw["model_identity"], budget=raw["budget"],
            source_policy_hash=raw["source_policy_hash"], approval_id=raw["approval_id"],
            decision=raw["decision"], approved_by=raw["approved_by"], approved_at=raw["approved_at"],
            decision_authority=raw["decision_authority"], expires_at=raw.get("expires_at"),
            consumed_at=raw.get("consumed_at"), schema=raw.get("schema", APPROVAL_SCHEMA),
        )


@dataclass(frozen=True)
class MaxRunState(_Model):
    run_id: str
    project_id: str
    status: RunStatus | str = RunStatus.AWAITING_START_APPROVAL
    charter_hash: str = ""
    model_identity: str = ""
    budget: Mapping[str, Any] = field(default_factory=dict)
    source_policy_hash: str = ""
    approval_id: str | None = None
    iteration_index: int = 0
    state_version: int = 1
    approval_consumed_at: str | None = None
    completion_result_id: str | None = None
    completion_state_hash: str | None = None
    schema: str = RUN_STATE_SCHEMA
    current_state_hash: str | None = None
    current_checkpoint_id: str | None = None
    approval_consumption_id: str | None = None
    budget_snapshot_hash: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "budget", _dict(self.budget))
        if isinstance(self.status, str):
            try:
                object.__setattr__(self, "status", RunStatus(self.status))
            except ValueError:
                pass

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "MaxRunState":
        raw = _strict(
            value,
            {"run_id", "project_id", "status", "charter_hash", "model_identity", "budget", "source_policy_hash", "approval_id", "iteration_index", "state_version", "approval_consumed_at", "completion_result_id", "completion_state_hash", "schema", "current_state_hash", "current_checkpoint_id", "approval_consumption_id", "budget_snapshot_hash"},
            {"run_id", "project_id", "status", "charter_hash", "model_identity", "budget", "source_policy_hash", "iteration_index", "state_version"},
        )
        return cls(
            run_id=raw["run_id"], project_id=raw["project_id"], status=raw["status"],
            charter_hash=raw["charter_hash"], model_identity=raw["model_identity"], budget=raw["budget"],
            source_policy_hash=raw["source_policy_hash"], approval_id=raw.get("approval_id"),
            iteration_index=raw["iteration_index"], state_version=raw["state_version"],
            approval_consumed_at=raw.get("approval_consumed_at"),
            completion_result_id=raw.get("completion_result_id"),
            completion_state_hash=raw.get("completion_state_hash"), schema=raw.get("schema", RUN_STATE_SCHEMA),
            current_state_hash=raw.get("current_state_hash"), current_checkpoint_id=raw.get("current_checkpoint_id"),
            approval_consumption_id=raw.get("approval_consumption_id"), budget_snapshot_hash=raw.get("budget_snapshot_hash"),
        )


@dataclass(frozen=True)
class ApprovalConsumption(_Model):
    approval_id: str
    project_id: str
    run_id: str
    charter_hash: str
    prior_state_version: int
    consumed_at: str
    resulting_state_version: int
    consumption_id: str = ""
    schema: str = APPROVAL_CONSUMPTION_SCHEMA

    def __post_init__(self) -> None:
        if not self.consumption_id:
            object.__setattr__(
                self,
                "consumption_id",
                make_event_id(
                    "approval_consumption",
                    self.project_id,
                    {
                        "approval_id": self.approval_id,
                        "run_id": self.run_id,
                        "charter_hash": self.charter_hash,
                        "prior_state_version": self.prior_state_version,
                        "consumed_at": self.consumed_at,
                        "resulting_state_version": self.resulting_state_version,
                    },
                ),
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ApprovalConsumption":
        raw = _strict(
            value,
            {"approval_id", "project_id", "run_id", "charter_hash", "prior_state_version", "consumed_at", "resulting_state_version", "consumption_id", "schema"},
            {"approval_id", "project_id", "run_id", "charter_hash", "prior_state_version", "consumed_at", "resulting_state_version"},
        )
        return cls(
            raw["approval_id"], raw["project_id"], raw["run_id"], raw["charter_hash"],
            raw["prior_state_version"], raw["consumed_at"], raw["resulting_state_version"],
            raw.get("consumption_id", ""), raw.get("schema", APPROVAL_CONSUMPTION_SCHEMA),
        )


@dataclass(frozen=True)
class RunTransitionResult(_Model):
    new_state: MaxRunState | Mapping[str, Any]
    approval_consumption: ApprovalConsumption | Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.new_state, MaxRunState):
            object.__setattr__(self, "new_state", MaxRunState.from_mapping(self.new_state))
        if self.approval_consumption is not None and not isinstance(self.approval_consumption, ApprovalConsumption):
            object.__setattr__(self, "approval_consumption", ApprovalConsumption.from_mapping(self.approval_consumption))

    def __getattr__(self, name: str) -> Any:
        # Compatibility for MR-0A callers while making the consumption record
        # explicit and serializable in MR-0B.
        return getattr(self.new_state, name)


@dataclass(frozen=True)
class CanonicalRef(_Model):
    stable_id: str
    project_id: str
    kind: str | None = None
    version_id: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CanonicalRef":
        raw = _strict(value, {"stable_id", "id", "project_id", "kind", "version_id"}, {"project_id"})
        return cls(stable_id=raw.get("stable_id", raw.get("id", "")), project_id=raw["project_id"], kind=raw.get("kind"), version_id=raw.get("version_id"))


@dataclass(frozen=True)
class CanonicalObject(_Model):
    stable_id: str
    kind: CanonicalObjectKind | str
    project_id: str
    version: int = 1
    version_id: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)
    supersedes_version_id: str | None = None
    schema: str = CANONICAL_OBJECT_SCHEMA

    def __post_init__(self) -> None:
        normalized = normalize_kind(self.kind)
        object.__setattr__(self, "kind", normalized)
        object.__setattr__(self, "version_id", self.version_id or make_version_id(normalized, self.project_id, self.stable_id, self.version))
        object.__setattr__(self, "payload", _dict(self.payload))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CanonicalObject":
        raw = _strict(value, {"stable_id", "id", "kind", "project_id", "version", "version_id", "payload", "supersedes_version_id", "supersedes_id", "schema"}, {"stable_id", "kind", "project_id", "payload"})
        return cls(
            stable_id=raw.get("stable_id", raw.get("id", "")), kind=raw["kind"], project_id=raw["project_id"],
            version=raw.get("version", 1), version_id=raw.get("version_id"), payload=raw["payload"],
            supersedes_version_id=raw.get("supersedes_version_id", raw.get("supersedes_id")), schema=raw.get("schema", CANONICAL_OBJECT_SCHEMA),
        )


@dataclass(frozen=True)
class CanonicalRelation(_Model):
    source_id: str
    target_id: str
    relation: RelationKind | str
    project_id: str
    relation_id: str = ""
    source_version_id: str | None = None
    target_version_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema: str = RELATION_SCHEMA

    def __post_init__(self) -> None:
        relation_value = getattr(self.relation, "value", self.relation)
        object.__setattr__(self, "relation", relation_value)
        object.__setattr__(self, "relation_id", self.relation_id or make_relation_id(self.project_id, self.source_id, self.target_id, relation_value, self.source_version_id, self.target_version_id))
        object.__setattr__(self, "metadata", _dict(self.metadata))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CanonicalRelation":
        raw = _strict(value, {"source_id", "from_id", "target_id", "to_id", "relation", "project_id", "relation_id", "source_version_id", "target_version_id", "metadata", "schema"}, {"source_id", "target_id", "project_id", "relation"})
        return cls(
            source_id=raw.get("source_id", raw.get("from_id", "")), target_id=raw.get("target_id", raw.get("to_id", "")),
            relation=raw["relation"], project_id=raw["project_id"], relation_id=raw.get("relation_id", ""),
            source_version_id=raw.get("source_version_id"), target_version_id=raw.get("target_version_id"), metadata=raw.get("metadata", {}), schema=raw.get("schema", RELATION_SCHEMA),
        )


@dataclass(frozen=True)
class WorkingState(_Model):
    project_id: str
    run_id: str
    iteration_index: int
    budget_remaining: Mapping[str, Any] = field(default_factory=dict)
    canonical_object_ids: tuple[str, ...] = ()
    claim_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    active_leading_hypothesis_id: str | None = None
    search_strategy_ids: tuple[str, ...] = ()
    pending_questions: tuple[str, ...] = ()
    unresolved_issue_ids: tuple[str, ...] = ()
    summary: str = ""
    schema: str = WORKING_STATE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "budget_remaining", _dict(self.budget_remaining))
        for name in ("canonical_object_ids", "claim_ids", "evidence_ids", "search_strategy_ids", "pending_questions", "unresolved_issue_ids"):
            object.__setattr__(self, name, _tuple(getattr(self, name)))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WorkingState":
        raw = _strict(value, {"project_id", "run_id", "iteration_index", "budget_remaining", "budget", "canonical_object_ids", "claim_ids", "evidence_ids", "active_leading_hypothesis_id", "search_strategy_ids", "pending_questions", "unresolved_issue_ids", "summary", "schema"}, {"project_id", "run_id", "iteration_index", "canonical_object_ids"})
        return cls(
            project_id=raw["project_id"], run_id=raw["run_id"], iteration_index=raw["iteration_index"], budget_remaining=raw.get("budget_remaining", raw.get("budget", {})),
            canonical_object_ids=raw["canonical_object_ids"], claim_ids=raw.get("claim_ids", ()), evidence_ids=raw.get("evidence_ids", ()), active_leading_hypothesis_id=raw.get("active_leading_hypothesis_id"), search_strategy_ids=raw.get("search_strategy_ids", ()), pending_questions=raw.get("pending_questions", ()), unresolved_issue_ids=raw.get("unresolved_issue_ids", ()), summary=raw.get("summary", ""), schema=raw.get("schema", WORKING_STATE_SCHEMA),
        )


@dataclass(frozen=True)
class Checkpoint(_Model):
    project_id: str
    run_id: str
    working_state: WorkingState | Mapping[str, Any]
    budget: Mapping[str, Any]
    iteration_pointer: int
    canonical_ids: tuple[str, ...]
    checkpoint_id: str = ""
    supersedes_item_id: str | None = None
    created_at: str | None = None
    checkpoint_version: int = 1
    frontier_extension_ids: tuple[str, ...] = ()
    schema: str = CHECKPOINT_SCHEMA

    def __post_init__(self) -> None:
        if not isinstance(self.working_state, WorkingState):
            object.__setattr__(self, "working_state", WorkingState.from_mapping(self.working_state))
        object.__setattr__(self, "budget", _dict(self.budget))
        object.__setattr__(self, "canonical_ids", _tuple(self.canonical_ids))
        object.__setattr__(self, "frontier_extension_ids", _tuple(self.frontier_extension_ids))
        if not self.checkpoint_id:
            object.__setattr__(self, "checkpoint_id", make_event_id("checkpoint", self.project_id, {"run_id": self.run_id, "iteration": self.iteration_pointer, "canonical_ids": sorted(self.canonical_ids)}))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Checkpoint":
        raw = _strict(value, {"project_id", "run_id", "working_state", "budget", "iteration_pointer", "canonical_ids", "checkpoint_id", "item_id", "supersedes_item_id", "created_at", "checkpoint_version", "frontier_extension_ids", "schema"}, {"project_id", "run_id", "working_state", "budget", "iteration_pointer", "canonical_ids"})
        return cls(project_id=raw["project_id"], run_id=raw["run_id"], working_state=raw["working_state"], budget=raw["budget"], iteration_pointer=raw["iteration_pointer"], canonical_ids=raw["canonical_ids"], checkpoint_id=raw.get("checkpoint_id", raw.get("item_id", "")), supersedes_item_id=raw.get("supersedes_item_id"), created_at=raw.get("created_at"), checkpoint_version=raw.get("checkpoint_version", 1), frontier_extension_ids=raw.get("frontier_extension_ids", ()), schema=raw.get("schema", CHECKPOINT_SCHEMA))


@dataclass(frozen=True)
class ResearchState(_Model):
    project_id: str
    run_id: str | None
    objects: tuple[CanonicalObject, ...]
    relations: tuple[CanonicalRelation, ...]
    latest_by_id: Mapping[str, CanonicalObject]
    active_leading_hypothesis_id: str | None
    state_hash: str
    materialized_fields: tuple[str, ...] = ("latest_by_id", "active_leading_hypothesis_id", "state_hash")

    def __post_init__(self) -> None:
        object.__setattr__(self, "objects", tuple(self.objects))
        object.__setattr__(self, "relations", tuple(self.relations))
        object.__setattr__(self, "latest_by_id", _dict(self.latest_by_id))
        object.__setattr__(self, "materialized_fields", _tuple(self.materialized_fields))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ResearchState":
        raw = _strict(value, {"project_id", "run_id", "objects", "relations", "latest_by_id", "active_leading_hypothesis_id", "state_hash", "materialized_fields"}, {"project_id", "objects", "relations", "latest_by_id", "active_leading_hypothesis_id", "state_hash"})
        objects = tuple(CanonicalObject.from_mapping(item) if not isinstance(item, CanonicalObject) else item for item in raw["objects"])
        relations = tuple(CanonicalRelation.from_mapping(item) if not isinstance(item, CanonicalRelation) else item for item in raw["relations"])
        latest_raw = raw["latest_by_id"]
        latest = {key: CanonicalObject.from_mapping(item) if not isinstance(item, CanonicalObject) else item for key, item in latest_raw.items()}
        return cls(raw["project_id"], raw.get("run_id"), objects, relations, latest, raw["active_leading_hypothesis_id"], raw["state_hash"], raw.get("materialized_fields", ("latest_by_id", "active_leading_hypothesis_id", "state_hash")))


@dataclass(frozen=True)
class RehydrationInput(_Model):
    project_id: str
    run_id: str
    checkpoint: Checkpoint | Mapping[str, Any]
    canonical_objects: tuple[CanonicalObject, ...]
    relations: tuple[CanonicalRelation, ...]
    working_summary: Mapping[str, Any] | None = None
    prior_state: ResearchState | None = None
    iteration_index: int | None = None
    events: tuple[str, ...] = ()
    policy: "RehydrationPolicy | Mapping[str, Any] | None" = None

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint, Checkpoint):
            object.__setattr__(self, "checkpoint", Checkpoint.from_mapping(self.checkpoint))
        object.__setattr__(self, "canonical_objects", tuple(self.canonical_objects))
        object.__setattr__(self, "relations", tuple(self.relations))
        object.__setattr__(self, "working_summary", _dict(self.working_summary) if self.working_summary is not None else None)
        object.__setattr__(self, "events", _tuple(self.events))
        if self.policy is not None and not isinstance(self.policy, RehydrationPolicy):
            object.__setattr__(self, "policy", RehydrationPolicy.from_mapping(self.policy))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RehydrationInput":
        raw = _strict(value, {"project_id", "run_id", "checkpoint", "canonical_objects", "relations", "working_summary", "prior_state", "iteration_index", "events", "policy"}, {"project_id", "run_id", "checkpoint", "canonical_objects", "relations"})
        return cls(raw["project_id"], raw["run_id"], raw["checkpoint"], tuple(raw["canonical_objects"]), tuple(raw["relations"]), raw.get("working_summary"), raw.get("prior_state"), raw.get("iteration_index"), raw.get("events", ()), raw.get("policy"))


@dataclass(frozen=True)
class RehydrationOutput(_Model):
    accepted: bool
    state: ResearchState | None
    drift_flags: tuple[DriftKind | str, ...] = ()
    issues: tuple[Mapping[str, Any], ...] = ()
    canonical_object_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "drift_flags", _tuple(self.drift_flags))
        object.__setattr__(self, "issues", tuple(_dict(item) for item in self.issues))
        object.__setattr__(self, "canonical_object_ids", _tuple(self.canonical_object_ids))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RehydrationOutput":
        raw = _strict(value, {"accepted", "state", "drift_flags", "issues", "canonical_object_ids"}, {"accepted", "state"})
        state = raw.get("state")
        if isinstance(state, Mapping):
            state = ResearchState.from_mapping(state)
        return cls(raw["accepted"], state, raw.get("drift_flags", ()), raw.get("issues", ()), raw.get("canonical_object_ids", ()))


@dataclass(frozen=True)
class RehydrationPolicy(_Model):
    interval_iterations: int = 12
    triggers: tuple[str, ...] = ("leading_hypothesis_changed", "major_counterevidence", "recovery", "before_completion")
    schema: str = REHYDRATION_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "triggers", _tuple(self.triggers))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RehydrationPolicy":
        raw = _strict(value, {"interval_iterations", "triggers", "schema"}, set())
        return cls(interval_iterations=raw.get("interval_iterations", 12), triggers=raw.get("triggers", ("leading_hypothesis_changed", "major_counterevidence", "recovery", "before_completion")), schema=raw.get("schema", REHYDRATION_SCHEMA))


@dataclass(frozen=True)
class Iteration(_Model):
    project_id: str
    run_id: str
    sequence: int
    kind: IterationKind | str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    canonical_object_ids: tuple[str, ...] = ()
    status: str = "completed"
    iteration_id: str = ""
    schema: str = ITERATION_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", getattr(self.kind, "value", self.kind))
        object.__setattr__(self, "inputs", _tuple(self.inputs))
        object.__setattr__(self, "outputs", _tuple(self.outputs))
        object.__setattr__(self, "canonical_object_ids", _tuple(self.canonical_object_ids))
        object.__setattr__(self, "iteration_id", self.iteration_id or make_event_id("iteration", self.project_id, {"run_id": self.run_id, "sequence": self.sequence, "kind": self.kind}))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Iteration":
        raw = _strict(value, {"project_id", "run_id", "sequence", "kind", "inputs", "outputs", "canonical_object_ids", "status", "iteration_id", "schema"}, {"project_id", "run_id", "sequence", "kind"})
        return cls(raw["project_id"], raw["run_id"], raw["sequence"], raw["kind"], raw.get("inputs", ()), raw.get("outputs", ()), raw.get("canonical_object_ids", ()), raw.get("status", "completed"), raw.get("iteration_id", ""), raw.get("schema", ITERATION_SCHEMA))


@dataclass(frozen=True)
class RolePosition(_Model):
    role: str
    position: str
    canonical_claim_ids: tuple[str, ...] = ()
    canonical_evidence_ids: tuple[str, ...] = ()
    rationale: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "canonical_claim_ids", _tuple(self.canonical_claim_ids))
        object.__setattr__(self, "canonical_evidence_ids", _tuple(self.canonical_evidence_ids))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RolePosition":
        raw = _strict(value, {"role", "position", "canonical_claim_ids", "canonical_evidence_ids", "rationale"}, {"role", "position"})
        return cls(raw["role"], raw["position"], raw.get("canonical_claim_ids", ()), raw.get("canonical_evidence_ids", ()), raw.get("rationale", ""))


@dataclass(frozen=True)
class RolePacket(_Model):
    project_id: str
    run_id: str
    state_hash: str
    target_id: str
    role: str
    allowed_canonical_ids: tuple[str, ...]
    model_identity: str
    inference_profile_hash: str
    forbidden_output_ids: tuple[str, ...] = ()
    sees_other_role_outputs: bool = False
    packet_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_canonical_ids", _tuple(self.allowed_canonical_ids))
        object.__setattr__(self, "forbidden_output_ids", _tuple(self.forbidden_output_ids))
        if not self.packet_id:
            object.__setattr__(self, "packet_id", make_event_id("role_packet", self.project_id, {"run_id": self.run_id, "state_hash": self.state_hash, "target_id": self.target_id, "role": self.role, "allowed": sorted(self.allowed_canonical_ids), "model": self.model_identity, "inference": self.inference_profile_hash}))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RolePacket":
        raw = _strict(value, {"project_id", "run_id", "state_hash", "target_id", "role", "allowed_canonical_ids", "model_identity", "inference_profile_hash", "forbidden_output_ids", "sees_other_role_outputs", "packet_id"}, {"project_id", "run_id", "state_hash", "target_id", "role", "allowed_canonical_ids", "model_identity", "inference_profile_hash"})
        return cls(raw["project_id"], raw["run_id"], raw["state_hash"], raw["target_id"], raw["role"], raw["allowed_canonical_ids"], raw["model_identity"], raw["inference_profile_hash"], raw.get("forbidden_output_ids", ()), raw.get("sees_other_role_outputs", False), raw.get("packet_id", ""))


@dataclass(frozen=True)
class CrossExamination(_Model):
    examiner_role: str
    respondent_role: str
    question: str
    answer: str
    challenged_claim_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "challenged_claim_ids", _tuple(self.challenged_claim_ids))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CrossExamination":
        raw = _strict(value, {"examiner_role", "respondent_role", "question", "answer", "challenged_claim_ids"}, {"examiner_role", "respondent_role", "question", "answer"})
        return cls(raw["examiner_role"], raw["respondent_role"], raw["question"], raw["answer"], raw.get("challenged_claim_ids", ()))


@dataclass(frozen=True)
class CorrectionPosition(_Model):
    role: str
    correction: str
    corrected_claim_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "corrected_claim_ids", _tuple(self.corrected_claim_ids))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CorrectionPosition":
        raw = _strict(value, {"role", "correction", "corrected_claim_ids"}, {"role", "correction"})
        return cls(raw["role"], raw["correction"], raw.get("corrected_claim_ids", ()))


@dataclass(frozen=True)
class ValidityAudit(_Model):
    auditor_role: str
    passed: bool
    findings: tuple[str, ...] = ()
    audited_claim_ids: tuple[str, ...] = ()
    facts_evidence_true: bool | None = None
    normative_valid: bool | None = None
    expression_clear: bool | None = None
    role_fidelity: bool | None = None
    rationale: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", _tuple(self.findings))
        object.__setattr__(self, "audited_claim_ids", _tuple(self.audited_claim_ids))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ValidityAudit":
        raw = _strict(value, {"auditor_role", "passed", "findings", "audited_claim_ids", "facts_evidence_true", "normative_valid", "expression_clear", "role_fidelity", "rationale"}, {"auditor_role", "passed", "facts_evidence_true", "normative_valid", "expression_clear", "role_fidelity"})
        return cls(raw["auditor_role"], raw["passed"], raw.get("findings", ()), raw.get("audited_claim_ids", ()), raw["facts_evidence_true"], raw["normative_valid"], raw["expression_clear"], raw["role_fidelity"], raw.get("rationale", ""))


@dataclass(frozen=True)
class MinorityReport(_Model):
    role: str
    position: str
    preserved_reason: str
    canonical_claim_ids: tuple[str, ...] = ()
    report_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "canonical_claim_ids", _tuple(self.canonical_claim_ids))
        if not self.report_id:
            object.__setattr__(self, "report_id", make_stable_id("report", canonical_sha256({"role": self.role, "position": self.position, "reason": self.preserved_reason, "claims": sorted(self.canonical_claim_ids)})[:48]))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "MinorityReport":
        raw = _strict(value, {"role", "position", "preserved_reason", "canonical_claim_ids", "report_id"}, {"role", "position", "preserved_reason"})
        return cls(raw["role"], raw["position"], raw["preserved_reason"], raw.get("canonical_claim_ids", ()), raw.get("report_id", ""))


@dataclass(frozen=True)
class Adjudication(_Model):
    value: AdjudicationValue | str
    rationale: str
    rival_ids: tuple[str, ...] = ()
    canonical_evidence_ids: tuple[str, ...] = ()
    minority_report_ids: tuple[str, ...] = ()
    adjudicator_role: str = "adjudicator"

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", getattr(self.value, "value", self.value))
        object.__setattr__(self, "rival_ids", _tuple(self.rival_ids))
        object.__setattr__(self, "canonical_evidence_ids", _tuple(self.canonical_evidence_ids))
        object.__setattr__(self, "minority_report_ids", _tuple(self.minority_report_ids))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Adjudication":
        raw = _strict(value, {"value", "rationale", "rival_ids", "canonical_evidence_ids", "minority_report_ids", "adjudicator_role"}, {"value", "rationale"})
        return cls(raw["value"], raw["rationale"], raw.get("rival_ids", ()), raw.get("canonical_evidence_ids", ()), raw.get("minority_report_ids", ()), raw.get("adjudicator_role", "adjudicator"))


@dataclass(frozen=True)
class DiscussionSession(_Model):
    project_id: str
    run_id: str
    target_id: str
    independent_positions: tuple[RolePosition, ...]
    cross_examinations: tuple[CrossExamination, ...] = ()
    corrections: tuple[CorrectionPosition, ...] = ()
    validity_audits: tuple[ValidityAudit, ...] = ()
    adjudication: Adjudication | None = None
    minority_reports: tuple[MinorityReport, ...] = ()
    session_id: str = ""
    state_hash: str = ""
    model_identity: str = ""
    inference_profile_hash: str = ""
    role_packets: tuple[RolePacket, ...] = ()
    schema: str = DISCUSSION_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "independent_positions", _nested_tuple(self.independent_positions, RolePosition))
        object.__setattr__(self, "cross_examinations", _nested_tuple(self.cross_examinations, CrossExamination))
        object.__setattr__(self, "corrections", _nested_tuple(self.corrections, CorrectionPosition))
        object.__setattr__(self, "validity_audits", _nested_tuple(self.validity_audits, ValidityAudit))
        object.__setattr__(self, "minority_reports", _nested_tuple(self.minority_reports, MinorityReport))
        object.__setattr__(self, "role_packets", _nested_tuple(self.role_packets, RolePacket))
        if not self.session_id:
            object.__setattr__(self, "session_id", make_event_id("discussion_session", self.project_id, {"run_id": self.run_id, "target_id": self.target_id, "state_hash": self.state_hash, "roles": sorted(position.role for position in self.independent_positions)}))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DiscussionSession":
        raw = _strict(value, {"project_id", "run_id", "target_id", "independent_positions", "cross_examinations", "corrections", "validity_audits", "adjudication", "minority_reports", "session_id", "state_hash", "model_identity", "inference_profile_hash", "role_packets", "schema"}, {"project_id", "run_id", "target_id", "independent_positions", "state_hash", "model_identity", "inference_profile_hash", "role_packets"})
        adjudication = raw.get("adjudication")
        if adjudication is not None and not isinstance(adjudication, Adjudication):
            adjudication = Adjudication.from_mapping(adjudication)
        return cls(project_id=raw["project_id"], run_id=raw["run_id"], target_id=raw["target_id"], independent_positions=tuple(RolePosition.from_mapping(item) if not isinstance(item, RolePosition) else item for item in raw["independent_positions"]), cross_examinations=tuple(CrossExamination.from_mapping(item) if not isinstance(item, CrossExamination) else item for item in raw.get("cross_examinations", ())), corrections=tuple(CorrectionPosition.from_mapping(item) if not isinstance(item, CorrectionPosition) else item for item in raw.get("corrections", ())), validity_audits=tuple(ValidityAudit.from_mapping(item) if not isinstance(item, ValidityAudit) else item for item in raw.get("validity_audits", ())), adjudication=adjudication, minority_reports=tuple(MinorityReport.from_mapping(item) if not isinstance(item, MinorityReport) else item for item in raw.get("minority_reports", ())), session_id=raw.get("session_id", ""), state_hash=raw["state_hash"], model_identity=raw["model_identity"], inference_profile_hash=raw["inference_profile_hash"], role_packets=tuple(RolePacket.from_mapping(item) if not isinstance(item, RolePacket) else item for item in raw["role_packets"]), schema=raw.get("schema", DISCUSSION_SCHEMA))


@dataclass(frozen=True)
class EpistemicConflictRecord(_Model):
    """Typed, non-mentalistic record of a proposal/evidence conflict."""

    project_id: str
    run_id: str
    iteration_id: str
    logical_call_id: str
    intent_hash: str
    request_hash: str
    proposal_hash: str
    validator_hash: str
    canonical_state_hash: str
    canonical_version_hashes: tuple[str, ...]
    issue_codes: tuple[str, ...]
    conflict_type: str
    canonical_basis: Mapping[str, Any]
    fingerprint: str
    repeat_count: int
    resolution: str
    actor_id: str
    created_at: str
    conflict_id: str = ""
    schema: str = EPISTEMIC_CONFLICT_SCHEMA

    def __post_init__(self) -> None:
        for name in ("project_id", "run_id", "iteration_id", "logical_call_id", "intent_hash", "request_hash", "proposal_hash", "validator_hash", "canonical_state_hash", "conflict_type", "fingerprint", "resolution", "actor_id", "created_at"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ContractValidationError(f"epistemic conflict {name} is required")
        object.__setattr__(self, "canonical_version_hashes", tuple(str(item) for item in self.canonical_version_hashes))
        object.__setattr__(self, "issue_codes", tuple(str(item) for item in self.issue_codes))
        object.__setattr__(self, "canonical_basis", deep_freeze(dict(self.canonical_basis)))
        if isinstance(self.repeat_count, bool) or not isinstance(self.repeat_count, int) or self.repeat_count < 1:
            raise ContractValidationError("epistemic conflict repeat_count is invalid")
        if self.resolution not in {"rejected", "rehydration_required", "paused", "resolved"}:
            raise ContractValidationError("epistemic conflict resolution is invalid")
        expected_id = self.conflict_id or make_event_id("epistemic_conflict", self.project_id, {"run_id": self.run_id, "fingerprint": self.fingerprint, "repeat_count": self.repeat_count})
        object.__setattr__(self, "conflict_id", expected_id)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EpistemicConflictRecord":
        raw = require_mapping_fields(value, allowed={"project_id", "run_id", "iteration_id", "logical_call_id", "intent_hash", "request_hash", "proposal_hash", "validator_hash", "canonical_state_hash", "canonical_version_hashes", "issue_codes", "conflict_type", "canonical_basis", "fingerprint", "repeat_count", "resolution", "actor_id", "created_at", "conflict_id", "schema"}, required={"project_id", "run_id", "iteration_id", "logical_call_id", "intent_hash", "request_hash", "proposal_hash", "validator_hash", "canonical_state_hash", "canonical_version_hashes", "issue_codes", "conflict_type", "canonical_basis", "fingerprint", "repeat_count", "resolution", "actor_id", "created_at"})
        return cls(raw["project_id"], raw["run_id"], raw["iteration_id"], raw["logical_call_id"], raw["intent_hash"], raw["request_hash"], raw["proposal_hash"], raw["validator_hash"], raw["canonical_state_hash"], tuple(raw["canonical_version_hashes"]), tuple(raw["issue_codes"]), raw["conflict_type"], raw["canonical_basis"], raw["fingerprint"], raw["repeat_count"], raw["resolution"], raw["actor_id"], raw["created_at"], raw.get("conflict_id", ""), raw.get("schema", EPISTEMIC_CONFLICT_SCHEMA))


@dataclass(frozen=True)
class AcquisitionRequest(_Model):
    project_id: str
    research_gap: str
    target_ids: tuple[str, ...]
    why_needed: str
    expected_information_gain: Any
    possible_falsification: tuple[str, ...]
    desired_source_role: str
    preferred_types: tuple[str, ...] = ()
    preferred_languages: tuple[str, ...] = ()
    preferred_date_range: Mapping[str, Any] = field(default_factory=dict)
    exclusions: tuple[str, ...] = ()
    max_candidates: int = 10
    request_id: str = ""
    run_id: str = ""
    source_policy_hash: str = ""
    schema: str = ACQUISITION_SCHEMA

    def __post_init__(self) -> None:
        for name in ("target_ids", "possible_falsification", "preferred_types", "preferred_languages", "exclusions"):
            object.__setattr__(self, name, _tuple(getattr(self, name)))
        object.__setattr__(self, "preferred_date_range", _dict(self.preferred_date_range))
        if not self.request_id:
            object.__setattr__(self, "request_id", make_event_id("acquisition_request", self.project_id, {"run_id": self.run_id, "gap": self.research_gap, "targets": sorted(self.target_ids), "why": self.why_needed, "gain": self.expected_information_gain, "falsification": self.possible_falsification, "role": self.desired_source_role, "types": self.preferred_types, "languages": self.preferred_languages, "date_range": self.preferred_date_range, "exclusions": self.exclusions, "max_candidates": self.max_candidates}))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AcquisitionRequest":
        raw = _strict(value, {"project_id", "research_gap", "target_ids", "why_needed", "expected_information_gain", "possible_falsification", "desired_source_role", "preferred_types", "preferred_languages", "preferred_date_range", "exclusions", "max_candidates", "request_id", "run_id", "source_policy_hash", "schema"}, {"project_id", "research_gap", "target_ids", "why_needed", "expected_information_gain", "possible_falsification", "desired_source_role", "run_id", "source_policy_hash"})
        return cls(project_id=raw["project_id"], research_gap=raw["research_gap"], target_ids=raw["target_ids"], why_needed=raw["why_needed"], expected_information_gain=raw["expected_information_gain"], possible_falsification=raw["possible_falsification"], desired_source_role=raw["desired_source_role"], preferred_types=raw.get("preferred_types", ()), preferred_languages=raw.get("preferred_languages", ()), preferred_date_range=raw.get("preferred_date_range", {}), exclusions=raw.get("exclusions", ()), max_candidates=raw.get("max_candidates", 10), request_id=raw.get("request_id", ""), run_id=raw["run_id"], source_policy_hash=raw["source_policy_hash"], schema=raw.get("schema", ACQUISITION_SCHEMA))


@dataclass(frozen=True)
class SpeculativeIdea(_Model):
    project_id: str
    idea: str
    status: SpeculativeStatus | str = SpeculativeStatus.SPECULATIVE
    supporting_ids: tuple[str, ...] = ()
    counterevidence_ids: tuple[str, ...] = ()
    rationale: str = ""
    idea_id: str = ""
    version: int = 1
    supersedes_version_id: str | None = None
    run_id: str = ""
    source_policy_hash: str = ""
    version_id: str | None = None
    schema: str = SPECULATION_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", getattr(self.status, "value", self.status))
        object.__setattr__(self, "supporting_ids", _tuple(self.supporting_ids))
        object.__setattr__(self, "counterevidence_ids", _tuple(self.counterevidence_ids))
        if not self.idea_id:
            object.__setattr__(self, "idea_id", make_event_id("speculative_idea", self.project_id, {"run_id": self.run_id, "idea": self.idea, "supporting": sorted(self.supporting_ids), "counterevidence": sorted(self.counterevidence_ids)}))
        object.__setattr__(self, "version_id", self.version_id or make_version_id("speculative_idea", self.project_id, self.idea_id, self.version))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SpeculativeIdea":
        raw = _strict(value, {"project_id", "idea", "status", "supporting_ids", "counterevidence_ids", "rationale", "idea_id", "version", "supersedes_version_id", "run_id", "source_policy_hash", "version_id", "schema"}, {"project_id", "idea", "run_id", "source_policy_hash"})
        return cls(project_id=raw["project_id"], idea=raw["idea"], status=raw.get("status", SpeculativeStatus.SPECULATIVE), supporting_ids=raw.get("supporting_ids", ()), counterevidence_ids=raw.get("counterevidence_ids", ()), rationale=raw.get("rationale", ""), idea_id=raw.get("idea_id", ""), version=raw.get("version", 1), supersedes_version_id=raw.get("supersedes_version_id"), run_id=raw["run_id"], source_policy_hash=raw["source_policy_hash"], version_id=raw.get("version_id"), schema=raw.get("schema", SPECULATION_SCHEMA))


@dataclass(frozen=True)
class SearchStrategy(_Model):
    project_id: str
    family: str
    query: str
    target_ids: tuple[str, ...] = ()
    filters: Mapping[str, Any] = field(default_factory=dict)
    result_ids: tuple[str, ...] = ()
    new_evidence_ids: tuple[str, ...] = ()
    coverage_keys: tuple[str, ...] = ()
    strategy_id: str = ""
    run_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_ids", _tuple(self.target_ids))
        object.__setattr__(self, "result_ids", _tuple(self.result_ids))
        object.__setattr__(self, "new_evidence_ids", _tuple(self.new_evidence_ids))
        object.__setattr__(self, "coverage_keys", _tuple(self.coverage_keys))
        object.__setattr__(self, "filters", _dict(self.filters))
        if not self.strategy_id:
            object.__setattr__(self, "strategy_id", make_event_id("iteration", self.project_id, {"run_id": self.run_id, "family": self.family, "query": self.query, "targets": sorted(self.target_ids), "filters": self.filters, "results": sorted(self.result_ids), "new_evidence": sorted(self.new_evidence_ids), "coverage": sorted(self.coverage_keys)}))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SearchStrategy":
        raw = _strict(value, {"project_id", "family", "query", "target_ids", "filters", "result_ids", "new_evidence_ids", "coverage_keys", "strategy_id", "run_id"}, {"project_id", "family", "query"})
        return cls(raw["project_id"], raw["family"], raw["query"], raw.get("target_ids", ()), raw.get("filters", {}), raw.get("result_ids", ()), raw.get("new_evidence_ids", ()), raw.get("coverage_keys", ()), raw.get("strategy_id", ""), raw.get("run_id", ""))


@dataclass(frozen=True)
class CoverageLedger(_Model):
    strategies: tuple[SearchStrategy, ...] = ()
    required_families: tuple[str, ...] = ()
    allow_empty_strategy_families: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "strategies", _nested_tuple(self.strategies, SearchStrategy))
        object.__setattr__(self, "required_families", _tuple(self.required_families))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CoverageLedger":
        raw = _strict(value, {"strategies", "required_families", "allow_empty_strategy_families"}, set())
        return cls(tuple(SearchStrategy.from_mapping(item) if not isinstance(item, SearchStrategy) else item for item in raw.get("strategies", ())), raw.get("required_families", ()), raw.get("allow_empty_strategy_families", False))


@dataclass(frozen=True)
class SaturationStatus(_Model):
    evidence_saturated: bool
    strategy_saturated: bool
    claim_stable: bool
    counterevidence_saturated: bool = False
    covered_strategy_families: tuple[str, ...] = ()
    duplicate_strategy_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "covered_strategy_families", _tuple(self.covered_strategy_families))
        object.__setattr__(self, "duplicate_strategy_ids", _tuple(self.duplicate_strategy_ids))
        object.__setattr__(self, "reasons", _tuple(self.reasons))


@dataclass(frozen=True)
class ClaimSnapshot(_Model):
    claim_id: str
    version_id: str
    status: str
    semantic_hash: str
    schema: str = CLAIM_SNAPSHOT_SCHEMA

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ClaimSnapshot":
        raw = _strict(value, {"claim_id", "version_id", "status", "semantic_hash", "schema"}, {"claim_id", "version_id", "status", "semantic_hash"})
        return cls(raw["claim_id"], raw["version_id"], raw["status"], raw["semantic_hash"], raw.get("schema", CLAIM_SNAPSHOT_SCHEMA))


@dataclass(frozen=True)
class EvidenceSnapshot(_Model):
    evidence_id: str
    version_id: str
    status: str
    semantic_hash: str
    schema: str = EVIDENCE_SNAPSHOT_SCHEMA

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EvidenceSnapshot":
        raw = _strict(value, {"evidence_id", "version_id", "status", "semantic_hash", "schema"}, {"evidence_id", "version_id", "status", "semantic_hash"})
        return cls(raw["evidence_id"], raw["version_id"], raw["status"], raw["semantic_hash"], raw.get("schema", EVIDENCE_SNAPSHOT_SCHEMA))


@dataclass(frozen=True)
class AttackRecord(_Model):
    project_id: str
    run_id: str
    charter_hash: str
    state_hash: str
    iteration_id: str
    target_id: str
    target_version_id: str
    objection_ids: tuple[str, ...]
    counterevidence_ids: tuple[str, ...]
    outcome: str
    rationale: str
    attack_id: str = ""
    schema: str = ATTACK_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "objection_ids", _tuple(self.objection_ids))
        object.__setattr__(self, "counterevidence_ids", _tuple(self.counterevidence_ids))
        if not self.attack_id:
            object.__setattr__(
                self,
                "attack_id",
                make_event_id(
                    "attack",
                    self.project_id,
                    {
                        "run_id": self.run_id,
                        "charter_hash": self.charter_hash,
                        "state_hash": self.state_hash,
                        "iteration_id": self.iteration_id,
                        "target_id": self.target_id,
                        "target_version_id": self.target_version_id,
                        "objection_ids": sorted(self.objection_ids),
                        "counterevidence_ids": sorted(self.counterevidence_ids),
                        "outcome": self.outcome,
                        "rationale": self.rationale,
                    },
                ),
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AttackRecord":
        raw = _strict(
            value,
            {"project_id", "run_id", "charter_hash", "state_hash", "iteration_id", "target_id", "target_version_id", "objection_ids", "counterevidence_ids", "outcome", "rationale", "attack_id", "schema"},
            {"project_id", "run_id", "charter_hash", "state_hash", "iteration_id", "target_id", "target_version_id", "objection_ids", "counterevidence_ids", "outcome", "rationale"},
        )
        return cls(
            raw["project_id"], raw["run_id"], raw["charter_hash"], raw["state_hash"], raw["iteration_id"],
            raw["target_id"], raw["target_version_id"], raw["objection_ids"], raw["counterevidence_ids"],
            raw["outcome"], raw["rationale"], raw.get("attack_id", ""), raw.get("schema", ATTACK_SCHEMA),
        )


@dataclass(frozen=True)
class ColdReviewPacket(_Model):
    project_id: str
    run_id: str
    state_hash: str
    charter_hash: str
    final_claim_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    source_link_records: tuple[Mapping[str, Any], ...]
    report_id: str
    excluded_sections: tuple[str, ...] = COLD_REVIEW_REQUIRED_EXCLUSIONS
    packet_id: str = ""
    schema: str = COLD_REVIEW_SCHEMA
    packet_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "final_claim_ids", _tuple(self.final_claim_ids))
        object.__setattr__(self, "evidence_ids", _tuple(self.evidence_ids))
        object.__setattr__(self, "source_link_records", tuple(_dict(item) for item in self.source_link_records))
        object.__setattr__(self, "excluded_sections", _tuple(self.excluded_sections))
        packet_payload = {
            "project_id": self.project_id,
            "run_id": self.run_id,
            "state_hash": self.state_hash,
            "charter_hash": self.charter_hash,
            "final_claim_ids": sorted(self.final_claim_ids),
            "evidence_ids": sorted(self.evidence_ids),
            "source_link_records": self.source_link_records,
            "report_id": self.report_id,
            "excluded_sections": sorted(self.excluded_sections),
        }
        if not self.packet_id:
            object.__setattr__(self, "packet_id", make_event_id("cold_review", self.project_id, packet_payload))
        if not self.packet_hash:
            object.__setattr__(self, "packet_hash", canonical_sha256(packet_payload))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ColdReviewPacket":
        raw = _strict(value, {"project_id", "run_id", "state_hash", "charter_hash", "final_claim_ids", "evidence_ids", "source_link_records", "report_id", "excluded_sections", "packet_id", "schema", "packet_hash"}, {"project_id", "run_id", "state_hash", "charter_hash", "final_claim_ids", "evidence_ids", "source_link_records", "report_id"})
        return cls(raw["project_id"], raw["run_id"], raw["state_hash"], raw["charter_hash"], raw["final_claim_ids"], raw["evidence_ids"], raw["source_link_records"], raw["report_id"], raw.get("excluded_sections", COLD_REVIEW_REQUIRED_EXCLUSIONS), raw.get("packet_id", ""), raw.get("schema", COLD_REVIEW_SCHEMA), raw.get("packet_hash", ""))


@dataclass(frozen=True)
class ColdReviewResult(_Model):
    packet_id: str
    packet_hash: str
    project_id: str
    run_id: str
    charter_hash: str
    state_hash: str
    report_id: str
    reviewer_model_identity: str
    inference_profile_hash: str
    passed: bool
    blocking_findings: tuple[str, ...]
    claim_audit: Mapping[str, Any]
    evidence_audit: Mapping[str, Any]
    citation_audit: Mapping[str, Any]
    evaluated_at: str
    result_id: str = ""
    schema: str = COLD_REVIEW_RESULT_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "blocking_findings", _tuple(self.blocking_findings))
        object.__setattr__(self, "claim_audit", _dict(self.claim_audit))
        object.__setattr__(self, "evidence_audit", _dict(self.evidence_audit))
        object.__setattr__(self, "citation_audit", _dict(self.citation_audit))
        if not self.result_id:
            object.__setattr__(self, "result_id", make_event_id("cold_review_result", self.project_id, {
                "packet_id": self.packet_id, "packet_hash": self.packet_hash, "run_id": self.run_id,
                "charter_hash": self.charter_hash, "state_hash": self.state_hash, "report_id": self.report_id,
                "reviewer_model_identity": self.reviewer_model_identity, "inference_profile_hash": self.inference_profile_hash,
                "passed": self.passed, "blocking_findings": self.blocking_findings,
                "claim_audit": self.claim_audit, "evidence_audit": self.evidence_audit, "citation_audit": self.citation_audit,
                "evaluated_at": self.evaluated_at,
            }))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ColdReviewResult":
        raw = _strict(value, {"packet_id", "packet_hash", "project_id", "run_id", "charter_hash", "state_hash", "report_id", "reviewer_model_identity", "inference_profile_hash", "passed", "blocking_findings", "claim_audit", "evidence_audit", "citation_audit", "evaluated_at", "result_id", "schema"}, {"packet_id", "packet_hash", "project_id", "run_id", "charter_hash", "state_hash", "report_id", "reviewer_model_identity", "inference_profile_hash", "passed", "blocking_findings", "claim_audit", "evidence_audit", "citation_audit", "evaluated_at"})
        return cls(raw["packet_id"], raw["packet_hash"], raw["project_id"], raw["run_id"], raw["charter_hash"], raw["state_hash"], raw["report_id"], raw["reviewer_model_identity"], raw["inference_profile_hash"], raw["passed"], raw["blocking_findings"], raw["claim_audit"], raw["evidence_audit"], raw["citation_audit"], raw["evaluated_at"], raw.get("result_id", ""), raw.get("schema", COLD_REVIEW_RESULT_SCHEMA))


@dataclass(frozen=True)
class CompletionGate(_Model):
    attack_count: int
    required_attack_count: int = 1
    adjudication_complete: bool = False
    rehydration_complete: bool = False
    citations_traceable: bool = False
    unresolved_critical_major: tuple[str, ...] = ()
    cold_review_passed: bool = False
    budget_ok: bool = True
    source_policy_ok: bool = True
    model_identity_ok: bool = True
    active_leading_hypothesis_id: str | None = None
    required_strategy_families: tuple[str, ...] = ()
    covered_strategy_families: tuple[str, ...] = ()
    project_id: str = ""
    run_id: str = ""
    charter_hash: str = ""
    state_hash: str = ""
    research_state: ResearchState | None = None
    strategy_ledger: CoverageLedger | Mapping[str, Any] | None = None
    attack_records: tuple[Mapping[str, Any], ...] = ()
    adjudication_records: tuple[DiscussionSession, ...] = ()
    rehydration_output: RehydrationOutput | None = None
    cold_review_packet: ColdReviewPacket | None = None
    source_policy: Mapping[str, Any] | None = None
    formal_completion_evidence: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "unresolved_critical_major", _tuple(self.unresolved_critical_major))
        object.__setattr__(self, "required_strategy_families", _tuple(self.required_strategy_families))
        object.__setattr__(self, "covered_strategy_families", _tuple(self.covered_strategy_families))
        object.__setattr__(self, "attack_records", tuple(_dict(item) for item in self.attack_records))
        object.__setattr__(self, "adjudication_records", _nested_tuple(self.adjudication_records, DiscussionSession))
        object.__setattr__(self, "formal_completion_evidence", tuple(_dict(item) for item in self.formal_completion_evidence))
        if self.strategy_ledger is not None and not isinstance(self.strategy_ledger, CoverageLedger):
            object.__setattr__(self, "strategy_ledger", CoverageLedger.from_mapping(self.strategy_ledger) if isinstance(self.strategy_ledger, Mapping) else self.strategy_ledger)
        if self.research_state is not None and isinstance(self.research_state, Mapping):
            object.__setattr__(self, "research_state", ResearchState.from_mapping(self.research_state))
        if self.rehydration_output is not None and isinstance(self.rehydration_output, Mapping):
            object.__setattr__(self, "rehydration_output", RehydrationOutput.from_mapping(self.rehydration_output))
        if self.cold_review_packet is not None and isinstance(self.cold_review_packet, Mapping):
            object.__setattr__(self, "cold_review_packet", ColdReviewPacket.from_mapping(self.cold_review_packet))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CompletionGate":
        allowed = {"attack_count", "required_attack_count", "adjudication_complete", "rehydration_complete", "citations_traceable", "unresolved_critical_major", "cold_review_passed", "budget_ok", "source_policy_ok", "model_identity_ok", "active_leading_hypothesis_id", "required_strategy_families", "covered_strategy_families", "project_id", "run_id", "charter_hash", "state_hash", "research_state", "strategy_ledger", "attack_records", "adjudication_records", "rehydration_output", "cold_review_packet", "source_policy", "formal_completion_evidence"}
        raw = _strict(value, allowed, {"attack_count", "project_id", "run_id", "charter_hash", "state_hash"})
        return cls(**{name: raw[name] for name in allowed if name in raw})


@dataclass(frozen=True)
class FormalCompletionEvidence(_Model):
    project_id: str
    run_id: str
    state_hash: str
    report_id: str
    claim_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    source_links: tuple[Mapping[str, Any], ...]
    evidence_eligibility_hash: str
    record_id: str = ""
    schema: str = FORMAL_COMPLETION_EVIDENCE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_ids", _tuple(self.claim_ids))
        object.__setattr__(self, "evidence_ids", _tuple(self.evidence_ids))
        object.__setattr__(self, "source_links", tuple(_dict(item) for item in self.source_links))
        if not self.record_id:
            object.__setattr__(self, "record_id", make_event_id("formal_completion_evidence", self.project_id, {
                "run_id": self.run_id, "state_hash": self.state_hash, "report_id": self.report_id,
                "claim_ids": sorted(self.claim_ids), "evidence_ids": sorted(self.evidence_ids),
                "source_links": self.source_links, "evidence_eligibility_hash": self.evidence_eligibility_hash,
            }))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FormalCompletionEvidence":
        raw = _strict(value, {"project_id", "run_id", "state_hash", "report_id", "claim_ids", "evidence_ids", "source_links", "evidence_eligibility_hash", "record_id", "schema"}, {"project_id", "run_id", "state_hash", "report_id", "claim_ids", "evidence_ids", "source_links", "evidence_eligibility_hash"})
        return cls(raw["project_id"], raw["run_id"], raw["state_hash"], raw["report_id"], raw["claim_ids"], raw["evidence_ids"], raw["source_links"], raw["evidence_eligibility_hash"], raw.get("record_id", ""), raw.get("schema", FORMAL_COMPLETION_EVIDENCE_SCHEMA))


@dataclass(frozen=True)
class CompletionGateResult(_Model):
    passed: bool
    reasons: tuple[str, ...] = ()
    checks: Mapping[str, bool] = field(default_factory=dict)
    project_id: str = ""
    run_id: str = ""
    charter_hash: str = ""
    state_hash: str = ""
    gate_hash: str = ""
    gate_input_hash: str = ""
    evaluated_at: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", _tuple(self.reasons))
        object.__setattr__(self, "checks", _dict(self.checks))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CompletionGateResult":
        raw = _strict(value, {"passed", "reasons", "checks", "project_id", "run_id", "charter_hash", "state_hash", "gate_hash", "gate_input_hash", "evaluated_at"}, {"passed"})
        return cls(raw["passed"], raw.get("reasons", ()), raw.get("checks", {}), raw.get("project_id", ""), raw.get("run_id", ""), raw.get("charter_hash", ""), raw.get("state_hash", ""), raw.get("gate_hash", ""), raw.get("gate_input_hash", ""), raw.get("evaluated_at", ""))


@dataclass(frozen=True)
class CompletionEvaluationInput(_Model):
    project_id: str
    run_id: str
    charter_hash: str
    state_hash: str
    charter: MaxResearchCharter | Mapping[str, Any]
    run_state: MaxRunState | Mapping[str, Any]
    research_state: ResearchState | Mapping[str, Any]
    strategy_ledger: CoverageLedger | Mapping[str, Any]
    attack_records: tuple[AttackRecord | Mapping[str, Any], ...]
    discussion_sessions: tuple[DiscussionSession | Mapping[str, Any], ...]
    rehydration_output: RehydrationOutput | Mapping[str, Any]
    cold_review_packet: ColdReviewPacket | Mapping[str, Any]
    cold_review_result: ColdReviewResult | Mapping[str, Any]
    final_report: ReportProjection | Mapping[str, Any]
    formal_completion_evidence: FormalCompletionEvidence | Mapping[str, Any]
    claim_snapshots: tuple[ClaimSnapshot | Mapping[str, Any], ...]
    evidence_snapshots: tuple[EvidenceSnapshot | Mapping[str, Any], ...]
    counterevidence_snapshots: tuple[EvidenceSnapshot | Mapping[str, Any], ...]
    budget_snapshot: Mapping[str, Any]
    source_policy_snapshot: Mapping[str, Any]
    model_identity: str
    evaluated_at: str
    current_checkpoint_id: str | None = None
    allow_empty_strategy_families: bool = False
    schema: str = COMPLETION_INPUT_SCHEMA
    input_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.charter, MaxResearchCharter): object.__setattr__(self, "charter", MaxResearchCharter.from_mapping(self.charter))
        if isinstance(self.run_state, RunTransitionResult): object.__setattr__(self, "run_state", self.run_state.new_state)
        elif not isinstance(self.run_state, MaxRunState): object.__setattr__(self, "run_state", MaxRunState.from_mapping(self.run_state))
        if not isinstance(self.research_state, ResearchState): object.__setattr__(self, "research_state", ResearchState.from_mapping(self.research_state))
        if not isinstance(self.strategy_ledger, CoverageLedger): object.__setattr__(self, "strategy_ledger", CoverageLedger.from_mapping(self.strategy_ledger))
        object.__setattr__(self, "attack_records", tuple(item if isinstance(item, AttackRecord) else AttackRecord.from_mapping(item) for item in self.attack_records))
        object.__setattr__(self, "discussion_sessions", tuple(item if isinstance(item, DiscussionSession) else DiscussionSession.from_mapping(item) for item in self.discussion_sessions))
        if not isinstance(self.rehydration_output, RehydrationOutput): object.__setattr__(self, "rehydration_output", RehydrationOutput.from_mapping(self.rehydration_output))
        if not isinstance(self.cold_review_packet, ColdReviewPacket): object.__setattr__(self, "cold_review_packet", ColdReviewPacket.from_mapping(self.cold_review_packet))
        if not isinstance(self.cold_review_result, ColdReviewResult): object.__setattr__(self, "cold_review_result", ColdReviewResult.from_mapping(self.cold_review_result))
        if not isinstance(self.final_report, ReportProjection): object.__setattr__(self, "final_report", ReportProjection.from_mapping(self.final_report))
        if not isinstance(self.formal_completion_evidence, FormalCompletionEvidence): object.__setattr__(self, "formal_completion_evidence", FormalCompletionEvidence.from_mapping(self.formal_completion_evidence))
        object.__setattr__(self, "claim_snapshots", tuple(item if isinstance(item, ClaimSnapshot) else ClaimSnapshot.from_mapping(item) for item in self.claim_snapshots))
        object.__setattr__(self, "evidence_snapshots", tuple(item if isinstance(item, EvidenceSnapshot) else EvidenceSnapshot.from_mapping(item) for item in self.evidence_snapshots))
        object.__setattr__(self, "counterevidence_snapshots", tuple(item if isinstance(item, EvidenceSnapshot) else EvidenceSnapshot.from_mapping(item) for item in self.counterevidence_snapshots))
        object.__setattr__(self, "budget_snapshot", _dict(self.budget_snapshot))
        object.__setattr__(self, "source_policy_snapshot", _dict(self.source_policy_snapshot))
        payload = model_to_dict(self)
        payload["input_hash"] = ""
        object.__setattr__(self, "input_hash", canonical_sha256(payload))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CompletionEvaluationInput":
        raw = _strict(value, {"project_id", "run_id", "charter_hash", "state_hash", "charter", "run_state", "research_state", "strategy_ledger", "attack_records", "discussion_sessions", "rehydration_output", "cold_review_packet", "cold_review_result", "final_report", "formal_completion_evidence", "claim_snapshots", "evidence_snapshots", "counterevidence_snapshots", "budget_snapshot", "source_policy_snapshot", "model_identity", "evaluated_at", "current_checkpoint_id", "allow_empty_strategy_families", "schema", "input_hash"}, {"project_id", "run_id", "charter_hash", "state_hash", "charter", "run_state", "research_state", "strategy_ledger", "attack_records", "discussion_sessions", "rehydration_output", "cold_review_packet", "cold_review_result", "final_report", "formal_completion_evidence", "claim_snapshots", "evidence_snapshots", "counterevidence_snapshots", "budget_snapshot", "source_policy_snapshot", "model_identity", "evaluated_at"})
        return cls(raw["project_id"], raw["run_id"], raw["charter_hash"], raw["state_hash"], raw["charter"], raw["run_state"], raw["research_state"], raw["strategy_ledger"], tuple(raw["attack_records"]), tuple(raw["discussion_sessions"]), raw["rehydration_output"], raw["cold_review_packet"], raw["cold_review_result"], raw["final_report"], raw["formal_completion_evidence"], tuple(raw["claim_snapshots"]), tuple(raw["evidence_snapshots"]), tuple(raw["counterevidence_snapshots"]), raw["budget_snapshot"], raw["source_policy_snapshot"], raw["model_identity"], raw["evaluated_at"], raw.get("current_checkpoint_id"), raw.get("allow_empty_strategy_families", False), raw.get("schema", COMPLETION_INPUT_SCHEMA), raw.get("input_hash", ""))


@dataclass(frozen=True)
class CompletionResult(_Model):
    project_id: str
    run_id: str
    charter_hash: str
    state_hash: str
    gate_result: CompletionGateResult | Mapping[str, Any]
    evaluated_at: str
    result_id: str = ""
    schema: str = COMPLETION_RESULT_SCHEMA

    def __post_init__(self) -> None:
        if not isinstance(self.gate_result, CompletionGateResult):
            object.__setattr__(self, "gate_result", CompletionGateResult.from_mapping(self.gate_result))
        if not self.result_id:
            object.__setattr__(self, "result_id", make_event_id("completion_result", self.project_id, {"run_id": self.run_id, "charter_hash": self.charter_hash, "state_hash": self.state_hash, "gate_hash": self.gate_result.gate_hash, "gate_input_hash": self.gate_result.gate_input_hash, "evaluated_at": self.evaluated_at}))

    @property
    def gate_input_hash(self) -> str:
        return self.gate_result.gate_input_hash

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CompletionResult":
        raw = _strict(value, {"project_id", "run_id", "charter_hash", "state_hash", "gate_result", "evaluated_at", "result_id", "schema"}, {"project_id", "run_id", "charter_hash", "state_hash", "gate_result", "evaluated_at"})
        gate = raw["gate_result"] if isinstance(raw["gate_result"], CompletionGateResult) else CompletionGateResult.from_mapping(raw["gate_result"])
        return cls(raw["project_id"], raw["run_id"], raw["charter_hash"], raw["state_hash"], gate, raw["evaluated_at"], raw.get("result_id", ""), raw.get("schema", COMPLETION_RESULT_SCHEMA))


@dataclass(frozen=True)
class ReportProjection(_Model):
    project_id: str
    state_hash: str
    claim_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    source_links: tuple[Mapping[str, Any], ...]
    summary: str = ""
    report_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_ids", _tuple(self.claim_ids))
        object.__setattr__(self, "evidence_ids", _tuple(self.evidence_ids))
        object.__setattr__(self, "source_links", tuple(_dict(item) for item in self.source_links))
        if not self.report_id:
            object.__setattr__(self, "report_id", make_stable_id("report", canonical_sha256({"project_id": self.project_id, "state_hash": self.state_hash, "claims": sorted(self.claim_ids), "evidence": sorted(self.evidence_ids), "links": self.source_links})[:48]))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ReportProjection":
        raw = _strict(value, {"project_id", "state_hash", "claim_ids", "evidence_ids", "source_links", "summary", "report_id"}, {"project_id", "state_hash", "claim_ids", "evidence_ids", "source_links"})
        return cls(raw["project_id"], raw["state_hash"], raw["claim_ids"], raw["evidence_ids"], raw["source_links"], raw.get("summary", ""), raw.get("report_id", ""))


__all__ = [
    "ACQUISITION_SCHEMA", "Adjudication", "AdjudicationValue", "AcquisitionRequest", "APPROVAL_CONSUMPTION_SCHEMA", "ApprovalConsumption", "APPROVAL_SCHEMA", "AttackRecord", "ATTACK_SCHEMA", "CANONICAL_OBJECT_SCHEMA", "CHARTER_SCHEMA", "CanonicalObject", "CanonicalObjectKind", "CanonicalRef", "CanonicalRelation", "ClaimSnapshot", "CLAIM_SNAPSHOT_SCHEMA", "Checkpoint", "CHECKPOINT_SCHEMA", "ColdReviewPacket", "ColdReviewResult", "COLD_REVIEW_REQUIRED_EXCLUSIONS", "COLD_REVIEW_RESULT_SCHEMA", "COLD_REVIEW_SCHEMA", "CompletionEvaluationInput", "COMPLETION_INPUT_SCHEMA", "CompletionGate", "CompletionGateResult", "CompletionResult", "COMPLETION_RESULT_SCHEMA", "CorrectionPosition", "CoverageLedger", "CrossExamination", "DISCUSSION_SCHEMA", "DiscussionSession", "DriftKind", "EPISTEMIC_CONFLICT_SCHEMA", "EpistemicConflictRecord", "EVIDENCE_SNAPSHOT_SCHEMA", "EvidenceSnapshot", "EVIDENCE_STATUSES", "FINAL_CLAIM_STATUSES", "FINAL_EVIDENCE_STATUSES", "FormalCompletionEvidence", "FORMAL_COMPLETION_EVIDENCE_SCHEMA", "Iteration", "IterationKind", "MAX_RESEARCH_PROTOCOL", "MaxResearchCharter", "MaxRunState", "MinorityReport", "RehydrationInput", "RehydrationOutput", "RehydrationPolicy", "REHYDRATION_SCHEMA", "RelationKind", "ReportProjection", "ResearchState", "RolePacket", "RolePosition", "RunStatus", "RUN_STATE_SCHEMA", "RunTransitionResult", "SaturationStatus", "SearchStrategy", "SPECULATION_SCHEMA", "SpeculativeIdea", "SpeculativeStatus", "StartApproval", "ValidityAudit", "WorkingState", "WORKING_STATE_SCHEMA",
]
