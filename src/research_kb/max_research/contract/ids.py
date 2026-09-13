"""Stable identifier grammar and semantic namespaces for MR-0A.

Identifiers are deliberately derived from the complete identity boundary.  A
project-local object may therefore reuse a human-facing label in another
project without colliding, while a version or relation can never silently
refer to a different object/version pair.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .base import canonical_sha256


STABLE_ID_PREFIX = "mr1"
PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
STABLE_ID_RE = re.compile(
    r"^mr1:(?P<kind>[a-z][a-z0-9_-]{0,63}):(?P<opaque>[A-Za-z0-9][A-Za-z0-9._~!-]{0,127})$"
)


_KIND_ALIASES = {
    "source": "source",
    "document": "document",
    "document_version": "document_version",
    "document-version": "document_version",
    "passage": "passage",
    "quote": "quote",
    "evidence": "evidence",
    "evidence_link": "evidence_link",
    "evidence-link": "evidence_link",
    "claim": "claim",
    "hypothesis": "hypothesis",
    "objection": "objection",
    "research_question": "research_question",
    "research-question": "research_question",
    "decision": "decision",
    "citation": "citation",
    "source_role": "source_role",
    "source-role": "source_role",
    "report": "report",
    "iteration": "iteration",
    "discussion_session": "discussion_session",
    "discussion-session": "discussion_session",
    "acquisition_request": "acquisition_request",
    "acquisition-request": "acquisition_request",
    "speculative_idea": "speculative_idea",
    "speculative-idea": "speculative_idea",
    "checkpoint": "checkpoint",
    "working_state": "working_state",
    "working-state": "working_state",
    "research_state": "research_state",
    "research-state": "research_state",
    "completion_gate": "completion_gate",
    "completion-gate": "completion_gate",
    "start_approval": "start_approval",
    "start-approval": "start_approval",
    "relation": "relation",
    "completion_result": "completion_result",
    "completion-result": "completion_result",
    "cold_review": "cold_review",
    "cold-review": "cold_review",
    "role_packet": "role_packet",
    "role-packet": "role_packet",
    "attack": "attack",
    "approval_consumption": "approval_consumption",
    "approval-consumption": "approval_consumption",
    "verification_record": "verification_record",
    "verification-record": "verification_record",
    "cold_review_result": "cold_review_result",
    "cold-review-result": "cold_review_result",
    "formal_completion_evidence": "formal_completion_evidence",
    "formal-completion-evidence": "formal_completion_evidence",
}


# These sets are documentation as well as a small amount of machine-checkable
# vocabulary.  ``make_stable_id`` remains generic so future pure contract
# types can be added without changing the grammar.
GLOBAL_STABLE_ID_KINDS = frozenset({"source", "document"})
PROJECT_LOCAL_STABLE_ID_KINDS = frozenset(
    {
        "document_version",
        "passage",
        "quote",
        "evidence",
        "evidence_link",
        "claim",
        "hypothesis",
        "objection",
        "research_question",
        "decision",
        "citation",
        "source_role",
        "report",
        "iteration",
        "discussion_session",
        "acquisition_request",
        "speculative_idea",
        "checkpoint",
        "working_state",
        "research_state",
        "completion_gate",
        "completion_result",
        "start_approval",
        "relation",
        "cold_review",
        "role_packet",
        "attack",
        "approval_consumption",
        "verification_record",
        "cold_review_result",
        "formal_completion_evidence",
    }
)


def normalize_kind(kind: Any) -> str:
    value = getattr(kind, "value", kind)
    if not isinstance(value, str):
        raise ValueError("canonical kind must be a string")
    normalized = value.strip().lower().replace(" ", "_")
    return _KIND_ALIASES.get(normalized, normalized)


def make_stable_id(kind: Any, object_id: str) -> str:
    """Create an MR-1 identity from an existing stable system identifier."""

    normalized_kind = normalize_kind(kind)
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", normalized_kind):
        raise ValueError(f"invalid canonical kind: {kind!r}")
    if not isinstance(object_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._~!-]{0,127}", object_id
    ):
        raise ValueError("object_id does not satisfy the stable ID grammar")
    return f"{STABLE_ID_PREFIX}:{normalized_kind}:{object_id}"


def id_namespace(kind: Any) -> str:
    """Return the declared namespace for a canonical kind."""

    normalized = normalize_kind(kind)
    if normalized in GLOBAL_STABLE_ID_KINDS:
        return "global"
    if normalized in PROJECT_LOCAL_STABLE_ID_KINDS:
        return "project_local"
    return "project_local"


def _semantic_opaque(kind: Any, payload: Any) -> str:
    return canonical_sha256(
        {"namespace": id_namespace(kind), "kind": normalize_kind(kind), "identity": payload}
    )[:48]


def make_version_id(
    kind: Any,
    project_id: str,
    stable_id: str | None = None,
    version: int | None = None,
) -> str:
    """Create a version ID bound to project, stable identity, kind and number.

    The two-argument form is retained only as an explicit legacy constructor
    for callers that need to display an ID before a project object exists.  It
    is not accepted by the canonical-object validator.
    """

    normalized = normalize_kind(kind)
    if stable_id is None and version is None:
        opaque = _semantic_opaque(normalized, {"legacy": project_id})
    else:
        if stable_id is None or version is None:
            raise ValueError("make_version_id requires stable_id and version together")
        if not isinstance(project_id, str) or not project_id:
            raise ValueError("project_id is required for a semantic version ID")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ValueError("version must be a positive integer")
        opaque = _semantic_opaque(
            normalized,
            {
                "project_id": project_id,
                "stable_id": stable_id,
                "version": version,
            },
        )
    return make_stable_id(f"{normalized}-version", opaque)


def expected_version_id(kind: Any, project_id: str, stable_id: str, version: int) -> str:
    """Alias used by validators to make the binding rule conspicuous."""

    return make_version_id(kind, project_id, stable_id, version)


def make_relation_id(
    project_id: str,
    source_id: str,
    target_id: str,
    relation: Any,
    source_version_id: str | None,
    target_version_id: str | None,
) -> str:
    """Create a relation ID bound to both endpoint versions."""

    relation_value = getattr(relation, "value", relation)
    return make_stable_id(
        "relation",
        _semantic_opaque(
            "relation",
            {
                "project_id": project_id,
                "source_id": source_id,
                "target_id": target_id,
                "relation": relation_value,
                "source_version_id": source_version_id,
                "target_version_id": target_version_id,
            },
        ),
    )


def make_event_id(kind: Any, project_id: str, identity: Any) -> str:
    """Create a deterministic project-local event ID from semantic content."""

    return make_stable_id(
        kind,
        _semantic_opaque(kind, {"project_id": project_id, "identity": identity}),
    )


@dataclass(frozen=True)
class StableId:
    kind: str
    opaque: str

    @property
    def value(self) -> str:
        return make_stable_id(self.kind, self.opaque)


def parse_stable_id(value: Any) -> StableId | None:
    if not isinstance(value, str):
        return None
    match = STABLE_ID_RE.fullmatch(value)
    if match is None:
        return None
    return StableId(normalize_kind(match.group("kind")), match.group("opaque"))


def is_stable_id(value: Any, *, expected_kind: Any | None = None) -> bool:
    parsed = parse_stable_id(value)
    if parsed is None:
        return False
    return expected_kind is None or parsed.kind == normalize_kind(expected_kind)


def is_project_id(value: Any) -> bool:
    return isinstance(value, str) and PROJECT_ID_RE.fullmatch(value) is not None


def require_stable_id(value: Any, *, expected_kind: Any | None = None) -> StableId:
    parsed = parse_stable_id(value)
    if parsed is None:
        raise ValueError("value is not an MR-1 stable ID")
    if expected_kind is not None and parsed.kind != normalize_kind(expected_kind):
        raise ValueError(
            f"stable ID kind {parsed.kind!r} does not match {normalize_kind(expected_kind)!r}"
        )
    return parsed


__all__ = [
    "PROJECT_ID_RE",
    "GLOBAL_STABLE_ID_KINDS",
    "PROJECT_LOCAL_STABLE_ID_KINDS",
    "STABLE_ID_PREFIX",
    "STABLE_ID_RE",
    "StableId",
    "expected_version_id",
    "id_namespace",
    "is_project_id",
    "is_stable_id",
    "make_event_id",
    "make_relation_id",
    "make_stable_id",
    "make_version_id",
    "normalize_kind",
    "parse_stable_id",
    "require_stable_id",
]
