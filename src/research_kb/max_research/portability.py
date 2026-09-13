"""Portable Max Research host/backend contracts and control-plane registry.

This module is deliberately separate from the researcher-facing MCP surface.
Agents discover and invoke it through the administrator CLI; they do not get a
SQLite connection.  Profiles and bindings are content-addressed, server-owned
records.  The only mutable rows are the explicitly named current projections.

The implementation does not select a provider from an agent name.  A Run has
to carry an explicit :class:`RunExecutionBinding`, and a change of backend is
only possible through a server-created, human-approved handoff.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping, Sequence

from ..policy import Actor, PolicyError, require_admin
from .contract import canonical_json, canonical_sha256
from .contract.base import deep_freeze
from .persistence.db import MaxControlError, control_transaction
from .persistence.repository import (
    MaxControlRepository,
    _hash,
    _parse_timestamp,
    _timestamp,
    _utc_now,
)


HOST_KINDS = ("codex", "luna", "qoder", "hermes", "generic_cli_agent")
BACKEND_KINDS = (
    "openai_compatible_http",
    "openai_responses_http",
    "local_agent_cli",
    "hermetic_fixture",
)
PROFILE_STATUSES = ("active", "disabled", "revoked")
HANDOFF_STATES = ("PENDING", "CONSUMED", "REJECTED", "EXPIRED")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "password",
        "credential_value",
        "access_token",
        "refresh_token",
        "bearer_token",
        "authorization_header",
        "client_secret",
        "private_key",
    }
)
_FORBIDDEN_AUTHORITY_WORDS = frozenset(
    {"verified", "accepted", "approved", "completed", "complete", "final"}
)

# A normalized result is an agent-produced proposal, not a document store.
# These limits are deliberately conservative and are enforced before a result
# is hashed or persisted so a caller cannot turn the control DB into an
# unbounded payload sink.
MAX_RESULT_CANONICAL_BYTES = 262_144
MAX_RESULT_LIST_ITEMS = 256
MAX_RESULT_STRING_LENGTH = 16_384
MAX_RESULT_DEPTH = 12
MAX_RESULT_OBJECT_KEYS = 128


def _require_text(value: Any, name: str, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise MaxControlError(f"{name} is invalid")
    if "\x00" in value or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise MaxControlError(f"{name} contains invalid Unicode")
    return value.strip()


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value.casefold()):
        raise MaxControlError(f"{name} must be a SHA-256 digest")
    return value.casefold()


def _copy_json(value: Any, name: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MaxControlError(f"{name} must be canonical JSON data") from exc


def _loads_safe(value: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _validate_bounded_json(value: Any, name: str, *, depth: int = 0) -> None:
    """Reject oversized or structurally abusive agent-controlled JSON."""

    if depth > MAX_RESULT_DEPTH:
        raise MaxControlError(f"{name} exceeds the maximum JSON depth")
    if isinstance(value, Mapping):
        if len(value) > MAX_RESULT_OBJECT_KEYS:
            raise MaxControlError(f"{name} contains too many object keys")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > MAX_RESULT_STRING_LENGTH:
                raise MaxControlError(f"{name} contains an invalid object key")
            _validate_bounded_json(item, name, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_RESULT_LIST_ITEMS:
            raise MaxControlError(f"{name} contains too many list items")
        for item in value:
            _validate_bounded_json(item, name, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > MAX_RESULT_STRING_LENGTH:
            raise MaxControlError(f"{name} contains an oversized string")
    elif value is None or isinstance(value, (bool, int, float)):
        return
    else:
        raise MaxControlError(f"{name} contains a non-JSON value")
    try:
        if len(canonical_json(value).encode("utf-8")) > MAX_RESULT_CANONICAL_BYTES:
            raise MaxControlError(f"{name} exceeds the maximum canonical size")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MaxControlError(f"{name} must be canonical JSON data") from exc


def _walk_for_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).casefold().replace("-", "_")
            if lowered in _FORBIDDEN_SECRET_KEYS or any(
                fragment in lowered
                for fragment in ("api_key", "apikey", "client_secret", "credential_value", "authorization_header")
            ):
                raise MaxControlError(f"credential value is not allowed at {path}.{key}")
            _walk_for_secrets(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _walk_for_secrets(item, f"{path}[{index}]")


def _strict_mapping(value: Any, *, allowed: set[str], required: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MaxControlError(f"{name} must be an object")
    unknown = sorted(str(key) for key in value if key not in allowed)
    missing = sorted(key for key in required if key not in value)
    if unknown:
        raise MaxControlError(f"{name} contains unknown fields: {', '.join(unknown)}")
    if missing:
        raise MaxControlError(f"{name} is missing fields: {', '.join(missing)}")
    return dict(value)


def _normalize_operations(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise MaxControlError("allowed_operations must be a non-empty list")
    result = tuple(sorted({_require_text(item, "allowed_operation", max_length=128) for item in value}))
    return result


@dataclass(frozen=True)
class AgentHostProfile:
    """A host identity, independent of any model/provider choice."""

    host_kind: str
    host_version: str
    control_surface: str
    capability_manifest_hash: str
    canonical_skill_hash: str
    adapter_hash: str
    allowed_operations: tuple[str, ...]
    created_by: str = "server"
    status: str = "active"
    host_profile_id: str = ""

    def __post_init__(self) -> None:
        if self.host_kind not in HOST_KINDS:
            raise MaxControlError("host_kind is not supported")
        object.__setattr__(self, "host_version", _require_text(self.host_version, "host_version", max_length=128))
        object.__setattr__(self, "control_surface", _require_text(self.control_surface, "control_surface", max_length=256))
        for name in ("capability_manifest_hash", "canonical_skill_hash", "adapter_hash"):
            object.__setattr__(self, name, _require_hash(getattr(self, name), name))
        object.__setattr__(self, "allowed_operations", _normalize_operations(self.allowed_operations))
        object.__setattr__(self, "created_by", _require_text(self.created_by, "created_by", max_length=128))
        if self.status not in PROFILE_STATUSES:
            raise MaxControlError("host profile status is invalid")
        supplied = self.host_profile_id
        expected = _stable_id("host_profile", self.profile_hash)
        if supplied and supplied != expected:
            raise MaxControlError("host_profile_id is not content-addressed")
        object.__setattr__(self, "host_profile_id", expected)

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "host_kind": self.host_kind,
            "host_version": self.host_version,
            "control_surface": self.control_surface,
            "capability_manifest_hash": self.capability_manifest_hash,
            "canonical_skill_hash": self.canonical_skill_hash,
            "adapter_hash": self.adapter_hash,
            "allowed_operations": list(self.allowed_operations),
            "created_by": self.created_by,
            "status": self.status,
        }

    @property
    def profile_hash(self) -> str:
        return canonical_sha256(self.payload)

    def to_mapping(self) -> dict[str, Any]:
        return {"host_profile_id": self.host_profile_id, "profile_hash": self.profile_hash, **self.payload}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AgentHostProfile":
        raw = _strict_mapping(
            value,
            allowed={
                "host_profile_id", "profile_hash", "host_kind", "host_version", "control_surface",
                "capability_manifest_hash", "canonical_skill_hash", "adapter_hash",
                "allowed_operations", "created_by", "status",
            },
            required={
                "host_kind", "host_version", "control_surface", "capability_manifest_hash",
                "canonical_skill_hash", "adapter_hash", "allowed_operations",
            },
            name="AgentHostProfile",
        )
        profile = cls(
            host_kind=_require_text(raw["host_kind"], "host_kind", max_length=64),
            host_version=_require_text(raw["host_version"], "host_version", max_length=128),
            control_surface=_require_text(raw["control_surface"], "control_surface", max_length=256),
            capability_manifest_hash=_require_hash(raw["capability_manifest_hash"], "capability_manifest_hash"),
            canonical_skill_hash=_require_hash(raw["canonical_skill_hash"], "canonical_skill_hash"),
            adapter_hash=_require_hash(raw["adapter_hash"], "adapter_hash"),
            allowed_operations=tuple(raw["allowed_operations"]),
            created_by=_require_text(raw.get("created_by", "server"), "created_by", max_length=128),
            status=_require_text(raw.get("status", "active"), "status", max_length=32),
            host_profile_id=str(raw.get("host_profile_id", "")),
        )
        if "profile_hash" in raw and _require_hash(raw["profile_hash"], "profile_hash") != profile.profile_hash:
            raise MaxControlError("AgentHostProfile hash does not match canonical payload")
        return profile


@dataclass(frozen=True)
class ExecutionBackendProfile:
    """A provider/model invocation contract, independent of its host."""

    backend_kind: str
    provider_name: str
    model_identity: str
    protocol_version: str
    invocation_contract_version: str
    capability_manifest: Any
    credential_strategy: Mapping[str, Any]
    usage_authority_strategy: Mapping[str, Any]
    idempotency_strategy: Mapping[str, Any]
    recovery_strategy: Mapping[str, Any]
    network_policy_requirement: Mapping[str, Any]
    source_egress_requirement: Mapping[str, Any]
    pricing_policy: Mapping[str, Any]
    status: str = "active"
    created_by: str = "server"
    backend_profile_id: str = ""

    def __post_init__(self) -> None:
        if self.backend_kind not in BACKEND_KINDS:
            raise MaxControlError("backend_kind is not supported")
        for name in ("provider_name", "model_identity", "protocol_version", "invocation_contract_version"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name, max_length=256))
        capability = _copy_json(self.capability_manifest, "capability_manifest")
        if not isinstance(capability, (Mapping, list, tuple)):
            raise MaxControlError("capability_manifest must be an object or list")
        object.__setattr__(self, "capability_manifest", deep_freeze(capability))
        for name in (
            "credential_strategy", "usage_authority_strategy", "idempotency_strategy",
            "recovery_strategy", "network_policy_requirement", "source_egress_requirement", "pricing_policy",
        ):
            item = _copy_json(getattr(self, name), name)
            if not isinstance(item, Mapping):
                raise MaxControlError(f"{name} must be an object")
            _walk_for_secrets(item, name)
            object.__setattr__(self, name, deep_freeze(item))
        if self.status not in PROFILE_STATUSES:
            raise MaxControlError("backend profile status is invalid")
        object.__setattr__(self, "created_by", _require_text(self.created_by, "created_by", max_length=128))
        supplied = self.backend_profile_id
        expected = _stable_id("backend_profile", self.profile_hash)
        if supplied and supplied != expected:
            raise MaxControlError("backend_profile_id is not content-addressed")
        object.__setattr__(self, "backend_profile_id", expected)

    @property
    def capability_manifest_hash(self) -> str:
        return canonical_sha256(self.capability_manifest)

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "backend_kind": self.backend_kind,
            "provider_name": self.provider_name,
            "model_identity": self.model_identity,
            "protocol_version": self.protocol_version,
            "invocation_contract_version": self.invocation_contract_version,
            "capability_manifest": self.capability_manifest,
            "capability_manifest_hash": self.capability_manifest_hash,
            "credential_strategy": self.credential_strategy,
            "usage_authority_strategy": self.usage_authority_strategy,
            "idempotency_strategy": self.idempotency_strategy,
            "recovery_strategy": self.recovery_strategy,
            "network_policy_requirement": self.network_policy_requirement,
            "source_egress_requirement": self.source_egress_requirement,
            "pricing_policy": self.pricing_policy,
            "status": self.status,
            "created_by": self.created_by,
        }

    @property
    def profile_hash(self) -> str:
        return canonical_sha256(self.payload)

    def to_mapping(self) -> dict[str, Any]:
        return {"backend_profile_id": self.backend_profile_id, "profile_hash": self.profile_hash, **self.payload}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExecutionBackendProfile":
        raw = _strict_mapping(
            value,
            allowed={
                "backend_profile_id", "profile_hash", "backend_kind", "provider_name", "model_identity",
                "protocol_version", "invocation_contract_version", "capability_manifest",
                "capability_manifest_hash", "credential_strategy", "usage_authority_strategy",
                "idempotency_strategy", "recovery_strategy", "network_policy_requirement",
                "source_egress_requirement", "pricing_policy", "status", "created_by",
            },
            required={
                "backend_kind", "provider_name", "model_identity", "protocol_version",
                "invocation_contract_version", "capability_manifest", "credential_strategy",
                "usage_authority_strategy", "idempotency_strategy", "recovery_strategy",
                "network_policy_requirement", "source_egress_requirement", "pricing_policy",
            },
            name="ExecutionBackendProfile",
        )
        profile = cls(
            backend_kind=_require_text(raw["backend_kind"], "backend_kind", max_length=64),
            provider_name=_require_text(raw["provider_name"], "provider_name", max_length=256),
            model_identity=_require_text(raw["model_identity"], "model_identity", max_length=256),
            protocol_version=_require_text(raw["protocol_version"], "protocol_version", max_length=128),
            invocation_contract_version=_require_text(raw["invocation_contract_version"], "invocation_contract_version", max_length=128),
            capability_manifest=raw["capability_manifest"],
            credential_strategy=raw["credential_strategy"],
            usage_authority_strategy=raw["usage_authority_strategy"],
            idempotency_strategy=raw["idempotency_strategy"],
            recovery_strategy=raw["recovery_strategy"],
            network_policy_requirement=raw["network_policy_requirement"],
            source_egress_requirement=raw["source_egress_requirement"],
            pricing_policy=raw["pricing_policy"],
            status=_require_text(raw.get("status", "active"), "status", max_length=32),
            created_by=_require_text(raw.get("created_by", "server"), "created_by", max_length=128),
            backend_profile_id=str(raw.get("backend_profile_id", "")),
        )
        if "capability_manifest_hash" in raw and _require_hash(raw["capability_manifest_hash"], "capability_manifest_hash") != profile.capability_manifest_hash:
            raise MaxControlError("backend capability manifest hash does not match payload")
        if "profile_hash" in raw and _require_hash(raw["profile_hash"], "profile_hash") != profile.profile_hash:
            raise MaxControlError("ExecutionBackendProfile hash does not match canonical payload")
        return profile


@dataclass(frozen=True)
class RunExecutionBinding:
    """The explicit host/backend choice carried by one Max Run."""

    run_id: str
    project_id: str
    host_profile_id: str
    backend_profile_id: str
    backend_profile_hash: str
    capability_manifest_hash: str
    model_identity: str
    source_policy_hash: str
    budget_hash: str
    binding_version: int
    binding_id: str = ""

    def __post_init__(self) -> None:
        for name in ("run_id", "project_id", "host_profile_id", "backend_profile_id", "model_identity"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name, max_length=256))
        for name in ("backend_profile_hash", "capability_manifest_hash", "source_policy_hash", "budget_hash"):
            object.__setattr__(self, name, _require_hash(getattr(self, name), name))
        if isinstance(self.binding_version, bool) or not isinstance(self.binding_version, int) or self.binding_version < 1:
            raise MaxControlError("binding_version must be a positive integer")
        expected = _stable_id("run_execution_binding", self.binding_hash)
        if self.binding_id and self.binding_id != expected:
            raise MaxControlError("binding_id is not content-addressed")
        object.__setattr__(self, "binding_id", expected)

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "project_id": self.project_id,
            "host_profile_id": self.host_profile_id,
            "backend_profile_id": self.backend_profile_id,
            "backend_profile_hash": self.backend_profile_hash,
            "capability_manifest_hash": self.capability_manifest_hash,
            "model_identity": self.model_identity,
            "source_policy_hash": self.source_policy_hash,
            "budget_hash": self.budget_hash,
            "binding_version": self.binding_version,
        }

    @property
    def binding_hash(self) -> str:
        return canonical_sha256(self.payload)

    def to_mapping(self) -> dict[str, Any]:
        return {"binding_id": self.binding_id, "binding_hash": self.binding_hash, **self.payload}


@dataclass(frozen=True)
class BackendHandoffApproval:
    """A server-owned, human-gated backend handoff preview."""

    run_id: str
    project_id: str
    old_binding_id: str | None
    old_host_profile_id: str | None
    old_backend_profile_id: str | None
    old_backend_profile_hash: str | None
    new_host_profile_id: str
    new_backend_profile_id: str
    new_backend_profile_hash: str
    current_research_state_hash: str
    current_checkpoint_id: str | None
    reason_hash: str
    created_at: str
    expires_at: str
    handoff_approval_id: str = ""
    handoff_hash: str = ""
    confirmation_phrase_hash: str = ""
    generation: int = 1
    supersedes_handoff_approval_id: str | None = None
    supersedes_handoff_hash: str | None = None

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "project_id": self.project_id,
            "old_binding_id": self.old_binding_id,
            "old_host_profile_id": self.old_host_profile_id,
            "old_backend_profile_id": self.old_backend_profile_id,
            "old_backend_profile_hash": self.old_backend_profile_hash,
            "new_host_profile_id": self.new_host_profile_id,
            "new_backend_profile_id": self.new_backend_profile_id,
            "new_backend_profile_hash": self.new_backend_profile_hash,
            "current_research_state_hash": self.current_research_state_hash,
            "current_checkpoint_id": self.current_checkpoint_id,
            "reason_hash": self.reason_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "generation": self.generation,
            "supersedes_handoff_approval_id": self.supersedes_handoff_approval_id,
            "supersedes_handoff_hash": self.supersedes_handoff_hash,
        }

    def with_identity(self) -> dict[str, Any]:
        return {
            **self.payload,
            "handoff_approval_id": self.handoff_approval_id,
            "handoff_hash": self.handoff_hash,
            "confirmation_phrase_hash": self.confirmation_phrase_hash,
            "state": "PENDING",
        }


@dataclass(frozen=True)
class NormalizedAgentResult:
    """A bounded agent result that cannot assert canonical authority."""

    cognitive_artifacts: tuple[Any, ...]
    proposed_canonical_objects: tuple[Any, ...]
    proposed_relations: tuple[Any, ...]
    objections: tuple[Any, ...]
    hypotheses: tuple[Any, ...]
    research_questions: tuple[Any, ...]
    usage_receipt: Mapping[str, Any]
    backend_status: str
    provider_call_ref: str | None
    finish_reason: str
    retry_classification: str

    def __post_init__(self) -> None:
        _validate_bounded_json(
            {
                "cognitive_artifacts": self.cognitive_artifacts,
                "proposed_canonical_objects": self.proposed_canonical_objects,
                "proposed_relations": self.proposed_relations,
                "objections": self.objections,
                "hypotheses": self.hypotheses,
                "research_questions": self.research_questions,
                "usage_receipt": self.usage_receipt,
            },
            "normalized_result",
        )
        for name in (
            "cognitive_artifacts", "proposed_canonical_objects", "proposed_relations",
            "objections", "hypotheses", "research_questions",
        ):
            object.__setattr__(self, name, tuple(deep_freeze(item) for item in getattr(self, name)))
        usage = _copy_json(self.usage_receipt, "usage_receipt")
        if not isinstance(usage, Mapping):
            raise MaxControlError("usage_receipt must be an object")
        _walk_for_secrets(usage, "usage_receipt")
        object.__setattr__(self, "usage_receipt", deep_freeze(usage))
        if self.backend_status not in {"succeeded", "failed", "paused", "unavailable", "unknown"}:
            raise MaxControlError("backend_status is invalid")
        if self.provider_call_ref is not None:
            object.__setattr__(self, "provider_call_ref", _require_text(self.provider_call_ref, "provider_call_ref", max_length=256))
        object.__setattr__(self, "finish_reason", _require_text(self.finish_reason, "finish_reason", max_length=128))
        object.__setattr__(self, "retry_classification", _require_text(self.retry_classification, "retry_classification", max_length=128))
        _reject_authority_claims(self.to_mapping())

    def to_mapping(self) -> dict[str, Any]:
        return {
            "cognitive_artifacts": self.cognitive_artifacts,
            "proposed_canonical_objects": self.proposed_canonical_objects,
            "proposed_relations": self.proposed_relations,
            "objections": self.objections,
            "hypotheses": self.hypotheses,
            "research_questions": self.research_questions,
            "usage_receipt": self.usage_receipt,
            "backend_status": self.backend_status,
            "provider_call_ref": self.provider_call_ref,
            "finish_reason": self.finish_reason,
            "retry_classification": self.retry_classification,
        }

    @property
    def result_hash(self) -> str:
        return canonical_sha256(self.to_mapping())

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "NormalizedAgentResult":
        raw = _strict_mapping(
            value,
            allowed={
                "cognitive_artifacts", "proposed_canonical_objects", "proposed_relations", "objections",
                "hypotheses", "research_questions", "usage_receipt", "backend_status", "provider_call_ref",
                "finish_reason", "retry_classification",
            },
            required={
                "cognitive_artifacts", "proposed_canonical_objects", "proposed_relations", "objections",
                "hypotheses", "research_questions", "usage_receipt", "backend_status", "finish_reason",
                "retry_classification",
            },
            name="NormalizedAgentResult",
        )
        for name in (
            "cognitive_artifacts", "proposed_canonical_objects", "proposed_relations",
            "objections", "hypotheses", "research_questions",
        ):
            if not isinstance(raw[name], (list, tuple)):
                raise MaxControlError(f"{name} must be a list")
        _validate_bounded_json(raw, "NormalizedAgentResult")
        return cls(
            cognitive_artifacts=tuple(raw["cognitive_artifacts"]),
            proposed_canonical_objects=tuple(raw["proposed_canonical_objects"]),
            proposed_relations=tuple(raw["proposed_relations"]),
            objections=tuple(raw["objections"]),
            hypotheses=tuple(raw["hypotheses"]),
            research_questions=tuple(raw["research_questions"]),
            usage_receipt=raw["usage_receipt"],
            backend_status=_require_text(raw["backend_status"], "backend_status", max_length=64),
            provider_call_ref=raw.get("provider_call_ref"),
            finish_reason=_require_text(raw["finish_reason"], "finish_reason", max_length=128),
            retry_classification=_require_text(raw.get("retry_classification", "not_applicable"), "retry_classification", max_length=128),
        )


def _reject_authority_claims(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).casefold()
            if lowered in {"verified", "accepted", "approved", "completed", "final", "authority"} and item is True:
                raise MaxControlError(f"agent result cannot assert authority at {path}.{key}")
            if lowered in {"status", "state", "decision", "finish_status"} and isinstance(item, str) and item.casefold() in _FORBIDDEN_AUTHORITY_WORDS:
                raise MaxControlError(f"agent result contains an authority state at {path}.{key}")
            _reject_authority_claims(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_authority_claims(item, f"{path}[{index}]")


def _stable_id(kind: str, digest: str) -> str:
    return f"mr1:{kind}:{digest}"


def _backend_redacted(profile: ExecutionBackendProfile) -> dict[str, Any]:
    # MappingProxy/tuple values are useful inside frozen contracts but the
    # command-line boundary must return ordinary JSON data.
    value = json.loads(canonical_json(profile.to_mapping()))
    strategy = value.get("credential_strategy", {})
    value["credential_strategy"] = {
        "kind": strategy.get("kind", "redacted"),
        "reference": "[redacted]",
        "reference_hash": canonical_sha256(strategy),
    }
    return value


def _builtin_host(host_kind: str) -> dict[str, Any]:
    """Describe a host kind without manufacturing an install identity.

    A declarative host-kind description is useful for discovery, but it is not
    evidence that this host has the canonical Skill, adapter, or package
    installed.  The hashes therefore remain absent until a server-owned
    installation attestation is registered.
    """
    if host_kind not in HOST_KINDS:
        raise MaxControlError("unsupported host kind")
    return {
        "host_kind": host_kind,
        "host_version": "max-portability/v1",
        "control_surface": "research-kb max portability",
        "capability_manifest_hash": None,
        "canonical_skill_hash": None,
        "adapter_hash": None,
        "allowed_operations": ["discover", "bind-backend", "preview-backend-handoff", "checkpoint", "resume"],
        "status": "active",
        "registered": False,
        "attested": False,
        "bindable": False,
        "identity_kind": "declarative_host_kind_only",
    }


def opencode_go_backend_profile() -> ExecutionBackendProfile:
    """Return the ordinary OpenAI-compatible profile; it is not a default."""

    caps = {
        "max_provider_calls": 1,
        "max_input_tokens": 4096,
        "max_output_tokens": 256,
        "retry": 0,
        "redirect": False,
    }
    return ExecutionBackendProfile(
        backend_kind="openai_compatible_http",
        provider_name="OpenCode Go",
        model_identity="deepseek-v4-flash",
        protocol_version="openai-compatible-http/v1",
        invocation_contract_version="max-research-invocation/v1",
        capability_manifest=caps,
        credential_strategy={"kind": "environment", "name": "OPENCODE_GO_API_KEY", "value_access": "server-only-at-send-boundary"},
        usage_authority_strategy={"kind": "provider-attested", "required": True},
        idempotency_strategy={"kind": "server-generated-request-key", "retry": False},
        recovery_strategy={"send_unknown": "freeze", "pre_send_failure": "close_without_retry"},
        network_policy_requirement={"scheme": "https", "hostname": "opencode.ai", "port": 443, "ssrf_check": "required"},
        source_egress_requirement={"kind": "server-owned-source-packet", "raw_text_persistence": False},
        pricing_policy={"human_ceiling_micro_usd": 1000, "effective_cap_micro_usd": 729},
    )


def supported_backend_descriptors() -> list[dict[str, Any]]:
    return [
        {"backend_kind": kind, "registered_only": True, "default_selection": False}
        for kind in BACKEND_KINDS
    ]


class MaxPortabilityService:
    """Server-owned registry and binding service for portable Max Runs."""

    def __init__(self, repository: MaxControlRepository, actor: Actor):
        self.repository = repository
        self.actor = actor

    def _admin(self) -> None:
        try:
            require_admin(self.actor)
        except PolicyError as exc:
            raise MaxControlError("Max portability writes require human admin authority") from exc

    def _now(self) -> tuple[str, Any]:
        now_dt = _utc_now(self.repository.clock)
        return _timestamp(self.repository.clock), now_dt

    @staticmethod
    def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone() is not None

    @staticmethod
    def _is_fixture_control_store(connection: sqlite3.Connection) -> bool:
        """Recognize only the reviewed fixture marker, never a caller flag."""

        marker = connection.execute(
            "SELECT marker_json, marker_hash, fixture_identity, authority_id "
            "FROM max_fixture_control_markers WHERE marker_id='fixture-control-db'"
        ).fetchone()
        if marker is None:
            return False
        expected = {
            "marker_id": "fixture-control-db",
            "marker_kind": "fixture-control-db",
            "fixture_identity": "research-kb-mr2a-fixture/v1",
            "authority_id": "fixture-authority",
        }
        return (
            _loads_safe(marker["marker_json"]) == expected
            and marker["marker_hash"] == _hash(expected)
            and marker["fixture_identity"] == expected["fixture_identity"]
            and marker["authority_id"] == expected["authority_id"]
        )

    def _effective_profile_status(
        self, connection: sqlite3.Connection, *, profile_kind: str, profile_id: str, base_status: str
    ) -> str:
        if self._table_exists(connection, "max_portability_profile_status_events"):
            row = connection.execute(
                "SELECT status FROM max_portability_profile_status_events "
                "WHERE profile_kind=? AND profile_id=? ORDER BY sequence_no DESC LIMIT 1",
                (profile_kind, profile_id),
            ).fetchone()
            if row is not None:
                return str(row["status"])
        return str(base_status)

    def _append_profile_status_locked(
        self,
        connection: sqlite3.Connection,
        *,
        profile_kind: str,
        profile_id: str,
        status: str,
        reason: str,
        now: str,
    ) -> dict[str, Any]:
        if status not in PROFILE_STATUSES:
            raise MaxControlError("profile status is invalid")
        previous = connection.execute(
            "SELECT sequence_no,status FROM max_portability_profile_status_events "
            "WHERE profile_kind=? AND profile_id=? ORDER BY sequence_no DESC LIMIT 1",
            (profile_kind, profile_id),
        ).fetchone()
        if previous is not None:
            prior_status = str(previous["status"])
            if prior_status == status:
                return {
                    "status": status,
                    "sequence_no": int(previous["sequence_no"]),
                    "idempotent": True,
                }
            if prior_status == "revoked" or (prior_status == "disabled" and status == "active"):
                raise MaxControlError("profile status transition is not permitted")
            sequence = int(previous["sequence_no"]) + 1
        else:
            sequence = 1
        reason_hash = canonical_sha256(_require_text(reason, "reason", max_length=2000))
        status_value = {
            "profile_kind": profile_kind,
            "profile_id": profile_id,
            "status": status,
            "sequence_no": sequence,
            "reason_hash": reason_hash,
            "created_at": now,
        }
        status_hash = canonical_sha256(status_value)
        event_id = _stable_id("portability_profile_status", status_hash)
        connection.execute(
            "INSERT INTO max_portability_profile_status_events(" 
            "status_event_id,profile_kind,profile_id,status,sequence_no,reason_hash,status_json,status_hash,created_at,actor_id,actor_kind,actor_session) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, profile_kind, profile_id, status, sequence, reason_hash,
             canonical_json(status_value), status_hash, now, self.actor.actor_id,
             self.actor.actor_kind, self.actor.session_id),
        )
        self._append_portability_event(
            connection,
            stream_key=f"{profile_kind}:{profile_id}",
            event_type=f"{profile_kind}_profile_status_changed",
            payload={"profile_id": profile_id, "status": status, "sequence_no": sequence, "status_hash": status_hash},
            now=now,
        )
        return {"status": status, "sequence_no": sequence, "status_hash": status_hash, "idempotent": False}

    def _assert_host_installation_locked(
        self, connection: sqlite3.Connection, *, host: sqlite3.Row
    ) -> None:
        """Require an attested installation for non-fixture control stores."""

        if self._is_fixture_control_store(connection):
            return
        rows = connection.execute(
            "SELECT * FROM max_host_installations WHERE host_profile_id=? "
            "AND registered=1 AND attested=1 AND bindable=1 ORDER BY created_at DESC, installation_id DESC",
            (host["host_profile_id"],),
        ).fetchall()
        for installation in rows:
            if (
                installation["canonical_skill_hash"] == host["canonical_skill_hash"]
                and installation["adapter_hash"] == host["adapter_hash"]
                and installation["capability_artifact_hash"] == host["capability_manifest_hash"]
            ):
                attestation = None
                if self._table_exists(connection, "max_host_installation_attestations"):
                    attestation = connection.execute(
                        "SELECT * FROM max_host_installation_attestations "
                        "WHERE installation_id=? ORDER BY created_at DESC LIMIT 1",
                        (installation["installation_id"],),
                    ).fetchone()
                if attestation is None:
                    continue
                attestation_value = _loads_safe(attestation["attestation_json"])
                if (
                    not isinstance(attestation_value, Mapping)
                    or canonical_sha256(attestation_value) != attestation["attestation_hash"]
                    or attestation["host_profile_id"] != host["host_profile_id"]
                    or attestation["attestation_kind"] not in {"admin_declared", "trusted_local_verifier"}
                ):
                    continue
                return
        raise MaxControlError("host profile has no attested bindable installation")

    def register_host_installation(
        self,
        *,
        host_profile_id: str,
        package_identity_hash: str,
        canonical_skill_hash: str,
        adapter_hash: str,
        capability_artifact_hash: str,
        attestation_id: str,
        registered: bool = True,
        attested: bool = True,
        bindable: bool = True,
    ) -> dict[str, Any]:
        """Register a server-owned, attested installation without paths."""

        self._admin()
        hashes = {
            "package_identity_hash": _require_hash(package_identity_hash, "package_identity_hash"),
            "canonical_skill_hash": _require_hash(canonical_skill_hash, "canonical_skill_hash"),
            "adapter_hash": _require_hash(adapter_hash, "adapter_hash"),
            "capability_artifact_hash": _require_hash(capability_artifact_hash, "capability_artifact_hash"),
        }
        attestation_id = _require_text(attestation_id, "attestation_id", max_length=256)
        flags = {"registered": bool(registered), "attested": bool(attested), "bindable": bool(bindable)}
        now, _ = self._now()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                host = connection.execute("SELECT * FROM max_agent_host_profiles WHERE host_profile_id=?", (host_profile_id,)).fetchone()
                if host is None:
                    raise MaxControlError("Agent Host profile was not found")
                # Installation identity is content-addressed by the
                # attestation facts, not by wall-clock time.  This makes a
                # replay of the same attestation idempotent while the
                # server-owned created_at column remains audit metadata.
                payload = {"host_profile_id": host_profile_id, "attestation_id": attestation_id, **hashes, **flags}
                installation_hash = canonical_sha256(payload)
                installation_id = _stable_id("host_installation", installation_hash)
                existing = connection.execute("SELECT installation_json,installation_hash FROM max_host_installations WHERE installation_id=?", (installation_id,)).fetchone()
                if existing is not None:
                    if existing["installation_hash"] != installation_hash or existing["installation_json"] != canonical_json(payload):
                        raise MaxControlError("host installation id collision")
                    attestation = connection.execute(
                        "SELECT attestation_id,attestation_hash,attestation_kind,verifier_authority,executable_proof "
                        "FROM max_host_installation_attestations WHERE installation_id=?",
                        (installation_id,),
                    ).fetchone() if self._table_exists(connection, "max_host_installation_attestations") else None
                    if attestation is None:
                        raise MaxControlError("host installation attestation is incomplete")
                    return {
                        "ok": True, "idempotent": True, "installation_id": installation_id,
                        "installation_hash": installation_hash,
                        "attestation_kind": attestation["attestation_kind"],
                        "verifier_authority": attestation["verifier_authority"],
                        "executable_proof": bool(attestation["executable_proof"]),
                    }
                connection.execute(
                    "INSERT INTO max_host_installations(installation_id,host_profile_id,package_identity_hash,canonical_skill_hash,adapter_hash,capability_artifact_hash,attestation_id,registered,attested,bindable,installation_json,installation_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (installation_id, host_profile_id, hashes["package_identity_hash"], hashes["canonical_skill_hash"], hashes["adapter_hash"], hashes["capability_artifact_hash"], attestation_id, int(flags["registered"]), int(flags["attested"]), int(flags["bindable"]), canonical_json(payload), installation_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
                )
                attestation_value = {
                    "installation_id": installation_id,
                    "host_profile_id": host_profile_id,
                    "installation_hash": installation_hash,
                    "attestation_id": attestation_id,
                    "attestation_kind": "admin_declared",
                    "verifier_authority": "admin_declared",
                    "executable_proof": False,
                    "declared_facts": hashes,
                    "created_at": now,
                }
                attestation_hash = canonical_sha256(attestation_value)
                connection.execute(
                    "INSERT INTO max_host_installation_attestations(attestation_id,installation_id,host_profile_id,attestation_kind,verifier_authority,executable_proof,attestation_json,attestation_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (attestation_id, installation_id, host_profile_id, "admin_declared", "admin_declared", 0, canonical_json(attestation_value), attestation_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
                )
                event = self._append_portability_event(connection, stream_key=f"host:{host_profile_id}", event_type="host_installation_admin_attested", payload={"host_profile_id": host_profile_id, "installation_id": installation_id, "installation_hash": installation_hash, "attestation_hash": attestation_hash, "attestation_kind": "admin_declared"}, now=now)
            return {"ok": True, "idempotent": False, "installation_id": installation_id, "installation_hash": installation_hash, "attestation_hash": attestation_hash, "attestation_kind": "admin_declared", "verifier_authority": "admin_declared", "executable_proof": False, "event": event}
        finally:
            connection.close()

    def _change_profile_status(self, *, profile_kind: str, profile_id: str, status: str, reason: str) -> dict[str, Any]:
        self._admin()
        if profile_kind not in {"host", "backend"}:
            raise MaxControlError("profile kind is invalid")
        now, _ = self._now()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                table = "max_agent_host_profiles" if profile_kind == "host" else "max_execution_backend_profiles"
                key = "host_profile_id" if profile_kind == "host" else "backend_profile_id"
                row = connection.execute(f"SELECT status FROM {table} WHERE {key}=?", (profile_id,)).fetchone()
                if row is None:
                    raise MaxControlError("profile was not found")
                current = self._effective_profile_status(connection, profile_kind=profile_kind, profile_id=profile_id, base_status=row["status"])
                if current == "revoked" and status != "revoked":
                    raise MaxControlError("revoked profile cannot be re-enabled")
                result = self._append_profile_status_locked(connection, profile_kind=profile_kind, profile_id=profile_id, status=status, reason=reason, now=now)
            return {"ok": True, "profile_kind": profile_kind, "profile_id": profile_id, "previous_status": current, **result}
        finally:
            connection.close()

    def disable_profile(self, *, profile_kind: str, profile_id: str, reason: str) -> dict[str, Any]:
        return self._change_profile_status(profile_kind=profile_kind, profile_id=profile_id, status="disabled", reason=reason)

    def revoke_profile(self, *, profile_kind: str, profile_id: str, reason: str) -> dict[str, Any]:
        return self._change_profile_status(profile_kind=profile_kind, profile_id=profile_id, status="revoked", reason=reason)

    def host_installation_status(self, *, host_profile_id: str) -> dict[str, Any]:
        """Return only redacted installation attestations for one host."""

        connection = self.repository._connect(read_only=True)
        try:
            host = connection.execute(
                "SELECT host_profile_id,host_kind,profile_hash,status FROM max_agent_host_profiles WHERE host_profile_id=?",
                (host_profile_id,),
            ).fetchone()
            if host is None:
                raise MaxControlError("Agent Host profile was not found")
            rows = list(connection.execute(
                "SELECT installation_id,installation_hash,package_identity_hash,canonical_skill_hash,adapter_hash,capability_artifact_hash,attestation_id,registered,attested,bindable,created_at FROM max_host_installations WHERE host_profile_id=? ORDER BY created_at,installation_id",
                (host_profile_id,),
            ))
            return {
                "ok": True,
                "host_profile_id": host["host_profile_id"],
                "host_kind": host["host_kind"],
                "profile_hash": host["profile_hash"],
                "profile_status": self._effective_profile_status(connection, profile_kind="host", profile_id=host_profile_id, base_status=host["status"]),
                "installations": [
                    {
                        "installation_id": row["installation_id"],
                        "installation_hash": row["installation_hash"],
                        "package_identity_hash": row["package_identity_hash"],
                        "canonical_skill_hash": row["canonical_skill_hash"],
                        "adapter_hash": row["adapter_hash"],
                        "capability_artifact_hash": row["capability_artifact_hash"],
                        "attestation_id": row["attestation_id"],
                        "registered": bool(row["registered"]),
                        "attested": bool(row["attested"]),
                        "bindable": bool(row["bindable"]),
                        "created_at": row["created_at"],
                        **(
                            {
                                "attestation_kind": attestation["attestation_kind"],
                                "verifier_authority": attestation["verifier_authority"],
                                "executable_proof": bool(attestation["executable_proof"]),
                                "attestation_hash": attestation["attestation_hash"],
                            }
                            if (attestation := connection.execute(
                                "SELECT attestation_kind,verifier_authority,executable_proof,attestation_hash "
                                "FROM max_host_installation_attestations WHERE installation_id=?",
                                (row["installation_id"],),
                            ).fetchone()) is not None
                            else {"attestation_kind": None, "verifier_authority": None, "executable_proof": False, "attestation_hash": None}
                        ),
                    }
                    for row in rows
                ],
            }
        finally:
            connection.close()

    disable_backend_profile = lambda self, *, profile_id, reason: self.disable_profile(profile_kind="backend", profile_id=profile_id, reason=reason)
    revoke_backend_profile = lambda self, *, profile_id, reason: self.revoke_profile(profile_kind="backend", profile_id=profile_id, reason=reason)
    disable_host_profile = lambda self, *, profile_id, reason: self.disable_profile(profile_kind="host", profile_id=profile_id, reason=reason)
    revoke_host_profile = lambda self, *, profile_id, reason: self.revoke_profile(profile_kind="host", profile_id=profile_id, reason=reason)

    def _append_portability_event(self, connection: sqlite3.Connection, *, stream_key: str, event_type: str, payload: Mapping[str, Any], now: str) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence_no,event_hash FROM max_portability_events WHERE stream_key=? ORDER BY sequence_no DESC LIMIT 1",
            (stream_key,),
        ).fetchone()
        sequence = int(previous["sequence_no"]) + 1 if previous else 1
        previous_hash = previous["event_hash"] if previous else None
        payload_json = canonical_json(payload)
        payload_hash = canonical_sha256(payload)
        identity = {
            "stream_key": stream_key,
            "sequence_no": sequence,
            "event_type": event_type,
            "payload_hash": payload_hash,
            "previous_event_hash": previous_hash,
            "created_at": now,
            "actor_id": self.actor.actor_id,
            "actor_kind": self.actor.actor_kind,
            "actor_session": self.actor.session_id,
        }
        event_hash = canonical_sha256(identity)
        event_id = _stable_id("portability_event", event_hash)
        connection.execute(
            "INSERT INTO max_portability_events(event_id,stream_key,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, stream_key, sequence, event_type, payload_json, payload_hash, previous_hash, event_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
        )
        return {"event_id": event_id, "sequence_no": sequence, "event_type": event_type, "event_hash": event_hash}

    def _append_handoff_event(self, connection: sqlite3.Connection, *, handoff_id: str, run_id: str, event_type: str, state: str, payload: Mapping[str, Any], now: str) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence_no,event_hash FROM max_backend_handoff_events WHERE handoff_approval_id=? ORDER BY sequence_no DESC LIMIT 1",
            (handoff_id,),
        ).fetchone()
        sequence = int(previous["sequence_no"]) + 1 if previous else 1
        previous_hash = previous["event_hash"] if previous else None
        payload_json = canonical_json(payload)
        payload_hash = canonical_sha256(payload)
        identity = {
            "handoff_approval_id": handoff_id,
            "run_id": run_id,
            "sequence_no": sequence,
            "event_type": event_type,
            "state": state,
            "payload_hash": payload_hash,
            "previous_event_hash": previous_hash,
            "created_at": now,
        }
        event_hash = canonical_sha256(identity)
        event_id = _stable_id("backend_handoff_event", event_hash)
        connection.execute(
            "INSERT INTO max_backend_handoff_events(event_id,handoff_approval_id,run_id,sequence_no,event_type,state,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, handoff_id, run_id, sequence, event_type, state, payload_json, payload_hash, previous_hash, event_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
        )
        return {"event_id": event_id, "sequence_no": sequence, "event_type": event_type, "state": state, "event_hash": event_hash}

    def register_host_profile(self, *, profile: AgentHostProfile | Mapping[str, Any]) -> dict[str, Any]:
        self._admin()
        value = profile if isinstance(profile, AgentHostProfile) else AgentHostProfile.from_mapping(profile)
        now, _ = self._now()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                existing = connection.execute("SELECT * FROM max_agent_host_profiles WHERE host_profile_id=?", (value.host_profile_id,)).fetchone()
                if existing is not None:
                    if existing["profile_json"] != canonical_json(value.to_mapping()) or existing["profile_hash"] != value.profile_hash:
                        raise MaxControlError("Agent Host profile id collision")
                    return {"ok": True, "idempotent": True, "host_profile": value.to_mapping()}
                connection.execute(
                    "INSERT INTO max_agent_host_profiles(host_profile_id,host_kind,host_version,control_surface,capability_manifest_hash,canonical_skill_hash,adapter_hash,allowed_operations_json,created_by,status,created_at,profile_json,profile_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (value.host_profile_id, value.host_kind, value.host_version, value.control_surface, value.capability_manifest_hash, value.canonical_skill_hash, value.adapter_hash, canonical_json(list(value.allowed_operations)), value.created_by, value.status, now, canonical_json(value.to_mapping()), value.profile_hash),
                )
                status_event = self._append_profile_status_locked(
                    connection, profile_kind="host", profile_id=value.host_profile_id,
                    status=value.status, reason="profile_registered", now=now,
                )
                event = self._append_portability_event(connection, stream_key=f"host:{value.host_profile_id}", event_type="host_profile_registered", payload={"host_profile_id": value.host_profile_id, "profile_hash": value.profile_hash, "host_kind": value.host_kind}, now=now)
            return {"ok": True, "idempotent": False, "host_profile": value.to_mapping(), "status_event": status_event, "event": event}
        finally:
            connection.close()

    def register_backend_profile(self, *, profile: ExecutionBackendProfile | Mapping[str, Any]) -> dict[str, Any]:
        self._admin()
        value = profile if isinstance(profile, ExecutionBackendProfile) else ExecutionBackendProfile.from_mapping(profile)
        now, _ = self._now()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                existing = connection.execute("SELECT * FROM max_execution_backend_profiles WHERE backend_profile_id=?", (value.backend_profile_id,)).fetchone()
                if existing is not None:
                    if existing["profile_json"] != canonical_json(value.to_mapping()) or existing["profile_hash"] != value.profile_hash:
                        raise MaxControlError("Execution Backend profile id collision")
                    return {"ok": True, "idempotent": True, "backend_profile": _backend_redacted(value)}
                connection.execute(
                    "INSERT INTO max_execution_backend_profiles(backend_profile_id,backend_kind,provider_name,model_identity,protocol_version,invocation_contract_version,capability_manifest_json,capability_manifest_hash,credential_strategy_json,usage_authority_strategy_json,idempotency_strategy_json,recovery_strategy_json,network_policy_requirement_json,source_egress_requirement_json,pricing_policy_json,status,created_by,created_at,profile_json,profile_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (value.backend_profile_id, value.backend_kind, value.provider_name, value.model_identity, value.protocol_version, value.invocation_contract_version, canonical_json(value.capability_manifest), value.capability_manifest_hash, canonical_json(value.credential_strategy), canonical_json(value.usage_authority_strategy), canonical_json(value.idempotency_strategy), canonical_json(value.recovery_strategy), canonical_json(value.network_policy_requirement), canonical_json(value.source_egress_requirement), canonical_json(value.pricing_policy), value.status, value.created_by, now, canonical_json(value.to_mapping()), value.profile_hash),
                )
                status_event = self._append_profile_status_locked(
                    connection, profile_kind="backend", profile_id=value.backend_profile_id,
                    status=value.status, reason="profile_registered", now=now,
                )
                event = self._append_portability_event(connection, stream_key=f"backend:{value.backend_profile_id}", event_type="backend_profile_registered", payload={"backend_profile_id": value.backend_profile_id, "profile_hash": value.profile_hash, "backend_kind": value.backend_kind}, now=now)
            return {"ok": True, "idempotent": False, "backend_profile": _backend_redacted(value), "status_event": status_event, "event": event}
        finally:
            connection.close()

    def list_hosts(self) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            rows = list(connection.execute("SELECT profile_json FROM max_agent_host_profiles ORDER BY host_kind,host_version,host_profile_id"))
            registered = []
            for row in rows:
                profile = AgentHostProfile.from_mapping(json.loads(row[0]))
                value = profile.to_mapping()
                value["status"] = self._effective_profile_status(
                    connection, profile_kind="host", profile_id=profile.host_profile_id, base_status=profile.status
                )
                installation = connection.execute(
                    "SELECT installation_id, installation_hash, registered, attested, bindable "
                    "FROM max_host_installations WHERE host_profile_id=? ORDER BY created_at DESC LIMIT 1",
                    (profile.host_profile_id,),
                ).fetchone()
                value["installation"] = None if installation is None else {
                    "installation_id": installation["installation_id"],
                    "installation_hash": installation["installation_hash"],
                    "registered": bool(installation["registered"]),
                    "attested": bool(installation["attested"]),
                    "bindable": bool(installation["bindable"]),
                }
                registered.append(value)
            return {"ok": True, "supported_host_kinds": list(HOST_KINDS), "registered": registered}
        finally:
            connection.close()

    def describe_host(self, *, host_profile_id: str | None = None, host_kind: str | None = None) -> dict[str, Any]:
        if host_profile_id is None and host_kind is None:
            raise MaxControlError("host-describe requires a profile id or host kind")
        if host_profile_id is None:
            return {"ok": True, "registered": False, "host_profile": _builtin_host(str(host_kind))}
        connection = self.repository._connect(read_only=True)
        try:
            row = connection.execute("SELECT profile_json FROM max_agent_host_profiles WHERE host_profile_id=?", (host_profile_id,)).fetchone()
            if row is None:
                raise MaxControlError("Agent Host profile was not found")
            profile = AgentHostProfile.from_mapping(json.loads(row[0]))
            value = profile.to_mapping()
            value["status"] = self._effective_profile_status(
                connection, profile_kind="host", profile_id=profile.host_profile_id, base_status=profile.status
            )
            value["attested_installation"] = any(
                bool(item["registered"] and item["attested"] and item["bindable"])
                and item["canonical_skill_hash"] == profile.canonical_skill_hash
                and item["adapter_hash"] == profile.adapter_hash
                and item["capability_artifact_hash"] == profile.capability_manifest_hash
                for item in connection.execute(
                    "SELECT registered,attested,bindable,canonical_skill_hash,adapter_hash,capability_artifact_hash "
                    "FROM max_host_installations WHERE host_profile_id=?", (profile.host_profile_id,)
                )
            )
            return {"ok": True, "registered": True, "host_profile": value}
        finally:
            connection.close()

    def list_backends(self) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            rows = list(connection.execute("SELECT profile_json FROM max_execution_backend_profiles ORDER BY backend_kind,provider_name,model_identity,backend_profile_id"))
            registered = []
            for row in rows:
                profile = ExecutionBackendProfile.from_mapping(json.loads(row[0]))
                value = _backend_redacted(profile)
                value["status"] = self._effective_profile_status(
                    connection, profile_kind="backend", profile_id=profile.backend_profile_id, base_status=profile.status
                )
                registered.append(value)
            return {"ok": True, "supported_backend_kinds": supported_backend_descriptors(), "registered": registered, "default_backend_profile": None}
        finally:
            connection.close()

    def describe_backend(self, *, backend_profile_id: str | None = None, backend_kind: str | None = None, provider_name: str | None = None, model_identity: str | None = None) -> dict[str, Any]:
        if backend_profile_id is None and backend_kind is None:
            raise MaxControlError("backend-describe requires a profile id or backend kind")
        if backend_profile_id is None:
            if backend_kind == "openai_compatible_http" and (provider_name in (None, "OpenCode Go")) and (model_identity in (None, "deepseek-v4-flash")):
                return {"ok": True, "registered": False, "backend_profile": _backend_redacted(opencode_go_backend_profile())}
            return {"ok": True, "registered": False, "backend_kind": backend_kind, "backend_profile": None}
        connection = self.repository._connect(read_only=True)
        try:
            row = connection.execute("SELECT profile_json FROM max_execution_backend_profiles WHERE backend_profile_id=?", (backend_profile_id,)).fetchone()
            if row is None:
                raise MaxControlError("Execution Backend profile was not found")
            profile = ExecutionBackendProfile.from_mapping(json.loads(row[0]))
            value = _backend_redacted(profile)
            value["status"] = self._effective_profile_status(
                connection, profile_kind="backend", profile_id=profile.backend_profile_id, base_status=profile.status
            )
            return {"ok": True, "registered": True, "backend_profile": value}
        finally:
            connection.close()

    def _profile_rows(self, connection: sqlite3.Connection, *, host_profile_id: str, backend_profile_id: str) -> tuple[sqlite3.Row, sqlite3.Row]:
        host = connection.execute("SELECT * FROM max_agent_host_profiles WHERE host_profile_id=?", (host_profile_id,)).fetchone()
        backend = connection.execute("SELECT * FROM max_execution_backend_profiles WHERE backend_profile_id=?", (backend_profile_id,)).fetchone()
        if host is None or backend is None:
            raise MaxControlError("explicit host and backend profiles are required")
        host_status = self._effective_profile_status(connection, profile_kind="host", profile_id=host_profile_id, base_status=host["status"])
        backend_status = self._effective_profile_status(connection, profile_kind="backend", profile_id=backend_profile_id, base_status=backend["status"])
        if host_status != "active" or backend_status != "active":
            raise MaxControlError("disabled or revoked profile cannot be bound")
        self._assert_host_installation_locked(connection, host=host)
        # Reparse server-owned JSON to make a hash mismatch fail closed.
        host_value = AgentHostProfile.from_mapping(json.loads(host["profile_json"]))
        backend_value = ExecutionBackendProfile.from_mapping(json.loads(backend["profile_json"]))
        if host_value.profile_hash != host["profile_hash"] or backend_value.profile_hash != backend["profile_hash"]:
            raise MaxControlError("profile payload/hash mismatch")
        return host, backend

    def _insert_binding_locked(
        self,
        connection: sqlite3.Connection,
        *,
        run: sqlite3.Row,
        host_profile_id: str,
        backend_profile_id: str,
        source_policy_hash: str,
        budget_hash: str,
        binding_version: int,
        now: str,
        allow_current: bool,
    ) -> dict[str, Any]:
        host, backend = self._profile_rows(connection, host_profile_id=host_profile_id, backend_profile_id=backend_profile_id)
        source_policy_hash = _require_hash(source_policy_hash, "source_policy_hash")
        budget_hash = _require_hash(budget_hash, "budget_hash")
        binding = RunExecutionBinding(
            run_id=run["run_id"],
            project_id=run["project_id"],
            host_profile_id=host["host_profile_id"],
            backend_profile_id=backend["backend_profile_id"],
            backend_profile_hash=backend["profile_hash"],
            capability_manifest_hash=backend["capability_manifest_hash"],
            model_identity=backend["model_identity"],
            source_policy_hash=source_policy_hash,
            budget_hash=budget_hash,
            binding_version=binding_version,
        )
        current = connection.execute("SELECT * FROM max_run_execution_binding_current WHERE run_id=?", (run["run_id"],)).fetchone()
        if current is not None and not allow_current:
            history = connection.execute("SELECT * FROM max_run_execution_bindings WHERE binding_id=?", (current["binding_id"],)).fetchone()
            if history is not None and (
                history["host_profile_id"] == host_profile_id
                and history["backend_profile_id"] == backend["backend_profile_id"]
                and history["backend_profile_hash"] == backend["profile_hash"]
                and history["capability_manifest_hash"] == backend["capability_manifest_hash"]
                and history["source_policy_hash"] == source_policy_hash
                and history["budget_hash"] == budget_hash
            ):
                return {
                    "ok": True,
                    "idempotent": True,
                    "binding": json.loads(history["binding_json"]),
                    "current": True,
                }
            if history is not None and history["binding_hash"] == binding.binding_hash:
                return {"ok": True, "idempotent": True, "binding": binding.to_mapping(), "current": True}
            raise MaxControlError("backend binding already exists; use a human-approved handoff")
        existing = connection.execute("SELECT * FROM max_run_execution_bindings WHERE binding_id=?", (binding.binding_id,)).fetchone()
        if existing is not None:
            if existing["binding_json"] != canonical_json(binding.to_mapping()):
                raise MaxControlError("Run Execution binding id collision")
            return {"ok": True, "idempotent": True, "binding": binding.to_mapping(), "current": True}
        connection.execute(
            "INSERT INTO max_run_execution_bindings(binding_id,run_id,project_id,host_profile_id,backend_profile_id,backend_profile_hash,capability_manifest_hash,model_identity,source_policy_hash,budget_hash,binding_version,binding_json,binding_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (binding.binding_id, binding.run_id, binding.project_id, binding.host_profile_id, binding.backend_profile_id, binding.backend_profile_hash, binding.capability_manifest_hash, binding.model_identity, binding.source_policy_hash, binding.budget_hash, binding.binding_version, canonical_json(binding.to_mapping()), binding.binding_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
        )
        current_value = {
            "run_id": binding.run_id,
            "project_id": binding.project_id,
            "binding_id": binding.binding_id,
            "binding_hash": binding.binding_hash,
            "host_profile_id": binding.host_profile_id,
            "backend_profile_id": binding.backend_profile_id,
            "backend_profile_hash": binding.backend_profile_hash,
            "binding_version": binding.binding_version,
        }
        current_hash = canonical_sha256(current_value)
        if current is None:
            connection.execute(
                "INSERT INTO max_run_execution_binding_current(run_id,binding_id,project_id,host_profile_id,backend_profile_id,backend_profile_hash,binding_version,current_json,current_hash,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (binding.run_id, binding.binding_id, binding.project_id, binding.host_profile_id, binding.backend_profile_id, binding.backend_profile_hash, binding.binding_version, canonical_json(current_value), current_hash, now),
            )
        else:
            connection.execute(
                "UPDATE max_run_execution_binding_current SET binding_id=?,project_id=?,host_profile_id=?,backend_profile_id=?,backend_profile_hash=?,binding_version=?,current_json=?,current_hash=?,updated_at=? WHERE run_id=?",
                (binding.binding_id, binding.project_id, binding.host_profile_id, binding.backend_profile_id, binding.backend_profile_hash, binding.binding_version, canonical_json(current_value), current_hash, now, binding.run_id),
            )
        return {"ok": True, "idempotent": False, "binding": binding.to_mapping(), "current": True}

    def bind_backend(
        self,
        *,
        run_id: str,
        host_profile_id: str,
        backend_profile_id: str,
        source_policy_hash: str,
        budget_hash: str,
        capability_manifest_hash: str | None = None,
    ) -> dict[str, Any]:
        self._admin()
        now, _ = self._now()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None:
                    raise MaxControlError("Max run was not found")
                current = connection.execute("SELECT binding_version FROM max_run_execution_binding_current WHERE run_id=?", (run_id,)).fetchone()
                version = int(current["binding_version"]) if current else 0
                value = self._insert_binding_locked(connection, run=run, host_profile_id=host_profile_id, backend_profile_id=backend_profile_id, source_policy_hash=source_policy_hash, budget_hash=budget_hash, binding_version=version + 1, now=now, allow_current=False)
                if capability_manifest_hash is not None and value["binding"]["capability_manifest_hash"] != _require_hash(capability_manifest_hash, "capability_manifest_hash"):
                    raise MaxControlError("capability manifest hash does not match backend profile")
                event = self._append_portability_event(connection, stream_key=f"run:{run_id}", event_type="backend_bound" if not value["idempotent"] else "backend_binding_idempotent", payload={"run_id": run_id, "binding_id": value["binding"]["binding_id"], "binding_hash": value["binding"]["binding_hash"], "host_profile_id": host_profile_id, "backend_profile_id": backend_profile_id}, now=now)
                if not value["idempotent"]:
                    self.repository._append_event(connection, run_id=run_id, event_type="backend_bound", payload={"binding_id": value["binding"]["binding_id"], "binding_hash": value["binding"]["binding_hash"], "host_profile_id": host_profile_id, "backend_profile_id": backend_profile_id}, actor=self.actor, now=now)
            return {**value, "event": event}
        finally:
            connection.close()

    def _assert_portability_quiescent_locked(
        self, connection: sqlite3.Connection, *, run: sqlite3.Row, now_dt: Any
    ) -> dict[str, Any]:
        """Return a complete, server-derived proof that a Run is quiescent.

        The old gate looked at only two provider ``*_current`` projections.
        This gate deliberately inventories every durable activity category
        that can leave an external side effect or a stale worker behind.  It
        returns the proof so callers can persist it in an immutable snapshot;
        it never trusts a caller-supplied count.
        """

        status = str(run["status"]).upper()
        if status != "PAUSED":
            raise MaxControlError("backend handoff requires a PAUSED Run")
        checkpoint = connection.execute(
            "SELECT c.state_hash FROM max_checkpoints c "
            "JOIN max_checkpoint_current p ON p.checkpoint_id=c.checkpoint_id "
            "WHERE p.run_id=?", (run["run_id"],)
        ).fetchone()
        if checkpoint is None or checkpoint["state_hash"] != run["current_state_hash"]:
            raise MaxControlError("backend handoff requires a current checkpoint bound to the Run state")

        terminal = {
            "terminal", "succeeded", "success", "failed", "failure", "cancelled", "canceled",
            "settled", "closed", "released", "completed", "complete", "done", "stopped",
            "drained", "idle", "expired", "rejected", "consumed", "committed", "aborted",
        }

        def columns_for(table: str) -> set[str]:
            return {str(item[1]) for item in connection.execute(f"PRAGMA table_info({table})")}

        def row_is_open(row: sqlite3.Row, columns: set[str], *, no_state_is_open: bool = True) -> bool:
            for name in ("released_at", "closed_at", "finished_at", "consumed_at", "revoked_at", "completed_at"):
                if name in columns and row[name] is not None:
                    return False
            if "expires_at" in columns:
                expiry = _parse_timestamp(row["expires_at"])
                if expiry is not None and expiry <= now_dt:
                    return False
            state_column = next((name for name in ("state", "status", "lifecycle_state", "phase", "result_state", "terminal_status") if name in columns), None)
            if state_column is None:
                return no_state_is_open
            value = row[state_column]
            return value is None or str(value).casefold() not in terminal

        activity = {
            "active_runner_claims": 0,
            "call_groups": 0,
            "reservations": 0,
            "acquisition": 0,
            "scheduler": 0,
            "long_run_authority": 0,
            "authorization_bundles": 0,
            "jit_authority": 0,
            "permits": 0,
            "active_leases": 0,
            "terminal_provider_records": 0,
            "runner_dispatches": 0,
            "network_activity": 0,
            "active_provider_dispatches": 0,
        }
        evidence: dict[str, list[str]] = {key: [] for key in activity}

        for lease in connection.execute(
            "SELECT expires_at,released_at FROM max_leases WHERE run_id=?", (run["run_id"],)
        ).fetchall():
            expiry = _parse_timestamp(lease["expires_at"])
            if lease["released_at"] is None and expiry is not None and expiry > now_dt:
                activity["active_leases"] += 1
                evidence["active_leases"].append(str(lease["expires_at"]))

        def scan_run_tables(names: Sequence[str], category: str, *, no_state_is_open: bool = True) -> None:
            for table in names:
                if not self._table_exists(connection, table):
                    continue
                columns = columns_for(table)
                if "run_id" not in columns:
                    continue
                identity_column = next(
                    (name for name in ("id", "claim_id", "binding_id", "group_id", "authority_id", "permit_id", "grant_id", "session_id") if name in columns),
                    None,
                )
                for row in connection.execute(f"SELECT * FROM {table} WHERE run_id=?", (run["run_id"],)):
                    if row_is_open(row, columns, no_state_is_open=no_state_is_open):
                        activity[category] += 1
                        evidence[category].append(str(row[identity_column]) if identity_column else table)

        scan_run_tables(
            ("max_runner_invocation_claims", "max_runner_claims", "max_runner_call_bindings"),
            "active_runner_claims",
        )
        if self._table_exists(connection, "max_runner_plan_current"):
            for row in connection.execute(
                "SELECT * FROM max_runner_plan_current WHERE run_id=?", (run["run_id"],)
            ):
                if row["active_logical_call_id"] is not None:
                    activity["active_runner_claims"] += 1
                    evidence["active_runner_claims"].append(str(row["active_logical_call_id"]))
        if self._table_exists(connection, "max_model_call_attempts"):
            for row in connection.execute(
                "SELECT attempt_id,stage FROM max_model_call_attempts WHERE run_id=?", (run["run_id"],)
            ):
                stage = str(row["stage"] or "").casefold()
                if stage in {"dispatching", "dispatched", "unknown"}:
                    activity["runner_dispatches"] += 1
                    evidence["runner_dispatches"].append(str(row["attempt_id"]))
                elif stage != "failed":
                    raise MaxControlError("backend handoff encountered an unknown runner attempt state")
        if self._table_exists(connection, "max_model_dispatch_acks"):
            for row in connection.execute(
                "SELECT ack_id,dispatch_status,dispatch_known FROM max_model_dispatch_acks WHERE run_id=?", (run["run_id"],)
            ):
                dispatch_status = str(row["dispatch_status"] or "").casefold()
                if dispatch_status in {"dispatched", "unknown"}:
                    activity["runner_dispatches"] += 1
                    evidence["runner_dispatches"].append(str(row["ack_id"]))
                elif dispatch_status != "not_dispatched" or int(row["dispatch_known"]) not in {0, 1}:
                    raise MaxControlError("backend handoff encountered an unknown dispatch acknowledgement state")
        if self._table_exists(connection, "max_runner_attempt_outcomes"):
            for row in connection.execute(
                "SELECT outcome_id,status FROM max_runner_attempt_outcomes WHERE run_id=?", (run["run_id"],)
            ):
                outcome_status = str(row["status"] or "").casefold()
                if outcome_status == "paused":
                    activity["runner_dispatches"] += 1
                    evidence["runner_dispatches"].append(str(row["outcome_id"]))
                elif outcome_status not in {"completed", "aborted"}:
                    raise MaxControlError("backend handoff encountered an unknown runner outcome state")
        # max_runner_call_groups is immutable history.  Only its current
        # projection can establish whether a group is still open; paused is
        # deliberately non-terminal for handoff purposes.
        if self._table_exists(connection, "max_runner_call_group_current"):
            for row in connection.execute(
                "SELECT * FROM max_runner_call_group_current WHERE run_id=?", (run["run_id"],)
            ):
                status_value = str(row["status"] or "").casefold()
                if status_value not in {"completed", "aborted", "cancelled", "closed"}:
                    activity["call_groups"] += 1
                    evidence["call_groups"].append(str(row["group_id"]))
        if self._table_exists(connection, "max_acquisition_current"):
            for row in connection.execute(
                "SELECT * FROM max_acquisition_current WHERE run_id=?", (run["run_id"],)
            ):
                status_value = str(row["state"] or "").casefold()
                if status_value in {"claimed", "staged", "running", "in_flight"}:
                    activity["acquisition"] += 1
                    evidence["acquisition"].append(str(row["request_id"]))
        if self._table_exists(connection, "max_acquisition_worker_grants"):
            for row in connection.execute(
                "SELECT * FROM max_acquisition_worker_grants WHERE run_id=?", (run["run_id"],)
            ):
                expiry = _parse_timestamp(row["expires_at"])
                consumed = self._table_exists(connection, "max_acquisition_worker_grant_consumptions") and connection.execute(
                    "SELECT 1 FROM max_acquisition_worker_grant_consumptions WHERE worker_grant_id=?",
                    (row["worker_grant_id"],),
                ).fetchone() is not None
                staged = self._table_exists(connection, "max_acquisition_stage_receipts") and connection.execute(
                    "SELECT 1 FROM max_acquisition_stage_receipts WHERE request_id=?",
                    (row["request_id"],),
                ).fetchone() is not None
                if (expiry is None or expiry > now_dt) and not staged:
                    activity["acquisition"] += 1
                    evidence["acquisition"].append(str(row["worker_grant_id"]))
                elif consumed and not staged:
                    activity["acquisition"] += 1
                    evidence["acquisition"].append(str(row["worker_grant_id"]))
        if self._table_exists(connection, "max_acquisition_claims"):
            for row in connection.execute(
                "SELECT * FROM max_acquisition_claims WHERE run_id=?", (run["run_id"],)
            ):
                staged = self._table_exists(connection, "max_acquisition_stage_receipts") and connection.execute(
                    "SELECT 1 FROM max_acquisition_stage_receipts WHERE request_id=?",
                    (row["request_id"],),
                ).fetchone() is not None
                current = connection.execute(
                    "SELECT state FROM max_acquisition_current WHERE request_id=?",
                    (row["request_id"],),
                ).fetchone() if self._table_exists(connection, "max_acquisition_current") else None
                state_value = "" if current is None else str(current["state"] or "").casefold()
                if not staged and state_value not in {"accepted", "rejected", "cancelled"}:
                    activity["acquisition"] += 1
                    evidence["acquisition"].append(str(row["claim_id"]))
        if self._table_exists(connection, "max_worker_current"):
            for row in connection.execute(
                "SELECT * FROM max_worker_current WHERE run_id=?", (run["run_id"],)
            ):
                worker_state = str(row["state"] or "").casefold()
                if worker_state not in {"stopped", "failed", "cancelled", "completed"}:
                    activity["acquisition"] += 1
                    evidence["acquisition"].append(str(row["worker_id"]))
        scan_run_tables(("max_scheduler_current",), "scheduler")
        if self._table_exists(connection, "max_scheduler_sessions"):
            for row in connection.execute(
                "SELECT session_id,status FROM max_scheduler_sessions WHERE run_id=?", (run["run_id"],)
            ):
                session_status = str(row["status"] or "").casefold()
                if session_status in {"active", "paused"}:
                    activity["scheduler"] += 1
                    evidence["scheduler"].append(str(row["session_id"]))
                elif session_status not in {"stopped", "completed", "cancelled"}:
                    raise MaxControlError("backend handoff encountered an unknown scheduler session state")
        if self._table_exists(connection, "max_long_run_window_current"):
            for row in connection.execute(
                "SELECT window_id,state FROM max_long_run_window_current WHERE run_id=?", (run["run_id"],)
            ):
                window_state = str(row["state"] or "").casefold()
                if window_state in {"active", "paused", "draining", "completion_candidate", "acquisition_pending"}:
                    activity["long_run_authority"] += 1
                    evidence["long_run_authority"].append(str(row["window_id"]))
                elif window_state not in {"stopped", "revoked", "expired", "exhausted", "failed", "superseded"}:
                    raise MaxControlError("backend handoff encountered an unknown long-run window state")
        if self._table_exists(connection, "max_live_authorization_bundle_current"):
            for row in connection.execute(
                "SELECT bundle_id,state FROM max_live_authorization_bundle_current WHERE run_id=?", (run["run_id"],)
            ):
                bundle_state = str(row["state"] or "").casefold()
                if bundle_state == "active":
                    activity["authorization_bundles"] += 1
                    evidence["authorization_bundles"].append(str(row["bundle_id"]))
                elif bundle_state not in {"exhausted", "revoked", "expired"}:
                    raise MaxControlError("backend handoff encountered an unknown authorization bundle state")
        if self._table_exists(connection, "max_provider_grant_usage_current"):
            for row in connection.execute(
                "SELECT * FROM max_provider_grant_usage_current WHERE run_id=?", (run["run_id"],)
            ):
                dimensions = (
                    ("input", "reserved_input_tokens", "settled_input_tokens"),
                    ("output", "reserved_output_tokens", "settled_output_tokens"),
                    ("cache", "reserved_cache_read_tokens", "settled_cache_read_tokens"),
                    ("reasoning", "reserved_reasoning_tokens", "settled_reasoning_tokens"),
                    ("cost", "reserved_cost_units", "settled_cost_units"),
                )
                outstanding = any(
                    int(row[reserved]) > int(row[settled]) + int(row["released_cost_units"] if dimension == "cost" else 0)
                    for dimension, reserved, settled in dimensions
                )
                if outstanding:
                    activity["reservations"] += 1
                    evidence["reservations"].append(str(row["grant_id"]))

        def scan_authority_lifecycle(authority_table: str, event_table: str, category: str) -> None:
            if not self._table_exists(connection, authority_table):
                return
            for authority in connection.execute(
                f"SELECT authority_id FROM {authority_table} WHERE run_id=?",
                (run["run_id"],),
            ):
                latest = connection.execute(
                    f"SELECT state FROM {event_table} WHERE authority_id=? ORDER BY sequence_no DESC LIMIT 1",
                    (authority["authority_id"],),
                ).fetchone() if self._table_exists(connection, event_table) else None
                state_value = None if latest is None else str(latest["state"] or "").casefold()
                if state_value != "closed":
                    activity[category] += 1
                    evidence[category].append(str(authority["authority_id"]))

        scan_authority_lifecycle(
            "max_live_canary_native_jit_authorities",
            "max_live_canary_native_jit_events",
            "jit_authority",
        )
        scan_authority_lifecycle(
            "max_live_canary_native_live_jit_authorities",
            "max_live_canary_native_live_jit_events",
            "jit_authority",
        )
        if self._table_exists(connection, "max_live_canary_native_execution_authorizations"):
            for row in connection.execute(
                "SELECT a.execution_authorization_id,a.expires_at FROM max_live_canary_native_execution_authorizations a WHERE a.run_id=?",
                (run["run_id"],),
            ):
                consumed = self._table_exists(connection, "max_live_canary_native_execution_authorization_consumptions") and connection.execute(
                    "SELECT 1 FROM max_live_canary_native_execution_authorization_consumptions WHERE execution_authorization_id=?",
                    (row["execution_authorization_id"],),
                ).fetchone() is not None
                expiry = _parse_timestamp(row["expires_at"])
                if not consumed and (expiry is None or expiry > now_dt):
                    activity["jit_authority"] += 1
                    evidence["jit_authority"].append(str(row["execution_authorization_id"]))
        scan_run_tables(
            (
                "max_live_canary_jit_execution_authorities",
            ),
            "jit_authority",
            no_state_is_open=True,
        )
        scan_run_tables(
            ("max_live_canary_native_execution_previews",),
            "jit_authority",
            no_state_is_open=False,
        )
        scan_run_tables(
            (
                "max_live_canary_execution_permit_current",
                "max_live_canary_source_permit_current",
                "max_live_dispatch_permit_current",
                "max_live_network_authorization_current",
            ),
            "permits",
            no_state_is_open=True,
        )
        if self._table_exists(connection, "max_live_canary_native_source_permit_current"):
            for row in connection.execute(
                "SELECT source_permit_id,state FROM max_live_canary_native_source_permit_current WHERE run_id=?",
                (run["run_id"],),
            ):
                if str(row["state"] or "").casefold() == "issued":
                    activity["permits"] += 1
                    evidence["permits"].append(str(row["source_permit_id"]))
        if self._table_exists(connection, "max_long_run_window_current"):
            for row in connection.execute(
                "SELECT window_id,pending_permit_id,state FROM max_long_run_window_current WHERE run_id=?",
                (run["run_id"],),
            ):
                if row["pending_permit_id"] is not None and str(row["state"] or "").casefold() not in {"stopped", "revoked", "expired", "exhausted", "failed", "superseded"}:
                    activity["permits"] += 1
                    evidence["permits"].append(str(row["pending_permit_id"]))

        if self._table_exists(connection, "max_live_execution_grants"):
            for row in connection.execute(
                "SELECT grant_id,expires_at FROM max_live_execution_grants WHERE run_id=?", (run["run_id"],)
            ):
                closure = self._table_exists(connection, "max_live_execution_grant_closures") and connection.execute(
                    "SELECT 1 FROM max_live_execution_grant_closures WHERE grant_id=?", (row["grant_id"],)
                ).fetchone() is not None
                consumed = self._table_exists(connection, "max_live_execution_grant_consumptions") and connection.execute(
                    "SELECT 1 FROM max_live_execution_grant_consumptions WHERE grant_id=?", (row["grant_id"],)
                ).fetchone() is not None
                expiry = _parse_timestamp(row["expires_at"])
                if not closure and (consumed or expiry is None or expiry > now_dt):
                    activity["jit_authority"] += 1
                    evidence["jit_authority"].append(str(row["grant_id"]))

        if self._table_exists(connection, "max_budget_ledger"):
            reservation_ids = {
                row["reservation_id"] for row in connection.execute(
                    "SELECT reservation_id FROM max_budget_ledger WHERE run_id=? AND reservation_id IS NOT NULL",
                    (run["run_id"],),
                )
            }
            terminal_budget = {"release", "released", "settle", "settled", "usage", "commit", "committed", "refund", "refunded", "cancel", "cancelled"}
            for reservation_id in reservation_ids:
                rows = connection.execute(
                    "SELECT operation,entry_id FROM max_budget_ledger WHERE run_id=? AND reservation_id=? ORDER BY sequence_no DESC, entry_id DESC",
                    (run["run_id"], reservation_id),
                ).fetchall()
                if rows and str(rows[0]["operation"]).casefold() not in terminal_budget:
                    activity["reservations"] += 1
                    evidence["reservations"].append(str(reservation_id))

        if self._table_exists(connection, "max_provider_call_records"):
            columns = columns_for("max_provider_call_records")
            state_column = next((name for name in ("state", "status", "lifecycle_state", "result_state", "terminal_status") if name in columns), None)
            for row in connection.execute("SELECT * FROM max_provider_call_records WHERE run_id=?", (run["run_id"],)):
                state = str(row[state_column]).casefold() if state_column and row[state_column] is not None else "unknown"
                if state not in terminal:
                    raise MaxControlError("backend handoff is blocked by non-terminal provider evidence")
                activity["terminal_provider_records"] += 1

        for table in ("max_provider_dispatch_attempt_current", "max_provider_call_claim_current"):
            if not self._table_exists(connection, table):
                continue
            columns = columns_for(table)
            if "run_id" not in columns:
                continue
            for row in connection.execute(f"SELECT * FROM {table} WHERE run_id=?", (run["run_id"],)):
                if row_is_open(row, columns):
                    activity["active_provider_dispatches"] += 1
                    evidence["active_provider_dispatches"].append(table)
        if self._table_exists(connection, "max_live_network_attempt_records"):
            for row in connection.execute(
                "SELECT live_attempt_id,outcome FROM max_live_network_attempt_records WHERE run_id=?",
                (run["run_id"],),
            ):
                outcome = str(row["outcome"] or "").casefold()
                if outcome in {"unknown", "disputed"}:
                    activity["network_activity"] += 1
                    evidence["network_activity"].append(str(row["live_attempt_id"]))
                elif outcome not in {"not_dispatched", "settled"}:
                    raise MaxControlError("backend handoff encountered an unknown network attempt state")

        blocked = [key for key, value in activity.items() if key != "terminal_provider_records" and value]
        if blocked:
            raise MaxControlError(
                "backend handoff is blocked by active portability activity: " + ", ".join(sorted(blocked))
            )
        return {
            "run_status": status,
            "checkpoint_bound": True,
            **activity,
            "evidence": {key: sorted(values) for key, values in evidence.items() if values},
            "activity_hash": canonical_sha256(activity),
        }

    def _create_quiescence_snapshot_locked(
        self,
        connection: sqlite3.Connection,
        *,
        run: sqlite3.Row,
        handoff_id: str,
        phase: str,
        now: str,
        now_dt: Any,
    ) -> dict[str, Any]:
        """Persist the exact activity proof used by a handoff decision."""

        if phase not in {"preview", "approval_consume"}:
            raise MaxControlError("portability quiescence snapshot phase is invalid")
        current = connection.execute(
            "SELECT binding_id FROM max_run_execution_binding_current WHERE run_id=?", (run["run_id"],)
        ).fetchone()
        if current is None:
            raise MaxControlError("portability quiescence requires a current Run binding")
        activity = self._assert_portability_quiescent_locked(connection, run=run, now_dt=now_dt)
        activity_hash = _require_hash(activity["activity_hash"], "activity_hash")
        payload = {
            "schema": "max-portability-quiescence-snapshot/v1",
            "run_id": run["run_id"],
            "project_id": run["project_id"],
            "handoff_approval_id": handoff_id,
            "phase": phase,
            "state_version": int(run["state_version"]),
            "state_hash": run["current_state_hash"],
            "checkpoint_id": run["current_checkpoint_id"],
            "binding_id": current["binding_id"],
            "activity": activity,
            "activity_hash": activity_hash,
            "created_at": now,
        }
        snapshot_hash = canonical_sha256(payload)
        snapshot_id = _stable_id("portability_quiescence_snapshot", snapshot_hash)
        connection.execute(
            "INSERT INTO max_portability_quiescence_snapshots(snapshot_id,run_id,project_id,handoff_approval_id,phase,state_version,state_hash,checkpoint_id,binding_id,activity_json,activity_hash,snapshot_json,snapshot_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                snapshot_id, run["run_id"], run["project_id"], handoff_id, phase,
                int(run["state_version"]), run["current_state_hash"], run["current_checkpoint_id"],
                current["binding_id"], canonical_json(activity), activity_hash,
                canonical_json(payload), snapshot_hash, now, self.actor.actor_id,
                self.actor.actor_kind, self.actor.session_id,
            ),
        )
        return {"snapshot_id": snapshot_id, "snapshot_hash": snapshot_hash, **activity}

    def _append_rehydration_packet_event_locked(
        self,
        connection: sqlite3.Connection,
        *,
        packet_id: str,
        handoff_id: str,
        run_id: str,
        event_type: str,
        state: str,
        payload: Mapping[str, Any],
        now: str,
    ) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence_no,event_hash FROM max_rehydration_packet_events "
            "WHERE packet_id=? ORDER BY sequence_no DESC LIMIT 1", (packet_id,)
        ).fetchone()
        sequence = int(previous["sequence_no"]) + 1 if previous else 1
        previous_hash = None if previous is None else previous["event_hash"]
        payload_json = canonical_json(payload)
        payload_hash = canonical_sha256(payload)
        identity = {
            "packet_id": packet_id,
            "handoff_approval_id": handoff_id,
            "run_id": run_id,
            "sequence_no": sequence,
            "event_type": event_type,
            "state": state,
            "payload_hash": payload_hash,
            "previous_event_hash": previous_hash,
            "created_at": now,
        }
        event_hash = canonical_sha256(identity)
        event_id = _stable_id("rehydration_packet_event", event_hash)
        connection.execute(
            "INSERT INTO max_rehydration_packet_events(event_id,packet_id,handoff_approval_id,run_id,sequence_no,event_type,state,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, packet_id, handoff_id, run_id, sequence, event_type, state, payload_json, payload_hash, previous_hash, event_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
        )
        return {"event_id": event_id, "sequence_no": sequence, "event_type": event_type, "state": state, "event_hash": event_hash}

    def _create_rehydration_packet_locked(
        self,
        connection: sqlite3.Connection,
        *,
        run: sqlite3.Row,
        handoff: sqlite3.Row,
        old_binding_id: str | None,
        new_binding_id: str,
        now: str,
    ) -> dict[str, Any]:
        object_rows = list(connection.execute(
            "SELECT v.version_id,v.kind,v.payload_hash FROM max_canonical_object_versions v "
            "JOIN max_run_object_memberships m ON m.version_id=v.version_id "
            "WHERE m.run_id=? ORDER BY v.version_id",
            (run["run_id"],),
        ))
        relation_rows = list(connection.execute(
            "SELECT r.relation_id,r.metadata_hash FROM max_canonical_relations r "
            "JOIN max_run_relation_memberships m ON m.relation_id=r.relation_id "
            "WHERE m.run_id=? ORDER BY r.relation_id",
            (run["run_id"],),
        ))
        object_ids = [row["version_id"] for row in object_rows]
        relation_ids = [row["relation_id"] for row in relation_rows]
        category_names = {
            "claim": "claim_ids", "evidence": "evidence_ids", "objection": "objection_ids",
            "hypothesis": "hypothesis_ids", "research_question": "research_question_ids",
            "source_role": "source_role_ids",
        }
        categories: dict[str, list[str]] = {name: [] for name in category_names.values()}
        manifest_items: list[dict[str, Any]] = []
        for row in object_rows:
            kind = str(row["kind"])
            item = {
                "item_type": f"canonical_object:{kind}",
                "item_id": row["version_id"],
                "item_hash": _require_hash(row["payload_hash"], "canonical object payload hash"),
            }
            manifest_items.append(item)
            category = category_names.get(kind.casefold())
            if category is not None:
                categories[category].append(row["version_id"])
        for row in relation_rows:
            manifest_items.append({
                "item_type": "canonical_relation",
                "item_id": row["relation_id"],
                "item_hash": _require_hash(row["metadata_hash"], "canonical relation metadata hash"),
            })
        tip = connection.execute(
            "SELECT event_hash FROM max_events WHERE run_id=? ORDER BY sequence_no DESC LIMIT 1",
            (run["run_id"],),
        ).fetchone()
        manifest_items.extend(
            [
                {"item_type": "checkpoint", "item_id": run["current_checkpoint_id"], "item_hash": _require_hash(connection.execute("SELECT state_hash FROM max_checkpoints WHERE checkpoint_id=?", (run["current_checkpoint_id"],)).fetchone()[0], "checkpoint state hash")},
                {"item_type": "source_policy", "item_id": f"source-policy:{run['run_id']}", "item_hash": _require_hash(run["source_policy_hash"], "source_policy_hash")},
                {"item_type": "budget", "item_id": f"budget:{run['run_id']}", "item_hash": _require_hash(run["budget_hash"], "budget_hash")},
                {"item_type": "frontier:unresolved", "item_id": f"frontier:{run['run_id']}:unresolved", "item_hash": canonical_sha256({"run_id": run["run_id"], "frontier": "unresolved", "ids": []})},
            ]
        )
        manifest_items.sort(key=lambda item: (item["item_type"], item["item_id"]))
        manifest_root = canonical_sha256(manifest_items)
        packet_value = {
            "schema": "max-rehydration-packet/v2",
            "handoff_approval_id": handoff["handoff_approval_id"],
            "handoff_hash": handoff["handoff_hash"],
            "run_id": run["run_id"],
            "project_id": run["project_id"],
            "old_binding_id": old_binding_id,
            "new_binding_id": new_binding_id,
            "checkpoint_id": run["current_checkpoint_id"],
            "state_version": int(run["state_version"]),
            "state_hash": run["current_state_hash"],
            "canonical_object_version_ids": object_ids,
            "canonical_relation_ids": relation_ids,
            **categories,
            "unresolved_frontier_ids": [],
            "event_chain_tip_hash": None if tip is None else tip["event_hash"],
            "source_policy_hash": run["source_policy_hash"],
            "budget_hash": run["budget_hash"],
            "canonical_object_version": 1,
            "manifest_root": manifest_root,
            "manifest_count": len(manifest_items),
            "manifest_cutoff": now,
            "created_at": now,
        }
        packet_hash = canonical_sha256(packet_value)
        packet_id = _stable_id("rehydration_packet", packet_hash)
        connection.execute(
            "INSERT INTO max_rehydration_packets(packet_id,handoff_approval_id,run_id,project_id,old_binding_id,new_binding_id,checkpoint_id,state_version,state_hash,canonical_object_version_ids_json,canonical_relation_ids_json,claim_ids_json,evidence_ids_json,objection_ids_json,hypothesis_ids_json,research_question_ids_json,source_role_ids_json,unresolved_frontier_ids_json,event_chain_tip_hash,source_policy_hash,budget_hash,canonical_object_version,packet_json,packet_hash,state,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (packet_id, handoff["handoff_approval_id"], run["run_id"], run["project_id"], old_binding_id, new_binding_id, run["current_checkpoint_id"], int(run["state_version"]), run["current_state_hash"], canonical_json(object_ids), canonical_json(relation_ids), "[]", "[]", "[]", "[]", "[]", "[]", "[]", packet_value["event_chain_tip_hash"], run["source_policy_hash"], run["budget_hash"], 1, canonical_json(packet_value), packet_hash, "AWAITING_ACK", now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
        )
        for ordinal, item in enumerate(manifest_items):
            item_hash = canonical_sha256(item)
            manifest_item_id = _stable_id("rehydration_manifest_item", canonical_sha256({"packet_id": packet_id, "ordinal": ordinal, **item}))
            connection.execute(
                "INSERT INTO max_rehydration_packet_manifest_items(manifest_item_id,packet_id,ordinal,item_type,item_id,item_hash,item_json,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (manifest_item_id, packet_id, ordinal, item["item_type"], item["item_id"], item["item_hash"], canonical_json(item), now),
            )
        event = self._append_rehydration_packet_event_locked(
            connection, packet_id=packet_id, handoff_id=handoff["handoff_approval_id"],
            run_id=run["run_id"], event_type="created", state="AWAITING_ACK",
            payload={"packet_id": packet_id, "packet_hash": packet_hash, "handoff_hash": handoff["handoff_hash"]}, now=now,
        )
        return {"packet_id": packet_id, "packet_hash": packet_hash, "state": "AWAITING_ACK", "manifest_root": manifest_root, "manifest_count": len(manifest_items), "manifest_cutoff": now, "event": event}

    def rehydration_packet_status(self, *, packet_id: str) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            packet = connection.execute("SELECT * FROM max_rehydration_packets WHERE packet_id=?", (packet_id,)).fetchone()
            if packet is None:
                raise MaxControlError("rehydration packet was not found")
            ack = connection.execute("SELECT ack_id,ack_hash,created_at FROM max_rehydration_packet_acks WHERE packet_id=?", (packet_id,)).fetchone()
            state = "ACKNOWLEDGED" if ack is not None else str(packet["state"])
            target_ack = connection.execute(
                "SELECT target_ack_id,manifest_root,manifest_count,read_complete,target_host_profile_id,target_installation_id,created_at "
                "FROM max_rehydration_packet_target_acks WHERE packet_id=?",
                (packet_id,),
            ).fetchone() if self._table_exists(connection, "max_rehydration_packet_target_acks") else None
            return {"ok": True, "packet_id": packet_id, "packet_hash": packet["packet_hash"], "state": state, "ack": None if ack is None else {"ack_id": ack["ack_id"], "ack_hash": ack["ack_hash"], "created_at": ack["created_at"]}, "target_ack": None if target_ack is None else {"target_ack_id": target_ack["target_ack_id"], "manifest_root": target_ack["manifest_root"], "manifest_count": target_ack["manifest_count"], "read_complete": bool(target_ack["read_complete"]), "target_host_profile_id": target_ack["target_host_profile_id"], "target_installation_id": target_ack["target_installation_id"], "created_at": target_ack["created_at"]}}
        finally:
            connection.close()

    def read_rehydration_packet(self, *, packet_id: str, page_size: int = 64, cursor: str | None = None) -> dict[str, Any]:
        """Return a segmented metadata view; no source/prose payload is exposed."""

        if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1 or page_size > 256:
            raise MaxControlError("rehydration packet page size is invalid")
        if cursor is not None and (not isinstance(cursor, str) or not cursor.isdigit()):
            raise MaxControlError("rehydration packet cursor is invalid")
        offset = int(cursor or "0")
        connection = self.repository._connect(read_only=True)
        try:
            packet = connection.execute(
                "SELECT packet_id,packet_hash,handoff_approval_id,run_id,project_id,new_binding_id,checkpoint_id,state_version,state_hash,canonical_object_version_ids_json,canonical_relation_ids_json,event_chain_tip_hash,source_policy_hash,budget_hash,canonical_object_version,packet_json,created_at FROM max_rehydration_packets WHERE packet_id=?",
                (packet_id,),
            ).fetchone()
            if packet is None:
                raise MaxControlError("rehydration packet was not found")
            packet_value = _loads_safe(packet["packet_json"]) or {}
            items: list[dict[str, Any]] = []
            next_cursor: str | None = None
            if self._table_exists(connection, "max_rehydration_packet_manifest_items"):
                rows = connection.execute(
                    "SELECT ordinal,item_type,item_id,item_hash,item_json FROM max_rehydration_packet_manifest_items WHERE packet_id=? ORDER BY ordinal LIMIT ? OFFSET ?",
                    (packet_id, page_size + 1, offset),
                ).fetchall()
                for row in rows[:page_size]:
                    item = _loads_safe(row["item_json"])
                    if isinstance(item, Mapping):
                        items.append({"ordinal": int(row["ordinal"]), "item_type": row["item_type"], "item_id": row["item_id"], "item_hash": row["item_hash"]})
                if len(rows) > page_size:
                    next_cursor = str(offset + page_size)
            return {"ok": True, "packet": {"packet_id": packet["packet_id"], "packet_hash": packet["packet_hash"], "handoff_approval_id": packet["handoff_approval_id"], "run_id": packet["run_id"], "project_id": packet["project_id"], "new_binding_id": packet["new_binding_id"], "checkpoint_id": packet["checkpoint_id"], "state_version": packet["state_version"], "state_hash": packet["state_hash"], "canonical_object_version_count": len(_loads_safe(packet["canonical_object_version_ids_json"]) or []), "canonical_relation_count": len(_loads_safe(packet["canonical_relation_ids_json"]) or []), "event_chain_tip_hash": packet["event_chain_tip_hash"], "source_policy_hash": packet["source_policy_hash"], "budget_hash": packet["budget_hash"], "canonical_object_version": packet["canonical_object_version"], "manifest_root": packet_value.get("manifest_root"), "manifest_count": packet_value.get("manifest_count"), "manifest_cutoff": packet_value.get("manifest_cutoff"), "manifest_items": items, "next_cursor": next_cursor, "created_at": packet["created_at"]}}
        finally:
            connection.close()

    def acknowledge_rehydration(
        self,
        *,
        packet_id: str,
        packet_hash: str,
        handoff_id: str | None = None,
        new_binding_id: str | None = None,
        target_host_profile_id: str | None = None,
        target_installation_id: str | None = None,
        target_installation_hash: str | None = None,
        adapter_capability_hash: str | None = None,
        target_session: str | None = None,
        observed_checkpoint_hash: str | None = None,
        observed_state_hash: str | None = None,
        rehydrated_state_hash: str | None = None,
        manifest_root: str | None = None,
        manifest_count: int | None = None,
        read_complete: bool | None = None,
    ) -> dict[str, Any]:
        """Record a complete, target-bound rehydration acknowledgement.

        The two-argument form is retained only for the reviewed fixture
        marker.  A real host must identify the target installation, prove it
        read the complete metadata manifest, and echo server-derived state
        hashes.  No client packet contents or target identity become trusted
        merely because their hashes were supplied.
        """

        self._admin()
        packet_hash = _require_hash(packet_hash, "packet_hash")
        now, _ = self._now()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                packet = connection.execute("SELECT * FROM max_rehydration_packets WHERE packet_id=?", (packet_id,)).fetchone()
                if packet is None or packet["packet_hash"] != packet_hash:
                    raise MaxControlError("rehydration packet hash is invalid")
                fixture = self._is_fixture_control_store(connection)
                existing = connection.execute("SELECT * FROM max_rehydration_packet_acks WHERE packet_id=?", (packet_id,)).fetchone()
                if existing is not None:
                    target = connection.execute("SELECT target_ack_id FROM max_rehydration_packet_target_acks WHERE packet_id=?", (packet_id,)).fetchone()
                    if target is None:
                        raise MaxControlError("rehydration acknowledgement has no target proof")
                    if not fixture:
                        if any(
                            item is None for item in (
                                handoff_id, new_binding_id, target_host_profile_id, target_installation_id,
                                target_installation_hash, adapter_capability_hash, target_session,
                                observed_checkpoint_hash, observed_state_hash, rehydrated_state_hash,
                                manifest_root, manifest_count, read_complete,
                            )
                        ):
                            raise MaxControlError("production rehydration acknowledgement requires complete target proof")
                        target_value = connection.execute("SELECT * FROM max_rehydration_packet_target_acks WHERE packet_id=?", (packet_id,)).fetchone()
                        if target_value is None or (
                            handoff_id != target_value["handoff_approval_id"]
                            or new_binding_id != target_value["new_binding_id"]
                            or target_host_profile_id != target_value["target_host_profile_id"]
                            or target_installation_id != target_value["target_installation_id"]
                            or target_installation_hash != target_value["target_installation_hash"]
                            or adapter_capability_hash != target_value["adapter_capability_hash"]
                            or target_session != target_value["target_session"]
                            or observed_checkpoint_hash != target_value["observed_checkpoint_hash"]
                            or observed_state_hash != target_value["observed_state_hash"]
                            or rehydrated_state_hash != target_value["rehydrated_state_hash"]
                            or manifest_root != target_value["manifest_root"]
                            or manifest_count != int(target_value["manifest_count"])
                            or read_complete is not True
                            or target_session != self.actor.session_id
                        ):
                            raise MaxControlError("rehydration acknowledgement target does not match the server record")
                    return {"ok": True, "idempotent": True, "ack_id": existing["ack_id"], "ack_hash": existing["ack_hash"], "target_ack_id": target["target_ack_id"], "state": "ACKNOWLEDGED"}

                fixture = self._is_fixture_control_store(connection)
                packet_value = _loads_safe(packet["packet_json"]) or {}
                manifest_items = list(connection.execute(
                    "SELECT manifest_item_id,ordinal,item_type,item_id,item_hash,item_json FROM max_rehydration_packet_manifest_items WHERE packet_id=? ORDER BY ordinal",
                    (packet_id,),
                )) if self._table_exists(connection, "max_rehydration_packet_manifest_items") else []
                expected_manifest_root = packet_value.get("manifest_root")
                expected_manifest_count = packet_value.get("manifest_count")
                if not isinstance(expected_manifest_root, str) or not _HEX64.fullmatch(expected_manifest_root):
                    expected_manifest_root = canonical_sha256([
                        {"item_type": row["item_type"], "item_id": row["item_id"], "item_hash": row["item_hash"]}
                        for row in manifest_items
                    ])
                if not isinstance(expected_manifest_count, int):
                    expected_manifest_count = len(manifest_items)
                canonical_manifest_items: list[dict[str, Any]] = []
                for expected_ordinal, item in enumerate(manifest_items):
                    item_value = _loads_safe(item["item_json"])
                    if (
                        not isinstance(item_value, Mapping)
                        or int(item["ordinal"]) != expected_ordinal
                        or item_value.get("item_type") != item["item_type"]
                        or item_value.get("item_id") != item["item_id"]
                        or item_value.get("item_hash") != item["item_hash"]
                        or not _HEX64.fullmatch(str(item["item_hash"]))
                        or canonical_json(item_value) != item["item_json"]
                        or item["manifest_item_id"] != _stable_id(
                            "rehydration_manifest_item",
                            canonical_sha256({"packet_id": packet_id, "ordinal": expected_ordinal, **dict(item_value)}),
                        )
                    ):
                        raise MaxControlError("rehydration packet manifest item is invalid")
                    canonical_manifest_items.append({
                        "item_type": item["item_type"],
                        "item_id": item["item_id"],
                        "item_hash": item["item_hash"],
                    })
                if (
                    expected_manifest_count != len(canonical_manifest_items)
                    or expected_manifest_root != canonical_sha256(canonical_manifest_items)
                ):
                    raise MaxControlError("rehydration packet manifest root or count is invalid")

                if fixture:
                    target_host = connection.execute(
                        "SELECT h.host_profile_id,h.adapter_hash,h.capability_manifest_hash FROM max_agent_host_profiles h "
                        "JOIN max_run_execution_bindings b ON b.host_profile_id=h.host_profile_id "
                        "WHERE b.binding_id=?", (packet["new_binding_id"],)
                    ).fetchone()
                    if target_host is None:
                        raise MaxControlError("fixture rehydration target host was not found")
                    handoff_id = packet["handoff_approval_id"]
                    new_binding_id = packet["new_binding_id"]
                    target_host_profile_id = target_host["host_profile_id"]
                    target_installation_id = f"fixture-installation:{target_host_profile_id}"
                    target_installation_hash = canonical_sha256({"installation_id": target_installation_id, "fixture": True})
                    adapter_capability_hash = canonical_sha256({"adapter_hash": target_host["adapter_hash"], "capability_manifest_hash": target_host["capability_manifest_hash"]})
                    target_session = "fixture-compat"
                    observed_checkpoint_hash = packet["state_hash"]
                    observed_state_hash = packet["state_hash"]
                    rehydrated_state_hash = packet["state_hash"]
                    manifest_root = expected_manifest_root
                    manifest_count = expected_manifest_count
                    read_complete = True
                else:
                    if any(item is None for item in (handoff_id, new_binding_id, target_host_profile_id, target_installation_id, target_installation_hash, adapter_capability_hash, target_session, observed_checkpoint_hash, observed_state_hash, rehydrated_state_hash, manifest_root, manifest_count, read_complete)):
                        raise MaxControlError("production rehydration acknowledgement requires complete target proof")
                    if handoff_id != packet["handoff_approval_id"] or new_binding_id != packet["new_binding_id"]:
                        raise MaxControlError("rehydration acknowledgement binding is invalid")
                    if target_session != self.actor.session_id:
                        raise MaxControlError("rehydration acknowledgement target session is not the authenticated session")
                    current_handoff = connection.execute(
                        "SELECT handoff_approval_id,state,binding_id FROM max_backend_handoff_current WHERE run_id=?",
                        (packet["run_id"],),
                    ).fetchone()
                    if (
                        current_handoff is None
                        or current_handoff["handoff_approval_id"] != packet["handoff_approval_id"]
                        or current_handoff["state"] != "CONSUMED"
                        or current_handoff["binding_id"] != packet["new_binding_id"]
                    ):
                        raise MaxControlError("rehydration acknowledgement handoff is not the current consumed handoff")
                    target_installation_hash = _require_hash(target_installation_hash, "target_installation_hash")
                    adapter_capability_hash = _require_hash(adapter_capability_hash, "adapter_capability_hash")
                    observed_checkpoint_hash = _require_hash(observed_checkpoint_hash, "observed_checkpoint_hash")
                    observed_state_hash = _require_hash(observed_state_hash, "observed_state_hash")
                    rehydrated_state_hash = _require_hash(rehydrated_state_hash, "rehydrated_state_hash")
                    manifest_root = _require_hash(manifest_root, "manifest_root")
                    if not isinstance(manifest_count, int) or isinstance(manifest_count, bool) or manifest_count < 0 or read_complete is not True:
                        raise MaxControlError("rehydration manifest read proof is invalid")
                    if manifest_root != expected_manifest_root or manifest_count != expected_manifest_count:
                        raise MaxControlError("rehydration manifest root or count is invalid")
                    if rehydrated_state_hash != packet["state_hash"] or observed_state_hash != packet["state_hash"]:
                        raise MaxControlError("rehydration state proof does not match the packet")
                    checkpoint = connection.execute("SELECT state_hash FROM max_checkpoints WHERE checkpoint_id=? AND run_id=?", (packet["checkpoint_id"], packet["run_id"])).fetchone()
                    if checkpoint is None or checkpoint["state_hash"] != observed_checkpoint_hash:
                        raise MaxControlError("rehydration checkpoint proof is invalid")
                    target_host = connection.execute("SELECT * FROM max_agent_host_profiles WHERE host_profile_id=?", (target_host_profile_id,)).fetchone()
                    if target_host is None:
                        raise MaxControlError("rehydration target host was not found")
                    target_binding = connection.execute(
                        "SELECT backend_profile_id,run_id,project_id FROM max_run_execution_bindings WHERE binding_id=?",
                        (new_binding_id,),
                    ).fetchone()
                    if (
                        target_binding is None
                        or target_binding["run_id"] != packet["run_id"]
                        or target_binding["project_id"] != packet["project_id"]
                    ):
                        raise MaxControlError("rehydration target binding is invalid")
                    self._profile_rows(
                        connection,
                        host_profile_id=target_host_profile_id,
                        backend_profile_id=target_binding["backend_profile_id"],
                    )
                    installation = connection.execute(
                        "SELECT * FROM max_host_installations WHERE installation_id=? AND host_profile_id=? AND registered=1 AND attested=1 AND bindable=1",
                        (target_installation_id, target_host_profile_id),
                    ).fetchone()
                    if installation is None or installation["installation_hash"] != target_installation_hash:
                        raise MaxControlError("rehydration target installation proof is invalid")
                    expected_adapter_capability = canonical_sha256({"adapter_hash": target_host["adapter_hash"], "capability_manifest_hash": target_host["capability_manifest_hash"]})
                    if adapter_capability_hash != expected_adapter_capability:
                        raise MaxControlError("rehydration adapter capability proof is invalid")

                ack_value = {
                    "schema": "max-rehydration-target-ack/v1",
                    "packet_id": packet_id,
                    "packet_hash": packet_hash,
                    "handoff_approval_id": handoff_id,
                    "run_id": packet["run_id"],
                    "project_id": packet["project_id"],
                    "new_binding_id": new_binding_id,
                    "target_host_profile_id": target_host_profile_id,
                    "target_installation_id": target_installation_id,
                    "target_installation_hash": target_installation_hash,
                    "adapter_capability_hash": adapter_capability_hash,
                    "target_session": _require_text(target_session, "target_session", max_length=256),
                    "observed_checkpoint_hash": observed_checkpoint_hash,
                    "observed_state_hash": observed_state_hash,
                    "rehydrated_state_hash": rehydrated_state_hash,
                    "manifest_root": manifest_root,
                    "manifest_count": manifest_count,
                    "read_complete": bool(read_complete),
                    "fixture_only": fixture,
                    "created_at": now,
                }
                ack_hash = canonical_sha256(ack_value)
                ack_id = _stable_id("rehydration_packet_ack", ack_hash)
                connection.execute(
                    "INSERT INTO max_rehydration_packet_acks(ack_id,packet_id,handoff_approval_id,run_id,project_id,new_binding_id,packet_hash,ack_json,ack_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ack_id, packet_id, handoff_id, packet["run_id"], packet["project_id"], new_binding_id, packet_hash, canonical_json(ack_value), ack_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
                )
                target_ack_value = {**ack_value, "ack_id": ack_id, "ack_hash": ack_hash}
                target_ack_hash = canonical_sha256(target_ack_value)
                target_ack_id = _stable_id("rehydration_packet_target_ack", target_ack_hash)
                connection.execute(
                    "INSERT INTO max_rehydration_packet_target_acks(target_ack_id,ack_id,packet_id,handoff_approval_id,run_id,project_id,new_binding_id,target_host_profile_id,target_installation_id,target_installation_hash,adapter_capability_hash,target_session,observed_checkpoint_hash,observed_state_hash,rehydrated_state_hash,manifest_root,manifest_count,read_complete,fixture_only,ack_json,ack_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (target_ack_id, ack_id, packet_id, handoff_id, packet["run_id"], packet["project_id"], new_binding_id, target_host_profile_id, target_installation_id, target_installation_hash, adapter_capability_hash, target_session, observed_checkpoint_hash, observed_state_hash, rehydrated_state_hash, manifest_root, manifest_count, int(bool(read_complete)), int(fixture), canonical_json(target_ack_value), target_ack_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
                )
                event = self._append_rehydration_packet_event_locked(
                    connection, packet_id=packet_id, handoff_id=handoff_id, run_id=packet["run_id"], event_type="acknowledged", state="ACKNOWLEDGED", payload={"packet_id": packet_id, "packet_hash": packet_hash, "ack_id": ack_id, "ack_hash": ack_hash, "target_ack_id": target_ack_id, "target_ack_hash": target_ack_hash, "manifest_root": manifest_root, "manifest_count": manifest_count}, now=now,
                )
            return {"ok": True, "idempotent": False, "ack_id": ack_id, "ack_hash": ack_hash, "target_ack_id": target_ack_id, "target_ack_hash": target_ack_hash, "state": "ACKNOWLEDGED", "event": event}
        finally:
            connection.close()

    def assert_portability_quiescent(self, *, run_id: str) -> dict[str, Any]:
        """Read-only public gate used by adapters and the administrator CLI."""

        connection = self.repository._connect(read_only=True)
        try:
            run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None:
                raise MaxControlError("Max run was not found")
            return {"ok": True, "run_id": run_id, "quiescence": self._assert_portability_quiescent_locked(connection, run=run, now_dt=_utc_now(self.repository.clock))}
        finally:
            connection.close()

    def preview_backend_handoff(
        self,
        *,
        run_id: str,
        new_backend_profile_id: str,
        reason: str,
        new_host_profile_id: str | None = None,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        self._admin()
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1 or ttl_seconds > 7 * 24 * 3600:
            raise MaxControlError("handoff TTL is outside the supported range")
        reason_hash = canonical_sha256(_require_text(reason, "reason", max_length=2000))
        now, now_dt = self._now()
        expires = _timestamp(lambda: now_dt + timedelta(seconds=ttl_seconds))
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None:
                    raise MaxControlError("Max run was not found")
                quiescence = self._assert_portability_quiescent_locked(connection, run=run, now_dt=now_dt)
                current = connection.execute("SELECT * FROM max_run_execution_binding_current WHERE run_id=?", (run_id,)).fetchone()
                if current is None:
                    raise MaxControlError("backend handoff requires an existing Run binding")
                self._profile_rows(
                    connection,
                    host_profile_id=current["host_profile_id"],
                    backend_profile_id=current["backend_profile_id"],
                )
                host_id = new_host_profile_id or current["host_profile_id"]
                self._profile_rows(connection, host_profile_id=host_id, backend_profile_id=new_backend_profile_id)
                pending = connection.execute("SELECT * FROM max_backend_handoff_current WHERE run_id=?", (run_id,)).fetchone()
                if pending is not None and pending["state"] == "PENDING":
                    existing = connection.execute("SELECT * FROM max_backend_handoff_approvals WHERE handoff_approval_id=?", (pending["handoff_approval_id"],)).fetchone()
                    if existing is not None and existing["new_backend_profile_id"] == new_backend_profile_id and existing["new_host_profile_id"] == host_id:
                        phrase = f"APPROVE MR-PORTABILITY HANDOFF {existing['handoff_hash']}"
                        return {"ok": True, "idempotent": True, "handoff_approval_id": existing["handoff_approval_id"], "handoff_hash": existing["handoff_hash"], "confirmation_phrase": phrase, "confirmation_phrase_hash": existing["confirmation_phrase_hash"], "state": "PENDING", "expires_at": existing["expires_at"]}
                    raise MaxControlError("a backend handoff is already pending for this Run")
                prior_handoff_id = None if pending is None else pending["handoff_approval_id"]
                prior_handoff = None if prior_handoff_id is None else connection.execute(
                    "SELECT handoff_hash FROM max_backend_handoff_approvals WHERE handoff_approval_id=?",
                    (prior_handoff_id,),
                ).fetchone()
                prior_handoff_hash = None if prior_handoff is None else prior_handoff["handoff_hash"]
                generation_row = connection.execute(
                    "SELECT COALESCE(MAX(generation),0) AS generation FROM max_backend_handoff_lineage WHERE run_id=?",
                    (run_id,),
                ).fetchone()
                generation = int(generation_row["generation"]) + 1
                payload = {
                    "run_id": run_id,
                    "project_id": run["project_id"],
                    "old_binding_id": current["binding_id"],
                    "old_host_profile_id": current["host_profile_id"],
                    "old_backend_profile_id": current["backend_profile_id"],
                    "old_backend_profile_hash": current["backend_profile_hash"],
                    "new_host_profile_id": host_id,
                    "new_backend_profile_id": new_backend_profile_id,
                    "new_backend_profile_hash": connection.execute("SELECT profile_hash FROM max_execution_backend_profiles WHERE backend_profile_id=?", (new_backend_profile_id,)).fetchone()[0],
                    "current_research_state_hash": _require_hash(run["current_state_hash"], "current_research_state_hash"),
                    "current_checkpoint_id": run["current_checkpoint_id"],
                    "reason_hash": reason_hash,
                    "created_at": now,
                    "expires_at": expires,
                    "generation": generation,
                    "supersedes_handoff_approval_id": prior_handoff_id,
                    "supersedes_handoff_hash": prior_handoff_hash,
                }
                handoff_hash = canonical_sha256(payload)
                handoff_id = _stable_id("backend_handoff", handoff_hash)
                phrase = f"APPROVE MR-PORTABILITY HANDOFF {handoff_hash}"
                phrase_hash = canonical_sha256(phrase)
                record = BackendHandoffApproval(
                    run_id=run_id, project_id=run["project_id"], old_binding_id=current["binding_id"], old_host_profile_id=current["old_host_profile_id"] if "old_host_profile_id" in current.keys() else current["host_profile_id"], old_backend_profile_id=current["old_backend_profile_id"] if "old_backend_profile_id" in current.keys() else current["backend_profile_id"], old_backend_profile_hash=current["old_backend_profile_hash"] if "old_backend_profile_hash" in current.keys() else current["backend_profile_hash"], new_host_profile_id=host_id, new_backend_profile_id=new_backend_profile_id, new_backend_profile_hash=payload["new_backend_profile_hash"], current_research_state_hash=payload["current_research_state_hash"], current_checkpoint_id=run["current_checkpoint_id"], reason_hash=reason_hash, created_at=now, expires_at=expires, handoff_approval_id=handoff_id, handoff_hash=handoff_hash, confirmation_phrase_hash=phrase_hash, generation=generation, supersedes_handoff_approval_id=prior_handoff_id, supersedes_handoff_hash=prior_handoff_hash,
                )
                connection.execute(
                    "INSERT INTO max_backend_handoff_approvals(handoff_approval_id,run_id,project_id,old_binding_id,old_host_profile_id,old_backend_profile_id,old_backend_profile_hash,new_host_profile_id,new_backend_profile_id,new_backend_profile_hash,current_research_state_hash,current_checkpoint_id,reason_hash,confirmation_phrase_hash,state,created_at,expires_at,handoff_json,handoff_hash,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (handoff_id, run_id, run["project_id"], current["binding_id"], current["host_profile_id"], current["backend_profile_id"], current["backend_profile_hash"], host_id, new_backend_profile_id, payload["new_backend_profile_hash"], payload["current_research_state_hash"], run["current_checkpoint_id"], reason_hash, phrase_hash, "PENDING", now, expires, canonical_json(record.with_identity()), handoff_hash, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
                )
                current_value = {"run_id": run_id, "handoff_approval_id": handoff_id, "state": "PENDING", "binding_id": current["binding_id"], "handoff_hash": handoff_hash}
                if pending is None:
                    connection.execute(
                        "INSERT INTO max_backend_handoff_current(run_id,handoff_approval_id,state,binding_id,current_json,current_hash,updated_at) VALUES (?,?,?,?,?,?,?)",
                        (run_id, handoff_id, "PENDING", current["binding_id"], canonical_json(current_value), canonical_sha256(current_value), now),
                    )
                else:
                    # The current row is an explicit projection.  Historical
                    # approvals remain immutable while the projection moves
                    # to the next append-only handoff generation.
                    connection.execute(
                        "UPDATE max_backend_handoff_current SET handoff_approval_id=?,state=?,binding_id=?,current_json=?,current_hash=?,updated_at=? WHERE run_id=?",
                        (handoff_id, "PENDING", current["binding_id"], canonical_json(current_value), canonical_sha256(current_value), now, run_id),
                    )
                lineage_payload = {
                    "run_id": run_id,
                    "project_id": run["project_id"],
                    "generation": generation,
                    "handoff_approval_id": handoff_id,
                    "handoff_hash": handoff_hash,
                    "supersedes_handoff_approval_id": prior_handoff_id,
                    "supersedes_handoff_hash": prior_handoff_hash,
                    "state": "PENDING",
                }
                lineage_hash = canonical_sha256(lineage_payload)
                connection.execute(
                    "INSERT INTO max_backend_handoff_lineage(handoff_approval_id,run_id,project_id,generation,supersedes_handoff_approval_id,supersedes_handoff_hash,handoff_hash,state,lineage_json,lineage_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (handoff_id, run_id, run["project_id"], generation, lineage_payload["supersedes_handoff_approval_id"], lineage_payload["supersedes_handoff_hash"], handoff_hash, "PENDING", canonical_json(lineage_payload), lineage_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
                )
                quiescence = self._create_quiescence_snapshot_locked(
                    connection, run=run, handoff_id=handoff_id, phase="preview",
                    now=now, now_dt=now_dt,
                )
                event = self._append_handoff_event(connection, handoff_id=handoff_id, run_id=run_id, event_type="created", state="PENDING", payload={"handoff_hash": handoff_hash, "new_host_profile_id": host_id, "new_backend_profile_id": new_backend_profile_id}, now=now)
                self._append_portability_event(connection, stream_key=f"run:{run_id}", event_type="backend_handoff_previewed", payload={"handoff_approval_id": handoff_id, "handoff_hash": handoff_hash, "new_host_profile_id": host_id, "new_backend_profile_id": new_backend_profile_id}, now=now)
            return {"ok": True, "idempotent": False, "handoff_approval_id": handoff_id, "handoff_hash": handoff_hash, "confirmation_phrase": phrase, "confirmation_phrase_hash": phrase_hash, "state": "PENDING", "expires_at": expires, "quiescence": quiescence, "generation": generation, "supersedes_handoff_approval_id": lineage_payload["supersedes_handoff_approval_id"], "event": event}
        finally:
            connection.close()

    def approve_backend_handoff(self, *, handoff_approval_id: str, confirmation_phrase: str) -> dict[str, Any]:
        self._admin()
        now, now_dt = self._now()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_backend_handoff_approvals WHERE handoff_approval_id=?", (handoff_approval_id,)).fetchone()
                if row is None:
                    raise MaxControlError("backend handoff approval was not found")
                current = connection.execute("SELECT * FROM max_backend_handoff_current WHERE run_id=?", (row["run_id"],)).fetchone()
                if current is None or current["handoff_approval_id"] != handoff_approval_id or current["state"] != "PENDING":
                    raise MaxControlError("backend handoff approval is no longer pending")
                if _parse_timestamp(row["expires_at"]) is None or _parse_timestamp(row["expires_at"]) <= now_dt:
                    current_value = {"run_id": row["run_id"], "handoff_approval_id": handoff_approval_id, "state": "EXPIRED", "binding_id": current["binding_id"], "handoff_hash": row["handoff_hash"]}
                    connection.execute("UPDATE max_backend_handoff_current SET state=?,current_json=?,current_hash=?,updated_at=? WHERE run_id=?", ("EXPIRED", canonical_json(current_value), canonical_sha256(current_value), now, row["run_id"]))
                    self._append_handoff_event(connection, handoff_id=handoff_approval_id, run_id=row["run_id"], event_type="expired", state="EXPIRED", payload={"handoff_hash": row["handoff_hash"]}, now=now)
                    raise MaxControlError("backend handoff approval is expired")
                if canonical_sha256(confirmation_phrase) != row["confirmation_phrase_hash"]:
                    raise MaxControlError("backend handoff confirmation phrase is invalid")
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (row["run_id"],)).fetchone()
                if run is None or run["project_id"] != row["project_id"] or run["current_state_hash"] != row["current_research_state_hash"]:
                    raise MaxControlError("backend handoff Run state has drifted")
                quiescence = self._create_quiescence_snapshot_locked(
                    connection, run=run, handoff_id=handoff_approval_id,
                    phase="approval_consume", now=now, now_dt=now_dt,
                )
                current_binding = connection.execute("SELECT * FROM max_run_execution_binding_current WHERE run_id=?", (row["run_id"],)).fetchone()
                if current_binding is None or current_binding["binding_id"] != row["old_binding_id"]:
                    raise MaxControlError("backend handoff old binding has drifted")
                self._profile_rows(
                    connection,
                    host_profile_id=current_binding["host_profile_id"],
                    backend_profile_id=current_binding["backend_profile_id"],
                )
                binding = self._insert_binding_locked(connection, run=run, host_profile_id=row["new_host_profile_id"], backend_profile_id=row["new_backend_profile_id"], source_policy_hash=run["source_policy_hash"], budget_hash=run["budget_hash"], binding_version=int(current_binding["binding_version"]) + 1, now=now, allow_current=True)
                self._append_handoff_event(connection, handoff_id=handoff_approval_id, run_id=row["run_id"], event_type="approved", state="CONSUMED", payload={"handoff_hash": row["handoff_hash"], "binding_id": binding["binding"]["binding_id"]}, now=now)
                consumed_event = self._append_handoff_event(connection, handoff_id=handoff_approval_id, run_id=row["run_id"], event_type="consumed", state="CONSUMED", payload={"handoff_hash": row["handoff_hash"], "binding_id": binding["binding"]["binding_id"]}, now=now)
                current_value = {"run_id": row["run_id"], "handoff_approval_id": handoff_approval_id, "state": "CONSUMED", "binding_id": binding["binding"]["binding_id"], "handoff_hash": row["handoff_hash"]}
                connection.execute("UPDATE max_backend_handoff_current SET state=?,binding_id=?,current_json=?,current_hash=?,updated_at=? WHERE run_id=?", ("CONSUMED", binding["binding"]["binding_id"], canonical_json(current_value), canonical_sha256(current_value), now, row["run_id"]))
                packet = self._create_rehydration_packet_locked(
                    connection, run=run, handoff=row, old_binding_id=row["old_binding_id"],
                    new_binding_id=binding["binding"]["binding_id"], now=now,
                )
                self.repository._append_event(connection, run_id=row["run_id"], event_type="backend_handoff_consumed", payload={"handoff_approval_id": handoff_approval_id, "handoff_hash": row["handoff_hash"], "binding_id": binding["binding"]["binding_id"]}, actor=self.actor, now=now)
                event = self._append_portability_event(connection, stream_key=f"run:{row['run_id']}", event_type="backend_handoff_consumed", payload={"handoff_approval_id": handoff_approval_id, "handoff_hash": row["handoff_hash"], "binding_id": binding["binding"]["binding_id"]}, now=now)
            return {"ok": True, "handoff_approval_id": handoff_approval_id, "handoff_hash": row["handoff_hash"], "state": "CONSUMED", "approval_created": 1, "approval_consumed": 1, "binding": binding["binding"], "rehydration_packet": packet, "quiescence": quiescence, "event": event, "handoff_event": consumed_event}
        finally:
            connection.close()

    def _server_invocation_binding_locked(
        self,
        connection: sqlite3.Connection,
        *,
        run: sqlite3.Row,
        binding: sqlite3.Row,
        now: str,
    ) -> dict[str, Any]:
        """Resolve result attribution from the durable runner graph.

        A production caller supplies only the Run and execution binding.  The
        iteration, intent, manifest, invocation and input checkpoint are
        selected from server-owned runner rows and are never accepted from a
        CLI flag.  This makes a forged result hash or invocation label unable
        to move evidence across a Run boundary.
        """

        runner = connection.execute(
            "SELECT b.*, i.intent_id, i.intent_hash AS canonical_intent_hash, "
            "i.iteration_id AS intent_iteration_id, "
            "i.input_state_hash AS intent_input_state_hash, i.model_identity, "
            "m.manifest_hash "
            "FROM max_runner_call_bindings b "
            "JOIN max_model_call_intents i ON i.logical_call_id=b.logical_call_id AND i.run_id=b.run_id "
            "JOIN max_runner_intent_manifests m ON m.intent_id=i.intent_id "
            "WHERE b.run_id=? ORDER BY b.created_at,b.call_index,b.binding_id LIMIT 1",
            (run["run_id"],),
        ).fetchone()
        if runner is None:
            raise MaxControlError("server-owned runner invocation binding was not found")
        if runner["iteration_id"] != runner["intent_iteration_id"]:
            raise MaxControlError("runner invocation iteration binding is inconsistent")
        if runner["intent_hash"] != runner["canonical_intent_hash"]:
            raise MaxControlError("runner invocation intent hash is inconsistent")
        manifest_hash = _require_hash(runner["manifest_hash"], "runner intent manifest hash")
        backend = connection.execute(
            "SELECT model_identity FROM max_execution_backend_profiles WHERE backend_profile_id=?",
            (binding["backend_profile_id"],),
        ).fetchone()
        if backend is None or backend["model_identity"] != runner["model_identity"]:
            raise MaxControlError("runner invocation model binding is inconsistent")
        input_state_hash = _require_hash(runner["intent_input_state_hash"], "runner input state hash")
        checkpoint = connection.execute(
            "SELECT checkpoint_id,checkpoint_version FROM max_checkpoints WHERE run_id=? AND state_hash=? "
            "ORDER BY checkpoint_version DESC, created_at DESC LIMIT 1",
            (run["run_id"], input_state_hash),
        ).fetchone()
        if checkpoint is None:
            raise MaxControlError("server-owned runner input checkpoint was not found")
        descriptor = {
            "run_id": run["run_id"],
            "project_id": run["project_id"],
            "binding_id": binding["binding_id"],
            "runner_binding_id": runner["binding_id"],
            "group_id": runner["group_id"],
            "iteration_id": runner["iteration_id"],
            "intent_id": runner["intent_id"],
            "logical_call_id": runner["logical_call_id"],
            "intent_hash": runner["canonical_intent_hash"],
            "manifest_hash": manifest_hash,
            "input_state_hash": input_state_hash,
            "checkpoint_id": checkpoint["checkpoint_id"],
            "state_version": int(run["state_version"]),
        }
        invocation_hash = canonical_sha256(descriptor)
        invocation_id = _stable_id("portability_invocation", invocation_hash)
        binding_value = {"schema": "max-portability-invocation-binding/v1", "source_kind": "server_runner", **descriptor, "invocation_id": invocation_id, "invocation_hash": invocation_hash}
        binding_hash = canonical_sha256(binding_value)
        existing = connection.execute(
            "SELECT * FROM max_portability_invocation_bindings WHERE run_id=? AND binding_id=? AND invocation_id=?",
            (run["run_id"], binding["binding_id"], invocation_id),
        ).fetchone()
        if existing is not None:
            if existing["binding_hash"] != binding_hash or existing["binding_json"] != canonical_json(binding_value):
                raise MaxControlError("server-owned invocation binding hash collision")
            return dict(existing)
        connection.execute(
            "INSERT INTO max_portability_invocation_bindings(invocation_binding_id,run_id,project_id,binding_id,iteration_id,group_id,intent_id,invocation_id,invocation_hash,intent_hash,manifest_hash,input_state_hash,checkpoint_id,state_version,source_kind,binding_json,binding_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (invocation_id, run["run_id"], run["project_id"], binding["binding_id"], runner["iteration_id"], runner["group_id"], runner["intent_id"], invocation_id, invocation_hash, runner["canonical_intent_hash"], manifest_hash, input_state_hash, checkpoint["checkpoint_id"], int(run["state_version"]), "server_runner", canonical_json(binding_value), binding_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
        )
        return {
            "invocation_binding_id": invocation_id,
            "run_id": run["run_id"],
            "project_id": run["project_id"],
            "binding_id": binding["binding_id"],
            "iteration_id": runner["iteration_id"],
            "group_id": runner["group_id"],
            "intent_id": runner["intent_id"],
            "invocation_id": invocation_id,
            "invocation_hash": invocation_hash,
            "intent_hash": runner["canonical_intent_hash"],
            "manifest_hash": manifest_hash,
            "input_state_hash": input_state_hash,
            "checkpoint_id": checkpoint["checkpoint_id"],
            "state_version": int(run["state_version"]),
            "source_kind": "server_runner",
            "binding_json": canonical_json(binding_value),
            "binding_hash": binding_hash,
        }

    def _fixture_invocation_binding_locked(
        self,
        connection: sqlite3.Connection,
        *,
        run: sqlite3.Row,
        binding: sqlite3.Row,
        iteration_id: str | None,
        invocation_id: str | None,
        intent_id: str | None,
        input_state_hash: str | None,
        checkpoint_id: str | None,
        invocation_hash: str | None,
        now: str,
    ) -> dict[str, Any]:
        """Compatibility attribution explicitly confined to the fixture DB."""

        state_hash = _require_hash(input_state_hash or run["current_state_hash"], "input_state_hash")
        if state_hash != run["current_state_hash"]:
            raise MaxControlError("normalized result input state is stale")
        checkpoint = checkpoint_id or run["current_checkpoint_id"]
        if checkpoint != run["current_checkpoint_id"]:
            raise MaxControlError("normalized result checkpoint is stale")
        iteration = _require_text(iteration_id or "legacy-iteration", "iteration_id", max_length=256)
        invocation = _require_text(invocation_id or _stable_id("invocation", canonical_sha256({"run_id": run["run_id"], "binding_id": binding["binding_id"]})), "invocation_id", max_length=256)
        intent = _require_text(intent_id or "legacy-intent", "intent_id", max_length=256)
        computed_hash = canonical_sha256({"run_id": run["run_id"], "binding_id": binding["binding_id"], "iteration_id": iteration, "invocation_id": invocation, "intent_id": intent, "input_state_hash": state_hash, "checkpoint_id": checkpoint, "fixture_only": True})
        supplied_hash = computed_hash if invocation_hash is None else _require_hash(invocation_hash, "invocation_hash")
        value = {"schema": "max-portability-invocation-binding/v1", "source_kind": "fixture_compat", "run_id": run["run_id"], "project_id": run["project_id"], "binding_id": binding["binding_id"], "iteration_id": iteration, "invocation_id": invocation, "intent_id": intent, "invocation_hash": supplied_hash, "input_state_hash": state_hash, "checkpoint_id": checkpoint, "state_version": int(run["state_version"]), "fixture_only": True}
        binding_hash = canonical_sha256(value)
        existing = connection.execute(
            "SELECT * FROM max_portability_invocation_bindings WHERE run_id=? AND binding_id=? AND invocation_id=?",
            (run["run_id"], binding["binding_id"], invocation),
        ).fetchone()
        if existing is not None:
            if existing["binding_hash"] != binding_hash or existing["binding_json"] != canonical_json(value):
                raise MaxControlError("fixture invocation binding already has different attribution")
            return dict(existing)
        connection.execute(
            "INSERT INTO max_portability_invocation_bindings(invocation_binding_id,run_id,project_id,binding_id,iteration_id,group_id,intent_id,invocation_id,invocation_hash,intent_hash,manifest_hash,input_state_hash,checkpoint_id,state_version,source_kind,binding_json,binding_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (_stable_id("portability_invocation", binding_hash), run["run_id"], run["project_id"], binding["binding_id"], None, None, None, invocation, supplied_hash, None, None, state_hash, checkpoint, int(run["state_version"]), "fixture_compat", canonical_json(value), binding_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
        )
        value["invocation_binding_id"] = _stable_id("portability_invocation", binding_hash)
        value["binding_hash"] = binding_hash
        return value

    def record_normalized_result(
        self,
        *,
        run_id: str,
        binding_id: str,
        result: NormalizedAgentResult | Mapping[str, Any],
        project_id: str | None = None,
        iteration_id: str | None = None,
        invocation_id: str | None = None,
        intent_id: str | None = None,
        input_state_hash: str | None = None,
        checkpoint_id: str | None = None,
        invocation_hash: str | None = None,
    ) -> dict[str, Any]:
        """Persist a result with server-derived Run/Invocation attribution.

        The legacy table keyed identity by result payload alone.  Schema 30
        keeps that history untouched and records new results in a table whose
        uniqueness boundary is the invocation tuple, so identical payloads
        from two Runs cannot become cross-Run idempotency.  Schema 31 adds a
        server-owned runner binding and a historical result-binding receipt.
        """
        self._admin()
        value = result if isinstance(result, NormalizedAgentResult) else NormalizedAgentResult.from_mapping(result)
        now, _ = self._now()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                binding = connection.execute("SELECT * FROM max_run_execution_bindings WHERE binding_id=? AND run_id=?", (binding_id, run_id)).fetchone()
                if binding is None:
                    raise MaxControlError("normalized result binding was not found")
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None:
                    raise MaxControlError("normalized result Run was not found")
                current_binding = connection.execute("SELECT * FROM max_run_execution_binding_current WHERE run_id=?", (run_id,)).fetchone()
                if current_binding is None or current_binding["binding_id"] != binding_id:
                    raise MaxControlError("normalized result binding is not the current Run binding")
                fixture = self._is_fixture_control_store(connection)
                if not fixture and any(item is not None for item in (project_id, iteration_id, invocation_id, intent_id, input_state_hash, checkpoint_id, invocation_hash)):
                    raise MaxControlError("production normalized result attribution must be server-derived")
                if fixture:
                    invocation_binding = self._fixture_invocation_binding_locked(
                        connection, run=run, binding=binding, iteration_id=iteration_id,
                        invocation_id=invocation_id, intent_id=intent_id,
                        input_state_hash=input_state_hash, checkpoint_id=checkpoint_id,
                        invocation_hash=invocation_hash, now=now,
                    )
                else:
                    invocation_binding = self._server_invocation_binding_locked(
                        connection, run=run, binding=binding, now=now,
                    )
                iteration = str(invocation_binding["iteration_id"] or "legacy-iteration")
                invocation = str(invocation_binding["invocation_id"])
                intent = str(invocation_binding.get("intent_id") or intent_id or "legacy-intent")
                state_hash = _require_hash(invocation_binding["input_state_hash"], "input_state_hash")
                expected_checkpoint = invocation_binding["checkpoint_id"]
                invocation_value = _require_hash(invocation_binding["invocation_hash"], "invocation_hash")
                descriptor = {
                    "project_id": run["project_id"],
                    "run_id": run_id,
                    "binding_id": binding_id,
                    "iteration_id": iteration,
                    "invocation_id": invocation,
                    "intent_id": intent,
                    "input_state_hash": state_hash,
                    "checkpoint_id": expected_checkpoint,
                }
                attribution = {**descriptor, "invocation_hash": invocation_value}
                attribution_hash = canonical_sha256(attribution)
                result_id = _stable_id("normalized_agent_result", f"{attribution_hash}:{value.result_hash}")
                result_json = canonical_json(value.to_mapping())
                result_size = len(result_json.encode("utf-8"))
                if result_size > MAX_RESULT_CANONICAL_BYTES:
                    raise MaxControlError("normalized result exceeds the maximum canonical size")
                existing = connection.execute(
                    "SELECT * FROM max_normalized_agent_results_v2 WHERE run_id=? AND binding_id=? AND iteration_id=? AND invocation_id=? AND intent_id=?",
                    (run_id, binding_id, iteration, invocation, intent),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["result_hash"] != value.result_hash
                        or existing["result_json"] != result_json
                        or existing["attribution_hash"] != attribution_hash
                    ):
                        raise MaxControlError("normalized result invocation already has a different payload")
                    return {
                        "ok": True, "idempotent": True, "result_id": existing["result_id"],
                        "result_hash": value.result_hash, "attribution_hash": attribution_hash,
                        "project_id": run["project_id"], "run_id": run_id,
                        "invocation_binding_id": invocation_binding["invocation_binding_id"],
                        "source_kind": invocation_binding["source_kind"],
                    }
                connection.execute(
                    "INSERT INTO max_normalized_agent_results_v2(result_id,project_id,run_id,binding_id,iteration_id,invocation_id,intent_id,input_state_hash,checkpoint_id,input_research_state_hash,invocation_hash,result_json,result_hash,attribution_hash,result_size_bytes,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (result_id, run["project_id"], run_id, binding_id, iteration, invocation, intent, state_hash, expected_checkpoint, state_hash, invocation_value, result_json, value.result_hash, attribution_hash, result_size, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
                )
                result_binding_value = {
                    "schema": "max-portability-result-binding/v1",
                    "result_id": result_id,
                    "invocation_binding_id": invocation_binding["invocation_binding_id"],
                    "run_id": run_id,
                    "project_id": run["project_id"],
                    "result_hash": value.result_hash,
                    "attribution_hash": attribution_hash,
                    "invocation_hash": invocation_value,
                    "input_state_hash": state_hash,
                    "checkpoint_id": expected_checkpoint,
                    "source_kind": invocation_binding["source_kind"],
                }
                result_binding_hash = canonical_sha256(result_binding_value)
                connection.execute(
                    "INSERT INTO max_portability_result_bindings(result_id,invocation_binding_id,run_id,project_id,result_hash,attribution_hash,binding_json,binding_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (result_id, invocation_binding["invocation_binding_id"], run_id, run["project_id"], value.result_hash, attribution_hash, canonical_json(result_binding_value), result_binding_hash, now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id),
                )
                event = self._append_portability_event(connection, stream_key=f"run:{run_id}", event_type="agent_result_normalized", payload={"result_id": result_id, "result_hash": value.result_hash, "attribution_hash": attribution_hash, "binding_id": binding_id, "backend_status": value.backend_status}, now=now)
            return {"ok": True, "idempotent": False, "result_id": result_id, "result_hash": value.result_hash, "attribution_hash": attribution_hash, "invocation_binding_id": invocation_binding["invocation_binding_id"], "source_kind": invocation_binding["source_kind"], "project_id": run["project_id"], "run_id": run_id, "event": event}
        finally:
            connection.close()

    def status(self, *, run_id: str | None = None) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            result: dict[str, Any] = {
                "ok": True,
                "supported_host_kinds": list(HOST_KINDS),
                "supported_backend_kinds": supported_backend_descriptors(),
                "host_profile_count": int(connection.execute("SELECT COUNT(*) FROM max_agent_host_profiles").fetchone()[0]),
                "backend_profile_count": int(connection.execute("SELECT COUNT(*) FROM max_execution_backend_profiles").fetchone()[0]),
                "binding_count": int(connection.execute("SELECT COUNT(*) FROM max_run_execution_bindings").fetchone()[0]),
                "handoff_count": int(connection.execute("SELECT COUNT(*) FROM max_backend_handoff_approvals").fetchone()[0]),
                "normalized_result_count": int(connection.execute("SELECT COUNT(*) FROM max_normalized_agent_results").fetchone()[0]) + int(connection.execute("SELECT COUNT(*) FROM max_normalized_agent_results_v2").fetchone()[0]),
                "normalized_result_v2_count": int(connection.execute("SELECT COUNT(*) FROM max_normalized_agent_results_v2").fetchone()[0]),
                "rehydration_packet_count": int(connection.execute("SELECT COUNT(*) FROM max_rehydration_packets").fetchone()[0]),
                "profile_status_event_count": int(connection.execute("SELECT COUNT(*) FROM max_portability_profile_status_events").fetchone()[0]),
                "quiescence_snapshot_count": int(connection.execute("SELECT COUNT(*) FROM max_portability_quiescence_snapshots").fetchone()[0]) if self._table_exists(connection, "max_portability_quiescence_snapshots") else 0,
                "rehydration_manifest_item_count": int(connection.execute("SELECT COUNT(*) FROM max_rehydration_packet_manifest_items").fetchone()[0]) if self._table_exists(connection, "max_rehydration_packet_manifest_items") else 0,
                "rehydration_target_ack_count": int(connection.execute("SELECT COUNT(*) FROM max_rehydration_packet_target_acks").fetchone()[0]) if self._table_exists(connection, "max_rehydration_packet_target_acks") else 0,
                "invocation_binding_count": int(connection.execute("SELECT COUNT(*) FROM max_portability_invocation_bindings").fetchone()[0]) if self._table_exists(connection, "max_portability_invocation_bindings") else 0,
                "result_binding_count": int(connection.execute("SELECT COUNT(*) FROM max_portability_result_bindings").fetchone()[0]) if self._table_exists(connection, "max_portability_result_bindings") else 0,
                "installation_attestation_count": int(connection.execute("SELECT COUNT(*) FROM max_host_installation_attestations").fetchone()[0]) if self._table_exists(connection, "max_host_installation_attestations") else 0,
                "default_backend_profile": None,
            }
            if run_id is not None:
                current = connection.execute("SELECT * FROM max_run_execution_binding_current WHERE run_id=?", (run_id,)).fetchone()
                handoff = connection.execute("SELECT * FROM max_backend_handoff_current WHERE run_id=?", (run_id,)).fetchone()
                result["run_id"] = run_id
                result["current_binding"] = None if current is None else {"run_id": current["run_id"], "binding_id": current["binding_id"], "project_id": current["project_id"], "host_profile_id": current["host_profile_id"], "backend_profile_id": current["backend_profile_id"], "backend_profile_hash": current["backend_profile_hash"], "binding_version": current["binding_version"], "current_hash": current["current_hash"]}
                result["current_handoff"] = None if handoff is None else {"handoff_approval_id": handoff["handoff_approval_id"], "state": handoff["state"], "binding_id": handoff["binding_id"], "current_hash": handoff["current_hash"]}
            return result
        finally:
            connection.close()

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True, verify_schema=False)
        issues: list[str] = []
        try:
            def selected(sql: str, params: tuple[Any, ...] = ()):
                return list(connection.execute(sql, params))

            for row in selected("SELECT * FROM max_agent_host_profiles ORDER BY host_profile_id"):
                try:
                    profile = AgentHostProfile.from_mapping(json.loads(row["profile_json"]))
                    if profile.host_profile_id != row["host_profile_id"] or profile.profile_hash != row["profile_hash"]:
                        issues.append("host profile payload/hash mismatch")
                except Exception:
                    issues.append("host profile JSON is invalid")
            for row in selected("SELECT * FROM max_execution_backend_profiles ORDER BY backend_profile_id"):
                try:
                    profile = ExecutionBackendProfile.from_mapping(json.loads(row["profile_json"]))
                    if profile.backend_profile_id != row["backend_profile_id"] or profile.profile_hash != row["profile_hash"] or profile.capability_manifest_hash != row["capability_manifest_hash"]:
                        issues.append("backend profile payload/hash mismatch")
                except Exception:
                    issues.append("backend profile JSON is invalid")
            binding_rows = selected("SELECT * FROM max_run_execution_bindings ORDER BY run_id,binding_version,binding_id")
            by_run: dict[str, list[sqlite3.Row]] = {}
            for row in binding_rows:
                by_run.setdefault(row["run_id"], []).append(row)
                try:
                    value = RunExecutionBinding(**{key: row[key] for key in ("run_id", "project_id", "host_profile_id", "backend_profile_id", "backend_profile_hash", "capability_manifest_hash", "model_identity", "source_policy_hash", "budget_hash", "binding_version", "binding_id")})
                    if value.binding_hash != row["binding_hash"] or canonical_json(value.to_mapping()) != row["binding_json"]:
                        issues.append("Run Execution binding payload/hash mismatch")
                    run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (row["run_id"],)).fetchone()
                    backend = connection.execute("SELECT * FROM max_execution_backend_profiles WHERE backend_profile_id=?", (row["backend_profile_id"],)).fetchone()
                    if run is None or run["project_id"] != row["project_id"] or backend is None or backend["profile_hash"] != row["backend_profile_hash"] or backend["model_identity"] != row["model_identity"] or backend["capability_manifest_hash"] != row["capability_manifest_hash"]:
                        issues.append("Run Execution binding is not bound to canonical Run/backend")
                except Exception:
                    issues.append("Run Execution binding is invalid")
            for run_key, rows in by_run.items():
                versions = [int(row["binding_version"]) for row in rows]
                if versions != list(range(1, len(versions) + 1)):
                    issues.append("Run Execution binding generations are not contiguous")
            current_rows = selected("SELECT * FROM max_run_execution_binding_current" + (" WHERE run_id=?" if run_id else ""), (run_id,) if run_id else ())
            for current in current_rows:
                history = connection.execute("SELECT * FROM max_run_execution_bindings WHERE binding_id=?", (current["binding_id"],)).fetchone()
                if history is None or history["run_id"] != current["run_id"] or history["binding_version"] != current["binding_version"]:
                    issues.append("current Run Execution binding projection is orphaned")
                try:
                    value = json.loads(current["current_json"])
                    if canonical_sha256(value) != current["current_hash"] or value.get("binding_id") != current["binding_id"]:
                        issues.append("current Run Execution binding projection hash mismatch")
                except Exception:
                    issues.append("current Run Execution binding projection JSON is invalid")
            handoff_rows = selected("SELECT * FROM max_backend_handoff_approvals" + (" WHERE run_id=?" if run_id else ""), (run_id,) if run_id else ())
            for row in handoff_rows:
                try:
                    value = json.loads(row["handoff_json"])
                    base_keys = ("run_id", "project_id", "old_binding_id", "old_host_profile_id", "old_backend_profile_id", "old_backend_profile_hash", "new_host_profile_id", "new_backend_profile_id", "new_backend_profile_hash", "current_research_state_hash", "current_checkpoint_id", "reason_hash", "created_at", "expires_at")
                    base = {key: value[key] for key in base_keys}
                    for key in ("generation", "supersedes_handoff_approval_id", "supersedes_handoff_hash"):
                        if key in value:
                            base[key] = value[key]
                    if canonical_sha256(base) != row["handoff_hash"] or value.get("handoff_approval_id") != row["handoff_approval_id"] or value.get("confirmation_phrase_hash") != row["confirmation_phrase_hash"]:
                        issues.append("backend handoff payload/hash mismatch")
                    if canonical_sha256(f"APPROVE MR-PORTABILITY HANDOFF {row['handoff_hash']}") != row["confirmation_phrase_hash"]:
                        issues.append("backend handoff confirmation hash mismatch")
                except Exception:
                    issues.append("backend handoff JSON is invalid")
                events = selected("SELECT * FROM max_backend_handoff_events WHERE handoff_approval_id=? ORDER BY sequence_no", (row["handoff_approval_id"],))
                previous = None
                for event in events:
                    try:
                        if int(event["sequence_no"]) != (1 if previous is None else int(previous["sequence_no"]) + 1) or event["previous_event_hash"] != (None if previous is None else previous["event_hash"]):
                            issues.append("backend handoff event sequence is broken")
                        payload = json.loads(event["payload_json"])
                        if canonical_sha256(payload) != event["payload_hash"]:
                            issues.append("backend handoff event payload hash mismatch")
                        identity = {"handoff_approval_id": event["handoff_approval_id"], "run_id": event["run_id"], "sequence_no": event["sequence_no"], "event_type": event["event_type"], "state": event["state"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if canonical_sha256(identity) != event["event_hash"]:
                            issues.append("backend handoff event hash mismatch")
                    except Exception:
                        issues.append("backend handoff event is invalid")
                    previous = event
            event_rows = selected("SELECT * FROM max_portability_events ORDER BY stream_key,sequence_no")
            previous_by_stream: dict[str, sqlite3.Row] = {}
            for event in event_rows:
                previous = previous_by_stream.get(event["stream_key"])
                try:
                    if int(event["sequence_no"]) != (1 if previous is None else int(previous["sequence_no"]) + 1) or event["previous_event_hash"] != (None if previous is None else previous["event_hash"]):
                        issues.append("portability event sequence is broken")
                    payload = json.loads(event["payload_json"])
                    if canonical_sha256(payload) != event["payload_hash"]:
                        issues.append("portability event payload hash mismatch")
                    identity = {"stream_key": event["stream_key"], "sequence_no": event["sequence_no"], "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"], "actor_id": event["actor_id"], "actor_kind": event["actor_kind"], "actor_session": event["actor_session"]}
                    if canonical_sha256(identity) != event["event_hash"]:
                        issues.append("portability event hash mismatch")
                except Exception:
                    issues.append("portability event is invalid")
                previous_by_stream[event["stream_key"]] = event
            lineage_rows = selected(
                "SELECT * FROM max_backend_handoff_lineage" + (" WHERE run_id=?" if run_id else "") + " ORDER BY run_id,generation",
                (run_id,) if run_id else (),
            )
            lineage_by_run: dict[str, list[sqlite3.Row]] = {}
            for lineage in lineage_rows:
                lineage_by_run.setdefault(lineage["run_id"], []).append(lineage)
                approval = connection.execute("SELECT handoff_hash,run_id,project_id FROM max_backend_handoff_approvals WHERE handoff_approval_id=?", (lineage["handoff_approval_id"],)).fetchone()
                try:
                    lineage_value = json.loads(lineage["lineage_json"])
                    if canonical_sha256(lineage_value) != lineage["lineage_hash"] or lineage_value.get("handoff_hash") != lineage["handoff_hash"]:
                        issues.append("backend handoff lineage hash mismatch")
                    if approval is None or approval["handoff_hash"] != lineage["handoff_hash"] or approval["run_id"] != lineage["run_id"] or approval["project_id"] != lineage["project_id"]:
                        issues.append("backend handoff lineage binding is invalid")
                    if lineage["supersedes_handoff_approval_id"] is not None:
                        prior = connection.execute("SELECT handoff_hash FROM max_backend_handoff_approvals WHERE handoff_approval_id=?", (lineage["supersedes_handoff_approval_id"],)).fetchone()
                        if prior is None or prior["handoff_hash"] != lineage["supersedes_handoff_hash"]:
                            issues.append("backend handoff lineage successor is invalid")
                except Exception:
                    issues.append("backend handoff lineage JSON is invalid")
            for lineage_run, rows in lineage_by_run.items():
                generations = [int(row["generation"]) for row in rows]
                if generations != list(range(1, len(generations) + 1)):
                    issues.append("backend handoff lineage generations are not contiguous")
                if len({row["handoff_hash"] for row in rows}) != len(rows):
                    issues.append("backend handoff lineage contains duplicate hashes")
            current_handoffs = selected("SELECT * FROM max_backend_handoff_current" + (" WHERE run_id=?" if run_id else ""), (run_id,) if run_id else ())
            for current in current_handoffs:
                approval = connection.execute("SELECT handoff_hash FROM max_backend_handoff_approvals WHERE handoff_approval_id=?", (current["handoff_approval_id"],)).fetchone()
                try:
                    value = json.loads(current["current_json"])
                    if approval is None or approval["handoff_hash"] != value.get("handoff_hash"):
                        issues.append("current backend handoff projection is orphaned")
                    if canonical_sha256(value) != current["current_hash"] or value.get("handoff_approval_id") != current["handoff_approval_id"]:
                        issues.append("current backend handoff projection hash mismatch")
                except Exception:
                    issues.append("current backend handoff projection JSON is invalid")
            if self._table_exists(connection, "max_portability_quiescence_snapshots"):
                snapshot_rows = selected(
                    "SELECT * FROM max_portability_quiescence_snapshots"
                    + (" WHERE run_id=?" if run_id else "")
                    + " ORDER BY run_id,created_at,snapshot_id",
                    (run_id,) if run_id else (),
                )
                snapshot_hashes: set[str] = set()
                activity_counter_keys = (
                    "active_runner_claims", "call_groups", "reservations", "acquisition",
                    "scheduler", "long_run_authority", "authorization_bundles", "jit_authority",
                    "permits", "active_leases", "terminal_provider_records", "runner_dispatches",
                    "network_activity", "active_provider_dispatches",
                )
                required_activity = {
                    "run_status", "checkpoint_bound", *activity_counter_keys,
                    "evidence", "activity_hash",
                }
                for snapshot in snapshot_rows:
                    try:
                        value = _loads_safe(snapshot["snapshot_json"])
                        activity = _loads_safe(snapshot["activity_json"])
                        if not isinstance(value, Mapping) or not isinstance(activity, Mapping):
                            raise ValueError("snapshot JSON is not an object")
                        activity_without_hash = {
                            key: activity[key]
                            for key in activity_counter_keys
                            if key in activity
                        }
                        if (
                            canonical_sha256(activity_without_hash) != snapshot["activity_hash"]
                            or value.get("activity") != activity
                            or value.get("activity_hash") != snapshot["activity_hash"]
                            or not required_activity.issubset(activity)
                            or not _HEX64.fullmatch(str(snapshot["activity_hash"]))
                        ):
                            issues.append("portability quiescence activity proof is invalid")
                        base = {
                            "schema": "max-portability-quiescence-snapshot/v1",
                            "run_id": snapshot["run_id"],
                            "project_id": snapshot["project_id"],
                            "handoff_approval_id": snapshot["handoff_approval_id"],
                            "phase": snapshot["phase"],
                            "state_version": int(snapshot["state_version"]),
                            "state_hash": snapshot["state_hash"],
                            "checkpoint_id": snapshot["checkpoint_id"],
                            "binding_id": snapshot["binding_id"],
                            "activity": activity,
                            "activity_hash": snapshot["activity_hash"],
                            "created_at": snapshot["created_at"],
                        }
                        if (
                            canonical_sha256(value) != snapshot["snapshot_hash"]
                            or snapshot["snapshot_id"] != _stable_id("portability_quiescence_snapshot", snapshot["snapshot_hash"])
                            or value != base
                            or snapshot["phase"] not in {"preview", "approval_consume"}
                            or snapshot["snapshot_hash"] in snapshot_hashes
                        ):
                            issues.append("portability quiescence snapshot payload/hash mismatch")
                        snapshot_hashes.add(snapshot["snapshot_hash"])
                        run = connection.execute(
                            "SELECT project_id,current_state_hash FROM max_runs WHERE run_id=?",
                            (snapshot["run_id"],),
                        ).fetchone()
                        handoff = connection.execute(
                            "SELECT run_id,project_id,handoff_hash FROM max_backend_handoff_approvals WHERE handoff_approval_id=?",
                            (snapshot["handoff_approval_id"],),
                        ).fetchone()
                        binding = connection.execute(
                            "SELECT run_id,project_id FROM max_run_execution_bindings WHERE binding_id=?",
                            (snapshot["binding_id"],),
                        ).fetchone()
                        checkpoint = connection.execute(
                            "SELECT run_id,state_hash FROM max_checkpoints WHERE checkpoint_id=?",
                            (snapshot["checkpoint_id"],),
                        ).fetchone() if snapshot["checkpoint_id"] is not None else None
                        if (
                            run is None or run["project_id"] != snapshot["project_id"]
                            or handoff is None or handoff["run_id"] != snapshot["run_id"] or handoff["project_id"] != snapshot["project_id"]
                            or binding is None or binding["run_id"] != snapshot["run_id"] or binding["project_id"] != snapshot["project_id"]
                            or checkpoint is None or checkpoint["run_id"] != snapshot["run_id"] or checkpoint["state_hash"] != snapshot["state_hash"]
                        ):
                            issues.append("portability quiescence snapshot canonical binding is invalid")
                    except Exception:
                        issues.append("portability quiescence snapshot is invalid")
                for handoff in handoff_rows:
                    preview_snapshot = connection.execute(
                        "SELECT 1 FROM max_portability_quiescence_snapshots WHERE handoff_approval_id=? AND phase='preview' LIMIT 1",
                        (handoff["handoff_approval_id"],),
                    ).fetchone()
                    if preview_snapshot is None:
                        issues.append("backend handoff has no persisted preview quiescence snapshot")
                    consumed = connection.execute(
                        "SELECT 1 FROM max_backend_handoff_events WHERE handoff_approval_id=? AND state='CONSUMED' LIMIT 1",
                        (handoff["handoff_approval_id"],),
                    ).fetchone()
                    if consumed is not None:
                        approval_snapshot = connection.execute(
                            "SELECT 1 FROM max_portability_quiescence_snapshots WHERE handoff_approval_id=? AND phase='approval_consume' LIMIT 1",
                            (handoff["handoff_approval_id"],),
                        ).fetchone()
                        if approval_snapshot is None:
                            issues.append("consumed backend handoff has no persisted approval quiescence snapshot")
            invocation_binding_rows = selected(
                "SELECT * FROM max_portability_invocation_bindings"
                + (" WHERE run_id=?" if run_id else "")
                + " ORDER BY run_id,created_at,invocation_binding_id",
                (run_id,) if run_id else (),
            ) if self._table_exists(connection, "max_portability_invocation_bindings") else []
            fixture_store = self._is_fixture_control_store(connection)
            for invocation_binding in invocation_binding_rows:
                try:
                    value = _loads_safe(invocation_binding["binding_json"])
                    source_kind = invocation_binding["source_kind"]
                    required_keys = {
                        "schema", "source_kind", "run_id", "project_id", "binding_id", "iteration_id",
                        "invocation_id", "invocation_hash", "input_state_hash", "checkpoint_id", "state_version",
                    }
                    if (
                        not isinstance(value, Mapping)
                        or not required_keys.issubset(value)
                        or canonical_sha256(value) != invocation_binding["binding_hash"]
                    ):
                        raise ValueError("invocation binding hash")
                    if invocation_binding["invocation_binding_id"] != _stable_id("portability_invocation", invocation_binding["binding_hash"]):
                        raise ValueError("invocation binding id")
                    column_map = {
                        "run_id": "run_id", "project_id": "project_id", "binding_id": "binding_id",
                        "iteration_id": "iteration_id", "group_id": "group_id", "intent_id": "intent_id",
                        "invocation_id": "invocation_id", "invocation_hash": "invocation_hash",
                        "intent_hash": "intent_hash", "manifest_hash": "manifest_hash",
                        "input_state_hash": "input_state_hash", "checkpoint_id": "checkpoint_id",
                        "state_version": "state_version", "source_kind": "source_kind",
                    }
                    if any(
                        (
                            None
                            if source_kind == "fixture_compat" and key in {"iteration_id", "intent_id"}
                            else value.get(key)
                        ) != invocation_binding[column]
                        for key, column in column_map.items()
                    ):
                        raise ValueError("invocation binding column mismatch")
                    if source_kind == "fixture_compat":
                        if not fixture_store or value.get("fixture_only") is not True:
                            raise ValueError("fixture invocation binding escaped fixture store")
                    elif source_kind == "server_runner":
                        if value.get("fixture_only") is True:
                            raise ValueError("server invocation binding is marked fixture-only")
                        runner = connection.execute(
                            "SELECT binding_id,group_id,iteration_id,logical_call_id,intent_hash FROM max_runner_call_bindings WHERE binding_id=? AND run_id=?",
                            (value.get("runner_binding_id"), invocation_binding["run_id"]),
                        ).fetchone()
                        intent = connection.execute(
                            "SELECT intent_id,intent_hash,iteration_id,input_state_hash,model_identity FROM max_model_call_intents WHERE intent_id=? AND run_id=?",
                            (invocation_binding["intent_id"], invocation_binding["run_id"]),
                        ).fetchone()
                        manifest = connection.execute(
                            "SELECT manifest_hash FROM max_runner_intent_manifests WHERE intent_id=?",
                            (invocation_binding["intent_id"],),
                        ).fetchone()
                        binding = connection.execute(
                            "SELECT backend_profile_id FROM max_run_execution_bindings WHERE binding_id=? AND run_id=?",
                            (invocation_binding["binding_id"], invocation_binding["run_id"]),
                        ).fetchone()
                        backend = None if binding is None else connection.execute(
                            "SELECT model_identity FROM max_execution_backend_profiles WHERE backend_profile_id=?",
                            (binding["backend_profile_id"],),
                        ).fetchone()
                        if (
                            runner is None or intent is None or manifest is None or backend is None
                            or runner["group_id"] != value.get("group_id")
                            or runner["iteration_id"] != value.get("iteration_id")
                            or runner["logical_call_id"] != value.get("logical_call_id")
                            or runner["intent_hash"] != value.get("intent_hash")
                            or intent["intent_hash"] != value.get("intent_hash")
                            or intent["iteration_id"] != value.get("iteration_id")
                            or intent["input_state_hash"] != value.get("input_state_hash")
                            or intent["model_identity"] != backend["model_identity"]
                            or manifest["manifest_hash"] != value.get("manifest_hash")
                        ):
                            raise ValueError("server invocation binding does not match runner graph")
                    else:
                        raise ValueError("unknown invocation binding source")
                except Exception:
                    issues.append("portability invocation binding is invalid")
            result_v2_rows = selected(
                "SELECT * FROM max_normalized_agent_results_v2" + (" WHERE run_id=?" if run_id else "") + " ORDER BY run_id,iteration_id,invocation_id,intent_id",
                (run_id,) if run_id else (),
            )
            for row in result_v2_rows:
                try:
                    result = NormalizedAgentResult.from_mapping(json.loads(row["result_json"]))
                    descriptor = {
                        "project_id": row["project_id"], "run_id": row["run_id"], "binding_id": row["binding_id"],
                        "iteration_id": row["iteration_id"], "invocation_id": row["invocation_id"], "intent_id": row["intent_id"],
                        "input_state_hash": row["input_state_hash"], "checkpoint_id": row["checkpoint_id"],
                    }
                    attribution_hash = canonical_sha256({**descriptor, "invocation_hash": row["invocation_hash"]})
                    expected_id = _stable_id("normalized_agent_result", f"{attribution_hash}:{result.result_hash}")
                    if result.result_hash != row["result_hash"] or expected_id != row["result_id"] or attribution_hash != row["attribution_hash"] or int(row["result_size_bytes"]) != len(row["result_json"].encode("utf-8")):
                        issues.append("normalized agent result attribution/hash mismatch")
                    binding = connection.execute("SELECT run_id,project_id FROM max_run_execution_bindings WHERE binding_id=?", (row["binding_id"],)).fetchone()
                    run = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (row["run_id"],)).fetchone()
                    checkpoint = connection.execute("SELECT state_hash FROM max_checkpoints WHERE checkpoint_id=? AND run_id=?", (row["checkpoint_id"], row["run_id"])).fetchone()
                    result_binding = connection.execute("SELECT * FROM max_portability_result_bindings WHERE result_id=?", (row["result_id"],)).fetchone() if self._table_exists(connection, "max_portability_result_bindings") else None
                    invocation_binding = None if result_binding is None else connection.execute("SELECT * FROM max_portability_invocation_bindings WHERE invocation_binding_id=?", (result_binding["invocation_binding_id"],)).fetchone()
                    invocation_binding_payload = _loads_safe(invocation_binding["binding_json"]) if invocation_binding is not None else None
                    bound_iteration_id = invocation_binding["iteration_id"] if invocation_binding is not None else None
                    bound_intent_id = invocation_binding["intent_id"] if invocation_binding is not None else None
                    if invocation_binding is not None and invocation_binding["source_kind"] == "fixture_compat" and isinstance(invocation_binding_payload, Mapping):
                        bound_iteration_id = invocation_binding_payload.get("iteration_id") or "legacy-iteration"
                        bound_intent_id = invocation_binding_payload.get("intent_id") or "legacy-intent"
                    valid_boundary = (
                        binding is not None and run is not None and checkpoint is not None
                        and binding["run_id"] == row["run_id"] and binding["project_id"] == row["project_id"]
                        and run["project_id"] == row["project_id"] and checkpoint["state_hash"] == row["input_state_hash"]
                        and invocation_binding is not None and invocation_binding["run_id"] == row["run_id"]
                        and invocation_binding["project_id"] == row["project_id"]
                        and invocation_binding["binding_id"] == row["binding_id"]
                        and (bound_iteration_id or "legacy-iteration") == row["iteration_id"]
                        and (bound_intent_id or "legacy-intent") == row["intent_id"]
                        and invocation_binding["invocation_id"] == row["invocation_id"]
                        and invocation_binding["invocation_hash"] == row["invocation_hash"]
                        and invocation_binding["input_state_hash"] == row["input_state_hash"]
                        and invocation_binding["checkpoint_id"] == row["checkpoint_id"]
                    )
                    if result_binding is None or invocation_binding is None:
                        issues.append("normalized agent result has no server-owned invocation binding")
                    else:
                        result_binding_value = _loads_safe(result_binding["binding_json"])
                        if (
                            not isinstance(result_binding_value, Mapping)
                            or canonical_sha256(result_binding_value) != result_binding["binding_hash"]
                            or result_binding["run_id"] != row["run_id"]
                            or result_binding["project_id"] != row["project_id"]
                            or result_binding["result_hash"] != row["result_hash"]
                            or result_binding["attribution_hash"] != row["attribution_hash"]
                            or result_binding_value.get("result_id") != row["result_id"]
                            or result_binding_value.get("invocation_binding_id") != invocation_binding["invocation_binding_id"]
                            or result_binding_value.get("run_id") != row["run_id"]
                            or result_binding_value.get("project_id") != row["project_id"]
                            or result_binding_value.get("result_hash") != row["result_hash"]
                            or result_binding_value.get("attribution_hash") != row["attribution_hash"]
                            or result_binding_value.get("invocation_hash") != row["invocation_hash"]
                            or result_binding_value.get("input_state_hash") != row["input_state_hash"]
                            or result_binding_value.get("checkpoint_id") != row["checkpoint_id"]
                            or result_binding_value.get("source_kind") != invocation_binding["source_kind"]
                        ):
                            issues.append("normalized agent result binding receipt is invalid")
                        invocation_value = _loads_safe(invocation_binding["binding_json"])
                        if (
                            not isinstance(invocation_value, Mapping)
                            or canonical_sha256(invocation_value) != invocation_binding["binding_hash"]
                            or invocation_value.get("run_id") != row["run_id"]
                            or invocation_value.get("project_id") != row["project_id"]
                            or invocation_value.get("invocation_id") != row["invocation_id"]
                            or invocation_value.get("invocation_hash") != row["invocation_hash"]
                        ):
                            issues.append("server-owned invocation binding payload is invalid")
                        if invocation_binding["source_kind"] == "server_runner":
                            runner = connection.execute(
                                "SELECT binding_id,group_id,iteration_id,logical_call_id,intent_hash FROM max_runner_call_bindings WHERE binding_id=? AND run_id=?",
                                (invocation_value.get("runner_binding_id"), row["run_id"]),
                            ).fetchone()
                            intent = connection.execute(
                                "SELECT intent_id,intent_hash,iteration_id,input_state_hash FROM max_model_call_intents WHERE intent_id=? AND run_id=?",
                                (invocation_binding["intent_id"], row["run_id"]),
                            ).fetchone()
                            manifest = connection.execute(
                                "SELECT manifest_hash FROM max_runner_intent_manifests WHERE intent_id=?",
                                (invocation_binding["intent_id"],),
                            ).fetchone()
                            if (
                                runner is None or intent is None or manifest is None
                                or runner["group_id"] != invocation_binding["group_id"]
                                or runner["iteration_id"] != invocation_binding["iteration_id"]
                                or runner["logical_call_id"] != invocation_value.get("logical_call_id")
                                or intent["intent_hash"] != invocation_binding["intent_hash"]
                                or intent["input_state_hash"] != invocation_binding["input_state_hash"]
                                or manifest["manifest_hash"] != invocation_binding["manifest_hash"]
                            ):
                                issues.append("server-owned runner invocation binding is invalid")
                    if not valid_boundary:
                        issues.append("normalized agent result is outside the canonical Run boundary")
                except Exception:
                    issues.append("normalized agent result v2 is invalid")
            status_rows = selected("SELECT * FROM max_portability_profile_status_events ORDER BY profile_kind,profile_id,sequence_no")
            status_by_profile: dict[tuple[str, str], list[sqlite3.Row]] = {}
            for status_row in status_rows:
                status_by_profile.setdefault((status_row["profile_kind"], status_row["profile_id"]), []).append(status_row)
                try:
                    status_value = json.loads(status_row["status_json"])
                    if canonical_sha256(status_value) != status_row["status_hash"] or status_value.get("status") != status_row["status"] or int(status_value.get("sequence_no")) != int(status_row["sequence_no"]):
                        issues.append("profile status event hash mismatch")
                except Exception:
                    issues.append("profile status event JSON is invalid")
            for key, rows in status_by_profile.items():
                if [int(row["sequence_no"]) for row in rows] != list(range(1, len(rows) + 1)):
                    issues.append("profile status event sequence is broken")
                if rows and rows[0]["status"] not in PROFILE_STATUSES:
                    issues.append("profile status event starts with an invalid status")
            installation_rows = selected("SELECT * FROM max_host_installations")
            for installation in installation_rows:
                try:
                    installation_value = json.loads(installation["installation_json"])
                    if canonical_sha256(installation_value) != installation["installation_hash"] or installation_value.get("host_profile_id") != installation["host_profile_id"]:
                        issues.append("host installation payload/hash mismatch")
                    if installation["installation_id"] != _stable_id("host_installation", installation["installation_hash"]):
                        issues.append("host installation ID is not content-addressed")
                    for column in ("package_identity_hash", "canonical_skill_hash", "adapter_hash", "capability_artifact_hash"):
                        if installation_value.get(column) != installation[column]:
                            issues.append("host installation column/payload mismatch")
                    host = connection.execute("SELECT canonical_skill_hash,adapter_hash,capability_manifest_hash FROM max_agent_host_profiles WHERE host_profile_id=?", (installation["host_profile_id"],)).fetchone()
                    if host is None or installation["canonical_skill_hash"] != host["canonical_skill_hash"] or installation["adapter_hash"] != host["adapter_hash"] or installation["capability_artifact_hash"] != host["capability_manifest_hash"]:
                        issues.append("host installation is not bound to its profile")
                except Exception:
                    issues.append("host installation JSON is invalid")
            attestation_rows = selected("SELECT * FROM max_host_installation_attestations") if self._table_exists(connection, "max_host_installation_attestations") else []
            for attestation in attestation_rows:
                try:
                    value = json.loads(attestation["attestation_json"])
                    installation = connection.execute("SELECT * FROM max_host_installations WHERE installation_id=?", (attestation["installation_id"],)).fetchone()
                    host = connection.execute("SELECT host_profile_id FROM max_agent_host_profiles WHERE host_profile_id=?", (attestation["host_profile_id"],)).fetchone()
                    if (
                        canonical_sha256(value) != attestation["attestation_hash"]
                        or value.get("installation_id") != attestation["installation_id"]
                        or value.get("attestation_kind") != attestation["attestation_kind"]
                        or attestation["attestation_kind"] not in {"admin_declared", "trusted_local_verifier"}
                        or installation is None or host is None
                        or installation["host_profile_id"] != attestation["host_profile_id"]
                        or int(attestation["executable_proof"]) not in {0, 1}
                    ):
                        issues.append("host installation attestation is invalid")
                except Exception:
                    issues.append("host installation attestation JSON is invalid")
            packet_rows = selected("SELECT * FROM max_rehydration_packets" + (" WHERE run_id=?" if run_id else "") + " ORDER BY run_id,created_at,packet_id", (run_id,) if run_id else ())
            for packet in packet_rows:
                try:
                    packet_value = json.loads(packet["packet_json"])
                    if canonical_sha256(packet_value) != packet["packet_hash"] or packet["packet_id"] != _stable_id("rehydration_packet", packet["packet_hash"]):
                        issues.append("rehydration packet payload/hash mismatch")
                    if (
                        packet_value.get("handoff_approval_id") != packet["handoff_approval_id"]
                        or packet_value.get("run_id") != packet["run_id"]
                        or packet_value.get("project_id") != packet["project_id"]
                        or packet_value.get("old_binding_id") != packet["old_binding_id"]
                        or packet_value.get("new_binding_id") != packet["new_binding_id"]
                        or packet_value.get("checkpoint_id") != packet["checkpoint_id"]
                        or packet_value.get("state_version") != int(packet["state_version"])
                        or packet_value.get("state_hash") != packet["state_hash"]
                        or packet_value.get("event_chain_tip_hash") != packet["event_chain_tip_hash"]
                        or packet_value.get("source_policy_hash") != packet["source_policy_hash"]
                        or packet_value.get("budget_hash") != packet["budget_hash"]
                    ):
                        issues.append("rehydration packet binding mismatch")
                    for column in ("canonical_object_version_ids_json", "canonical_relation_ids_json", "claim_ids_json", "evidence_ids_json", "objection_ids_json", "hypothesis_ids_json", "research_question_ids_json", "source_role_ids_json", "unresolved_frontier_ids_json"):
                        if not isinstance(json.loads(packet[column]), list):
                            issues.append("rehydration packet ID segment is invalid")
                    if self._table_exists(connection, "max_rehydration_packet_manifest_items"):
                        manifest_rows = selected(
                            "SELECT manifest_item_id,ordinal,item_type,item_id,item_hash,item_json FROM max_rehydration_packet_manifest_items WHERE packet_id=? ORDER BY ordinal",
                            (packet["packet_id"],),
                        )
                        manifest_items = []
                        for expected_ordinal, item in enumerate(manifest_rows):
                            item_value = _loads_safe(item["item_json"])
                            if (
                                not isinstance(item_value, Mapping)
                                or int(item["ordinal"]) != expected_ordinal
                                or item_value.get("item_type") != item["item_type"]
                                or item_value.get("item_id") != item["item_id"]
                                or item_value.get("item_hash") != item["item_hash"]
                                or not _HEX64.fullmatch(str(item["item_hash"]))
                                or canonical_json(item_value) != item["item_json"]
                                or item["manifest_item_id"] != _stable_id(
                                    "rehydration_manifest_item",
                                    canonical_sha256({"packet_id": packet["packet_id"], "ordinal": expected_ordinal, **dict(item_value)})
                                )
                            ):
                                issues.append("rehydration manifest item is invalid")
                            manifest_items.append({"item_type": item["item_type"], "item_id": item["item_id"], "item_hash": item["item_hash"]})
                        if (
                            packet_value.get("schema") != "max-rehydration-packet/v2"
                            or packet_value.get("manifest_count") != len(manifest_items)
                            or packet_value.get("manifest_root") != canonical_sha256(manifest_items)
                        ):
                            issues.append("rehydration packet manifest root/count mismatch")
                        if len(manifest_rows) != len({int(item["ordinal"]) for item in manifest_rows}):
                            issues.append("rehydration packet manifest ordinals are duplicated")
                except Exception:
                    issues.append("rehydration packet JSON is invalid")
                packet_events = selected("SELECT * FROM max_rehydration_packet_events WHERE packet_id=? ORDER BY sequence_no", (packet["packet_id"],))
                previous_packet_event = None
                for event in packet_events:
                    try:
                        payload = json.loads(event["payload_json"])
                        identity = {"packet_id": event["packet_id"], "handoff_approval_id": event["handoff_approval_id"], "run_id": event["run_id"], "sequence_no": event["sequence_no"], "event_type": event["event_type"], "state": event["state"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if canonical_sha256(payload) != event["payload_hash"] or canonical_sha256(identity) != event["event_hash"] or int(event["sequence_no"]) != (1 if previous_packet_event is None else int(previous_packet_event["sequence_no"]) + 1) or event["previous_event_hash"] != (None if previous_packet_event is None else previous_packet_event["event_hash"]):
                            issues.append("rehydration packet event chain is broken")
                    except Exception:
                        issues.append("rehydration packet event is invalid")
                    previous_packet_event = event
            ack_rows = selected("SELECT * FROM max_rehydration_packet_acks")
            for ack in ack_rows:
                try:
                    ack_value = _loads_safe(ack["ack_json"])
                    packet_ref = connection.execute(
                        "SELECT packet_hash,run_id,project_id,handoff_approval_id,new_binding_id FROM max_rehydration_packets WHERE packet_id=?",
                        (ack["packet_id"],),
                    ).fetchone()
                    ack_valid = (
                        isinstance(ack_value, Mapping)
                        and packet_ref is not None
                        and canonical_sha256(ack_value) == ack["ack_hash"]
                        and ack["ack_id"] == _stable_id("rehydration_packet_ack", ack["ack_hash"])
                        and ack_value.get("packet_id") == ack["packet_id"]
                        and ack_value.get("packet_hash") == ack["packet_hash"] == packet_ref["packet_hash"]
                        and ack_value.get("handoff_approval_id") == ack["handoff_approval_id"] == packet_ref["handoff_approval_id"]
                        and ack_value.get("run_id") == ack["run_id"] == packet_ref["run_id"]
                        and ack_value.get("project_id") == ack["project_id"] == packet_ref["project_id"]
                        and ack_value.get("new_binding_id") == ack["new_binding_id"] == packet_ref["new_binding_id"]
                        and ack_value.get("created_at") == ack["created_at"]
                    )
                    if not ack_valid:
                        issues.append("rehydration packet acknowledgement mismatch")
                except Exception:
                    issues.append("rehydration packet acknowledgement is invalid")
            target_ack_rows = selected("SELECT * FROM max_rehydration_packet_target_acks") if self._table_exists(connection, "max_rehydration_packet_target_acks") else []
            for target_ack in target_ack_rows:
                try:
                    target_value = _loads_safe(target_ack["ack_json"])
                    base_ack = connection.execute(
                        "SELECT * FROM max_rehydration_packet_acks WHERE ack_id=?",
                        (target_ack["ack_id"],),
                    ).fetchone()
                    packet_ref = connection.execute(
                        "SELECT * FROM max_rehydration_packets WHERE packet_id=?",
                        (target_ack["packet_id"],),
                    ).fetchone()
                    host = connection.execute(
                        "SELECT host_profile_id,adapter_hash,capability_manifest_hash FROM max_agent_host_profiles WHERE host_profile_id=?",
                        (target_ack["target_host_profile_id"],),
                    ).fetchone()
                    installation = connection.execute(
                        "SELECT installation_hash,host_profile_id,registered,attested,bindable FROM max_host_installations WHERE installation_id=?",
                        (target_ack["target_installation_id"],),
                    ).fetchone()
                    target_valid = (
                        isinstance(target_value, Mapping)
                        and base_ack is not None
                        and packet_ref is not None
                        and host is not None
                        and canonical_sha256(target_value) == target_ack["ack_hash"]
                        and target_ack["target_ack_id"] == _stable_id("rehydration_packet_target_ack", target_ack["ack_hash"])
                        and target_value.get("ack_id") == target_ack["ack_id"] == base_ack["ack_id"]
                        and target_value.get("ack_hash") == base_ack["ack_hash"]
                        and target_value.get("packet_id") == target_ack["packet_id"] == packet_ref["packet_id"]
                        and target_value.get("packet_hash") == packet_ref["packet_hash"]
                        and target_value.get("handoff_approval_id") == target_ack["handoff_approval_id"] == packet_ref["handoff_approval_id"]
                        and target_value.get("run_id") == target_ack["run_id"] == packet_ref["run_id"]
                        and target_value.get("project_id") == target_ack["project_id"] == packet_ref["project_id"]
                        and target_value.get("new_binding_id") == target_ack["new_binding_id"] == packet_ref["new_binding_id"]
                        and target_value.get("target_host_profile_id") == target_ack["target_host_profile_id"]
                        and target_value.get("target_installation_id") == target_ack["target_installation_id"]
                        and target_value.get("target_installation_hash") == target_ack["target_installation_hash"]
                        and target_value.get("adapter_capability_hash") == target_ack["adapter_capability_hash"]
                        and target_value.get("target_session") == target_ack["target_session"]
                        and target_value.get("observed_checkpoint_hash") == target_ack["observed_checkpoint_hash"]
                        and target_value.get("observed_state_hash") == target_ack["observed_state_hash"]
                        and target_value.get("rehydrated_state_hash") == target_ack["rehydrated_state_hash"]
                        and target_value.get("manifest_root") == target_ack["manifest_root"]
                        and target_value.get("manifest_count") == target_ack["manifest_count"]
                        and bool(target_value.get("read_complete")) == bool(target_ack["read_complete"])
                        and bool(target_value.get("fixture_only")) == bool(target_ack["fixture_only"])
                        and target_value.get("created_at") == target_ack["created_at"]
                        and target_ack["ack_id"] == base_ack["ack_id"]
                        and target_ack["handoff_approval_id"] == base_ack["handoff_approval_id"]
                        and target_ack["run_id"] == base_ack["run_id"]
                        and target_ack["project_id"] == base_ack["project_id"]
                        and target_ack["new_binding_id"] == base_ack["new_binding_id"]
                        and canonical_sha256({"adapter_hash": host["adapter_hash"], "capability_manifest_hash": host["capability_manifest_hash"]}) == target_ack["adapter_capability_hash"]
                    )
                    if installation is None or installation["host_profile_id"] != target_ack["target_host_profile_id"] if installation is not None else True:
                        target_valid = False
                    if installation is None or not all(bool(installation[column]) for column in ("registered", "attested", "bindable")) or installation["installation_hash"] != target_ack["target_installation_hash"]:
                        target_valid = False
                    if not bool(target_ack["fixture_only"]):
                        current_handoff = connection.execute(
                            "SELECT handoff_approval_id,state,binding_id FROM max_backend_handoff_current WHERE run_id=?",
                            (target_ack["run_id"],),
                        ).fetchone()
                        current_binding = connection.execute(
                            "SELECT binding_id,project_id FROM max_run_execution_binding_current WHERE run_id=?",
                            (target_ack["run_id"],),
                        ).fetchone()
                        if (
                            current_handoff is None
                            or current_handoff["handoff_approval_id"] != target_ack["handoff_approval_id"]
                            or current_handoff["state"] != "CONSUMED"
                            or current_handoff["binding_id"] != target_ack["new_binding_id"]
                            or current_binding is None
                            or current_binding["binding_id"] != target_ack["new_binding_id"]
                            or current_binding["project_id"] != target_ack["project_id"]
                            or target_ack["actor_session"] != target_ack["target_session"]
                        ):
                            target_valid = False
                    if not target_valid:
                        issues.append("rehydration target acknowledgement is invalid")
                except Exception:
                    issues.append("rehydration target acknowledgement is invalid")
            result_rows = selected("SELECT * FROM max_normalized_agent_results" + (" WHERE run_id=?" if run_id else ""), (run_id,) if run_id else ())
            for row in result_rows:
                try:
                    result = NormalizedAgentResult.from_mapping(json.loads(row["result_json"]))
                    if result.result_hash != row["result_hash"] or row["result_id"] != _stable_id("normalized_agent_result", result.result_hash):
                        issues.append("normalized agent result hash mismatch")
                except Exception:
                    issues.append("normalized agent result is invalid")
            return {
                "ok": not issues,
                "run_id": run_id,
                "counts": {
                    "host_profiles": len(selected("SELECT host_profile_id FROM max_agent_host_profiles")),
                    "backend_profiles": len(selected("SELECT backend_profile_id FROM max_execution_backend_profiles")),
                    "bindings": len(binding_rows),
                    "handoff_approvals": len(handoff_rows),
                    "normalized_results": len(result_rows),
                    "normalized_results_v2": len(result_v2_rows),
                    "handoff_lineage": len(lineage_rows),
                    "rehydration_packets": len(packet_rows),
                    "rehydration_acks": len(ack_rows),
                    "rehydration_manifest_items": int(connection.execute("SELECT COUNT(*) FROM max_rehydration_packet_manifest_items" ).fetchone()[0]) if self._table_exists(connection, "max_rehydration_packet_manifest_items") else 0,
                    "rehydration_target_acks": len(target_ack_rows),
                    "quiescence_snapshots": int(connection.execute("SELECT COUNT(*) FROM max_portability_quiescence_snapshots").fetchone()[0]) if self._table_exists(connection, "max_portability_quiescence_snapshots") else 0,
                    "invocation_bindings": len(invocation_binding_rows),
                    "result_bindings": int(connection.execute("SELECT COUNT(*) FROM max_portability_result_bindings").fetchone()[0]) if self._table_exists(connection, "max_portability_result_bindings") else 0,
                    "profile_status_events": len(status_rows),
                    "host_installations": len(installation_rows),
                    "installation_attestations": int(connection.execute("SELECT COUNT(*) FROM max_host_installation_attestations").fetchone()[0]) if self._table_exists(connection, "max_host_installation_attestations") else 0,
                },
                "issues": sorted(set(issues)),
            }
        finally:
            connection.close()


# Short aliases are useful for callers that use the terms in the MR text.
HostProfile = AgentHostProfile
BackendProfile = ExecutionBackendProfile


__all__ = [
    "AgentHostProfile", "BackendHandoffApproval", "BACKEND_KINDS", "BackendProfile",
    "ExecutionBackendProfile", "HOST_KINDS", "HostProfile", "MaxPortabilityService",
    "NormalizedAgentResult", "RunExecutionBinding", "opencode_go_backend_profile",
    "supported_backend_descriptors",
]
