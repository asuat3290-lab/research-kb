"""Strict, provider-neutral contracts for the MR-2A bounded runner.

The runner contracts deliberately contain no control-plane authority.  A model
adapter receives a bounded request envelope and returns a bounded proposal; it
never receives a StartApproval, a lease token, a database path, or a secret.
All values are immutable and hash from the same canonical serializer used by
MR-0B.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence

from ..contract import (
    CanonicalObject,
    CanonicalRelation,
    RolePacket,
    canonical_sha256,
    model_to_dict,
)
from ..contract.base import ContractValidationError, deep_freeze, require_mapping_fields


def _strict(value: Mapping[str, Any], allowed: set[str], required: set[str] = frozenset()) -> Mapping[str, Any]:
    return require_mapping_fields(value, allowed=allowed, required=required)


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{name} is required")
    return value.strip()


def _tuple(value: Sequence[Any] | None, name: str) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ContractValidationError(f"{name} must be a list or tuple")
    return tuple(deep_freeze(item) for item in value)


def _mapping(value: Mapping[str, Any] | None, name: str) -> Mapping[str, Any]:
    if value is None:
        return deep_freeze({})
    if not isinstance(value, Mapping):
        raise ContractValidationError(f"{name} must be an object")
    return deep_freeze(dict(value))


class _StrEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class ModelCallStatus(_StrEnum):
    PLANNED = "planned"
    DISPATCHED = "dispatched"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


class RecoveryDisposition(_StrEnum):
    NEW_CALL = "new_call"
    REUSE_INTENT = "reuse_intent"
    QUERY_PROVIDER_RESULT = "query_provider_result"
    CONSUME_STORED_RESULT = "consume_stored_result"
    REPLAY_CHANGE_SET = "replay_change_set"
    FINISH_OUTCOME = "finish_outcome"
    IDEMPOTENT_SUCCESS = "idempotent_success"
    AMBIGUOUS_PAUSE = "ambiguous_pause"
    ADMIN_DECISION_REQUIRED = "admin_decision_required"


@dataclass(frozen=True)
class ModelIdentity:
    """A frozen provider-neutral identity whose value matches the Charter."""

    value: str
    provider: str = "fixture"
    revision: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _text(self.value, "model identity"))
        object.__setattr__(self, "provider", _text(self.provider, "model provider"))
        if not isinstance(self.revision, str):
            raise ContractValidationError("model revision must be text")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ModelIdentity":
        raw = _strict(value, {"value", "identity", "model_id", "provider", "revision"}, set())
        identity = raw.get("value", raw.get("identity", raw.get("model_id")))
        if identity is None:
            raise ContractValidationError("model identity value is required")
        return cls(str(identity), str(raw.get("provider", "fixture")), str(raw.get("revision", "")))

    @property
    def identity(self) -> str:
        return self.value

    def as_string(self) -> str:
        return self.value

    @property
    def identity_hash(self) -> str:
        return canonical_sha256(self)


@dataclass(frozen=True)
class InferenceProfile:
    """The bounded generation settings frozen by the first model call."""

    temperature: float = 0.0
    top_p: float = 1.0
    max_output_tokens: int = 1024
    seed: int | None = 0
    response_format: str = "bounded-json"
    timeout_seconds: int = 120
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.temperature, bool) or not isinstance(self.temperature, (int, float)) or not 0 <= self.temperature <= 2:
            raise ContractValidationError("inference temperature is outside the supported range")
        if isinstance(self.top_p, bool) or not isinstance(self.top_p, (int, float)) or not 0 < self.top_p <= 1:
            raise ContractValidationError("inference top_p is outside the supported range")
        if isinstance(self.max_output_tokens, bool) or not isinstance(self.max_output_tokens, int) or not 1 <= self.max_output_tokens <= 1_000_000:
            raise ContractValidationError("inference max_output_tokens is outside the supported range")
        if self.seed is not None and (isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0):
            raise ContractValidationError("inference seed is invalid")
        if not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= 86_400:
            raise ContractValidationError("inference timeout is outside the supported range")
        object.__setattr__(self, "response_format", _text(self.response_format, "inference response_format"))
        object.__setattr__(self, "extra", _mapping(self.extra, "inference extra"))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "InferenceProfile":
        raw = _strict(value, {"temperature", "top_p", "max_output_tokens", "seed", "response_format", "timeout_seconds", "extra", "inference_profile_hash"}, set())
        return cls(
            temperature=raw.get("temperature", 0.0), top_p=raw.get("top_p", 1.0),
            max_output_tokens=raw.get("max_output_tokens", 1024), seed=raw.get("seed", 0),
            response_format=raw.get("response_format", "bounded-json"),
            timeout_seconds=raw.get("timeout_seconds", 120), extra=raw.get("extra", {}),
        )

    @property
    def inference_profile_hash(self) -> str:
        return canonical_sha256(self)

    @property
    def profile_hash(self) -> str:
        return self.inference_profile_hash


@dataclass(frozen=True)
class RunnerProfile:
    """An administrator-registered, single-model runner configuration."""

    profile_id: str
    model_identity: str | ModelIdentity
    inference_profile: InferenceProfile | Mapping[str, Any]
    role_names: tuple[str, ...] = ("socratic", "attack", "adjudicator", "rehydrator")
    gateway_name: str = "fixture"
    profile_hash: str = ""
    call_budget: Mapping[str, Any] = field(default_factory=lambda: {"input_tokens": 1024, "output_tokens": 256, "cost_units": 1})

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile_id", _text(self.profile_id, "runner profile_id"))
        if isinstance(self.model_identity, ModelIdentity):
            identity = self.model_identity
        elif isinstance(self.model_identity, Mapping):
            identity = ModelIdentity.from_mapping(self.model_identity)
        else:
            identity = ModelIdentity(str(self.model_identity))
        object.__setattr__(self, "model_identity", identity.value)
        profile = self.inference_profile if isinstance(self.inference_profile, InferenceProfile) else InferenceProfile.from_mapping(self.inference_profile)
        object.__setattr__(self, "inference_profile", profile)
        roles = tuple(_text(item, "runner role") for item in _tuple(self.role_names, "role_names"))
        if not roles:
            raise ContractValidationError("runner profile requires at least one role")
        object.__setattr__(self, "role_names", roles)
        object.__setattr__(self, "gateway_name", _text(self.gateway_name, "runner gateway_name"))
        raw_budget = self.call_budget if isinstance(self.call_budget, Mapping) else {}
        normalized_budget: dict[str, int | float] = {}
        for key, value in raw_budget.items():
            unit = _text(key, "runner call budget unit")
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ContractValidationError("runner call budget values must be positive numbers")
            normalized_budget[unit] = value
        if not normalized_budget:
            raise ContractValidationError("runner call budget must declare at least one unit")
        object.__setattr__(self, "call_budget", deep_freeze(normalized_budget))
        expected = canonical_sha256({"profile_id": self.profile_id, "model_identity": self.model_identity, "inference_profile": model_to_dict(profile), "role_names": roles, "gateway_name": self.gateway_name, "call_budget": normalized_budget})
        if self.profile_hash and self.profile_hash != expected:
            raise ContractValidationError("runner profile hash is not canonical")
        object.__setattr__(self, "profile_hash", expected)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RunnerProfile":
        raw = _strict(value, {"profile_id", "model_identity", "inference_profile", "role_names", "gateway_name", "profile_hash", "call_budget"}, {"profile_id", "model_identity", "inference_profile"})
        return cls(raw["profile_id"], raw["model_identity"], raw["inference_profile"], tuple(raw.get("role_names", ("socratic", "attack", "adjudicator", "rehydrator"))), raw.get("gateway_name", "fixture"), raw.get("profile_hash", ""), raw.get("call_budget", {"input_tokens": 1024, "output_tokens": 256, "cost_units": 1}))


@dataclass(frozen=True)
class AdapterCapabilities:
    provider_name: str = "fixture"
    supports_provider_idempotency: bool = True
    supports_result_query: bool = True
    supports_usage_receipt: bool = True
    max_request_chars: int = 200_000

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_name", _text(self.provider_name, "adapter provider_name"))
        if not isinstance(self.max_request_chars, int) or isinstance(self.max_request_chars, bool) or self.max_request_chars < 1:
            raise ContractValidationError("adapter max_request_chars is invalid")
        for name in ("supports_provider_idempotency", "supports_result_query", "supports_usage_receipt"):
            if not isinstance(getattr(self, name), bool):
                raise ContractValidationError(f"adapter capability {name} must be boolean")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AdapterCapabilities":
        raw = _strict(value, {"provider_name", "supports_provider_idempotency", "supports_result_query", "supports_usage_receipt", "max_request_chars"}, set())
        return cls(**raw)


@dataclass(frozen=True)
class ModelRequestEnvelope:
    project_id: str
    run_id: str
    iteration_id: str
    role_packet: RolePacket | Mapping[str, Any]
    model_identity: str
    inference_profile: InferenceProfile | Mapping[str, Any]
    context: Mapping[str, Any]
    request_payload: Mapping[str, Any]
    request_hash: str = ""
    intent_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_id", _text(self.project_id, "request project_id"))
        object.__setattr__(self, "run_id", _text(self.run_id, "request run_id"))
        object.__setattr__(self, "iteration_id", _text(self.iteration_id, "request iteration_id"))
        packet = self.role_packet if isinstance(self.role_packet, RolePacket) else RolePacket.from_mapping(self.role_packet)
        object.__setattr__(self, "role_packet", packet)
        object.__setattr__(self, "model_identity", _text(self.model_identity, "request model_identity"))
        profile = self.inference_profile if isinstance(self.inference_profile, InferenceProfile) else InferenceProfile.from_mapping(self.inference_profile)
        object.__setattr__(self, "inference_profile", profile)
        object.__setattr__(self, "context", _mapping(self.context, "request context"))
        object.__setattr__(self, "request_payload", _mapping(self.request_payload, "request payload"))
        computed = canonical_sha256({"project_id": self.project_id, "run_id": self.run_id, "iteration_id": self.iteration_id, "role_packet": model_to_dict(packet), "model_identity": self.model_identity, "inference_profile": model_to_dict(profile), "context": self.context, "request_payload": self.request_payload})
        if self.request_hash and self.request_hash != computed:
            raise ContractValidationError("request hash is not canonical")
        object.__setattr__(self, "request_hash", computed)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ModelRequestEnvelope":
        raw = _strict(value, {"project_id", "run_id", "iteration_id", "role_packet", "model_identity", "inference_profile", "context", "request_payload", "request_hash", "intent_hash"}, {"project_id", "run_id", "iteration_id", "role_packet", "model_identity", "inference_profile", "context", "request_payload"})
        return cls(raw["project_id"], raw["run_id"], raw["iteration_id"], raw["role_packet"], raw["model_identity"], raw["inference_profile"], raw["context"], raw["request_payload"], raw.get("request_hash", ""), raw.get("intent_hash", ""))


@dataclass(frozen=True)
class ModelCallIntent:
    project_id: str
    run_id: str
    iteration_id: str
    input_state_hash: str
    role_packet_id: str
    round_type: str
    model_identity: str
    inference_profile_hash: str
    request_hash: str
    idempotency_key: str
    request: ModelRequestEnvelope | Mapping[str, Any]
    logical_call_id: str = ""
    intent_id: str = ""
    intent_hash: str = ""
    phase: str = ""
    call_spec_id: str = ""
    upstream_call_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("project_id", "run_id", "iteration_id", "input_state_hash", "role_packet_id", "round_type", "model_identity", "inference_profile_hash", "request_hash", "idempotency_key"):
            object.__setattr__(self, name, _text(getattr(self, name), f"intent {name}"))
        request = self.request if isinstance(self.request, ModelRequestEnvelope) else ModelRequestEnvelope.from_mapping(self.request)
        if request.project_id != self.project_id or request.run_id != self.run_id or request.iteration_id != self.iteration_id:
            raise ContractValidationError("model request is outside the intent boundary")
        if request.model_identity != self.model_identity or request.request_hash != self.request_hash:
            raise ContractValidationError("model request does not bind the intent")
        object.__setattr__(self, "request", request)
        logical = self.logical_call_id or canonical_sha256({"run_id": self.run_id, "iteration_id": self.iteration_id, "idempotency_key": self.idempotency_key})[:48]
        object.__setattr__(self, "logical_call_id", logical)
        phase = self.phase or self.round_type
        call_spec_id = self.call_spec_id or self.role_packet_id
        object.__setattr__(self, "phase", _text(phase, "intent phase"))
        object.__setattr__(self, "call_spec_id", _text(call_spec_id, "intent call_spec_id"))
        object.__setattr__(self, "upstream_call_ids", tuple(_text(item, "intent upstream call ID") for item in _tuple(self.upstream_call_ids, "upstream_call_ids")))
        intent_id = self.intent_id or canonical_sha256({"project_id": self.project_id, "run_id": self.run_id, "iteration_id": self.iteration_id, "logical_call_id": logical})[:48]
        object.__setattr__(self, "intent_id", intent_id)
        # The durable intent identity is bound to the request hash, never to
        # the request body.  The full ModelRequestEnvelope remains an
        # in-process value and is rebuilt from the frozen plan/gateway after
        # recovery.
        payload = {"project_id": self.project_id, "run_id": self.run_id, "iteration_id": self.iteration_id, "input_state_hash": self.input_state_hash, "role_packet_id": self.role_packet_id, "round_type": self.round_type, "phase": self.phase, "call_spec_id": self.call_spec_id, "upstream_call_ids": list(self.upstream_call_ids), "model_identity": self.model_identity, "inference_profile_hash": self.inference_profile_hash, "request_hash": self.request_hash, "idempotency_key": self.idempotency_key, "logical_call_id": logical, "intent_id": intent_id}
        expected = canonical_sha256(payload)
        if self.intent_hash and self.intent_hash != expected:
            raise ContractValidationError("intent hash is not canonical")
        object.__setattr__(self, "intent_hash", expected)
        object.__setattr__(self, "request", replace(request, intent_hash=expected))

    def durable_mapping(self) -> Mapping[str, Any]:
        """Return the metadata-only intent manifest persisted by MR-2A.1."""

        packet = self.request.role_packet
        context = self.request.context
        source_references = context.get("source_reference_ids", ())
        if not isinstance(source_references, (list, tuple)):
            source_references = ()
        public_artifacts = context.get("public_upstream_artifacts", ())
        if not isinstance(public_artifacts, (list, tuple)):
            public_artifacts = ()
        return {
            "manifest_version": "mr-2a.2/v1",
            "project_id": self.project_id,
            "run_id": self.run_id,
            "iteration_id": self.iteration_id,
            "input_state_hash": self.input_state_hash,
            "role_packet_id": self.role_packet_id,
            "role": packet.role,
            "packet_hash": canonical_sha256(packet),
            "round_type": self.round_type,
            "phase": self.phase,
            "call_spec_id": self.call_spec_id,
            "upstream_call_ids": list(self.upstream_call_ids),
            "model_identity": self.model_identity,
            "inference_profile_hash": self.inference_profile_hash,
            "request_hash": self.request_hash,
            "idempotency_key": self.idempotency_key,
            "logical_call_id": self.logical_call_id,
            "intent_id": self.intent_id,
            "intent_hash": self.intent_hash,
            "canonical_ids": sorted(str(item) for item in packet.allowed_canonical_ids),
            "target_id": packet.target_id,
            "frontier_hash": self.request.context.get("frontier_hash"),
            "gateway_name": context.get("gateway_name", ""),
            "gateway_identity": context.get("gateway_identity", ""),
            "gateway_config_hash": context.get("gateway_config_hash", ""),
            "contract_version": context.get("contract_version", "research-kb/v1"),
            "source_reference_ids": list(source_references),
            "request_char_count": context.get("request_char_count", 0),
            "fragment_count": context.get("fragment_count", 0),
            "context_hash": context.get("context_hash", ""),
            "public_upstream_artifacts": list(public_artifacts),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ModelCallIntent":
        raw = _strict(value, {"project_id", "run_id", "iteration_id", "input_state_hash", "role_packet_id", "round_type", "phase", "call_spec_id", "upstream_call_ids", "model_identity", "inference_profile_hash", "request_hash", "idempotency_key", "request", "logical_call_id", "intent_id", "intent_hash"}, {"project_id", "run_id", "iteration_id", "input_state_hash", "role_packet_id", "round_type", "model_identity", "inference_profile_hash", "request_hash", "idempotency_key", "request"})
        return cls(raw["project_id"], raw["run_id"], raw["iteration_id"], raw["input_state_hash"], raw["role_packet_id"], raw["round_type"], raw["model_identity"], raw["inference_profile_hash"], raw["request_hash"], raw["idempotency_key"], raw["request"], raw.get("logical_call_id", ""), raw.get("intent_id", ""), raw.get("intent_hash", ""), raw.get("phase", ""), raw.get("call_spec_id", ""), tuple(raw.get("upstream_call_ids", ())))


@dataclass(frozen=True)
class ModelResponseEnvelope:
    logical_call_id: str
    intent_hash: str
    model_identity: str
    inference_profile_hash: str
    status: ModelCallStatus | str
    proposal: Mapping[str, Any]
    usage_receipt: Mapping[str, Any]
    provider_call_id: str = "fixture-call"
    dispatch_known: bool = True
    error_code: str | None = None
    response_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "logical_call_id", _text(self.logical_call_id, "response logical_call_id"))
        object.__setattr__(self, "intent_hash", _text(self.intent_hash, "response intent_hash"))
        object.__setattr__(self, "model_identity", _text(self.model_identity, "response model_identity"))
        object.__setattr__(self, "inference_profile_hash", _text(self.inference_profile_hash, "response inference_profile_hash"))
        status = getattr(self.status, "value", self.status)
        if status not in {item.value for item in ModelCallStatus}:
            raise ContractValidationError("unknown model call status")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "proposal", _mapping(self.proposal, "response proposal"))
        object.__setattr__(self, "usage_receipt", _mapping(self.usage_receipt, "response usage_receipt"))
        object.__setattr__(self, "provider_call_id", _text(self.provider_call_id, "response provider_call_id"))
        if not isinstance(self.dispatch_known, bool):
            raise ContractValidationError("response dispatch_known must be boolean")
        if self.error_code is not None and not isinstance(self.error_code, str):
            raise ContractValidationError("response error_code must be text")
        computed = canonical_sha256({"logical_call_id": self.logical_call_id, "intent_hash": self.intent_hash, "model_identity": self.model_identity, "inference_profile_hash": self.inference_profile_hash, "status": status, "proposal": self.proposal, "usage_receipt": self.usage_receipt, "provider_call_id": self.provider_call_id, "dispatch_known": self.dispatch_known, "error_code": self.error_code})
        if self.response_hash and self.response_hash != computed:
            raise ContractValidationError("response hash is not canonical")
        object.__setattr__(self, "response_hash", computed)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ModelResponseEnvelope":
        raw = _strict(value, {"logical_call_id", "intent_hash", "model_identity", "inference_profile_hash", "status", "proposal", "usage_receipt", "provider_call_id", "dispatch_known", "error_code", "response_hash"}, {"logical_call_id", "intent_hash", "model_identity", "inference_profile_hash", "status", "proposal", "usage_receipt"})
        return cls(raw["logical_call_id"], raw["intent_hash"], raw["model_identity"], raw["inference_profile_hash"], raw["status"], raw["proposal"], raw["usage_receipt"], raw.get("provider_call_id", "fixture-call"), raw.get("dispatch_known", True), raw.get("error_code"), raw.get("response_hash", ""))


@dataclass(frozen=True)
class ModelCallResult:
    logical_call_id: str
    intent_hash: str
    status: ModelCallStatus | str
    response: ModelResponseEnvelope | Mapping[str, Any]
    authoritative: bool = True
    result_hash: str = ""

    def __post_init__(self) -> None:
        response = self.response if isinstance(self.response, ModelResponseEnvelope) else ModelResponseEnvelope.from_mapping(self.response)
        if response.logical_call_id != self.logical_call_id or response.intent_hash != self.intent_hash:
            raise ContractValidationError("model result is not bound to the intent")
        status = getattr(self.status, "value", self.status)
        if status not in {ModelCallStatus.SUCCEEDED.value, ModelCallStatus.FAILED.value}:
            raise ContractValidationError("authoritative result status is invalid")
        if not isinstance(self.authoritative, bool) or not self.authoritative:
            raise ContractValidationError("only authoritative model results may be persisted")
        object.__setattr__(self, "response", response)
        object.__setattr__(self, "status", status)
        computed = canonical_sha256({"logical_call_id": self.logical_call_id, "intent_hash": self.intent_hash, "status": status, "response": model_to_dict(response), "authoritative": self.authoritative})
        if self.result_hash and self.result_hash != computed:
            raise ContractValidationError("model result hash is not canonical")
        object.__setattr__(self, "result_hash", computed)

    def durable_mapping(self) -> Mapping[str, Any]:
        """Persist typed proposal/receipt facts without a raw response blob."""

        response = self.response
        return {
            "result_manifest_version": "mr-2a.2/v1",
            "logical_call_id": self.logical_call_id,
            "intent_hash": self.intent_hash,
            "status": self.status,
            "authoritative": self.authoritative,
            "result_hash": self.result_hash,
            "response_hash": response.response_hash,
            "model_identity": response.model_identity,
            "inference_profile_hash": response.inference_profile_hash,
            "proposal": model_to_dict(response.proposal),
            "usage_receipt": model_to_dict(response.usage_receipt),
            "provider_call_id": response.provider_call_id,
            "dispatch_known": response.dispatch_known,
            "error_code": response.error_code,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ModelCallResult":
        raw = _strict(value, {"logical_call_id", "intent_hash", "status", "response", "authoritative", "result_hash"}, {"logical_call_id", "intent_hash", "status", "response"})
        return cls(raw["logical_call_id"], raw["intent_hash"], raw["status"], raw["response"], raw.get("authoritative", True), raw.get("result_hash", ""))


@dataclass(frozen=True)
class RunnerProposal:
    """The only model output that the runner may normalize into a change set."""

    objects: tuple[CanonicalObject, ...] = ()
    relations: tuple[CanonicalRelation, ...] = ()
    artifact_links: tuple[Mapping[str, Any], ...] = ()
    record_refs: tuple[str, ...] = ()
    strategy: Mapping[str, Any] | None = None
    output_summary: str = ""
    role_outputs: tuple[Mapping[str, Any], ...] = ()
    deliberation: Mapping[str, Any] | None = None
    source_handles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "objects", tuple(item if isinstance(item, CanonicalObject) else CanonicalObject.from_mapping(item) for item in self.objects))
        object.__setattr__(self, "relations", tuple(item if isinstance(item, CanonicalRelation) else CanonicalRelation.from_mapping(item) for item in self.relations))
        object.__setattr__(self, "artifact_links", tuple(_mapping(item, "artifact link") for item in self.artifact_links))
        object.__setattr__(self, "record_refs", tuple(_text(item, "record reference") for item in self.record_refs))
        object.__setattr__(self, "strategy", _mapping(self.strategy, "strategy") if self.strategy is not None else None)
        if not isinstance(self.output_summary, str):
            raise ContractValidationError("proposal output_summary must be text")
        object.__setattr__(self, "role_outputs", tuple(_mapping(item, "role output") for item in self.role_outputs))
        object.__setattr__(self, "deliberation", _mapping(self.deliberation, "deliberation") if self.deliberation is not None else None)
        object.__setattr__(self, "source_handles", tuple(_text(item, "source handle") for item in self.source_handles))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RunnerProposal":
        raw = _strict(value, {"objects", "relations", "artifact_links", "record_refs", "strategy", "output_summary", "role_outputs", "deliberation", "source_handles"}, set())
        return cls(tuple(raw.get("objects", ())), tuple(raw.get("relations", ())), tuple(raw.get("artifact_links", ())), tuple(raw.get("record_refs", ())), raw.get("strategy"), raw.get("output_summary", ""), tuple(raw.get("role_outputs", ())), raw.get("deliberation"), tuple(raw.get("source_handles", ())))


@dataclass(frozen=True)
class DeliberationCallSpec:
    """Frozen logical call contract for a multi-role adjudication group."""

    call_id: str
    phase: str
    role: str
    upstream_call_ids: tuple[str, ...] = ()
    input_mode: str = "canonical_packet"
    artifact_type: str = "position"

    def __post_init__(self) -> None:
        object.__setattr__(self, "call_id", _text(self.call_id, "deliberation call_id"))
        object.__setattr__(self, "phase", _text(self.phase, "deliberation phase"))
        object.__setattr__(self, "role", _text(self.role, "deliberation role"))
        object.__setattr__(self, "upstream_call_ids", tuple(_text(item, "deliberation upstream call_id") for item in _tuple(self.upstream_call_ids, "deliberation upstream_call_ids")))
        object.__setattr__(self, "input_mode", _text(self.input_mode, "deliberation input_mode"))
        object.__setattr__(self, "artifact_type", _text(self.artifact_type, "deliberation artifact_type"))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DeliberationCallSpec":
        raw = _strict(value, {"call_id", "phase", "role", "upstream_call_ids", "input_mode", "artifact_type"}, {"call_id", "phase", "role"})
        return cls(raw["call_id"], raw["phase"], raw["role"], tuple(raw.get("upstream_call_ids", ())), raw.get("input_mode", "canonical_packet"), raw.get("artifact_type", "position"))


@dataclass(frozen=True)
class RunnerPlan:
    project_id: str
    run_id: str
    sequence: int
    input_state_hash: str
    round_type: str
    cognitive_kind: str
    priority_reason: str
    model_identity: str
    inference_profile_hash: str
    iteration_id: str
    role_packets: tuple[RolePacket, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    plan_id: str = ""
    plan_hash: str = ""
    call_specs: tuple[DeliberationCallSpec, ...] = ()

    def __post_init__(self) -> None:
        for name in ("project_id", "run_id", "input_state_hash", "round_type", "cognitive_kind", "priority_reason", "model_identity", "inference_profile_hash", "iteration_id"):
            object.__setattr__(self, name, _text(getattr(self, name), f"plan {name}"))
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 1:
            raise ContractValidationError("plan sequence must be positive")
        packets = tuple(item if isinstance(item, RolePacket) else RolePacket.from_mapping(item) for item in self.role_packets)
        if not packets:
            raise ContractValidationError("plan requires at least one role packet")
        object.__setattr__(self, "role_packets", packets)
        object.__setattr__(self, "metadata", _mapping(self.metadata, "plan metadata"))
        specs = tuple(item if isinstance(item, DeliberationCallSpec) else DeliberationCallSpec.from_mapping(item) for item in self.call_specs)
        if not specs:
            specs = tuple(DeliberationCallSpec(call_id=f"{self.round_type}:{index}", phase=self.round_type, role=packet.role) for index, packet in enumerate(packets))
        if len(specs) != len(packets):
            raise ContractValidationError("runner plan call specs must cover every role packet exactly")
        if len({item.call_id for item in specs}) != len(specs):
            raise ContractValidationError("runner plan call spec IDs must be unique")
        if self.round_type == "adjudication":
            expected_adjudication = (
                ("lead_position", "lead_position", "lead", ()),
                ("rival_position", "rival_position", "rival", ()),
                ("rival_cross_examination", "rival_cross_examination", "rival", ("lead_position", "rival_position")),
                ("lead_cross_examination_response", "lead_cross_examination_response", "lead", ("lead_position", "rival_position", "rival_cross_examination")),
                ("adjudicator", "adjudicator", "adjudicator", ("lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response")),
            )
            actual_adjudication = tuple((item.call_id, item.phase, item.role, tuple(item.upstream_call_ids)) for item in specs)
            if actual_adjudication != expected_adjudication:
                raise ContractValidationError("adjudication plan must contain the frozen five-call topology")
        object.__setattr__(self, "call_specs", specs)
        payload = {"project_id": self.project_id, "run_id": self.run_id, "sequence": self.sequence, "input_state_hash": self.input_state_hash, "round_type": self.round_type, "cognitive_kind": self.cognitive_kind, "priority_reason": self.priority_reason, "model_identity": self.model_identity, "inference_profile_hash": self.inference_profile_hash, "iteration_id": self.iteration_id, "role_packets": model_to_dict(packets), "call_specs": model_to_dict(specs), "metadata": self.metadata}
        expected_hash = canonical_sha256(payload)
        if self.plan_hash and self.plan_hash != expected_hash:
            raise ContractValidationError("runner plan hash is not canonical")
        object.__setattr__(self, "plan_hash", expected_hash)
        expected_id = self.plan_id or canonical_sha256({"run_id": self.run_id, "sequence": self.sequence, "plan_hash": expected_hash})[:48]
        object.__setattr__(self, "plan_id", expected_id)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RunnerPlan":
        raw = _strict(value, {"project_id", "run_id", "sequence", "input_state_hash", "round_type", "cognitive_kind", "priority_reason", "model_identity", "inference_profile_hash", "iteration_id", "role_packets", "metadata", "plan_id", "plan_hash", "call_specs"}, {"project_id", "run_id", "sequence", "input_state_hash", "round_type", "cognitive_kind", "priority_reason", "model_identity", "inference_profile_hash", "iteration_id", "role_packets"})
        return cls(raw["project_id"], raw["run_id"], raw["sequence"], raw["input_state_hash"], raw["round_type"], raw["cognitive_kind"], raw["priority_reason"], raw["model_identity"], raw["inference_profile_hash"], raw["iteration_id"], tuple(raw["role_packets"]), raw.get("metadata", {}), raw.get("plan_id", ""), raw.get("plan_hash", ""), tuple(raw.get("call_specs", ())))


class ModelAdapter(Protocol):
    @property
    def capabilities(self) -> AdapterCapabilities:
        ...

    def dispatch(self, request: ModelRequestEnvelope, *, idempotency_key: str) -> ModelResponseEnvelope:
        ...

    def query(self, *, idempotency_key: str) -> ModelResponseEnvelope | None:
        ...


class ResearchGateway(Protocol):
    def context(self, *, project_id: str, run_id: str, state_hash: str, allowed_ids: Sequence[str], cold: bool = False) -> Mapping[str, Any]:
        ...


class DispatchUnknown(RuntimeError):
    """The adapter cannot prove whether an external dispatch happened."""

    def __init__(self, message: str = "model dispatch outcome is unknown", *, sent: bool = True) -> None:
        super().__init__(message)
        self.sent = sent


__all__ = [
    "AdapterCapabilities", "DeliberationCallSpec", "DispatchUnknown", "InferenceProfile", "ModelAdapter", "ModelCallIntent", "ModelCallResult", "ModelCallStatus", "ModelIdentity", "ModelRequestEnvelope", "ModelResponseEnvelope", "RecoveryDisposition", "ResearchGateway", "RolePacket", "RunnerPlan", "RunnerProfile", "RunnerProposal",
]
