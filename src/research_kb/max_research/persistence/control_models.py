"""Strict typed inputs owned by the MR-1A control plane."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from ..contract import CanonicalObject, CanonicalRelation, canonical_json, canonical_sha256, model_to_dict
from ..contract.base import ContractValidationError


def _strict_mapping(value: Any, allowed: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractValidationError(f"{name} must be an object")
    unknown = set(str(key) for key in value) - allowed
    if unknown:
        raise ContractValidationError(f"{name} contains unsupported fields")
    return value


@dataclass(frozen=True)
class CanonicalChangeSet:
    """An all-or-nothing graph mutation bound to one open iteration."""

    project_id: str
    run_id: str
    iteration_id: str
    input_state_hash: str
    objects: tuple[CanonicalObject, ...] = ()
    relations: tuple[CanonicalRelation, ...] = ()
    adopt_object_version_ids: tuple[str, ...] = ()
    adopt_relation_ids: tuple[str, ...] = ()
    source_reference_results: tuple[Mapping[str, Any], ...] = ()
    expected_output_state_hash: str | None = None
    change_set_id: str | None = None
    actor_id: str | None = None
    actor_kind: str | None = None
    actor_session: str | None = None
    fencing_token: int | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CanonicalChangeSet":
        allowed = {
            "project_id", "run_id", "iteration_id", "input_state_hash", "objects", "relations",
            "adopt_object_version_ids", "adopt_relation_ids", "source_reference_results",
            "expected_output_state_hash", "change_set_id", "actor_id", "actor_kind", "actor_session",
            "fencing_token",
        }
        raw = _strict_mapping(value, allowed, "canonical change set")
        def required_string(key: str) -> str:
            result = raw.get(key)
            if not isinstance(result, str) or not result:
                raise ContractValidationError(f"canonical change set {key} is required")
            return result
        objects = tuple(item if isinstance(item, CanonicalObject) else CanonicalObject.from_mapping(item) for item in raw.get("objects", ()))
        relations = tuple(item if isinstance(item, CanonicalRelation) else CanonicalRelation.from_mapping(item) for item in raw.get("relations", ()))
        refs = raw.get("source_reference_results", ())
        if not isinstance(refs, (list, tuple)) or not all(isinstance(item, Mapping) for item in refs):
            raise ContractValidationError("source_reference_results must be a list of objects")
        object_ids = tuple(raw.get("adopt_object_version_ids", ()))
        relation_ids = tuple(raw.get("adopt_relation_ids", ()))
        if not all(isinstance(item, str) and item for item in (*object_ids, *relation_ids)):
            raise ContractValidationError("adopted canonical IDs must be non-empty strings")
        token = raw.get("fencing_token")
        if token is not None and (isinstance(token, bool) or not isinstance(token, int) or token < 1):
            raise ContractValidationError("canonical change set fencing_token is invalid")
        return cls(
            project_id=required_string("project_id"), run_id=required_string("run_id"), iteration_id=required_string("iteration_id"),
            input_state_hash=required_string("input_state_hash"), objects=objects, relations=relations,
            adopt_object_version_ids=object_ids, adopt_relation_ids=relation_ids,
            source_reference_results=tuple(dict(item) for item in refs),
            expected_output_state_hash=raw.get("expected_output_state_hash"), change_set_id=raw.get("change_set_id"),
            actor_id=raw.get("actor_id"), actor_kind=raw.get("actor_kind"), actor_session=raw.get("actor_session"),
            fencing_token=token,
        )

    def payload(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id, "run_id": self.run_id, "iteration_id": self.iteration_id,
            "input_state_hash": self.input_state_hash,
            "objects": [model_to_dict(item) for item in self.objects],
            "relations": [model_to_dict(item) for item in self.relations],
            "adopt_object_version_ids": list(self.adopt_object_version_ids),
            "adopt_relation_ids": list(self.adopt_relation_ids),
            "source_reference_results": [dict(item) for item in self.source_reference_results],
        }

    def canonical_hash(self) -> str:
        return canonical_sha256(self.payload())


@dataclass(frozen=True)
class UsageReceipt:
    """Server-verifiable usage fact; an ``authoritative`` boolean is not enough."""

    receipt_id: str
    run_id: str
    iteration_id: str
    model_identity: str
    amount: Mapping[str, Any]
    issued_at: str
    authority_id: str
    payload_hash: str
    receipt_hash: str | None = None
    # MR-2A.2 call binding.  These fields are optional only for legacy MR-1
    # service-level usage tests; every runner result must populate all of
    # them and the authority verifies their exact values.
    logical_call_id: str = ""
    intent_hash: str = ""
    request_hash: str = ""
    provider_call_id: str = ""
    inference_profile_hash: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "UsageReceipt":
        allowed = {"receipt_id", "run_id", "iteration_id", "model_identity", "amount", "issued_at", "authority_id", "payload_hash", "receipt_hash", "logical_call_id", "intent_hash", "request_hash", "provider_call_id", "inference_profile_hash"}
        raw = _strict_mapping(value, allowed, "usage receipt")
        required = ("receipt_id", "run_id", "iteration_id", "model_identity", "issued_at", "authority_id", "payload_hash")
        for key in required:
            if not isinstance(raw.get(key), str) or not raw[key]:
                raise ContractValidationError(f"usage receipt {key} is required")
        amount = raw.get("amount")
        if not isinstance(amount, Mapping) or not amount:
            raise ContractValidationError("usage receipt amount is required")
        return cls(
            receipt_id=str(raw["receipt_id"]), run_id=str(raw["run_id"]), iteration_id=str(raw["iteration_id"]),
            model_identity=str(raw["model_identity"]), amount=dict(amount), issued_at=str(raw["issued_at"]),
            authority_id=str(raw["authority_id"]), payload_hash=str(raw["payload_hash"]), receipt_hash=raw.get("receipt_hash"),
            logical_call_id=str(raw.get("logical_call_id", "")), intent_hash=str(raw.get("intent_hash", "")),
            request_hash=str(raw.get("request_hash", "")), provider_call_id=str(raw.get("provider_call_id", "")),
            inference_profile_hash=str(raw.get("inference_profile_hash", "")),
        )

    def payload(self) -> dict[str, Any]:
        payload = {
            "receipt_id": self.receipt_id, "run_id": self.run_id, "iteration_id": self.iteration_id,
            "model_identity": self.model_identity, "amount": dict(self.amount), "issued_at": self.issued_at,
            "authority_id": self.authority_id,
        }
        binding = {
            "logical_call_id": self.logical_call_id,
            "intent_hash": self.intent_hash,
            "request_hash": self.request_hash,
            "provider_call_id": self.provider_call_id,
            "inference_profile_hash": self.inference_profile_hash,
        }
        if any(binding.values()):
            payload.update(binding)
        return payload

    def computed_payload_hash(self) -> str:
        return canonical_sha256(self.payload())

    def computed_receipt_hash(self) -> str:
        return canonical_sha256({"payload": self.payload(), "payload_hash": self.payload_hash})

    def as_mapping(self) -> dict[str, Any]:
        return {**self.payload(), "payload_hash": self.payload_hash, "receipt_hash": self.receipt_hash or self.computed_receipt_hash()}


class UsageAuthority(Protocol):
    def verify_usage_receipt(
        self,
        receipt: UsageReceipt,
        *,
        run_id: str,
        iteration_id: str,
        model_identity: str,
        logical_call_id: str | None = None,
        intent_hash: str | None = None,
        request_hash: str | None = None,
        provider_call_id: str | None = None,
        inference_profile_hash: str | None = None,
    ) -> Mapping[str, Any] | bool:
        """Return a server-owned verification result or False."""


__all__ = ["CanonicalChangeSet", "UsageAuthority", "UsageReceipt"]
