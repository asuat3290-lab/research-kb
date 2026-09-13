"""Provider call records, local usage attestation and ledger receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from ..contract import canonical_json, canonical_sha256, make_stable_id
from ..persistence.control_models import UsageReceipt
from .contract import ProviderContractError, ProviderProfile, normalize_usage


PROVIDER_USAGE_AUTHORITY_ID = "mr2b0-local-provider-usage-authority/v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class ProviderCallRecord:
    call_record_id: str
    provider_call_id: str
    run_id: str
    project_id: str
    profile_hash: str
    model_identity: str
    intent_hash: str
    request_hash: str
    idempotency_key: str
    transport_status: str
    terminal_status: str
    usage: Mapping[str, int]
    response_manifest: Mapping[str, Any]
    pricing_hash: str
    logical_call_id: str = ""
    intent_id: str = ""
    iteration_id: str = ""
    created_at: str = ""
    record_hash: str = ""

    def __post_init__(self) -> None:
        for name in ("call_record_id", "provider_call_id", "run_id", "project_id", "profile_hash", "model_identity", "intent_hash", "request_hash", "idempotency_key", "transport_status", "terminal_status", "pricing_hash"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ProviderContractError(f"provider call {name} is required")
        usage = normalize_usage(self.usage) if self.usage else {}
        object.__setattr__(self, "usage", usage)
        if not isinstance(self.response_manifest, Mapping):
            raise ProviderContractError("provider response manifest must be an object")
        created_at = self.created_at or _now()
        object.__setattr__(self, "created_at", created_at)
        expected = canonical_sha256(self.to_mapping(include_hash=False))
        if self.record_hash and self.record_hash != expected:
            raise ProviderContractError("provider call record hash is not canonical")
        object.__setattr__(self, "record_hash", expected)

    def to_mapping(self, *, include_hash: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "call_record_id": self.call_record_id, "provider_call_id": self.provider_call_id, "run_id": self.run_id, "project_id": self.project_id,
            "profile_hash": self.profile_hash, "model_identity": self.model_identity, "intent_hash": self.intent_hash, "request_hash": self.request_hash,
            "idempotency_key": self.idempotency_key, "transport_status": self.transport_status, "terminal_status": self.terminal_status,
            "usage": dict(self.usage), "response_manifest": dict(self.response_manifest), "pricing_hash": self.pricing_hash,
            "logical_call_id": self.logical_call_id, "intent_id": self.intent_id, "iteration_id": self.iteration_id, "created_at": self.created_at,
        }
        if include_hash:
            result["record_hash"] = self.record_hash
        return result


@dataclass(frozen=True)
class ProviderUsageAttestation:
    attestation_id: str
    call_record_id: str
    provider_call_id: str
    run_id: str
    profile_hash: str
    pricing_hash: str
    usage: Mapping[str, int]
    cost_units: int
    authority_id: str
    created_at: str = ""
    attestation_hash: str = ""

    def __post_init__(self) -> None:
        usage = normalize_usage(self.usage)
        object.__setattr__(self, "usage", usage)
        if isinstance(self.cost_units, bool) or not isinstance(self.cost_units, int) or self.cost_units < 0:
            raise ProviderContractError("attestation cost_units is invalid", code="USAGE_DISPUTE")
        if self.authority_id != PROVIDER_USAGE_AUTHORITY_ID or any(not isinstance(getattr(self, name), str) or not getattr(self, name) for name in ("attestation_id", "call_record_id", "provider_call_id", "run_id", "profile_hash", "pricing_hash")):
            raise ProviderContractError("provider usage attestation binding is incomplete", code="USAGE_DISPUTE")
        created_at = self.created_at or _now()
        object.__setattr__(self, "created_at", created_at)
        expected = canonical_sha256(self.to_mapping(include_hash=False))
        if self.attestation_hash and self.attestation_hash != expected:
            raise ProviderContractError("usage attestation hash is not canonical", code="USAGE_DISPUTE")
        object.__setattr__(self, "attestation_hash", expected)

    def to_mapping(self, *, include_hash: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "attestation_id": self.attestation_id, "call_record_id": self.call_record_id, "provider_call_id": self.provider_call_id,
            "run_id": self.run_id, "profile_hash": self.profile_hash, "pricing_hash": self.pricing_hash, "usage": dict(self.usage),
            "cost_units": self.cost_units, "authority_id": self.authority_id, "created_at": self.created_at,
        }
        if include_hash:
            result["attestation_hash"] = self.attestation_hash
        return result


class ProviderUsageAuthority:
    """Local authority for provider-reported usage, never an external bill."""

    authority_id = PROVIDER_USAGE_AUTHORITY_ID

    def __init__(self) -> None:
        self.calls: dict[str, ProviderCallRecord] = {}
        self.attestations: dict[str, ProviderUsageAttestation] = {}

    def record_call(self, record: ProviderCallRecord) -> ProviderCallRecord:
        existing = self.calls.get(record.idempotency_key)
        if existing is not None:
            if existing.record_hash != record.record_hash:
                raise ProviderContractError("provider idempotency key has a conflicting call record", code="PROVIDER_IDEMPOTENCY_CONFLICT")
            return existing
        if any(item.provider_call_id == record.provider_call_id and item.record_hash != record.record_hash for item in self.calls.values()):
            raise ProviderContractError("provider call ID was reused with different content", code="PROVIDER_IDEMPOTENCY_CONFLICT")
        self.calls[record.idempotency_key] = record
        return record

    def attest(self, record: ProviderCallRecord, profile: ProviderProfile) -> ProviderUsageAttestation:
        record = self.record_call(record)
        if record.profile_hash != profile.profile_hash or record.model_identity != profile.model_identity or record.pricing_hash != profile.pricing.pricing_hash:
            raise ProviderContractError("provider call is outside the frozen profile/pricing binding", code="PROFILE_MODEL_MISMATCH")
        if record.terminal_status != "succeeded":
            raise ProviderContractError("only a successful terminal provider call can be attested", code="USAGE_DISPUTE")
        if not record.usage:
            raise ProviderContractError("provider usage is missing", code="USAGE_DISPUTE")
        cost = profile.pricing.cost_units_for_usage(record.usage)
        attestation_id = make_stable_id("provider_usage_attestation", canonical_sha256(record.call_record_id)[:64])
        attestation = ProviderUsageAttestation(attestation_id, record.call_record_id, record.provider_call_id, record.run_id, record.profile_hash, record.pricing_hash, record.usage, cost, self.authority_id)
        existing = self.attestations.get(record.call_record_id)
        if existing is not None and existing.attestation_hash != attestation.attestation_hash:
            raise ProviderContractError("provider usage attestation replay differs", code="USAGE_DISPUTE")
        self.attestations[record.call_record_id] = attestation
        return attestation

    def to_usage_receipt(self, record: ProviderCallRecord, attestation: ProviderUsageAttestation, *, logical_call_id: str, intent_hash: str, request_hash: str, iteration_id: str, inference_profile_hash: str | None = None) -> UsageReceipt:
        if record.call_record_id != attestation.call_record_id or record.provider_call_id != attestation.provider_call_id or record.run_id != attestation.run_id or record.profile_hash != attestation.profile_hash or record.pricing_hash != attestation.pricing_hash or dict(record.usage) != dict(attestation.usage):
            raise ProviderContractError("usage receipt binding does not match provider attestation", code="USAGE_DISPUTE")
        amount = {**dict(attestation.usage), "cost_units": attestation.cost_units}
        payload = {
            "receipt_id": make_stable_id("provider_usage_receipt", canonical_sha256(attestation.attestation_id)[:64]), "run_id": record.run_id, "iteration_id": iteration_id,
            "model_identity": record.model_identity, "amount": amount, "issued_at": attestation.created_at, "authority_id": self.authority_id,
            "logical_call_id": logical_call_id, "intent_hash": intent_hash, "request_hash": request_hash, "provider_call_id": record.provider_call_id,
            # The runner inference hash and the provider profile hash are
            # separate bindings.  MR-2B0 keeps both: the former lets the
            # existing runner accept the response; the latter remains on the
            # provider call/attestation rows and is checked by this authority.
            "inference_profile_hash": inference_profile_hash or record.profile_hash,
        }
        payload_hash = canonical_sha256(payload)
        return UsageReceipt(**payload, payload_hash=payload_hash, receipt_hash=canonical_sha256({"payload": payload, "payload_hash": payload_hash}))

    def verify_usage_receipt(self, receipt: UsageReceipt, *, run_id: str, iteration_id: str, model_identity: str, logical_call_id: str | None = None, intent_hash: str | None = None, request_hash: str | None = None, provider_call_id: str | None = None, inference_profile_hash: str | None = None) -> Mapping[str, Any] | bool:
        if receipt.run_id != run_id or receipt.iteration_id != iteration_id or receipt.model_identity != model_identity:
            return False
        if logical_call_id is not None and receipt.logical_call_id != logical_call_id:
            return False
        for expected, actual in ((intent_hash, receipt.intent_hash), (request_hash, receipt.request_hash), (provider_call_id, receipt.provider_call_id), (inference_profile_hash, receipt.inference_profile_hash)):
            if expected is not None and expected != actual:
                return False
        if receipt.computed_payload_hash() != receipt.payload_hash or receipt.computed_receipt_hash() != receipt.receipt_hash:
            return False
        return {"verified": True, "authority_id": self.authority_id, "receipt_hash": receipt.receipt_hash}


__all__ = ["PROVIDER_USAGE_AUTHORITY_ID", "ProviderCallRecord", "ProviderUsageAttestation", "ProviderUsageAuthority"]
