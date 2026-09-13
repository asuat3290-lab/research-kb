"""Deterministic MR-2A adapter and research gateway fixtures.

There is intentionally no provider SDK in this module.  The fake adapter is a
test seam for dispatch/recovery semantics and is suitable only for temporary
control databases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..contract import canonical_json, canonical_sha256, make_stable_id, model_to_dict
from .contracts import (
    AdapterCapabilities,
    DispatchUnknown,
    InferenceProfile,
    ModelRequestEnvelope,
    ModelResponseEnvelope,
)


_FIXTURE_TIME = "2026-01-01T00:00:00.000Z"


def _usage_receipt(request: ModelRequestEnvelope, *, logical_call_id: str, provider_call_id: str) -> dict[str, Any]:
    request_chars = len(canonical_json(request))
    candidate = {"input_tokens": max(1, (request_chars + 3) // 4), "output_tokens": 32, "cost_units": 1}
    declared = request.context.get("call_budget_limits", {})
    if isinstance(declared, Mapping):
        amount = {
            key: min(value, declared[key])
            for key, value in candidate.items()
            if key in declared and isinstance(declared.get(key), (int, float))
            and not isinstance(declared.get(key), bool) and declared.get(key, 0) > 0
        }
    else:
        amount = candidate
    if not amount:
        amount = {"cost_units": 1}
    payload = {
        "receipt_id": make_stable_id("usage_receipt", logical_call_id),
        "run_id": request.run_id,
        "iteration_id": request.iteration_id,
        "model_identity": request.model_identity,
        "amount": amount,
        "issued_at": _FIXTURE_TIME,
        "authority_id": "fixture-authority",
        "logical_call_id": logical_call_id,
        "intent_hash": request.intent_hash,
        "request_hash": request.request_hash,
        "provider_call_id": provider_call_id,
        "inference_profile_hash": request.inference_profile.inference_profile_hash,
    }
    payload_hash = canonical_sha256(payload)
    return {**payload, "payload_hash": payload_hash, "receipt_hash": canonical_sha256({"payload": payload, "payload_hash": payload_hash})}


def _proposal(request: ModelRequestEnvelope, logical_call_id: str) -> dict[str, Any]:
    kind = str(request.request_payload.get("cognitive_kind", "socratic_exploration"))
    round_type = str(request.request_payload.get("round_type", "exploration"))
    call_spec_id = str(request.request_payload.get("call_spec_id", ""))
    allowed = tuple(request.role_packet.allowed_canonical_ids)
    target = allowed[0] if allowed else make_stable_id("research_question", "fixture")
    if call_spec_id in {"lead_position", "rival_position"}:
        role = "lead" if call_spec_id == "lead_position" else "rival"
        return {
            "objects": [], "relations": [], "artifact_links": [], "record_refs": [],
            "strategy": {"family": "historical_context", "query": f"fixture:{call_spec_id}", "target_ids": list(allowed[:4]), "filters": {"fixture": True}, "result_ids": [], "new_evidence_ids": [], "coverage_keys": ["historical_context"]},
            "output_summary": f"fixture {call_spec_id} public position", "role_outputs": [],
            "deliberation": {"kind": "position", "role": role, "position": f"fixture independent {role} position", "canonical_claim_ids": list(request.context.get("canonical_claim_ids", ())), "canonical_evidence_ids": list(request.context.get("canonical_evidence_ids", ())), "rationale": f"fixture rationale for {role}"},
        }
    if call_spec_id == "rival_cross_examination":
        return {
            "objects": [], "relations": [], "artifact_links": [], "record_refs": [], "strategy": None,
            "output_summary": "fixture rival cross-examination", "role_outputs": [],
            "deliberation": {"kind": "cross_examination", "examiner_role": "rival", "respondent_role": "lead", "question": "Which canonical evidence would falsify the lead position?", "challenged_claim_ids": list(request.context.get("canonical_claim_ids", ()))},
        }
    if call_spec_id == "lead_cross_examination_response":
        return {
            "objects": [], "relations": [], "artifact_links": [], "record_refs": [], "strategy": None,
            "output_summary": "fixture lead cross-examination response", "role_outputs": [],
            "deliberation": {"kind": "correction", "role": "lead", "correction": "The lead position remains bounded by the cited canonical evidence.", "corrected_claim_ids": list(request.context.get("canonical_claim_ids", ()))},
        }
    if call_spec_id == "adjudicator":
        object_id = make_stable_id("decision", logical_call_id)
        object_value = {"stable_id": object_id, "kind": "decision", "project_id": request.project_id, "version": 1, "payload": {"label": "fixture adjudication candidate", "rival_ids": list(allowed[:2])}}
        return {
            "objects": [object_value], "relations": [], "artifact_links": [], "record_refs": [],
            "strategy": {"family": "historical_context", "query": "fixture:adjudicator", "target_ids": list(allowed[:4]), "filters": {"fixture": True}, "result_ids": [], "new_evidence_ids": [], "coverage_keys": ["historical_context"]},
            "output_summary": "fixture adjudicator output", "role_outputs": [],
            "deliberation": {
                "kind": "adjudication",
                "validity_audit": {"auditor_role": "adjudicator", "passed": True, "facts_evidence_true": True, "normative_valid": True, "expression_clear": True, "role_fidelity": True, "findings": ["fixture audit"], "audited_claim_ids": list(request.context.get("canonical_claim_ids", ())), "rationale": "fixture adjudicator audit"},
                "adjudication": {"value": "underdetermined", "rationale": "fixture adjudicator preserves the bounded uncertainty", "rival_ids": list(allowed[:2]), "canonical_evidence_ids": list(request.context.get("canonical_evidence_ids", ()))},
                "minority_reports": [],
            },
        }
    if round_type == "attack":
        object_kind = "objection"
        payload = {"status": "candidate", "label": "fixture counterexample", "target_id": target}
        artifact = {"artifact_type": "attack_record", "artifact": {"target_id": target, "target_version_id": target, "outcome": "needs_review", "rationale": "fixture adversarial probe"}}
        family = "counterevidence"
        coverage = ("theoretical_opponent",)
    elif round_type == "adjudication":
        # The frozen MR-2A.2 topology must select one of the five explicit
        # logical calls above. There is no legacy two-role adjudication
        # fallback that can manufacture a discussion artifact.
        raise ValueError("fixture adjudication requires an explicit call spec")
    elif round_type == "rehydration":
        object_kind = "hypothesis"
        payload = {"status": "candidate", "label": "fixture rehydration interpretation"}
        artifact = {"artifact_type": "rehydration_review", "artifact": {"canonical_rebuild": True, "drift_flags": []}}
        family = "rehydration"
        coverage = ("canonical_rebuild",)
    elif round_type == "acquisition_review":
        object_kind = "evidence"
        payload = {"status": "candidate", "label": "fixture acquisition review evidence", "target_id": target}
        artifact = {"artifact_type": "search_strategy", "artifact": {"family": "direct", "query": "fixture acquisition review", "coverage_keys": ["source_role"]}}
        family = "direct"
        coverage = ("source_role",)
    else:
        object_kind = "hypothesis"
        payload = {"status": "candidate", "label": "fixture bounded hypothesis", "target_id": target}
        artifact = {"artifact_type": "search_strategy", "artifact": {"family": "direct", "query": "fixture bounded exploration", "coverage_keys": ["conceptual_definition"]}}
        family = "direct"
        coverage = ("conceptual_definition",)
    object_id = make_stable_id(object_kind, logical_call_id)
    object_value = {"stable_id": object_id, "kind": object_kind, "project_id": request.project_id, "version": 1, "payload": payload}
    strategy = {
        "family": family,
        "query": f"fixture:{kind}",
        "target_ids": list(allowed[:4]),
        "filters": {"fixture": True},
        "result_ids": [],
        "new_evidence_ids": [],
        "coverage_keys": list(coverage),
    }
    roles = tuple({"role": packet.role, "position": f"fixture independent {packet.role}", "canonical_ids": list(packet.allowed_canonical_ids)} for packet in (request.role_packet,))
    return {"objects": [object_value], "relations": [], "artifact_links": [artifact], "record_refs": [], "strategy": strategy, "output_summary": "bounded fixture proposal", "role_outputs": list(roles)}


@dataclass
class ScriptedFakeAdapter:
    """A deterministic adapter with explicit dispatch ambiguity injection."""

    fixture_only: bool = field(default=True, init=False)

    provider_idempotency: bool = True
    result_query: bool = True
    usage_receipts: bool = True

    def __post_init__(self) -> None:
        self._results: dict[str, ModelResponseEnvelope] = {}
        self._failures: list[str] = []
        self.dispatch_count = 0
        self.dispatch_log: list[str] = []

    @property
    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            provider_name="scripted-fixture",
            supports_provider_idempotency=self.provider_idempotency,
            supports_result_query=self.result_query,
            supports_usage_receipt=self.usage_receipts,
        )

    def inject_failure(self, mode: str) -> None:
        allowed = {"dispatch_before", "dispatch_unknown", "response_invalid", "usage_invalid"}
        if mode not in allowed:
            raise ValueError("unsupported fake adapter failure mode")
        self._failures.append(mode)

    def dispatch(self, request: ModelRequestEnvelope, *, idempotency_key: str) -> ModelResponseEnvelope:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ValueError("fake adapter requires a server idempotency key")
        if self.provider_idempotency and idempotency_key in self._results:
            return self._results[idempotency_key]
        if self._failures and self._failures[0] == "dispatch_before":
            self._failures.pop(0)
            raise DispatchUnknown(sent=False)
        self.dispatch_count += 1
        self.dispatch_log.append(idempotency_key)
        logical_call_id = str(request.request_payload.get("logical_call_id") or canonical_sha256(idempotency_key)[:48])
        provider_call_id = make_stable_id("provider_call", canonical_sha256(idempotency_key)[:48])
        response = ModelResponseEnvelope(
            logical_call_id=logical_call_id,
            intent_hash=request.intent_hash or request.request_hash,
            model_identity=request.model_identity,
            inference_profile_hash=request.inference_profile.inference_profile_hash,
            status="succeeded",
            proposal=_proposal(request, logical_call_id),
            usage_receipt=_usage_receipt(request, logical_call_id=logical_call_id, provider_call_id=provider_call_id),
            provider_call_id=provider_call_id,
        )
        if self._failures and self._failures[0] == "response_invalid":
            self._failures.pop(0)
            return ModelResponseEnvelope(
                logical_call_id=response.logical_call_id,
                intent_hash="0" * 64,
                model_identity=response.model_identity,
                inference_profile_hash=response.inference_profile_hash,
                status="succeeded",
                proposal=model_to_dict(response.proposal),
                usage_receipt=model_to_dict(response.usage_receipt),
            )
        if self._failures and self._failures[0] == "usage_invalid":
            self._failures.pop(0)
            response = ModelResponseEnvelope(
                logical_call_id=response.logical_call_id,
                intent_hash=response.intent_hash,
                model_identity=response.model_identity,
                inference_profile_hash=response.inference_profile_hash,
                status=response.status,
                proposal=response.proposal,
                usage_receipt={"amount": {"input_tokens": -1}},
                provider_call_id=response.provider_call_id,
            )
        if self._failures and self._failures[0] == "dispatch_unknown":
            self._failures.pop(0)
            if self.provider_idempotency:
                self._results[idempotency_key] = response
            raise DispatchUnknown(sent=True)
        if self.provider_idempotency:
            self._results[idempotency_key] = response
        return response

    def query(self, *, idempotency_key: str) -> ModelResponseEnvelope | None:
        if not self.result_query:
            raise RuntimeError("fake adapter does not support result query")
        return self._results.get(idempotency_key)

    def clear(self) -> None:
        self._results.clear()
        self._failures.clear()


class FixtureResearchGateway:
    """A bounded, deterministic gateway that never reads corpus data."""

    fixture_only = True

    def __init__(self, *, source_references: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self.source_references = dict(source_references or {})
        self.calls: list[dict[str, Any]] = []

    def context(self, *, project_id: str, run_id: str, state_hash: str, allowed_ids: Sequence[str], cold: bool = False) -> Mapping[str, Any]:
        ids = tuple(sorted(set(str(item) for item in allowed_ids)))
        result: dict[str, Any] = {"project_id": project_id, "run_id": run_id, "state_hash": state_hash, "canonical_ids": list(ids), "source_references": [self.source_references[item] for item in ids if item in self.source_references]}
        if cold:
            result["cold"] = True
            result["excluded_sections"] = ["working_summary", "recent_summaries", "working_interpretation", "search_history", "search_history_narrative", "role_discussion_history"]
        self.calls.append(dict(result))
        return result


class FixtureUsageAuthority:
    """Server-side verifier used by temporary fake-run fixtures."""

    fixture_only = True

    def __init__(self, repository=None) -> None:
        self.repository = repository

    def verify_usage_receipt(self, receipt, *, run_id: str, iteration_id: str, model_identity: str, logical_call_id=None, intent_hash=None, request_hash=None, provider_call_id=None, inference_profile_hash=None):
        if self.repository is None or not self.repository.is_fixture_database():
            return False
        if receipt.authority_id != "fixture-authority" or model_identity != "fixture-model/v1":
            return False
        if receipt.run_id != run_id or receipt.iteration_id != iteration_id or receipt.model_identity != model_identity:
            return False
        expected = {"logical_call_id": logical_call_id, "intent_hash": intent_hash, "request_hash": request_hash, "provider_call_id": provider_call_id, "inference_profile_hash": inference_profile_hash}
        if any(value is not None for value in expected.values()) and any(getattr(receipt, key, "") != value for key, value in expected.items() if value is not None):
            return False
        if not receipt.amount or any(isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 for value in receipt.amount.values()):
            return False
        if receipt.payload_hash != receipt.computed_payload_hash():
            return False
        if receipt.receipt_hash not in (None, receipt.computed_receipt_hash()):
            return False
        return {"authority": "fixture-authority", "fixture_identity": "research-kb-mr2a-fixture/v1", "receipt_hash": receipt.receipt_hash or receipt.computed_receipt_hash()}


__all__ = ["FixtureResearchGateway", "FixtureUsageAuthority", "ScriptedFakeAdapter"]
