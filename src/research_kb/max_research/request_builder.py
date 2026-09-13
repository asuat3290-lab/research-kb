"""Server-owned deterministic request and source binding for MR-4B1A-R.

The builder is intentionally one-way: it reads the durable runner plan and
the fixed local core evidence gateway, constructs a transient typed request,
and returns only hashes/counts in the manifest.  No caller-provided request,
callback, source text or prompt is accepted by the production entrypoint.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .contract import canonical_sha256, model_to_dict
from .long_run import LocalCoreEvidenceGateway
from .provider.codec import OpenAICompatibleCodec, TrustedSourceData
from .provider.contract import ProviderProfile
from .runner.contracts import ModelCallIntent, ModelRequestEnvelope, RolePacket, RunnerPlan, RunnerProfile


CORE_DATABASE = Path(r"D:\research-kb-pilot\data\research.db")
MAX_REQUEST_BYTES = 65_536
MAX_PROMPT_CHARS = 12_000


class ServerRequestBuildError(RuntimeError):
    """A server-owned request could not be rebuilt without widening authority."""


@dataclass(frozen=True)
class BuiltServerRequest:
    request: ModelRequestEnvelope
    body: bytes
    manifest: Mapping[str, Any]
    intent: ModelCallIntent


def _loads(value: Any, name: str) -> Any:
    try:
        result = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ServerRequestBuildError(f"durable {name} is invalid") from exc
    if not isinstance(result, (dict, list)):
        raise ServerRequestBuildError(f"durable {name} is invalid")
    return result


def _source_selection(authority: Mapping[str, Any]) -> dict[str, Any]:
    allowlist = authority.get("source_allowlist")
    if not isinstance(allowlist, (list, tuple)) or len(allowlist) != 1 or not isinstance(allowlist[0], Mapping):
        raise ServerRequestBuildError("exactly one server-owned source passage is required")
    item = dict(allowlist[0])
    required = ("passage_id", "document_id", "document_version_id", "source_role", "evidential_function")
    if any(not isinstance(item.get(key), str) or not item[key] for key in required):
        raise ServerRequestBuildError("server-owned source selection is incomplete")
    return item


def _plan_packet(plan: RunnerPlan, manifest: Mapping[str, Any]) -> tuple[RolePacket, Any]:
    packet_id = str(manifest.get("role_packet_id", ""))
    packets = list(plan.role_packets)
    index = next((idx for idx, packet in enumerate(packets) if packet.packet_id == packet_id), 0)
    if not packets or index >= len(plan.call_specs):
        raise ServerRequestBuildError("durable runner plan has no matching call packet")
    packet = packets[index]
    spec = plan.call_specs[index]
    if packet.packet_id != packet_id or str(manifest.get("packet_hash", canonical_sha256(packet))) != canonical_sha256(packet):
        raise ServerRequestBuildError("durable runner packet drifted")
    return packet, spec


def _prompt_chars(body_mapping: Mapping[str, Any]) -> int:
    messages = body_mapping.get("messages", ())
    if not isinstance(messages, (list, tuple)):
        return 0
    total = 0
    for item in messages:
        if isinstance(item, Mapping) and isinstance(item.get("content"), str):
            total += len(item["content"])
    return total


class ServerOwnedRequestBuilder:
    """Rebuild a request from the durable plan, state, profile and exact source."""

    def __init__(self, *, gateway: LocalCoreEvidenceGateway | None = None) -> None:
        self.gateway = gateway or LocalCoreEvidenceGateway(CORE_DATABASE)

    def _source(self, authority: Mapping[str, Any]) -> tuple[dict[str, Any], TrustedSourceData]:
        selection = _source_selection(authority)
        policy = authority.get("source_policy")
        if not isinstance(policy, Mapping):
            raise ServerRequestBuildError("durable source policy is missing")
        max_chars = int(policy.get("max_source_characters", authority.get("caps", {}).get("max_source_characters", 0)))
        max_tokens = int(policy.get("max_source_tokens", 512))
        if max_chars < 1 or max_chars > 2000 or max_tokens < 1 or max_tokens > 512:
            raise ServerRequestBuildError("source character authority is outside the one-passage bound")
        raw = self.gateway.get_packet_source(project_id=str(authority["project_id"]), passage_id=selection["passage_id"], context=0)
        if not isinstance(raw, Mapping):
            raise ServerRequestBuildError("exact source passage is unavailable")
        for key in ("project_id", "document_id", "passage_id", "source_version", "document_content_hash", "passage_content_hash", "text"):
            if key not in raw:
                raise ServerRequestBuildError("exact source passage is incomplete")
        if raw["project_id"] != authority["project_id"] or raw["document_id"] != selection["document_id"] or raw["passage_id"] != selection["passage_id"] or raw["source_version"] != selection["document_version_id"]:
            raise ServerRequestBuildError("source project/document/passage/version drifted")
        if not isinstance(raw["text"], str) or not raw["text"]:
            raise ServerRequestBuildError("exact source passage has no bounded text")
        # The exact passage identity remains bound to the document/passage
        # content hashes, while the egress permit may carry only its bounded
        # deterministic prefix.  This mirrors the canonical source-egress
        # truncation rule and keeps the full passage out of durable state.
        excerpt_limit = min(max_chars, max_tokens * 4)
        excerpt = raw["text"][:excerpt_limit]
        truncated = len(excerpt) < len(raw["text"])
        verification = str(raw.get("verification_status", "unverified"))
        reliability = str(raw.get("reliability_status", "unverified"))
        # This canary may cite the candidate source, but it may never upgrade
        # the source status as a side effect of producing a model request.
        if verification not in {"unverified", "candidate_only"} or reliability not in {"unverified", "candidate_only"}:
            raise ServerRequestBuildError("source status drifted outside candidate-only authority")
        purpose = str(selection.get("purpose", "supports"))
        source_binding = {
            "project_id": authority["project_id"], "document_id": raw["document_id"],
            "passage_id": raw["passage_id"], "source_version": raw["source_version"],
            "document_content_hash": raw["document_content_hash"], "passage_content_hash": raw["passage_content_hash"],
            "source_role": selection["source_role"], "evidential_function": selection["evidential_function"],
            "purpose": purpose, "policy_hash": authority["source_egress_policy_hash"],
            "excerpt_hash": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
            "excerpt_characters": len(excerpt), "source_tokens": (len(excerpt) + 3) // 4,
            "truncated": truncated,
        }
        packet_hash = canonical_sha256(source_binding)
        trusted = TrustedSourceData._from_server(
            source_handle="mr4b1ar-source-" + packet_hash[:32], excerpt=excerpt, context="",
            server_locator=dict(raw.get("locator", {})), source_version=raw["source_version"],
            reliability_status=reliability, verification_status=verification,
            source_role=selection["source_role"], evidential_function=selection["evidential_function"],
            purpose=purpose, truncated=truncated, packet_hash=packet_hash,
            policy_hash=authority["source_egress_policy_hash"],
        )
        return source_binding, trusted

    def _request(
        self,
        *,
        authority: Mapping[str, Any],
        plan: RunnerPlan,
        runner_profile: RunnerProfile,
        intent_manifest: Mapping[str, Any],
        source_binding: Mapping[str, Any],
        trusted_source: TrustedSourceData,
        logical_call_id: str,
    ) -> tuple[ModelCallIntent, bytes, dict[str, Any]]:
        packet, spec = _plan_packet(plan, intent_manifest)
        if runner_profile.model_identity != authority["model_identity"]:
            raise ServerRequestBuildError("runner/model identity drifted")
        context: dict[str, Any] = {
            "provider_profile_hash": authority["provider_profile_hash"],
            "gateway_name": self.gateway.gateway_name,
            "gateway_identity": self.gateway.gateway_identity,
            "gateway_config_hash": self.gateway.config_hash,
            "contract_version": "research-kb/v1",
            "source_reference_ids": [source_binding["document_id"], source_binding["passage_id"]],
            "context_hash": canonical_sha256(source_binding),
            "frontier_hash": intent_manifest.get("frontier_hash", "server-owned"),
            "canonical_ids": sorted(str(item) for item in packet.allowed_canonical_ids),
            "fragment_count": 1,
            "trusted_source_data": trusted_source,
        }
        request_payload = {
            "round_type": plan.round_type, "cognitive_kind": plan.cognitive_kind,
            "plan_hash": plan.plan_hash, "sequence": plan.sequence,
            "target_id": packet.target_id, "logical_call_id": logical_call_id,
            "phase": spec.phase, "call_spec_id": spec.call_id,
            "upstream_call_ids": list(spec.upstream_call_ids), "public_upstream": {},
        }
        request = ModelRequestEnvelope(
            project_id=str(authority["project_id"]), run_id=str(authority["run_id"]),
            iteration_id=plan.iteration_id, role_packet=packet,
            model_identity=runner_profile.model_identity,
            inference_profile=runner_profile.inference_profile,
            context=context, request_payload=request_payload,
        )
        intent = ModelCallIntent(
            project_id=request.project_id, run_id=request.run_id, iteration_id=request.iteration_id,
            input_state_hash=str(intent_manifest["input_state_hash"]), role_packet_id=packet.packet_id,
            round_type=plan.round_type, model_identity=request.model_identity,
            inference_profile_hash=runner_profile.inference_profile.inference_profile_hash,
            request_hash=request.request_hash, idempotency_key=str(intent_manifest["idempotency_key"]),
            request=request, logical_call_id=logical_call_id,
            intent_id=str(intent_manifest.get("intent_id", "")), intent_hash=str(intent_manifest.get("intent_hash", "")),
            phase=str(intent_manifest.get("phase", spec.phase)), call_spec_id=spec.call_id,
            upstream_call_ids=tuple(spec.upstream_call_ids),
        )
        expected_request_hash = str(intent_manifest.get("request_hash", ""))
        expected_intent_hash = str(intent_manifest.get("intent_hash", ""))
        if expected_request_hash and intent.request_hash != expected_request_hash:
            raise ServerRequestBuildError("durable ModelCallIntent request hash drifted")
        if expected_intent_hash and intent.intent_hash != expected_intent_hash:
            raise ServerRequestBuildError("durable ModelCallIntent intent hash drifted")
        provider_profile = authority.get("_provider_profile")
        if not isinstance(provider_profile, ProviderProfile):
            raise ServerRequestBuildError("provider profile is not available to the server builder")
        encoded = OpenAICompatibleCodec.encode(intent.request, provider_profile)
        body = encoded.body
        limits = provider_profile.request_limits
        if len(body) > MAX_REQUEST_BYTES or len(body) > int(limits.get("max_request_bytes", 0)):
            raise ServerRequestBuildError("provider request exceeds the 65,536-byte authority")
        prompt_chars = _prompt_chars(json.loads(body.decode("utf-8")))
        if prompt_chars > MAX_PROMPT_CHARS or prompt_chars > int(limits.get("max_prompt_chars", 0)):
            raise ServerRequestBuildError("provider prompt exceeds the 12,000-character authority")
        maximum = provider_profile.authority_maximum_usage()
        caps = authority["caps"]
        for component, cap_key in (("input_tokens", "max_input_tokens"), ("output_tokens", "max_output_tokens"), ("cache_read_tokens", "max_cache_read_tokens"), ("reasoning_tokens", "max_reasoning_tokens")):
            if int(caps[cap_key]) > int(maximum[component]):
                raise ServerRequestBuildError("request token cap exceeds the provider profile cap")
            profile_limit = limits.get(cap_key)
            if profile_limit is not None and int(caps[cap_key]) > int(profile_limit):
                raise ServerRequestBuildError("request token cap exceeds the provider request limit")
        wire_hash = hashlib.sha256(body).hexdigest()
        template_hash = canonical_sha256({
            "model_identity": provider_profile.model_identity,
            "inference_defaults": dict(provider_profile.inference_defaults),
            "phase": spec.phase, "call_spec_id": spec.call_id,
            "source_binding": dict(source_binding), "policy_hash": authority["source_egress_policy_hash"],
        })
        manifest = {
            "manifest_version": "mr4b1a-r/v1", "project_id": authority["project_id"], "run_id": authority["run_id"],
            "iteration_id": plan.iteration_id, "input_state_hash": intent.input_state_hash,
            "role_packet_id": packet.packet_id, "packet_hash": canonical_sha256(packet),
            "logical_call_id": intent.logical_call_id, "intent_id": intent.intent_id,
            "intent_hash": intent.intent_hash, "request_hash": intent.request_hash,
            "idempotency_key_hash": canonical_sha256(intent.idempotency_key),
            "provider_profile_hash": provider_profile.profile_hash, "model_identity": provider_profile.model_identity,
            "inference_profile_hash": runner_profile.inference_profile.inference_profile_hash,
            "source_policy_hash": authority["source_egress_policy_hash"], **dict(source_binding),
            "source_excerpt_hash": source_binding["excerpt_hash"],
            "source_excerpt_characters": source_binding["excerpt_characters"],
            "source_tokens": source_binding["source_tokens"],
            "source_truncated": source_binding["truncated"],
            "wire_template_hash": template_hash, "wire_request_hash": wire_hash,
            "request_bytes": len(body), "prompt_chars": prompt_chars,
            "max_input_tokens": int(caps["max_input_tokens"]), "max_output_tokens": int(caps["max_output_tokens"]),
            "max_cache_read_tokens": int(caps["max_cache_read_tokens"]), "max_reasoning_tokens": int(caps["max_reasoning_tokens"]),
        }
        manifest["manifest_hash"] = canonical_sha256(manifest)
        return intent, body, manifest

    def build_seed_request(
        self,
        *,
        authority: Mapping[str, Any],
        plan: RunnerPlan,
        runner_profile: RunnerProfile,
        provider_profile: ProviderProfile,
        logical_call_id: str,
        idempotency_key: str,
    ) -> BuiltServerRequest:
        """Build the first durable intent before it is persisted.

        The seed is still built by the same server-owned path used during
        Preview/execution.  It has no caller-supplied messages or source body;
        empty durable hashes are filled by the canonical intent constructor
        and then persisted by the runner control plane.
        """

        if not isinstance(logical_call_id, str) or not logical_call_id:
            raise ServerRequestBuildError("server logical call ID is required")
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ServerRequestBuildError("server idempotency key is required")
        enriched_authority = {**dict(authority), "_provider_profile": provider_profile}
        source_binding, trusted_source = self._source(enriched_authority)
        packet = plan.role_packets[0]
        spec = plan.call_specs[0]
        intent, body, manifest = self._request(
            authority=enriched_authority,
            plan=plan,
            runner_profile=runner_profile,
            intent_manifest={
                "input_state_hash": plan.input_state_hash,
                "role_packet_id": packet.packet_id,
                "packet_hash": canonical_sha256(packet),
                "idempotency_key": idempotency_key,
                "logical_call_id": logical_call_id,
                "phase": spec.phase,
                "frontier_hash": "server-owned",
            },
            source_binding=source_binding,
            trusted_source=trusted_source,
            logical_call_id=logical_call_id,
        )
        return BuiltServerRequest(intent.request, body, manifest, intent)

    def build_from_row(self, *, authority: Mapping[str, Any], connection: Any, provider_profile: ProviderProfile) -> BuiltServerRequest:
        row = connection.execute(
            "SELECT i.*, p.plan_json FROM max_model_call_intents i JOIN max_runner_plans p ON p.plan_id=i.plan_id WHERE i.run_id=? AND NOT EXISTS (SELECT 1 FROM max_runner_attempt_outcomes o WHERE o.logical_call_id=i.logical_call_id) ORDER BY i.created_at DESC LIMIT 1",
            (authority["run_id"],),
        ).fetchone()
        if row is None:
            raise ServerRequestBuildError("no unfinished durable ModelCallIntent is available")
        intent_manifest = _loads(row["intent_json"], "runner intent manifest")
        plan = RunnerPlan.from_mapping(_loads(row["plan_json"], "runner plan"))
        runner_row = connection.execute("SELECT profile_json FROM max_runner_profiles WHERE profile_hash=?", (authority["runner_profile_hash"],)).fetchone()
        if runner_row is None:
            raise ServerRequestBuildError("durable runner profile is missing")
        runner_profile = RunnerProfile.from_mapping(_loads(runner_row["profile_json"], "runner profile"))
        enriched_authority = dict(authority)
        enriched_authority["_provider_profile"] = provider_profile
        source_binding, trusted_source = self._source(enriched_authority)
        intent, body, manifest = self._request(
            authority=enriched_authority, plan=plan, runner_profile=runner_profile,
            intent_manifest={**intent_manifest, "intent_id": row["intent_id"], "intent_hash": row["intent_hash"], "request_hash": row["request_hash"], "idempotency_key": row["idempotency_key"], "input_state_hash": row["input_state_hash"], "logical_call_id": row["logical_call_id"]},
            source_binding=source_binding, trusted_source=trusted_source,
            logical_call_id=str(row["logical_call_id"]),
        )
        return BuiltServerRequest(intent.request, body, manifest, intent)


__all__ = ["BuiltServerRequest", "CORE_DATABASE", "MAX_PROMPT_CHARS", "MAX_REQUEST_BYTES", "ServerOwnedRequestBuilder", "ServerRequestBuildError"]
