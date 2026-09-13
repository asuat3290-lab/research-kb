"""MR-2B0 model adapter backed only by an injected hermetic transport."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from ...policy import Actor
from ..contract import canonical_sha256, make_stable_id
from ..persistence.db import MaxControlError
from ..runner.contracts import (
    AdapterCapabilities,
    DispatchUnknown,
    ModelRequestEnvelope,
    ModelResponseEnvelope,
)
from .codec import OpenAICompatibleCodec, ProviderCodecError
from .contract import ProviderProfile
from .store import ProviderStore
from .transport import HermeticTransport, ProviderTransport, ProviderTransportError, is_injected_hermetic_transport
from .usage import ProviderCallRecord, ProviderUsageAttestation, ProviderUsageAuthority


class OpenAICompatibleAdapter:
    """Translate one bounded runner call to one injected provider call.

    ``DisabledLiveTransport`` and every non-hermetic transport are refused at
    this boundary.  Consequently this class cannot open a socket, resolve a
    credential, follow a redirect, or incur a provider charge in MR-2B0.
    """

    # The existing BoundedRunner uses ``fixture_only`` for the old
    # ScriptedFakeAdapter path.  MR-2B0 is hermetic but is a separate provider
    # contract, so its safety is enforced by the transport type check above,
    # not by the legacy simulate-next marker.
    fixture_only = False

    def __init__(self, profile: ProviderProfile, transport: ProviderTransport, *, usage_authority: ProviderUsageAuthority | None = None, provider_store: ProviderStore | None = None, actor: Actor | None = None, grant_id: str | None = None, fencing_token: int | None = None) -> None:
        if not isinstance(profile, ProviderProfile):
            raise TypeError("OpenAICompatibleAdapter requires a ProviderProfile")
        if not is_injected_hermetic_transport(transport):
            raise ProviderTransportError("LIVE_PROVIDER_DISABLED", "MR-2B0 accepts only an injected hermetic transport")
        self.profile = profile
        self.transport = transport
        self.usage_authority = usage_authority or ProviderUsageAuthority()
        self.provider_store = provider_store
        self.actor = actor or Actor("mr2b0-provider-adapter", "mr2b0-provider-adapter-session", "agent", "runner", "research-kb-mr2b0")
        self.grant_id = grant_id
        self.fencing_token = fencing_token
        self._requests: dict[str, ModelRequestEnvelope] = {}

    @property
    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            provider_name=self.profile.provider_name,
            supports_provider_idempotency=self.profile.capabilities.idempotency,
            supports_result_query=self.profile.capabilities.result_query,
            supports_usage_receipt=self.profile.capabilities.usage_reporting,
            max_request_chars=int(self.profile.request_limits.get("max_request_bytes", 1_000_000)),
        )

    def _wire_request(self, request: ModelRequestEnvelope) -> ModelRequestEnvelope:
        context = dict(request.context)
        existing = context.get("provider_profile_hash")
        if existing is not None and existing != self.profile.profile_hash:
            raise ProviderCodecError("request provider profile binding conflicts", code="PROFILE_BINDING_MISMATCH")
        context["provider_profile_hash"] = self.profile.profile_hash
        # The wire request contains the provider binding, so its request hash
        # must be recomputed after the context is augmented.  The original
        # MR-2A intent request hash is retained from ``request`` in the
        # ProviderCallRecord and UsageReceipt; carrying it into this rebuilt
        # envelope would make ModelRequestEnvelope reject the changed context.
        return ModelRequestEnvelope(
            project_id=request.project_id,
            run_id=request.run_id,
            iteration_id=request.iteration_id,
            role_packet=request.role_packet,
            model_identity=request.model_identity,
            inference_profile=request.inference_profile,
            context=context,
            request_payload=request.request_payload,
            request_hash="",
            intent_hash=request.intent_hash,
        )

    @staticmethod
    def _intent_id(request: ModelRequestEnvelope, logical_call_id: str) -> str:
        return canonical_sha256({"project_id": request.project_id, "run_id": request.run_id, "iteration_id": request.iteration_id, "logical_call_id": logical_call_id})[:48]

    def _record_failed(self, request: ModelRequestEnvelope, *, idempotency_key: str, response: Any, code: str, claim: Mapping[str, Any] | None = None) -> None:
        if self.provider_store is None:
            return
        if claim is None:
            raise ProviderCodecError("provider failure has no durable call claim", code="AUTHORITY_PRECHECK_FAILED")
        logical_call_id = str(request.request_payload.get("logical_call_id", ""))
        provider_call_id = str(getattr(response, "provider_call_id", "") or make_stable_id("provider_call", canonical_sha256(idempotency_key)[:64]))
        manifest = dict(getattr(response, "response_manifest", {}) or {})
        manifest["error_code"] = code
        record = ProviderCallRecord(
            call_record_id=make_stable_id("provider_call_record", canonical_sha256(idempotency_key)[:64]),
            provider_call_id=provider_call_id,
            run_id=request.run_id,
            project_id=request.project_id,
            profile_hash=self.profile.profile_hash,
            model_identity=request.model_identity,
            intent_hash=request.intent_hash or request.request_hash,
            request_hash=request.request_hash,
            idempotency_key=idempotency_key,
            transport_status=str(getattr(response, "status_code", "transport_error")),
            terminal_status="failed",
            usage={},
            response_manifest=manifest,
            pricing_hash=self.profile.pricing.pricing_hash,
            logical_call_id=logical_call_id,
            intent_id=str(claim["intent_id"]),
            iteration_id=request.iteration_id,
        )
        # Failed calls are useful audit facts but deliberately cannot produce
        # a usage attestation or a budget receipt.
        self.provider_store.record_provider_call(record=record, actor=self.actor, attempt_id=str(claim.get("attempt_id")) if claim.get("attempt_id") else None)

    def _replay(self, request: ModelRequestEnvelope, durable: Mapping[str, Any]) -> ModelResponseEnvelope:
        """Rebuild a settled response from durable result/usage facts only."""

        if durable.get("terminal_status") != "succeeded" or not isinstance(durable.get("proposal"), Mapping) or not isinstance(durable.get("attestation"), Mapping):
            raise ProviderTransportError("DURABLE_REPLAY_UNAVAILABLE", "settled provider result is not durably replayable", dispatch_known=True)
        try:
            record = ProviderCallRecord(
                call_record_id=str(durable["call_record_id"]), provider_call_id=str(durable["provider_call_id"]),
                run_id=str(durable["run_id"]), project_id=str(durable["project_id"]), profile_hash=str(durable["profile_hash"]),
                model_identity=str(durable["model_identity"]), intent_hash=str(durable["intent_hash"]), request_hash=str(durable["request_hash"]),
                idempotency_key=str(durable["idempotency_key"]), transport_status=str(durable["transport_status"]), terminal_status="succeeded",
                usage=durable["usage"], response_manifest=durable["response_manifest"], pricing_hash=str(durable["pricing_hash"]),
                logical_call_id=str(durable.get("logical_call_id") or request.request_payload.get("logical_call_id", "")),
                intent_id=str(durable.get("intent_id") or request.intent_hash or request.request_hash), iteration_id=str(durable.get("iteration_id") or request.iteration_id),
                created_at=str(durable.get("created_at") or ""), record_hash=str(durable["record_hash"]),
            )
            attestation = ProviderUsageAttestation(**dict(durable["attestation"]))
            receipt = self.usage_authority.to_usage_receipt(record, attestation, logical_call_id=record.logical_call_id, intent_hash=record.intent_hash, request_hash=record.request_hash, iteration_id=request.iteration_id, inference_profile_hash=request.inference_profile.inference_profile_hash)
        except Exception as exc:
            raise ProviderTransportError("DURABLE_REPLAY_INVALID", "durable provider replay facts failed validation", dispatch_known=True) from exc
        return ModelResponseEnvelope(
            logical_call_id=record.logical_call_id, intent_hash=record.intent_hash, model_identity=request.model_identity,
            inference_profile_hash=request.inference_profile.inference_profile_hash, status="succeeded", proposal=dict(durable["proposal"]),
            usage_receipt=receipt.as_mapping(), provider_call_id=record.provider_call_id, dispatch_known=True,
        )

    def dispatch(self, request: ModelRequestEnvelope, *, idempotency_key: str) -> ModelResponseEnvelope:
        if not isinstance(request, ModelRequestEnvelope) or not isinstance(idempotency_key, str) or not idempotency_key or "\r" in idempotency_key or "\n" in idempotency_key:
            raise ProviderCodecError("provider dispatch request is invalid", code="INVALID_PROVIDER_REQUEST")
        wire_request = self._wire_request(request)
        encoded = OpenAICompatibleCodec.encode(wire_request, self.profile)
        self._requests[idempotency_key] = wire_request
        claim: Mapping[str, Any] | None = None
        if self.provider_store is not None:
            if not self.grant_id or self.fencing_token is None:
                raise ProviderTransportError("AUTHORITY_PRECHECK_FAILED", "provider dispatch requires a durable grant and fencing token")
            logical_call_id = str(request.request_payload.get("logical_call_id", ""))
            if not logical_call_id:
                raise ProviderCodecError("provider request logical call binding is missing", code="INVALID_PROVIDER_REQUEST")
            claim = self.provider_store.claim_provider_call(
                grant_id=self.grant_id,
                run_id=request.run_id,
                project_id=request.project_id,
                profile_hash=self.profile.profile_hash,
                model_identity=request.model_identity,
                pricing_hash=self.profile.pricing.pricing_hash,
                logical_call_id=logical_call_id,
                idempotency_key=idempotency_key,
                actor=self.actor,
                fencing_token=int(self.fencing_token),
            )
            if claim.get("replay"):
                durable = self.provider_store.provider_call(run_id=request.run_id, idempotency_key=idempotency_key)
                if durable is None:
                    raise ProviderTransportError("DURABLE_REPLAY_MISSING", "settled provider call is missing from the control store", dispatch_known=True)
                return self._replay(request, durable)
            started = self.provider_store.start_provider_dispatch_attempt(attempt_id=str(claim["attempt_id"]), actor=self.actor, fencing_token=int(self.fencing_token))
            if started.get("send") is False:
                raise ProviderTransportError("PHYSICAL_ATTEMPT_BUSY", "another worker owns the physical dispatch attempt", dispatch_known=False)
        timeout_ms = int(self.profile.timeout_policy.get("total_ms", 120_000))
        try:
            response = self.transport.send(encoded.body, headers={"Content-Type": "application/json"}, timeout_ms=timeout_ms, idempotency_key=idempotency_key)
        except ProviderTransportError as exc:
            if exc.code == "LIVE_PROVIDER_DISABLED":
                raise
            if not exc.dispatch_known:
                if self.provider_store is not None and claim is not None:
                    self.provider_store.mark_provider_call_unknown(claim_id=str(claim["claim_id"]), actor=self.actor, fencing_token=int(self.fencing_token))
                raise DispatchUnknown(sent=False) from exc
            self._record_failed(request, idempotency_key=idempotency_key, response=exc, code=exc.code, claim=claim)
            raise
        if not response.dispatch_known:
            if self.provider_store is not None and claim is not None:
                self.provider_store.mark_provider_call_unknown(claim_id=str(claim["claim_id"]), actor=self.actor, fencing_token=int(self.fencing_token))
            raise DispatchUnknown(sent=True)
        try:
            decoded = OpenAICompatibleCodec.decode(response, wire_request, self.profile, encoded=encoded)
        except ProviderCodecError as exc:
            self._record_failed(request, idempotency_key=idempotency_key, response=response, code=exc.code, claim=claim)
            raise
        logical_call_id = str(request.request_payload.get("logical_call_id", ""))
        if not logical_call_id:
            raise ProviderCodecError("provider request logical call binding is missing", code="INVALID_PROVIDER_REQUEST")
        record = ProviderCallRecord(
            call_record_id=make_stable_id("provider_call_record", canonical_sha256(idempotency_key)[:64]),
            provider_call_id=decoded.provider_call_id,
            run_id=request.run_id,
            project_id=request.project_id,
            profile_hash=self.profile.profile_hash,
            model_identity=decoded.model_identity,
            intent_hash=request.intent_hash or request.request_hash,
            request_hash=request.request_hash,
            idempotency_key=idempotency_key,
            transport_status=str(response.status_code),
            terminal_status="succeeded",
            usage=decoded.usage,
            response_manifest={**dict(decoded.response_manifest), "response_hash": decoded.response_hash},
            pricing_hash=self.profile.pricing.pricing_hash,
            logical_call_id=logical_call_id,
            intent_id=str(claim["intent_id"]) if claim is not None else self._intent_id(request, logical_call_id),
            iteration_id=request.iteration_id,
        )
        recorded = self.usage_authority.record_call(record)
        attestation = self.usage_authority.attest(recorded, self.profile)
        if self.provider_store is not None:
            self.provider_store.record_provider_call(record=recorded, actor=self.actor, proposal=decoded.proposal, attempt_id=str(claim["attempt_id"]) if claim is not None and claim.get("attempt_id") else None)
            try:
                self.provider_store.record_provider_attestation(attestation=attestation, actor=self.actor)
            except MaxControlError as exc:
                if any(token in str(exc).casefold() for token in ("usage", "aggregate", "reservation retained")):
                    try:
                        self.provider_store.repository.pause(run_id=request.run_id, actor=self.actor, fencing_token=int(self.fencing_token))
                    except Exception:
                        # The durable disputed attempt is already retained; a
                        # stale runner cannot force a transition merely while
                        # reporting the dispute.
                        pass
                raise
        receipt = self.usage_authority.to_usage_receipt(
            recorded,
            attestation,
            logical_call_id=logical_call_id,
            intent_hash=request.intent_hash or request.request_hash,
            request_hash=request.request_hash,
            iteration_id=request.iteration_id,
            inference_profile_hash=request.inference_profile.inference_profile_hash,
        )
        return ModelResponseEnvelope(
            logical_call_id=logical_call_id,
            intent_hash=request.intent_hash or request.request_hash,
            model_identity=request.model_identity,
            inference_profile_hash=request.inference_profile.inference_profile_hash,
            status="succeeded",
            proposal=decoded.proposal,
            usage_receipt=receipt.as_mapping(),
            provider_call_id=decoded.provider_call_id,
            dispatch_known=True,
        )

    def query(self, *, idempotency_key: str) -> ModelResponseEnvelope | None:
        request = self._requests.get(idempotency_key)
        if request is None:
            return None
        if self.provider_store is not None:
            durable = self.provider_store.provider_call(run_id=request.run_id, idempotency_key=idempotency_key)
            if durable is not None and durable.get("terminal_status") == "succeeded":
                return self._replay(request, durable)
        response = self.transport.query(idempotency_key=idempotency_key)
        if response is None:
            return None
        if not response.dispatch_known:
            raise DispatchUnknown(sent=True)
        decoded = OpenAICompatibleCodec.decode(response, request, self.profile)
        logical_call_id = str(request.request_payload.get("logical_call_id", ""))
        # Query is only a recovery projection.  Durable call/usage facts are
        # recorded by the original dispatch; the runner will re-enter its
        # normal usage binding path with this response.
        return ModelResponseEnvelope(
            logical_call_id=logical_call_id,
            intent_hash=request.intent_hash or request.request_hash,
            model_identity=request.model_identity,
            inference_profile_hash=request.inference_profile.inference_profile_hash,
            status="succeeded",
            proposal=decoded.proposal,
            usage_receipt={},
            provider_call_id=decoded.provider_call_id,
            dispatch_known=True,
        )


__all__ = ["OpenAICompatibleAdapter"]
