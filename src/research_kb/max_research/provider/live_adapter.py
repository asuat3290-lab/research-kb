"""Explicit live HTTPS adapter used only by a later, separately enabled stage.

The class is importable for offline adversarial tests, but it is not wired to
the current CLI, scheduler, MCP server, or default factory.  Its connector
and credential resolver are always dependency-injected.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from ...policy import Actor
from ..contract import canonical_sha256, make_stable_id
from ..persistence.db import MaxControlError
from ..runner.contracts import DispatchUnknown, ModelRequestEnvelope, ModelResponseEnvelope
from .adapter import OpenAICompatibleAdapter
from .codec import OpenAICompatibleCodec, ProviderCodecError
from .contract import ProviderProfile
from .live import PRE_SEND_ERROR_CODES, LiveDispatchPermit, LiveProviderTransportFactory, OpenAICompatibleHTTPSLiveTransport, is_trusted_live_transport_factory
from .store import ProviderStore
from .transport import ProviderTransportError
from .usage import ProviderCallRecord, ProviderUsageAttestation, ProviderUsageAuthority


class LiveOpenAICompatibleAdapter(OpenAICompatibleAdapter):
    """One-shot live adapter with persisted authorization and attempt fences."""

    def __init__(self, profile: ProviderProfile, transport: OpenAICompatibleHTTPSLiveTransport | None = None, *, transport_factory: LiveProviderTransportFactory | None = None, provider_store: ProviderStore, actor: Actor, grant_id: str, authorization_id: str, fencing_token: int, usage_authority: ProviderUsageAuthority | None = None, live_bundle_id: str | None = None, live_assignment_id: str | None = None, execution_event_callback: Callable[[str, Mapping[str, Any]], None] | None = None, prepared_dispatch: Mapping[str, Any] | None = None) -> None:
        if not isinstance(profile, ProviderProfile):
            raise ProviderTransportError("LIVE_TRANSPORT_TYPE_INVALID", "live adapter requires a valid provider profile")
        if (transport is None) == (transport_factory is None):
            raise ProviderTransportError("LIVE_TRANSPORT_TYPE_INVALID", "live adapter requires exactly one package HTTPS transport or transport factory")
        if transport is not None and not isinstance(transport, OpenAICompatibleHTTPSLiveTransport):
            raise ProviderTransportError("LIVE_TRANSPORT_TYPE_INVALID", "live adapter requires the package HTTPS transport")
        if not isinstance(provider_store, ProviderStore):
            raise TypeError("live adapter requires ProviderStore")
        if transport_factory is not None and not is_trusted_live_transport_factory(transport_factory):
            # The fixture transport is intentionally kept out of the
            # production transport module.  Resolve its type lazily here so
            # the production import graph remains acyclic, and accept the
            # exact package class only; marker attributes on a client class
            # are not an authority boundary.
            from ..native_live import FixtureLiveProviderTransportFactory

            fixture_factory = (
                isinstance(transport_factory, LiveProviderTransportFactory)
                and getattr(transport_factory, "fixture_only", False) is True
                and provider_store.repository.is_fixture_database()
            )
            if not fixture_factory:
                raise ProviderTransportError("LIVE_TRANSPORT_FACTORY_INVALID", "live adapter requires the package live transport factory")
        if (live_bundle_id is None) != (live_assignment_id is None):
            raise ProviderTransportError("LIVE_BUNDLE_BINDING_INVALID", "live bundle and assignment IDs must be provided together")
        self.profile = profile
        self.transport = transport
        self.transport_factory = transport_factory
        self.provider_store = provider_store
        self.actor = actor
        self.grant_id = grant_id
        self.authorization_id = authorization_id
        self.fencing_token = int(fencing_token)
        self.live_bundle_id = live_bundle_id
        self.live_assignment_id = live_assignment_id
        self.usage_authority = usage_authority or ProviderUsageAuthority()
        if execution_event_callback is not None and not callable(execution_event_callback):
            raise ProviderTransportError("LIVE_EXECUTION_EVENT_CALLBACK_INVALID", "live execution event callback is invalid", dispatch_known=True)
        self.execution_event_callback = execution_event_callback
        self.prepared_dispatch = None if prepared_dispatch is None else dict(prepared_dispatch)
        self._requests: dict[str, ModelRequestEnvelope] = {}

    def _live_attempt(self, *, run_id: str, project_id: str, outcome: str, claim: Mapping[str, Any] | None = None, details: Mapping[str, Any] | None = None) -> None:
        try:
            self.provider_store.record_live_network_attempt(
                authorization_id=self.authorization_id, run_id=run_id, project_id=project_id,
                outcome=outcome, actor=self.actor,
                provider_attempt_id=None if claim is None else str(claim.get("attempt_id") or "") or None,
                claim_id=None if claim is None else str(claim.get("claim_id") or "") or None,
                fencing_token=self.fencing_token,
                details=details or {},
            )
        except MaxControlError:
            # The primary durable provider state remains authoritative.  A
            # missing outcome audit is a verification failure, never a reason
            # to retry a possibly dispatched request.
            raise

    def _replay(self, request: ModelRequestEnvelope, durable: Mapping[str, Any], *, idempotency_key: str) -> ModelResponseEnvelope:
        logical_call_id = str(request.request_payload.get("logical_call_id", ""))
        expected = {
            "run_id": request.run_id,
            "project_id": request.project_id,
            "profile_hash": self.profile.profile_hash,
            "model_identity": request.model_identity,
            "pricing_hash": self.profile.pricing.pricing_hash,
            "intent_hash": request.intent_hash or request.request_hash,
            "request_hash": request.request_hash,
            "idempotency_key": idempotency_key,
            "logical_call_id": logical_call_id,
            "iteration_id": request.iteration_id,
        }
        if any(durable.get(key) != value for key, value in expected.items()):
            raise ProviderTransportError("DURABLE_REPLAY_BINDING_MISMATCH", "durable provider replay is not bound to the request", dispatch_known=True)
        return super()._replay(request, durable)

    def dispatch(self, request: ModelRequestEnvelope, *, idempotency_key: str) -> ModelResponseEnvelope:
        if not isinstance(request, ModelRequestEnvelope) or not isinstance(idempotency_key, str) or not idempotency_key or "\r" in idempotency_key or "\n" in idempotency_key:
            raise ProviderCodecError("provider dispatch request is invalid", code="INVALID_PROVIDER_REQUEST")
        wire_request = self._wire_request(request)
        encoded = OpenAICompatibleCodec.encode(wire_request, self.profile)
        self._requests[idempotency_key] = wire_request

        # A settled durable replay is resolved before the live authorization
        # consumption or credential resolver.  It is not a physical call.
        durable = self.provider_store.provider_call(run_id=request.run_id, idempotency_key=idempotency_key)
        if durable is not None and durable.get("terminal_status") == "succeeded":
            return self._replay(request, durable, idempotency_key=idempotency_key)

        logical_call_id = str(request.request_payload.get("logical_call_id", ""))
        if not logical_call_id:
            raise ProviderCodecError("provider request logical call binding is missing", code="INVALID_PROVIDER_REQUEST")
        if self.prepared_dispatch is None:
            preflight = self.provider_store.provider_live_preflight(run_id=request.run_id, authorization_id=self.authorization_id, grant_id=self.grant_id)
            if not preflight.get("ok"):
                raise ProviderTransportError("LIVE_AUTHORIZATION_PRECHECK_FAILED", "live provider preflight failed")
        claim: Mapping[str, Any] | None = None
        permit: LiveDispatchPermit | None = None
        try:
            prepared = self.prepared_dispatch or self.provider_store.prepare_live_dispatch(
                authorization_id=self.authorization_id, run_id=request.run_id, project_id=request.project_id,
                grant_id=self.grant_id, profile=self.profile,
                request_hash=request.request_hash,
                wire_request_hash=__import__("hashlib").sha256(encoded.body).hexdigest(),
                intent_hash=request.intent_hash or request.request_hash,
                logical_call_id=logical_call_id, idempotency_key=idempotency_key,
                actor=self.actor, fencing_token=self.fencing_token,
                live_bundle_id=self.live_bundle_id,
                live_assignment_id=self.live_assignment_id,
            )
            if prepared.get("replay"):
                claim = prepared.get("claim")
                durable = self.provider_store.provider_call(run_id=request.run_id, idempotency_key=idempotency_key)
                if durable is None:
                    raise ProviderTransportError("DURABLE_REPLAY_MISSING", "settled provider call is missing from the control store", dispatch_known=True)
                return self._replay(request, durable, idempotency_key=idempotency_key)
            permit = prepared["permit"]
            claim = prepared.get("claim") or {"claim_id": permit.claim_id, "attempt_id": permit.attempt_id}
            permit = self.provider_store.start_live_dispatch(permit=permit, actor=self.actor, fencing_token=self.fencing_token)

            def audit(event_type: str, payload: Mapping[str, Any]) -> None:
                if self.execution_event_callback is not None:
                    self.execution_event_callback(event_type, dict(payload))
                self.provider_store.record_live_network_access_event(
                    authorization_id=self.authorization_id,
                    run_id=request.run_id,
                    project_id=request.project_id,
                    event_type=event_type,
                    actor=self.actor,
                    provider_attempt_id=permit.attempt_id,
                    claim_id=permit.claim_id,
                    fencing_token=self.fencing_token,
                    details=payload,
                )

            def boundary(boundary_permit: LiveDispatchPermit) -> None:
                audit(
                    "http_dispatch_boundary_crossed",
                    {
                        "permit_id": boundary_permit.permit_id,
                        "attempt_id": boundary_permit.attempt_id,
                        "claim_id": boundary_permit.claim_id,
                        "request_hash": boundary_permit.request_hash,
                        "idempotency_key_hash": boundary_permit.idempotency_key_hash,
                        "send_boundary_reached": True,
                    },
                )

            transport = self.transport
            if transport is None:
                if self.transport_factory is None:  # defensive; constructor enforces this
                    raise ProviderTransportError("LIVE_TRANSPORT_FACTORY_INVALID", "live transport factory is unavailable")
                factory_kwargs = {
                    "profile": self.profile,
                    "permit": permit,
                    "provider_store": self.provider_store,
                }
                # Existing fixture-only factories deliberately expose the
                # pre-v7 three-argument seam.  They are still bound to the
                # same transport-owned callbacks immediately below; only the
                # production factory receives callbacks during construction.
                if not getattr(self.transport_factory, "fixture_only", False):
                    factory_kwargs.update(
                        network_event_callback=audit,
                        send_boundary_callback=boundary,
                    )
                transport = self.transport_factory.create_for_permit(**factory_kwargs)
            if not isinstance(transport, OpenAICompatibleHTTPSLiveTransport):
                raise ProviderTransportError("LIVE_TRANSPORT_TYPE_INVALID", "live transport factory returned an invalid transport")
            if self.execution_event_callback is not None:
                self.execution_event_callback("transport_created", {"transport_type": type(transport).__name__})
            transport.bind_server_permit(permit)
            transport.configure_boundary_callbacks(network_event_callback=audit, send_boundary_callback=boundary)
            response = transport.send(encoded.body, headers={"Content-Type": "application/json"}, timeout_ms=int(self.profile.timeout_policy.get("total_ms", 120_000)), idempotency_key=idempotency_key)
            if self.execution_event_callback is not None:
                self.execution_event_callback("response_headers_received", {"status_code": int(response.status_code), "provider_call_id_hash": canonical_sha256(response.provider_call_id)})
                self.execution_event_callback("response_body_received", {"body_hash": canonical_sha256(response.body_bytes().hex()), "body_size": len(response.body_bytes())})
        except ProviderTransportError as exc:
            if claim is not None and not exc.dispatch_known:
                self.provider_store.mark_provider_call_unknown(claim_id=str(claim["claim_id"]), actor=self.actor, fencing_token=self.fencing_token)
                if permit is not None:
                    self.provider_store.mark_live_dispatch_outcome(permit=permit, state="unknown", actor=self.actor, details={"code": exc.code})
                self._live_attempt(run_id=request.run_id, project_id=request.project_id, outcome="unknown", claim=claim, details={"code": exc.code})
                raise DispatchUnknown(sent=True) from exc
            if claim is not None:
                self._record_failed(request, idempotency_key=idempotency_key, response=exc, code=exc.code, claim=claim)
                if permit is not None:
                    self.provider_store.mark_live_dispatch_outcome(permit=permit, state="failed", actor=self.actor, details={"code": exc.code})
                outcome = "not_dispatched" if exc.code in PRE_SEND_ERROR_CODES else "disputed"
                self._live_attempt(run_id=request.run_id, project_id=request.project_id, outcome=outcome, claim=claim, details={"code": exc.code})
            raise
        if not response.dispatch_known:
            self.provider_store.mark_provider_call_unknown(claim_id=str(claim["claim_id"]), actor=self.actor, fencing_token=self.fencing_token)
            if permit is not None:
                self.provider_store.mark_live_dispatch_outcome(permit=permit, state="unknown", actor=self.actor, details={"code": "TRANSPORT_UNKNOWN"})
            self._live_attempt(run_id=request.run_id, project_id=request.project_id, outcome="unknown", claim=claim, details={"code": "TRANSPORT_UNKNOWN"})
            raise DispatchUnknown(sent=True)
        try:
            decoded = OpenAICompatibleCodec.decode(response, wire_request, self.profile, encoded=encoded)
        except ProviderCodecError as exc:
            self._record_failed(request, idempotency_key=idempotency_key, response=response, code=exc.code, claim=claim)
            if permit is not None:
                self.provider_store.mark_live_dispatch_outcome(permit=permit, state="disputed", actor=self.actor, details={"code": exc.code})
            self._live_attempt(run_id=request.run_id, project_id=request.project_id, outcome="disputed", claim=claim, details={"code": exc.code})
            raise
        record = ProviderCallRecord(
            call_record_id=make_stable_id("provider_call_record", canonical_sha256(idempotency_key)[:64]),
            provider_call_id=decoded.provider_call_id, run_id=request.run_id, project_id=request.project_id,
            profile_hash=self.profile.profile_hash, model_identity=decoded.model_identity,
            intent_hash=request.intent_hash or request.request_hash, request_hash=request.request_hash,
            idempotency_key=idempotency_key, transport_status=str(response.status_code), terminal_status="succeeded",
            usage=decoded.usage, response_manifest={**dict(decoded.response_manifest), "response_hash": decoded.response_hash},
            pricing_hash=self.profile.pricing.pricing_hash, logical_call_id=logical_call_id,
            intent_id=str(claim["intent_id"]), iteration_id=request.iteration_id,
        )
        recorded = self.usage_authority.record_call(record)
        attestation = self.usage_authority.attest(recorded, self.profile)
        try:
            self.provider_store.record_provider_call(record=recorded, actor=self.actor, proposal=decoded.proposal, attempt_id=str(claim["attempt_id"]))
            self.provider_store.record_provider_attestation(attestation=attestation, actor=self.actor)
        except MaxControlError:
            if permit is not None:
                self.provider_store.mark_live_dispatch_outcome(permit=permit, state="disputed", actor=self.actor, details={"code": "USAGE_OR_SETTLEMENT_DISPUTED"})
            self._live_attempt(run_id=request.run_id, project_id=request.project_id, outcome="disputed", claim=claim, details={"code": "USAGE_OR_SETTLEMENT_DISPUTED"})
            raise
        if permit is not None:
            self.provider_store.mark_live_dispatch_outcome(permit=permit, state="settled", actor=self.actor, details={"response_hash": decoded.response_hash})
        self._live_attempt(run_id=request.run_id, project_id=request.project_id, outcome="settled", claim=claim, details={"response_hash": decoded.response_hash, "usage_hash": canonical_sha256(decoded.usage), "provider_call_id_hash": canonical_sha256(decoded.provider_call_id)})
        receipt = self.usage_authority.to_usage_receipt(recorded, attestation, logical_call_id=logical_call_id, intent_hash=request.intent_hash or request.request_hash, request_hash=request.request_hash, iteration_id=request.iteration_id, inference_profile_hash=request.inference_profile.inference_profile_hash)
        return ModelResponseEnvelope(logical_call_id=logical_call_id, intent_hash=request.intent_hash or request.request_hash, model_identity=request.model_identity, inference_profile_hash=request.inference_profile.inference_profile_hash, status="succeeded", proposal=decoded.proposal, usage_receipt=receipt.as_mapping(), provider_call_id=decoded.provider_call_id, dispatch_known=True)

    def query(self, *, idempotency_key: str) -> ModelResponseEnvelope | None:
        request = self._requests.get(idempotency_key)
        if request is None:
            return None
        durable = self.provider_store.provider_call(run_id=request.run_id, idempotency_key=idempotency_key)
        if durable is not None and durable.get("terminal_status") == "succeeded":
            return self._replay(request, durable, idempotency_key=idempotency_key)
        raise ProviderTransportError("LIVE_RESULT_QUERY_DISABLED", "live provider result queries are disabled in MR-2B1")


__all__ = ["LiveOpenAICompatibleAdapter"]
