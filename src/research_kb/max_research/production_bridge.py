"""MR-4B1 production-shaped one-shot canary bridge.

The bridge owns the ordering of one physical call, but it does not create a
second runner or a second settlement protocol.  It reuses the existing
canary authority, provider live-network/dispatch permits, transport boundary
and authoritative MR-4A.1 pipeline name.  The default is deliberately
disabled: a caller must inject a transport and explicitly opt into execution.
The offline CLI and all readiness paths stop before this method.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import closing
from typing import Any, Callable, Mapping, Protocol

from .contract import canonical_json, canonical_sha256, make_stable_id
from .live_canary import LiveCanaryAuthorityError, LiveCanaryAuthorityStore
from .long_run_executor import AuthoritativeTickPipeline, LongRunExecutor
from .persistence.repository import MaxControlRepository
from .persistence.runner import RunnerPersistence
from .provider.contract import (
    ProviderContractError,
    ProviderProfile,
    normalize_openai_compatible_usage,
    token_envelope_within_caps,
)
from .provider.live import ProviderTransportError
from .provider.store import ProviderStore
from .provider.transport import TransportResponse
from .provider.usage import PROVIDER_USAGE_AUTHORITY_ID, ProviderCallRecord, ProviderUsageAttestation
from .provider.live import LiveProviderTransportFactory
from .request_builder import ServerOwnedRequestBuilder, ServerRequestBuildError
from ..policy import Actor


class OneShotTransport(Protocol):
    """The only transport seam accepted by the one-shot executor."""

    def send(
        self,
        request: bytes,
        *,
        headers: Mapping[str, str],
        timeout_ms: int,
        idempotency_key: str,
    ) -> TransportResponse:
        ...


_FORBIDDEN_REQUEST_KEYS = {
    "authorization", "cookie", "proxy-authorization", "api_key", "apikey",
    "secret", "password", "access_token", "refresh_token", "private_key",
}


def _reject_wire_secrets(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _FORBIDDEN_REQUEST_KEYS:
                raise LiveCanaryAuthorityError("one-shot request contains credential or header material")
            _reject_wire_secrets(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_wire_secrets(child)


_DEFAULT_PRE_SEND_ERROR = "LIVE_CANARY_PRE_SEND_ABORT"


def _profile_token_caps(profile: ProviderProfile) -> dict[str, int]:
    maximum = profile.authority_maximum_usage()
    return {"max_" + key: int(value) for key, value in maximum.items()}


def _usage_is_within_caps(usage: Mapping[str, Any], *, profile: ProviderProfile, caps: Mapping[str, Any]) -> bool:
    try:
        return token_envelope_within_caps(usage, _profile_token_caps(profile)) and token_envelope_within_caps(usage, caps)
    except (ProviderContractError, TypeError, ValueError):
        return False


def _response_usage(response: TransportResponse) -> dict[str, int] | None:
    body = response.body
    if not isinstance(body, Mapping):
        try:
            body = json.loads(response.body_bytes().decode("utf-8"))
        except Exception:
            return None
    raw = body.get("usage") if isinstance(body, Mapping) else None
    if not isinstance(raw, Mapping):
        return None
    try:
        return normalize_openai_compatible_usage(raw)
    except (ProviderContractError, TypeError, ValueError):
        return None


def _failure_diagnostics(*, boundary: Mapping[str, Any], failure_stage: str, details: Mapping[str, Any]) -> dict[str, Any]:
    """Build a bounded, hashable failure diagnosis without raw payloads."""

    failure_class = str(boundary.get("failure_class", "UNKNOWN_AFTER_SEND"))
    send_boundary_reached = bool(boundary.get("send_boundary_reached", True))
    diagnostics: dict[str, Any] = {
        "failure_stage": str(failure_stage),
        "failure_class": failure_class,
        "send_boundary_reached": send_boundary_reached,
        "reconciliation_required": bool(boundary.get("reconciliation_required", True)),
        "retry_allowed": False,
        "durable_evidence": boundary.get("durable_evidence", {}),
    }
    supplied_code = details.get("error_code") or boundary.get("error_code")
    if isinstance(supplied_code, str) and supplied_code and len(supplied_code) <= 128:
        diagnostics["error_code"] = supplied_code
    else:
        diagnostics["error_code"] = _DEFAULT_PRE_SEND_ERROR if not send_boundary_reached else "LIVE_CANARY_BOUNDARY_FAILURE"
    for key in ("human_cost_ceiling", "profile_worst_case_cost", "effective_provider_cost_cap"):
        raw = details.get(key)
        if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0:
            diagnostics[key] = int(raw)
    exception_type = details.get("exception_type") or details.get("error") or details.get("error_code") or "boundary_exception"
    diagnostics["exception_type"] = str(exception_type)
    for key in ("error_code", "reason"):
        value = details.get(key)
        if isinstance(value, str) and value and len(value) <= 200:
            diagnostics[key] = value
    response_hash = details.get("response_hash")
    if isinstance(response_hash, str) and len(response_hash) == 64:
        diagnostics["response_hash"] = response_hash
    status_code = details.get("status_code")
    if isinstance(status_code, int) and not isinstance(status_code, bool):
        diagnostics["status_code"] = status_code
    return diagnostics


class LiveCanaryExecutor:
    """A single-call executor whose live boundary is opt-in and injectable."""

    one_shot_only = True
    live_network_enabled = False
    pipeline_name = AuthoritativeTickPipeline.name

    def __init__(
        self,
        repository: MaxControlRepository,
        authority: LiveCanaryAuthorityStore,
        *,
        provider_store: ProviderStore | None = None,
        transport: OneShotTransport | None = None,
        transport_factory: Callable[..., OneShotTransport] | None = None,
        live_network_enabled: bool = False,
    ) -> None:
        if not isinstance(repository, MaxControlRepository) or not isinstance(authority, LiveCanaryAuthorityStore):
            raise TypeError("LiveCanaryExecutor dependencies are invalid")
        if provider_store is not None and not isinstance(provider_store, ProviderStore):
            raise TypeError("LiveCanaryExecutor provider store is invalid")
        self.repository = repository
        self.authority = authority
        self.provider_store = provider_store
        self.transport = transport
        self.transport_factory = transport_factory
        # Production never turns this on implicitly.  A later separately
        # approved release may inject both this flag and a real transport.
        self.live_network_enabled = bool(live_network_enabled)

    def preflight(self, *, authority_id: str) -> dict[str, Any]:
        """Revalidate the durable authority without consuming anything."""

        return self.authority.authority_preflight(authority_id=authority_id)

    def prepare(
        self,
        *,
        approval_id: str,
        preview_hash: str,
        actor: Any,
        worker_id: str,
        worker_session: str,
        fencing_token: int,
        claim_id: str,
        request_hash: str,
        idempotency_key_hash: str,
    ) -> dict[str, Any]:
        """Compatibility preparation seam retained for hermetic fixture tests."""

        try:
            fixture = self.repository.is_fixture_database()
        except Exception:
            fixture = False
        if not fixture:
            raise LiveCanaryAuthorityError("MR-4B1 preparation is not available for a production database without an explicit execution authority")
        return self.authority.consume_and_prepare(
            approval_id=approval_id,
            preview_hash=preview_hash,
            consumer=actor,
            worker_id=worker_id,
            worker_session=worker_session,
            fencing_token=fencing_token,
            claim_id=claim_id,
            request_hash=request_hash,
            idempotency_key_hash=idempotency_key_hash,
        )

    def execute(self, *, authority_id: str | None = None, approval_id: str | None = None, allow_execute: bool = False) -> dict[str, Any]:
        """Execute one server-rebuilt, one-time canary call.

        The production method intentionally accepts only durable authority
        identifiers.  The request, worker fence, claim, grant, network
        authorization, source permit and idempotency values are reconstructed
        from the control database after the final approval revalidation.
        """

        if not allow_execute:
            raise LiveCanaryAuthorityError("live-canary-execute requires an explicit execution flag")
        if not self.live_network_enabled:
            raise LiveCanaryAuthorityError("production live transport is disabled")
        if self.provider_store is None:
            raise LiveCanaryAuthorityError("one-shot execution requires the durable provider store")
        if not isinstance(authority_id, str) or not authority_id or not isinstance(approval_id, str) or not approval_id:
            raise LiveCanaryAuthorityError("one-shot execution requires durable authority and approval IDs")

        provider_permit = None
        canary_permit_id: str | None = None
        source_permit_id: str | None = None
        grant_id: str | None = None
        claim_id: str | None = None
        worker_actor: Actor | None = None
        approval_actor: Actor | None = None
        authorization_id: str | None = None
        fencing_token = 0
        preview: Mapping[str, Any] | None = None
        failure_stage = "startup"

        def close_unknown(*, reason: str, details: Mapping[str, Any]) -> None:
            """Close the saga from durable evidence, never from a process flag."""

            cleanup: list[str] = []
            if worker_actor is None:
                raise LiveCanaryAuthorityError("KNOWN_PRE_SEND_FAILURE: worker authority was not durably loaded; retry is forbidden")
            if canary_permit_id is None:
                boundary = {
                    "failure_class": "KNOWN_PRE_SEND_FAILURE",
                    "send_boundary_reached": False,
                    "reconciliation_required": False,
                    "retry_allowed": False,
                    "durable_evidence": {"canary_permit": "not_prepared"},
                }
            else:
                try:
                    boundary = self.authority.classify_provider_boundary(permit_id=canary_permit_id)
                except Exception as exc:
                    boundary = {
                        "failure_class": "UNKNOWN_AFTER_SEND",
                        "send_boundary_reached": True,
                        "reconciliation_required": True,
                        "retry_allowed": False,
                        "durable_evidence": {"classification_read_error": type(exc).__name__},
                    }
                    cleanup.append(f"classification:{type(exc).__name__}")
            preview_value_for_diagnostics = preview.get("preview", {}) if isinstance(preview, Mapping) else {}
            diagnostics = _failure_diagnostics(
                boundary=boundary,
                failure_stage=failure_stage,
                details={
                    **dict(details),
                    "reason": details.get("reason", reason),
                    "human_cost_ceiling": preview_value_for_diagnostics.get("human_cost_ceiling"),
                    "profile_worst_case_cost": preview_value_for_diagnostics.get("profile_worst_case_cost"),
                    "effective_provider_cost_cap": preview_value_for_diagnostics.get("effective_provider_cost_cap"),
                },
            )
            provider_details = {
                key: diagnostics[key]
                for key in ("failure_stage", "error_code", "failure_class", "send_boundary_reached", "reconciliation_required", "retry_allowed", "human_cost_ceiling", "profile_worst_case_cost", "effective_provider_cost_cap", "exception_type", "reason", "response_hash", "status_code")
                if key in diagnostics
            }
            if provider_permit is not None:
                if bool(boundary["send_boundary_reached"]):
                    try:
                        self.provider_store.mark_provider_call_unknown(claim_id=provider_permit.claim_id, actor=worker_actor, fencing_token=fencing_token)
                    except Exception as exc:
                        cleanup.append(f"provider_claim:{type(exc).__name__}")
                    try:
                        self.provider_store.mark_live_dispatch_outcome(permit=provider_permit, state="disputed" if reason == "disputed" else "unknown", actor=worker_actor, details=provider_details)
                    except Exception as exc:
                        cleanup.append(f"dispatch:{type(exc).__name__}")
                    try:
                        self.provider_store.record_live_network_attempt(authorization_id=str(authorization_id), run_id=str(preview["preview"]["run_id"]), project_id=str(preview["preview"]["project_id"]), outcome="disputed" if reason == "disputed" else "unknown", actor=worker_actor, provider_attempt_id=provider_permit.attempt_id, claim_id=provider_permit.claim_id, fencing_token=fencing_token, details=provider_details)
                    except Exception as exc:
                        cleanup.append(f"network:{type(exc).__name__}")
                else:
                    try:
                        self.provider_store.abort_live_dispatch_before_send(permit=provider_permit, actor=worker_actor, fencing_token=fencing_token, details=provider_details)
                    except Exception as exc:
                        cleanup.append(f"pre_send_abort:{type(exc).__name__}")
                        try:
                            self.provider_store.mark_live_dispatch_outcome(permit=provider_permit, state="failed", actor=worker_actor, details={**provider_details, "send_boundary_reached": False})
                        except Exception as fallback_exc:
                            cleanup.append(f"dispatch:{type(fallback_exc).__name__}")
            if not bool(boundary["send_boundary_reached"]):
                if source_permit_id is not None:
                    try:
                        self.authority.revoke_source_permit(source_permit_id=source_permit_id, actor=worker_actor, reason="known_pre_send_failure")
                    except Exception as exc:
                        cleanup.append(f"source_permit:{type(exc).__name__}")
                if grant_id is not None:
                    try:
                        self.provider_store.close_execution_grant_before_send(
                            grant_id=grant_id,
                            actor=worker_actor,
                            failure_stage=failure_stage,
                            error_code=str(diagnostics["error_code"]),
                        )
                    except Exception as exc:
                        cleanup.append(f"grant_closure:{type(exc).__name__}")
            try:
                if canary_permit_id is not None:
                    self.authority.record_outcome(
                        permit_id=canary_permit_id,
                        outcome="unknown" if bool(boundary["send_boundary_reached"]) else "aborted",
                        usage={},
                        cost_units=0,
                        actor=worker_actor,
                        diagnostics=diagnostics,
                    )
            except Exception as exc:
                cleanup.append(f"canary:{type(exc).__name__}")
            if not bool(boundary["send_boundary_reached"]):
                try:
                    RunnerPersistence(self.repository).abort_pre_send(
                        run_id=str(preview_value_for_diagnostics["run_id"]),
                        logical_call_id=str(provider_permit.logical_call_id) if provider_permit is not None else None,
                        actor=worker_actor,
                        fencing_token=fencing_token,
                        failure_stage=failure_stage,
                        error_code=str(diagnostics.get("error_code", _DEFAULT_PRE_SEND_ERROR)),
                    )
                except Exception as exc:
                    cleanup.append(f"runner_abort_closure:{type(exc).__name__}")
                try:
                    with closing(self.repository._connect(read_only=True)) as connection:
                        run_row = connection.execute("SELECT status FROM max_runs WHERE run_id=?", (preview_value_for_diagnostics.get("run_id"),)).fetchone() if preview_value_for_diagnostics.get("run_id") else None
                    if run_row is not None and run_row["status"] == "RUNNING":
                        self.repository.pause(run_id=str(preview_value_for_diagnostics["run_id"]), actor=worker_actor, fencing_token=fencing_token)
                except Exception as exc:
                    cleanup.append(f"run_pause:{type(exc).__name__}")
                if claim_id is not None:
                    try:
                        RunnerPersistence(self.repository).release_invocation(run_id=str(preview_value_for_diagnostics["run_id"]), claim_id=claim_id, actor=worker_actor, fencing_token=fencing_token)
                    except Exception as exc:
                        cleanup.append(f"invocation_release:{type(exc).__name__}")
            suffix = " (durable cleanup: " + ",".join(cleanup) + ")" if cleanup else ""
            error_code = str(diagnostics.get("error_code", _DEFAULT_PRE_SEND_ERROR))
            if bool(boundary["send_boundary_reached"]):
                raise LiveCanaryAuthorityError(
                    "UNKNOWN_AFTER_SEND: one-shot provider boundary is unknown/disputed; manual reconciliation is required and retry is forbidden" + suffix
                )
            raise LiveCanaryAuthorityError(
                f"KNOWN_PRE_SEND_FAILURE[{error_code}]: provider send boundary was not reached; reconciliation is not required and retry is forbidden" + suffix
            )

        try:
            failure_stage = "authority_load"
            connection = self.repository._connect(read_only=True)
            try:
                authority_row = connection.execute("SELECT authority_json FROM max_live_canary_authority_bindings WHERE authority_id=?", (authority_id,)).fetchone()
                if authority_row is None:
                    raise LiveCanaryAuthorityError("server canary authority was not found")
                stored_authority = json.loads(authority_row["authority_json"])
                worker_id = str(stored_authority["worker_id"])
                worker_session = str(stored_authority["worker_session"])
                fencing_token = int(stored_authority["fencing_token"])
                claim_id = str(stored_authority["claim_id"])
                worker_actor = Actor(worker_id, worker_session, "worker", "runner", "research-kb-server-executor")
            finally:
                connection.close()

            # This rebuild is server-owned; it never consumes approval or
            # creates a grant/network permit.  It also persists the hash-only
            # request manifest needed by the later source/transport closure.
            failure_stage = "preview_rebuild"
            preview = self.authority.preview_from_authority(authority_id=authority_id, actor=worker_actor)
            preview_value = preview["preview"]
            connection = self.repository._connect(read_only=True)
            try:
                approval_row = connection.execute("SELECT a.*, c.state AS approval_state FROM max_live_canary_approvals a JOIN max_live_canary_approval_current c ON c.approval_id=a.approval_id WHERE a.approval_id=?", (approval_id,)).fetchone()
                if approval_row is None or approval_row["approval_state"] != "active" or approval_row["preview_hash"] != preview["preview_hash"]:
                    raise LiveCanaryAuthorityError("approval is missing, foreign, consumed, revoked or drifted")
                approval_actor = Actor(str(approval_row["actor_id"]), str(approval_row["actor_session"]), "user", "admin", "research-kb-server-approval")
                unfinished = RunnerPersistence(self.repository).latest_unfinished(run_id=str(preview_value["run_id"]))
                if not isinstance(unfinished, Mapping):
                    raise LiveCanaryAuthorityError("server-owned ModelCallIntent is missing")
                idempotency_key = str(unfinished["idempotency_key"])
                if str(unfinished["logical_call_id"]) != str(preview_value.get("logical_call_id")):
                    raise LiveCanaryAuthorityError("server-owned logical call drifted from Preview")
            finally:
                connection.close()

            manifest_hash = str(preview_value.get("request_manifest_hash", ""))
            if not manifest_hash:
                raise LiveCanaryAuthorityError("Preview has no server request manifest")
            failure_stage = "request_manifest_load"
            manifest = self.authority.load_request_manifest(authority_id=authority_id, manifest_hash=manifest_hash)
            if manifest.get("request_hash") != unfinished["request_hash"] or manifest.get("intent_hash") != unfinished["intent_hash"] or manifest.get("logical_call_id") != unfinished["logical_call_id"]:
                raise LiveCanaryAuthorityError("server request manifest is outside the durable intent")
            profile = self.provider_store.get_profile(profile_hash=str(preview_value["provider_profile_hash"]))
            builder = ServerOwnedRequestBuilder()
            connection = self.repository._connect(read_only=True)
            try:
                built = builder.build_from_row(authority={**dict(preview_value), "_provider_profile": profile}, connection=connection, provider_profile=profile)
            finally:
                connection.close()
            if dict(built.manifest) != dict(manifest):
                raise LiveCanaryAuthorityError("server request rebuild does not match the Preview manifest")

            failure_stage = "consume_and_prepare"
            prepared = self.authority.consume_and_prepare(
                approval_id=approval_id, preview_hash=str(preview["preview_hash"]), consumer=worker_actor,
                worker_id=worker_actor.actor_id, worker_session=worker_actor.session_id,
                fencing_token=fencing_token, claim_id=claim_id,
                request_hash=str(manifest["request_hash"]), idempotency_key_hash=canonical_sha256(idempotency_key),
            )
            canary_permit_id = str(prepared["permit_id"])
            failure_stage = "source_permit_issue"
            source = self.authority.issue_source_permit(
                authority_id=authority_id, approval_id=approval_id, canary_permit_id=canary_permit_id,
                manifest=manifest, worker_id=worker_actor.actor_id, worker_session=worker_actor.session_id,
                fencing_token=fencing_token, actor=worker_actor,
            )
            source_permit_id = str(source["source_permit_id"])
            grant_caps = {
                "max_ticks": 1, "max_iterations": 1, "max_wall_clock_seconds": int(preview_value["caps"]["max_wall_clock_seconds"]),
                "max_provider_calls": 1, "max_input_tokens": int(preview_value["caps"]["max_input_tokens"]),
                "max_output_tokens": int(preview_value["caps"]["max_output_tokens"]),
                "max_cache_read_tokens": int(preview_value["caps"]["max_cache_read_tokens"]),
                "max_reasoning_tokens": int(preview_value["caps"]["max_reasoning_tokens"]),
                "max_cost_units": int(preview_value["effective_provider_cost_cap"]),
                "max_consecutive_failures": 1, "max_no_progress": 1,
            }
            failure_stage = "grant_issue"
            grant = self.provider_store.issue_live_execution_grant(
                run_id=str(preview_value["run_id"]), actor=approval_actor, profile_hash=profile.profile_hash,
                caps=grant_caps, reason="server-owned MR-4B1A-R execution closure", ttl_seconds=3600,
                network_policy_hash=profile.network_policy_hash, pricing_hash=profile.pricing.pricing_hash,
                budget_hash=str(preview_value["budget_hash"]),
            )
            grant_id = str(grant["grant_id"])
            failure_stage = "grant_consume"
            consumed_grant = self.provider_store.consume_execution_grant(
                grant_id=grant_id, run_id=str(preview_value["run_id"]), project_id=str(preview_value["project_id"]),
                profile_hash=profile.profile_hash, model_identity=profile.model_identity,
                network_policy_hash=profile.network_policy_hash, pricing_hash=profile.pricing.pricing_hash,
                budget_hash=str(preview_value["budget_hash"]), consumer=worker_actor,
            )
            network_value = self.provider_store.network_policy_status(network_policy_hash_value=profile.network_policy_hash)
            network_policy = network_value.get("policy") if isinstance(network_value, Mapping) else None
            if not isinstance(network_policy, Mapping):
                raise LiveCanaryAuthorityError("server network policy is missing")
            live_caps = {"max_provider_calls": 1, "max_input_tokens": int(preview_value["caps"]["max_input_tokens"]), "max_output_tokens": int(preview_value["caps"]["max_output_tokens"]), "max_cache_read_tokens": int(preview_value["caps"]["max_cache_read_tokens"]), "max_reasoning_tokens": int(preview_value["caps"]["max_reasoning_tokens"]), "max_cost_units": int(preview_value["effective_provider_cost_cap"])}
            failure_stage = "network_authorization_issue"
            authorization = self.provider_store.issue_live_network_authorization(
                run_id=str(preview_value["run_id"]), grant_id=grant_id, caps=live_caps,
                network_policy=network_policy, reason="server-owned MR-4B1A-R execution closure", actor=approval_actor,
                ttl_seconds=900, profile_hash=profile.profile_hash,
            )
            authorization_id = str(authorization["authorization_id"])
            failure_stage = "dispatch_prepare"
            dispatch = self.provider_store.prepare_live_dispatch(
                authorization_id=authorization_id, run_id=str(preview_value["run_id"]), project_id=str(preview_value["project_id"]),
                grant_id=grant_id, profile=profile, request_hash=str(manifest["request_hash"]),
                wire_request_hash=str(manifest["wire_request_hash"]), intent_hash=str(manifest["intent_hash"]),
                logical_call_id=str(manifest["logical_call_id"]), idempotency_key=idempotency_key,
                actor=worker_actor, fencing_token=fencing_token,
            )
            provider_permit = dispatch.get("permit")
            if provider_permit is None:
                raise LiveCanaryAuthorityError("server provider dispatch permit was not issued")
            failure_stage = "dispatch_start"
            provider_permit = self.provider_store.start_live_dispatch(permit=provider_permit, actor=worker_actor, fencing_token=fencing_token)
            failure_stage = "source_permit_consume"
            self.authority.consume_source_permit(source_permit_id=source_permit_id, manifest_hash=str(manifest["manifest_hash"]), worker_id=worker_actor.actor_id, worker_session=worker_actor.session_id, fencing_token=fencing_token, actor=worker_actor)
            def audit_network_event(event_type: str, payload: Mapping[str, Any]) -> None:
                self.provider_store.record_live_network_access_event(
                    authorization_id=str(authorization_id),
                    run_id=str(preview_value["run_id"]),
                    project_id=str(preview_value["project_id"]),
                    event_type=event_type,
                    actor=worker_actor,
                    provider_attempt_id=provider_permit.attempt_id,
                    claim_id=provider_permit.claim_id,
                    fencing_token=fencing_token,
                    details=payload,
                )

            def cross_http_boundary(boundary_permit: Any) -> None:
                boundary_result = self.authority.mark_http_dispatch_boundary_crossed(
                    permit_id=canary_permit_id,
                    run_id=str(preview_value["run_id"]),
                    project_id=str(preview_value["project_id"]),
                    claim_id=boundary_permit.claim_id,
                    attempt_id=boundary_permit.attempt_id,
                    fencing_token=fencing_token,
                    request_hash=str(manifest["request_hash"]),
                    idempotency_key_hash=canonical_sha256(idempotency_key),
                    actor=worker_actor,
                    canary_claim_id=claim_id,
                )
                if bool(boundary_result.get("idempotent")):
                    raise ProviderTransportError("HTTP_BOUNDARY_ALREADY_CROSSED", "physical provider retry is forbidden", dispatch_known=False)
                audit_network_event(
                    "http_dispatch_boundary_crossed",
                    {
                        "attempt_id": boundary_permit.attempt_id,
                        "claim_id": boundary_permit.claim_id,
                        "request_hash": str(manifest["request_hash"]),
                        "idempotency_key_hash": canonical_sha256(idempotency_key),
                        "fencing_token": fencing_token,
                        "send_boundary_reached": True,
                    },
                )

            failure_stage = "transport_preflight"
            transport = LiveProviderTransportFactory.create_for_permit(
                profile=profile,
                permit=provider_permit,
                provider_store=self.provider_store,
                network_event_callback=audit_network_event,
                send_boundary_callback=cross_http_boundary,
            )
            transport.bind_server_permit(provider_permit)
            timeout_ms = min(120_000, int(profile.timeout_policy.get("total_ms", 120_000)))
            failure_stage = "transport_send"
            response = transport.send(built.body, headers={"content-type": "application/json", "accept": "application/json", "idempotency-key": idempotency_key}, timeout_ms=timeout_ms, idempotency_key=idempotency_key)
            failure_stage = "response_validation"
            usage = _response_usage(response)
            response_hash = hashlib.sha256(response.body_bytes()).hexdigest()
            if not response.dispatch_known or not response.provider_call_id or usage is None:
                close_unknown(reason="unknown", details={"response_hash": response_hash, "status_code": response.status_code, "reason": "missing_provider_id_or_usage"})
            try:
                cost_units = profile.pricing.cost_units_for_usage(usage)
                caps = preview_value["caps"]
                within = _usage_is_within_caps(usage, profile=profile, caps=caps) and 0 <= int(cost_units) <= int(caps["max_cost_units"])
            except Exception:
                within = False
                cost_units = 0
            if not within or not (200 <= int(response.status_code) < 300):
                close_unknown(reason="disputed", details={"response_hash": response_hash, "status_code": response.status_code, "reason": "provider_receipt_or_cost_disputed"})
            context = self.provider_store.live_dispatch_context(permit=provider_permit)
            basis = {"provider_call_id": response.provider_call_id, "run_id": context["run_id"], "logical_call_id": context["logical_call_id"], "intent_hash": context["intent_hash"], "request_hash": context["request_hash"], "idempotency_key": idempotency_key, "response_hash": response_hash}
            call_record = ProviderCallRecord(call_record_id=make_stable_id("provider_call_record", canonical_sha256(basis)[:64]), provider_call_id=response.provider_call_id, run_id=context["run_id"], project_id=context["project_id"], profile_hash=context["profile_hash"], model_identity=context["model_identity"], intent_hash=context["intent_hash"], request_hash=context["request_hash"], idempotency_key=idempotency_key, transport_status=f"http_{response.status_code}", terminal_status="succeeded", usage=usage, response_manifest=response.response_manifest, pricing_hash=context["pricing_hash"], logical_call_id=context["logical_call_id"], intent_id=context["intent_id"], iteration_id=context["iteration_id"])
            self.provider_store.record_provider_call(record=call_record, actor=worker_actor, proposal={"kind": "one_shot_response_manifest", "response_hash": response_hash, "manifest": response.response_manifest}, attempt_id=provider_permit.attempt_id)
            RunnerPersistence(self.repository).record_dispatch_ack(
                run_id=context["run_id"],
                logical_call_id=context["logical_call_id"],
                status="dispatched",
                dispatch_known=True,
                provider_call_id=response.provider_call_id,
                actor=worker_actor,
                fencing_token=fencing_token,
                preserve_existing=True,
            )
            attestation = ProviderUsageAttestation(attestation_id=make_stable_id("provider_usage_attestation", canonical_sha256(call_record.call_record_id)[:64]), call_record_id=call_record.call_record_id, provider_call_id=call_record.provider_call_id, run_id=call_record.run_id, profile_hash=call_record.profile_hash, pricing_hash=call_record.pricing_hash, usage=call_record.usage, cost_units=cost_units, authority_id=PROVIDER_USAGE_AUTHORITY_ID)
            self.provider_store.record_provider_attestation(attestation=attestation, actor=worker_actor)
            self.provider_store.mark_live_dispatch_outcome(permit=provider_permit, state="settled", actor=worker_actor, details={"response_hash": response_hash, "usage_hash": canonical_sha256(usage), "cost_units": cost_units})
            self.provider_store.record_live_network_attempt(authorization_id=authorization_id, run_id=str(preview_value["run_id"]), project_id=str(preview_value["project_id"]), outcome="settled", actor=worker_actor, provider_attempt_id=provider_permit.attempt_id, claim_id=provider_permit.claim_id, fencing_token=fencing_token, details={"response_hash": response_hash, "status_code": response.status_code, "usage_hash": canonical_sha256(usage), "cost_units": cost_units})
            settled = self.authority.record_outcome(permit_id=canary_permit_id, outcome="succeeded", usage=usage, cost_units=cost_units, actor=worker_actor, provider_call_id=response.provider_call_id, response_hash=response_hash)
            return {"ok": True, "one_shot": True, "outcome": "succeeded", "permit_id": canary_permit_id, "provider_permit_id": provider_permit.permit_id, "provider_call_id": response.provider_call_id, "response": response.response_manifest, "settlement": settled, "network": {"dns_lookups": int(transport.dns_lookup_count), "credential_reads": int(transport.credential_read_count), "provider_calls": int(transport.network_call_count)}, "cost_units": cost_units, "grant_id": grant["grant_id"], "grant_consumption_id": consumed_grant["consumption_id"], "source_permit_id": source_permit_id}
        except ProviderTransportError as exc:
            close_unknown(reason="unknown", details={"error_code": exc.code, "reason": "transport_boundary"})
        except LiveCanaryAuthorityError:
            if canary_permit_id is not None:
                close_unknown(reason="unknown", details={"reason": "authority_boundary"})
            raise
        except Exception as exc:
            close_unknown(reason="unknown", details={"error": type(exc).__name__, "error_code": getattr(exc, "error_code", None) or getattr(exc, "code", None), "reason": "boundary_exception"})

    def execute_fixture(
        self,
        *,
        authority_id: str | None = None,
        approval_id: str | None = None,
        preview_hash: str | None = None,
        confirmation_phrase: str | None = None,
        actor: Any | None = None,
        worker_id: str | None = None,
        worker_session: str | None = None,
        fencing_token: int | None = None,
        claim_id: str | None = None,
        request: Mapping[str, Any] | None = None,
        request_builder: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        logical_call_id: str | None = None,
        idempotency_key: str | None = None,
        authorization_id: str | None = None,
        grant_id: str | None = None,
        source_permit_validator: Callable[[], bool] | None = None,
        transport: OneShotTransport | None = None,
        allow_execute: bool = False,
    ) -> dict[str, Any]:
        """Execute exactly one explicitly authorized physical call.

        This method is intentionally unusable by default.  In particular, it
        does not construct the production transport, resolve a credential, or
        perform DNS while validating arguments.  The actual transport is
        reached only after all server permits and the durable send-start
        transition have succeeded.
        """

        if not allow_execute:
            raise LiveCanaryAuthorityError("live-canary-execute requires an explicit execution flag")
        if not self.live_network_enabled:
            raise LiveCanaryAuthorityError("production live transport is disabled")
        if actor is None:
            raise LiveCanaryAuthorityError("one-shot execution requires a worker actor")
        if self.provider_store is None:
            raise LiveCanaryAuthorityError("one-shot execution requires the durable provider store")
        if not authority_id or not approval_id or not authorization_id or not grant_id:
            raise LiveCanaryAuthorityError("one-shot execution requires durable authority, approval, network authorization and grant IDs")
        if not worker_id or not worker_session or not claim_id or not logical_call_id or not idempotency_key:
            raise LiveCanaryAuthorityError("one-shot execution requires worker, claim, logical-call and idempotency bindings")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise LiveCanaryAuthorityError("one-shot execution fencing token is invalid")

        # Rebuild the whole Preview before touching approval or provider state.
        preview = self.authority.preview_from_authority(authority_id=authority_id, actor=actor)
        expected_preview_hash = str(preview["preview_hash"])
        if preview_hash != expected_preview_hash:
            raise LiveCanaryAuthorityError("one-shot Preview hash is stale or foreign")
        if confirmation_phrase != preview.get("confirmation_phrase"):
            raise LiveCanaryAuthorityError("one-shot execution requires the exact Preview confirmation phrase")
        if claim_id != preview["preview"].get("claim_id") or worker_id != preview["preview"].get("worker_id") or worker_session != preview["preview"].get("worker_session") or int(fencing_token) != int(preview["preview"].get("fencing_token")):
            raise LiveCanaryAuthorityError("one-shot worker/claim fence is outside the durable Preview")

        # The provider dispatch chain is keyed by the existing server-owned
        # ModelCallIntent.  Re-query it here; a caller must not turn an
        # arbitrary wire-body hash into a new intent authority.
        unfinished = RunnerPersistence(self.repository).latest_unfinished(run_id=preview["preview"]["run_id"])
        if not isinstance(unfinished, Mapping) or unfinished.get("logical_call_id") != logical_call_id:
            raise LiveCanaryAuthorityError("one-shot logical call is not the current server-owned runner intent")
        if unfinished.get("project_id") != preview["preview"]["project_id"] or unfinished.get("run_id") != preview["preview"]["run_id"]:
            raise LiveCanaryAuthorityError("one-shot runner intent crosses the project or run boundary")
        if unfinished.get("idempotency_key") != idempotency_key:
            raise LiveCanaryAuthorityError("one-shot idempotency key is outside the server-owned runner intent")
        durable_request_hash = str(unfinished["request_hash"])
        durable_intent_hash = str(unfinished["intent_hash"])

        if request_builder is not None:
            request = request_builder(preview["preview"])
        if not isinstance(request, Mapping):
            raise LiveCanaryAuthorityError("server-bounded provider request is required")
        _reject_wire_secrets(request)
        request_value = json.loads(canonical_json(request))
        request_bytes = canonical_json(request_value).encode("utf-8")
        if len(request_bytes) > 1_000_000:
            raise LiveCanaryAuthorityError("one-shot provider request exceeds its bounded size")
        # ``wire_payload_hash`` is diagnostic-only.  The provider claim must
        # use the durable ModelCallIntent request hash, not a caller-created
        # hash of an arbitrary body.
        wire_payload_hash = canonical_sha256(request_value)
        if len(wire_payload_hash) != 64:
            raise LiveCanaryAuthorityError("one-shot wire payload hash is invalid")
        request_hash = durable_request_hash
        wire_request_hash = hashlib.sha256(request_bytes).hexdigest()
        idempotency_hash = canonical_sha256(idempotency_key)
        intent_hash = durable_intent_hash

        # Validate the source permit before consuming the one-time human
        # approval.  A failed source gate must not leave an approval consumed
        # merely because the caller supplied a bad or missing permit.
        if source_permit_validator is not None and source_permit_validator() is not True:
            raise LiveCanaryAuthorityError("source-egress permit was not issued by the server")

        # Human approval, canary budget reservation and the one-shot canary
        # permit are consumed atomically before any provider permit exists.
        prepared = self.authority.consume_and_prepare(
            approval_id=approval_id,
            preview_hash=expected_preview_hash,
            consumer=actor,
            worker_id=worker_id,
            worker_session=worker_session,
            fencing_token=fencing_token,
            claim_id=claim_id,
            request_hash=request_hash,
            idempotency_key_hash=idempotency_hash,
        )
        canary_permit_id = str(prepared["permit_id"])
        source_permit_id: str | None = None
        source_manifest: dict[str, Any] | None = None
        provider_permit = None
        failure_stage = "fixture_dispatch_prepare"
        failure_closed = False
        boundary_result: dict[str, Any] = {
            "failure_class": "UNKNOWN_AFTER_SEND",
            "send_boundary_reached": True,
            "reconciliation_required": True,
            "retry_allowed": False,
            "durable_evidence": {},
        }

        def close_uncertain_provider(*, outcome: str, details: Mapping[str, Any]) -> list[str]:
            """Close the fixture saga from durable boundary evidence."""

            nonlocal boundary_result, failure_closed
            if failure_closed:
                return []
            failure_closed = True
            errors: list[str] = []
            try:
                boundary_result = self.authority.classify_provider_boundary(permit_id=canary_permit_id)
            except Exception as classify_exc:
                boundary_result = {
                    "failure_class": "UNKNOWN_AFTER_SEND",
                    "send_boundary_reached": True,
                    "reconciliation_required": True,
                    "retry_allowed": False,
                    "durable_evidence": {"classification_read_error": type(classify_exc).__name__},
                }
                errors.append(f"classification:{type(classify_exc).__name__}")
            diagnostics = _failure_diagnostics(
                boundary=boundary_result,
                failure_stage=failure_stage,
                details={
                    **dict(details),
                    "reason": details.get("reason", outcome),
                    "human_cost_ceiling": preview["preview"].get("human_cost_ceiling"),
                    "profile_worst_case_cost": preview["preview"].get("profile_worst_case_cost"),
                    "effective_provider_cost_cap": preview["preview"].get("effective_provider_cost_cap"),
                },
            )
            provider_details = {
                key: diagnostics[key]
                for key in ("failure_stage", "error_code", "failure_class", "send_boundary_reached", "reconciliation_required", "retry_allowed", "human_cost_ceiling", "profile_worst_case_cost", "effective_provider_cost_cap", "exception_type", "reason", "response_hash", "status_code")
                if key in diagnostics
            }
            if provider_permit is not None:
                if bool(boundary_result["send_boundary_reached"]):
                    try:
                        self.provider_store.mark_provider_call_unknown(
                            claim_id=provider_permit.claim_id,
                            actor=actor,
                            fencing_token=fencing_token,
                        )
                    except Exception as cleanup_exc:
                        errors.append(f"provider_claim:{type(cleanup_exc).__name__}")
                    try:
                        self.provider_store.mark_live_dispatch_outcome(
                            permit=provider_permit,
                            state="unknown" if outcome not in {"disputed"} else "disputed",
                            actor=actor,
                            details=provider_details,
                        )
                    except Exception as cleanup_exc:
                        errors.append(f"live_permit:{type(cleanup_exc).__name__}")
                    try:
                        self.provider_store.record_live_network_attempt(
                            authorization_id=authorization_id,
                            run_id=preview["preview"]["run_id"],
                            project_id=preview["preview"]["project_id"],
                            outcome="disputed" if outcome == "disputed" else "unknown",
                            actor=actor,
                            provider_attempt_id=provider_permit.attempt_id,
                            claim_id=provider_permit.claim_id,
                            fencing_token=fencing_token,
                            details=provider_details,
                        )
                    except Exception as cleanup_exc:
                        errors.append(f"network_attempt:{type(cleanup_exc).__name__}")
                else:
                    try:
                        self.provider_store.abort_live_dispatch_before_send(
                            permit=provider_permit,
                            actor=actor,
                            fencing_token=fencing_token,
                            details=provider_details,
                        )
                    except Exception as cleanup_exc:
                        errors.append(f"pre_send_abort:{type(cleanup_exc).__name__}")
                        try:
                            self.provider_store.mark_live_dispatch_outcome(
                                permit=provider_permit,
                                state="failed",
                                actor=actor,
                                details={**provider_details, "send_boundary_reached": False},
                            )
                        except Exception as fallback_exc:
                            errors.append(f"live_permit:{type(fallback_exc).__name__}")
            if not bool(boundary_result["send_boundary_reached"]):
                try:
                    RunnerPersistence(self.repository).abort_pre_send(
                        run_id=preview["preview"]["run_id"],
                        logical_call_id=logical_call_id,
                        actor=actor,
                        fencing_token=fencing_token,
                        failure_stage=failure_stage,
                        error_code=str(diagnostics.get("error_code", _DEFAULT_PRE_SEND_ERROR)),
                    )
                except Exception as cleanup_exc:
                    errors.append(f"runner_abort_closure:{type(cleanup_exc).__name__}")
                try:
                    if source_permit_id is not None:
                        self.authority.revoke_source_permit(source_permit_id=source_permit_id, actor=actor, reason="known_pre_send_failure")
                except Exception as cleanup_exc:
                    errors.append(f"source_permit:{type(cleanup_exc).__name__}")
                try:
                    if grant_id is not None:
                        self.provider_store.close_execution_grant_before_send(
                            grant_id=grant_id,
                            actor=actor,
                            failure_stage=failure_stage,
                            error_code=str(diagnostics["error_code"]),
                        )
                except Exception as cleanup_exc:
                    errors.append(f"grant_closure:{type(cleanup_exc).__name__}")
            try:
                self.authority.record_outcome(
                    permit_id=canary_permit_id,
                    outcome="unknown" if bool(boundary_result["send_boundary_reached"]) else "aborted",
                    usage={},
                    cost_units=0,
                    actor=actor,
                    diagnostics=diagnostics,
                )
            except Exception as cleanup_exc:
                errors.append(f"canary_outcome:{type(cleanup_exc).__name__}")
            if not bool(boundary_result["send_boundary_reached"]):
                try:
                    with closing(self.repository._connect(read_only=True)) as connection:
                        run_row = connection.execute("SELECT status FROM max_runs WHERE run_id=?", (preview["preview"]["run_id"],)).fetchone()
                    if run_row is not None and run_row["status"] == "RUNNING":
                        self.repository.pause(run_id=preview["preview"]["run_id"], actor=actor, fencing_token=fencing_token)
                except Exception as cleanup_exc:
                    errors.append(f"run_pause:{type(cleanup_exc).__name__}")
                try:
                    RunnerPersistence(self.repository).release_invocation(run_id=preview["preview"]["run_id"], claim_id=claim_id, actor=actor, fencing_token=fencing_token)
                except Exception as cleanup_exc:
                    errors.append(f"invocation_release:{type(cleanup_exc).__name__}")
            return errors

        def usage_is_within_preview(usage: Mapping[str, int], cost_units: int, profile: ProviderProfile) -> bool:
            """Apply both component and aggregate server-owned caps."""

            caps = preview["preview"].get("caps", {})
            return _usage_is_within_caps(usage, profile=profile, caps=caps) and 0 <= int(cost_units) <= int(caps.get("max_cost_units", 0))

        try:
            failure_stage = "source_permit_issue"
            source_allowlist = preview["preview"].get("source_allowlist")
            if not isinstance(source_allowlist, list) or len(source_allowlist) != 1 or not isinstance(source_allowlist[0], Mapping):
                raise LiveCanaryAuthorityError("server Preview has no exact source allowlist")
            source_item = source_allowlist[0]
            source_manifest = {
                "manifest_hash": preview["preview"].get("request_manifest_hash"),
                "project_id": preview["preview"]["project_id"],
                "run_id": preview["preview"]["run_id"],
                "passage_id": source_item.get("passage_id"),
                "document_id": source_item.get("document_id"),
                "source_version": source_item.get("document_version_id"),
                "source_policy_hash": preview["preview"]["source_egress_policy_hash"],
                "logical_call_id": logical_call_id,
                "provider_profile_hash": preview["preview"]["provider_profile_hash"],
                "source_role": source_item.get("source_role"),
                "evidential_function": source_item.get("evidential_function"),
                "purpose": "supports",
            }
            if any(not isinstance(source_manifest.get(key), str) or not source_manifest[key] for key in ("manifest_hash", "passage_id", "document_id", "source_version", "source_policy_hash", "logical_call_id", "provider_profile_hash", "source_role", "evidential_function")):
                raise LiveCanaryAuthorityError("server Preview source manifest binding is incomplete")
            issued_source = self.authority.issue_source_permit(
                authority_id=authority_id,
                approval_id=approval_id,
                canary_permit_id=canary_permit_id,
                manifest=source_manifest,
                worker_id=worker_id,
                worker_session=worker_session,
                fencing_token=fencing_token,
                actor=actor,
            )
            source_permit_id = str(issued_source["source_permit_id"])
            failure_stage = "dispatch_prepare"
            profile = self.provider_store.get_profile(profile_hash=preview["preview"]["provider_profile_hash"])
            dispatch = self.provider_store.prepare_live_dispatch(
                authorization_id=authorization_id,
                run_id=preview["preview"]["run_id"],
                project_id=preview["preview"]["project_id"],
                grant_id=grant_id,
                profile=profile,
                request_hash=request_hash,
                wire_request_hash=wire_request_hash,
                intent_hash=intent_hash,
                logical_call_id=logical_call_id,
                idempotency_key=idempotency_key,
                actor=actor,
                fencing_token=fencing_token,
            )
            provider_permit = dispatch.get("permit")
            if provider_permit is None:
                raise LiveCanaryAuthorityError("provider dispatch permit was not issued")
            failure_stage = "dispatch_start"
            provider_permit = self.provider_store.start_live_dispatch(permit=provider_permit, actor=actor, fencing_token=fencing_token)

            # This is the final durable write before credential resolution.
            failure_stage = "source_permit_consume"
            self.authority.consume_source_permit(
                source_permit_id=source_permit_id,
                manifest_hash=str(source_manifest["manifest_hash"]),
                worker_id=worker_id,
                worker_session=worker_session,
                fencing_token=fencing_token,
                actor=actor,
            )
            active_transport = transport or self.transport
            if active_transport is None and self.transport_factory is not None:
                active_transport = self.transport_factory(profile=profile, permit=provider_permit, provider_store=self.provider_store)
            if active_transport is None:
                raise LiveCanaryAuthorityError("one-shot transport is not injected")
            bind = getattr(active_transport, "bind_server_permit", None)
            if callable(bind):
                bind(provider_permit)

            def audit_network_event(event_type: str, payload: Mapping[str, Any]) -> None:
                self.provider_store.record_live_network_access_event(
                    authorization_id=authorization_id,
                    run_id=str(preview["preview"]["run_id"]),
                    project_id=str(preview["preview"]["project_id"]),
                    event_type=event_type,
                    actor=actor,
                    provider_attempt_id=provider_permit.attempt_id,
                    claim_id=provider_permit.claim_id,
                    fencing_token=fencing_token,
                    details=payload,
                )

            def cross_http_boundary(boundary_permit: Any) -> None:
                boundary_result = self.authority.mark_http_dispatch_boundary_crossed(
                    permit_id=canary_permit_id,
                    run_id=str(preview["preview"]["run_id"]),
                    project_id=str(preview["preview"]["project_id"]),
                    claim_id=boundary_permit.claim_id,
                    attempt_id=boundary_permit.attempt_id,
                    fencing_token=fencing_token,
                    request_hash=request_hash,
                    idempotency_key_hash=idempotency_hash,
                    actor=actor,
                    canary_claim_id=claim_id,
                )
                if bool(boundary_result.get("idempotent")):
                    raise ProviderTransportError("HTTP_BOUNDARY_ALREADY_CROSSED", "physical provider retry is forbidden", dispatch_known=False)
                audit_network_event(
                    "http_dispatch_boundary_crossed",
                    {
                        "attempt_id": boundary_permit.attempt_id,
                        "claim_id": boundary_permit.claim_id,
                        "request_hash": request_hash,
                        "idempotency_key_hash": idempotency_hash,
                        "fencing_token": fencing_token,
                        "send_boundary_reached": True,
                    },
                )

            # The package transport owns DNS, credential and connector
            # ordering.  Hermetic fixture transports have no such seam, so
            # their injected send method is the connector boundary itself.
            configure_callbacks = getattr(active_transport, "configure_boundary_callbacks", None)
            boundary_configured = False
            if callable(configure_callbacks):
                configure_callbacks(network_event_callback=audit_network_event, send_boundary_callback=cross_http_boundary)
                boundary_configured = True

            timeout_ms = min(120_000, int(profile.timeout_policy.get("total_ms", 120_000)))
            failure_stage = "transport_send"
            if not boundary_configured:
                cross_http_boundary(provider_permit)
            response = active_transport.send(
                request_bytes,
                headers={"content-type": "application/json", "accept": "application/json", "idempotency-key": idempotency_key},
                timeout_ms=timeout_ms,
                idempotency_key=idempotency_key,
            )
            failure_stage = "response_validation"
            usage = _response_usage(response)
            response_hash = hashlib.sha256(response.body_bytes()).hexdigest()
            known_provider_response = bool(response.dispatch_known and response.provider_call_id)
            if usage is not None:
                try:
                    cost_units = profile.pricing.cost_units_for_usage(usage)
                except Exception:
                    cost_units = 0
            else:
                cost_units = 0

            # A transport response is not a settled provider fact until its
            # provider call ID, usage, frozen pricing, and caps all bind to
            # the durable claim.  Redirects are recorded as known failures
            # only when the provider identified the call; otherwise they are
            # unknown and require reconciliation.
            if not known_provider_response or not response.dispatch_known:
                errors = close_uncertain_provider(
                    outcome="unknown",
                    details={"response_hash": response_hash, "status_code": response.status_code, "reason": "missing_provider_attestation"},
                )
                message = "one-shot provider response is unknown; manual reconciliation is required and retry is forbidden"
                if errors:
                    message += " (durable cleanup: " + ",".join(errors) + ")"
                raise LiveCanaryAuthorityError(message)
            if usage is not None and not usage_is_within_preview(usage, cost_units, profile):
                errors = close_uncertain_provider(
                    outcome="disputed",
                    details={"response_hash": response_hash, "status_code": response.status_code, "reason": "usage_or_cost_outside_cap"},
                )
                message = "one-shot provider usage exceeded the frozen authority; manual reconciliation is required"
                if errors:
                    message += " (durable cleanup: " + ",".join(errors) + ")"
                raise LiveCanaryAuthorityError(message)

            outcome = "succeeded" if 200 <= response.status_code < 300 and usage is not None else "failed"
            context = self.provider_store.live_dispatch_context(permit=provider_permit)
            call_basis = {
                "provider_call_id": response.provider_call_id,
                "run_id": context["run_id"],
                "logical_call_id": context["logical_call_id"],
                "intent_hash": context["intent_hash"],
                "request_hash": context["request_hash"],
                "idempotency_key": idempotency_key,
                "response_hash": response_hash,
            }
            call_record = ProviderCallRecord(
                call_record_id=make_stable_id("provider_call_record", canonical_sha256(call_basis)[:64]),
                provider_call_id=response.provider_call_id,
                run_id=context["run_id"],
                project_id=context["project_id"],
                profile_hash=context["profile_hash"],
                model_identity=context["model_identity"],
                intent_hash=context["intent_hash"],
                request_hash=context["request_hash"],
                idempotency_key=idempotency_key,
                transport_status=f"http_{response.status_code}",
                terminal_status=outcome,
                usage={} if usage is None else usage,
                response_manifest=response.response_manifest,
                pricing_hash=context["pricing_hash"],
                logical_call_id=context["logical_call_id"],
                intent_id=context["intent_id"],
                iteration_id=context["iteration_id"],
            )
            self.provider_store.record_provider_call(
                record=call_record,
                actor=actor,
                proposal={"kind": "one_shot_response_manifest", "response_hash": response_hash, "manifest": response.response_manifest} if outcome == "succeeded" else None,
                attempt_id=provider_permit.attempt_id,
            )
            if outcome == "succeeded":
                RunnerPersistence(self.repository).record_dispatch_ack(
                    run_id=context["run_id"],
                    logical_call_id=context["logical_call_id"],
                    status="dispatched",
                    dispatch_known=True,
                    provider_call_id=response.provider_call_id,
                    actor=actor,
                    fencing_token=fencing_token,
                    preserve_existing=True,
                )
            attestation = None
            if outcome == "succeeded":
                attestation = ProviderUsageAttestation(
                    attestation_id=make_stable_id("provider_usage_attestation", canonical_sha256(call_record.call_record_id)[:64]),
                    call_record_id=call_record.call_record_id,
                    provider_call_id=call_record.provider_call_id,
                    run_id=call_record.run_id,
                    profile_hash=call_record.profile_hash,
                    pricing_hash=call_record.pricing_hash,
                    usage=call_record.usage,
                    cost_units=cost_units,
                    authority_id=PROVIDER_USAGE_AUTHORITY_ID,
                )
                try:
                    self.provider_store.record_provider_attestation(attestation=attestation, actor=actor)
                except Exception as exc:
                    errors = close_uncertain_provider(
                        outcome="disputed",
                        details={"response_hash": response_hash, "status_code": response.status_code, "reason": "usage_attestation_failed"},
                    )
                    message = "one-shot provider usage attestation is disputed; manual reconciliation is required"
                    if errors:
                        message += " (durable cleanup: " + ",".join(errors) + ")"
                    raise LiveCanaryAuthorityError(message) from exc

            provider_state = "settled" if outcome == "succeeded" else "failed"
            self.provider_store.mark_live_dispatch_outcome(
                permit=provider_permit,
                state=provider_state,
                actor=actor,
                details={"response_hash": response_hash, "usage_hash": None if usage is None else canonical_sha256(usage), "cost_units": cost_units, "terminal_status": outcome},
            )
            self.provider_store.record_live_network_attempt(
                authorization_id=authorization_id,
                run_id=preview["preview"]["run_id"],
                project_id=preview["preview"]["project_id"],
                outcome="settled",
                actor=actor,
                provider_attempt_id=provider_permit.attempt_id,
                claim_id=provider_permit.claim_id,
                fencing_token=fencing_token,
                details={"response_hash": response_hash, "status_code": response.status_code, "usage_hash": None if usage is None else canonical_sha256(usage), "cost_units": cost_units, "terminal_status": outcome},
            )
            settled = self.authority.record_outcome(permit_id=canary_permit_id, outcome=outcome, usage={} if usage is None else usage, cost_units=cost_units, actor=actor, provider_call_id=response.provider_call_id or None, response_hash=response_hash)
            counters = {"dns_lookups": int(getattr(active_transport, "dns_lookup_count", 0)), "credential_reads": int(getattr(active_transport, "credential_read_count", 0)), "provider_calls": int(getattr(active_transport, "network_call_count", 0))}
            return {"ok": outcome == "succeeded", "one_shot": True, "outcome": outcome, "permit_id": canary_permit_id, "source_permit_id": source_permit_id, "provider_permit_id": provider_permit.permit_id, "provider_call_id": response.provider_call_id, "response": response.response_manifest, "settlement": settled, "network": counters, "cost_units": cost_units}
        except ProviderTransportError as exc:
            errors = close_uncertain_provider(outcome="unknown", details={"error_code": exc.code, "reason": "transport_boundary"}) if not failure_closed else []
            message = f"{boundary_result['failure_class']}: one-shot provider boundary ended; retry is forbidden"
            if errors:
                message += " (durable cleanup: " + ",".join(errors) + ")"
            raise LiveCanaryAuthorityError(message) from exc
        except Exception as exc:
            if failure_closed:
                if isinstance(exc, LiveCanaryAuthorityError):
                    raise
                raise LiveCanaryAuthorityError(str(exc)) from exc
            errors = close_uncertain_provider(outcome="unknown", details={"exception_type": type(exc).__name__, "reason": "boundary_exception"})
            message = f"{boundary_result['failure_class']}: one-shot provider boundary ended; retry is forbidden"
            if errors:
                message += " (durable cleanup: " + ",".join(errors) + ")"
            raise LiveCanaryAuthorityError(message) from exc

    def reconcile(self, *, permit_id: str, actor: Any, confirmation_phrase: str, allow_reconcile: bool = False) -> dict[str, Any]:
        """Expose only a human-gated read of an unknown outcome."""

        if not allow_reconcile:
            raise LiveCanaryAuthorityError("unknown outcome reconciliation requires an explicit human permission")
        expected = f"RECONCILE MR-4B1 UNKNOWN {permit_id}"
        if confirmation_phrase != expected:
            raise LiveCanaryAuthorityError("reconciliation phrase does not bind the permit")
        status = self.authority.status()
        matches = [item for item in status.get("previews", ()) if item.get("permit_id") == permit_id]
        if not matches:
            raise LiveCanaryAuthorityError("unknown canary permit was not found")
        if matches[0].get("permit_state") != "unknown":
            raise LiveCanaryAuthorityError("reconcile is allowed only for an unknown outcome")
        return {"ok": True, "permit_id": permit_id, "state": "unknown", "manual_decision_required": True, "network": {"dns_lookups": 0, "credential_reads": 0, "provider_calls": 0}}

    def run_fixture_tick(self, executor: LongRunExecutor) -> dict[str, Any]:
        """Use the exact MR-4A.1 pipeline in an explicitly marked fixture only."""

        try:
            fixture = self.repository.is_fixture_database()
        except Exception:
            fixture = False
        if not fixture:
            raise LiveCanaryAuthorityError("production bridge does not accept a production database for a fixture tick")
        if not isinstance(executor, LongRunExecutor):
            raise TypeError("fixture tick requires the existing LongRunExecutor")
        return AuthoritativeTickPipeline(executor).run_one()


__all__ = ["LiveCanaryExecutor", "OneShotTransport"]
