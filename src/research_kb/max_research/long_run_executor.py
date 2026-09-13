"""MR-4A.1 integrated offline long-run executor.

This module is the one service-shaped path that may settle a long-run
iteration.  It deliberately uses the existing BoundedRunner, provider live
adapter, bundle assignment and source-egress stores.  The transport seam is
hermetic, but the authority records are the same records used by the
production-shaped lower provider boundary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any, Mapping

from ..policy import Actor
from .contract import canonical_sha256, make_stable_id
from .contract.models import ResearchState
from .long_run import (
    _INTEGRATED_SETTLEMENT_TOKEN,
    CanonicalSourcePacket,
    CoreEvidenceGateway,
    LocalCoreEvidenceGateway,
    LongRunAuthorizationError,
    LongRunAuthorizationStore,
    SourceEgressStore,
    TrustedSourceData,
)
from .persistence.repository import MaxControlRepository
from .persistence.runner import RunnerPersistence
from .provider import (
    InjectedHermeticTransport,
    LiveAuthorizationBundleStore,
    LiveAuthorizationPoolAdapter,
    LiveProviderTransportFactory,
    NullCredentialResolver,
    OpenAICompatibleHTTPSLiveTransport,
    ProviderProfile,
    ProviderStore,
    ProviderUsageAuthority,
    TransportResponse,
    credential_reference_hash,
    endpoint_hashes,
    network_policy_hash,
)
from .provider.live import ProviderTransportError
from .runner.contracts import RunnerPlan, RunnerProfile
from .runner.planner import build_plan
from .runner.runner import BoundedRunner


class _BoundSourceGateway:
    """Add one server-issued transient source value to gateway context."""

    fixture_only = False

    def __init__(self, base: CoreEvidenceGateway, packet: CanonicalSourcePacket, trusted: TrustedSourceData) -> None:
        self._base = base
        self._packet = packet
        self._trusted = trusted
        self.gateway_name = str(getattr(base, "gateway_name", "controlled_local_research_kb_read_only_api"))
        self.gateway_identity = str(getattr(base, "gateway_identity", self.gateway_name))
        self.config_hash = str(getattr(base, "config_hash", canonical_sha256({"gateway": self.gateway_identity})))

    def context(self, *, project_id: str, run_id: str, state_hash: str, allowed_ids: tuple[str, ...] | list[str], cold: bool = False) -> Mapping[str, Any]:
        context = dict(self._base.context(project_id=project_id, run_id=run_id, state_hash=state_hash, allowed_ids=allowed_ids, cold=cold))  # type: ignore[attr-defined]
        context["source_references"] = [{"passage_id": self._packet.passage_id}]
        # The dataclass is deliberately not a mapping.  It is accepted only
        # when its private server-owned marker is set by SourceEgressStore.
        context["trusted_source_data"] = self._trusted
        return context

    def get_packet_source(self, *, project_id: str, passage_id: str, context: int) -> Mapping[str, Any] | None:
        return self._base.get_packet_source(project_id=project_id, passage_id=passage_id, context=context)


class _HermeticLiveTransport(OpenAICompatibleHTTPSLiveTransport):
    """A permit-validating live-shaped transport with no DNS/credential/socket."""

    hermetic = True

    def __init__(self, *, injected: InjectedHermeticTransport, **kwargs: Any) -> None:
        super().__init__(
            credential_resolver=NullCredentialResolver(),
            dns_resolver=None,
            connector=None,
            **kwargs,
        )
        self._injected = injected

    @staticmethod
    def _reject_wire_credentials(value: Any) -> None:
        if isinstance(value, Mapping):
            forbidden = {"authorization", "cookie", "proxy-authorization", "api_key", "apikey", "secret", "password", "access_token"}
            for key, child in value.items():
                if str(key).casefold() in forbidden:
                    raise ProviderTransportError("REQUEST_PAYLOAD_FORBIDDEN", "provider request contains forbidden credential material", dispatch_known=True)
                _HermeticLiveTransport._reject_wire_credentials(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                _HermeticLiveTransport._reject_wire_credentials(child)

    def send(self, request: bytes, *, headers: Mapping[str, str], timeout_ms: int, idempotency_key: str) -> TransportResponse:
        if not isinstance(request, bytes) or len(request) > int(self.network_policy["max_request_bytes"]):
            raise ProviderTransportError("REQUEST_TOO_LARGE", "provider request exceeded its bounded limit", dispatch_known=True)
        if not isinstance(idempotency_key, str) or not idempotency_key or "\r" in idempotency_key or "\n" in idempotency_key:
            raise ProviderTransportError("INVALID_IDEMPOTENCY_KEY", "provider idempotency key is invalid", dispatch_known=True)
        permit = self._require_permit()
        if permit.state != "send_started":
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "live HTTPS send requires a current send-start permit", dispatch_known=True)
        authority = self.permit_validator(permit)
        if not isinstance(authority, Mapping) or authority.get("ok") is not True:
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "live dispatch permit is not currently valid", dispatch_known=True)
        expected_origin_hash, expected_path_hash = endpoint_hashes(self.endpoint_origin, self.endpoint_path_policy)
        if (
            expected_origin_hash != permit.endpoint_origin_hash
            or expected_path_hash != permit.endpoint_path_policy_hash
            or network_policy_hash(self.network_policy) != permit.network_policy_hash
            or credential_reference_hash(self.credential_ref) != permit.credential_ref_hash
        ):
            raise ProviderTransportError("LIVE_PERMIT_BINDING_MISMATCH", "live dispatch permit endpoint binding is invalid", dispatch_known=True)
        if hashlib.sha256(request).hexdigest() != permit.wire_request_hash or canonical_sha256(idempotency_key) != permit.idempotency_key_hash:
            raise ProviderTransportError("LIVE_PERMIT_BINDING_MISMATCH", "live dispatch permit request binding is invalid", dispatch_known=True)
        try:
            request_value = json.loads(request.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderTransportError("REQUEST_JSON_INVALID", "provider request JSON is invalid", dispatch_known=True) from exc
        self._reject_wire_credentials(request_value)
        if not isinstance(headers, Mapping):
            raise ProviderTransportError("REQUEST_HEADER_INVALID", "provider request headers are invalid", dispatch_known=True)
        for key, value in headers.items():
            if str(key).casefold() in {"authorization", "cookie", "proxy-authorization"} or not isinstance(value, str) or "\r" in value or "\n" in value:
                raise ProviderTransportError("REQUEST_HEADER_FORBIDDEN", "provider request header is not allowed", dispatch_known=True)
        # InjectedHermeticTransport itself rejects credential-bearing headers
        # and records only a request hash, never a source body or credential.
        return self._injected.send(request, headers={"Content-Type": "application/json"}, timeout_ms=timeout_ms, idempotency_key=idempotency_key)


class _HermeticLiveFactory(LiveProviderTransportFactory):
    """Fixture-only factory that still requires all lower live authority checks."""

    fixture_only = True

    def __init__(self, repository: MaxControlRepository) -> None:
        self.repository = repository
        self.requests: list[dict[str, Any]] = []
        self._transport = InjectedHermeticTransport(handler=self._respond)

    @property
    def network_call_count(self) -> int:
        return int(self._transport.network_call_count)

    @property
    def credential_read_count(self) -> int:
        return int(self._transport.credential_read_count)

    @property
    def dns_lookup_count(self) -> int:
        return 0

    def _respond(self, request: bytes, headers: Mapping[str, str], idempotency_key: str) -> TransportResponse:
        value = json.loads(request.decode("utf-8"))
        metadata = value.get("metadata") if isinstance(value, Mapping) else {}
        user = value.get("messages", [{}, {}])[1].get("content", "") if isinstance(value, Mapping) else ""
        user_value = json.loads(user) if isinstance(user, str) else {}
        typed = user_value.get("typed_input", {}) if isinstance(user_value, Mapping) else {}
        phase = str(user_value.get("phase", "exploration")) if isinstance(user_value, Mapping) else "exploration"
        source = user_value.get("trusted_source_data", {}) if isinstance(user_value, Mapping) else {}
        quoted = source.get("quoted_source_data", {}) if isinstance(source, Mapping) else {}
        source_handle = str(quoted.get("source_handle", "")) if isinstance(quoted, Mapping) else ""
        logical_call_id = str(metadata.get("logical_call_id", ""))
        proposal = self._proposal(phase=phase, typed=typed, source_handle=source_handle, logical_call_id=logical_call_id, run_id=str(metadata.get("run_id", "")))
        provider_call_id = make_stable_id("hermetic_provider_call", logical_call_id)
        response = {
            "id": provider_call_id,
            "object": "chat.completion",
            "created": 0,
            "model": str(value.get("model", "")),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps(proposal, ensure_ascii=False, separators=(",", ":"))}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        self.requests.append({"logical_call_id": logical_call_id, "phase": phase, "source_handle": source_handle})
        return TransportResponse(200, response, {"content-type": "application/json"}, provider_call_id, True)

    def _run_project(self, run_id: str) -> str:
        connection = self.repository._connect(read_only=True)
        try:
            row = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
            return str(row["project_id"]) if row is not None else ""
        finally:
            connection.close()

    def _canonical_ids(self, run_id: str) -> tuple[list[str], list[str]]:
        try:
            state = ResearchState.from_mapping(self.repository.get_state(run_id=run_id))
        except Exception:
            return [], []
        claims = [obj.stable_id for obj in state.latest_by_id.values() if str(getattr(obj.kind, "value", obj.kind)) == "claim"]
        evidence = [obj.stable_id for obj in state.latest_by_id.values() if str(getattr(obj.kind, "value", obj.kind)) == "evidence"]
        return sorted(claims), sorted(evidence)

    def _proposal(self, *, phase: str, typed: Mapping[str, Any], source_handle: str, logical_call_id: str, run_id: str) -> dict[str, Any]:
        claims, evidence = self._canonical_ids(run_id)
        project_id = self._run_project(run_id)
        target = str(typed.get("target_id", ""))
        handles = [source_handle] if source_handle else []
        base: dict[str, Any] = {"objects": [], "relations": [], "artifact_links": [], "record_refs": [], "strategy": None, "output_summary": "hermetic MR-4A.1 bounded response", "role_outputs": [], "deliberation": None, "source_handles": handles}
        call_spec = str(typed.get("call_spec_id", ""))
        if call_spec in {"lead_position", "rival_position"}:
            role = "lead" if call_spec == "lead_position" else "rival"
            base["deliberation"] = {"kind": "position", "role": role, "position": f"bounded {role} position", "canonical_claim_ids": claims, "canonical_evidence_ids": evidence, "rationale": "server-bounded hermetic position"}
            return base
        if call_spec == "rival_cross_examination":
            base["deliberation"] = {"kind": "cross_examination", "examiner_role": "rival", "respondent_role": "lead", "question": "Which canonical record would falsify this position?", "challenged_claim_ids": claims}
            return base
        if call_spec == "lead_cross_examination_response":
            base["deliberation"] = {"kind": "correction", "role": "lead", "correction": "The position remains conditional on the canonical record.", "corrected_claim_ids": claims}
            return base
        if call_spec == "adjudicator":
            base["deliberation"] = {
                "kind": "adjudication",
                "validity_audit": {"auditor_role": "adjudicator", "passed": True, "facts_evidence_true": True, "normative_valid": True, "expression_clear": True, "role_fidelity": True, "findings": ["hermetic bounded audit"], "audited_claim_ids": claims, "rationale": "server-bounded hermetic audit"},
                "adjudication": {"value": "underdetermined", "rationale": "bounded evidence remains conditional", "rival_ids": [target] if target else [], "canonical_evidence_ids": evidence},
                "minority_reports": [],
            }
            if not evidence:
                # The integrated fixture is expected to acquire evidence before
                # its first adjudication.  Keep the response invalid if that
                # canonical prerequisite is absent; the runner must fail closed.
                base["deliberation"]["adjudication"]["canonical_evidence_ids"] = []
            return base

        kind = "objection" if phase == "attack" else "evidence" if phase == "acquisition_review" else "hypothesis"
        object_id = make_stable_id(kind, logical_call_id)
        payload = {"status": "candidate", "label": "hermetic bounded canonical candidate", "target_id": target, "source_handle": source_handle}
        base["objects"] = [{"stable_id": object_id, "kind": kind, "project_id": project_id, "version": 1, "payload": payload}]
        family = "counterevidence" if phase == "attack" else "direct"
        coverage = "adversarial" if phase == "attack" else "canonical_retrieval" if phase == "acquisition_review" else "bounded_reasoning"
        base["strategy"] = {"family": family, "query": f"hermetic:{phase}", "target_ids": [target] if target else [], "filters": {"server_bounded": True}, "result_ids": [], "new_evidence_ids": [object_id] if kind == "evidence" else [], "coverage_keys": [coverage]}
        if phase == "attack":
            base["artifact_links"] = [{"artifact_type": "attack_record", "artifact": {"target_id": target, "outcome": "needs_review", "rationale": "hermetic adversarial fixture"}}]
        elif phase == "rehydration":
            base["artifact_links"] = [{"artifact_type": "rehydration_review", "artifact": {"canonical_rebuild": True, "drift_flags": []}}]
        base["role_outputs"] = [{"role": str(typed.get("role", "worker")), "position": "bounded hermetic role output", "canonical_ids": [target] if target else []}]
        return base

    def create_for_permit(self, *, profile: ProviderProfile, permit: Any, provider_store: ProviderStore) -> OpenAICompatibleHTTPSLiveTransport:
        # Reuse the package factory's complete profile/run/policy/permit
        # validation.  Its returned transport is constructed only; no DNS,
        # credential or connector method is called here.
        package_transport = LiveProviderTransportFactory.create_for_permit(profile=profile, permit=permit, provider_store=provider_store)
        return _HermeticLiveTransport(
            endpoint_origin=profile.endpoint_origin,
            endpoint_path_policy=profile.endpoint_path_policy,
            credential_ref=profile.credential_ref,
            network_policy=package_transport.network_policy,
            permit=permit,
            permit_validator=provider_store.validate_live_dispatch_permit,
            injected=self._transport,
        )


class AuthoritativeTickPipeline:
    """The single authority-owned tick implementation.

    The pipeline is intentionally kept behind the existing fixture-only
    executor.  A later production bridge may assemble this same object for
    one explicitly permitted canary, but it cannot provide a second
    settlement implementation or a loop.
    """

    name = "mr4a1-authoritative-tick-pipeline/v1"

    def __init__(self, executor: "LongRunExecutor") -> None:
        self.executor = executor

    def run_one(self) -> dict[str, Any]:
        return self.executor._run_one_authoritative_tick()


class LongRunExecutor:
    """Execute one or more server-planned integrated long-run ticks."""

    def __init__(
        self,
        repository: MaxControlRepository,
        *,
        window_id: str,
        execution_binding_id: str,
        grant_id: str,
        bundle_id: str,
        provider_store: ProviderStore,
        profile: ProviderProfile,
        runner_profile: RunnerProfile,
        source_egress: SourceEgressStore,
        source_policy_id: str,
        gateway: LocalCoreEvidenceGateway,
        actor: Actor,
        passage_id: str,
        usage_authority: ProviderUsageAuthority | None = None,
        transport_factory: _HermeticLiveFactory | None = None,
    ) -> None:
        if not repository.is_fixture_database():
            raise LongRunAuthorizationError("MR-4A.1 hermetic integrated executor requires an explicitly marked fixture database")
        if not isinstance(provider_store, ProviderStore) or not isinstance(profile, ProviderProfile) or not isinstance(runner_profile, RunnerProfile):
            raise TypeError("integrated executor provider dependencies are invalid")
        if not isinstance(gateway, LocalCoreEvidenceGateway):
            raise TypeError("integrated executor requires the production-shaped LocalCoreEvidenceGateway")
        if not isinstance(source_egress, SourceEgressStore):
            raise TypeError("integrated executor requires SourceEgressStore")
        self.repository = repository
        self.window_id = str(window_id)
        self.execution_binding_id = str(execution_binding_id)
        self.grant_id = str(grant_id)
        self.bundle_id = str(bundle_id)
        self.provider_store = provider_store
        self.profile = profile
        self.runner_profile = runner_profile
        self.source_egress = source_egress
        self.source_policy_id = str(source_policy_id)
        self.gateway = gateway
        self.actor = actor
        self.passage_id = str(passage_id)
        self.usage_authority = usage_authority or ProviderUsageAuthority()
        self.transport_factory = transport_factory or _HermeticLiveFactory(repository)
        self.long_run = LongRunAuthorizationStore(repository)
        self.bundle_store = LiveAuthorizationBundleStore(provider_store)
        self._last_source_packet: CanonicalSourcePacket | None = None

    def _source_request(self, round_type: str) -> dict[str, Any]:
        if round_type == "rehydration":
            return {"purpose": "rehydration", "source_role": "primary", "evidential_function": "rehydrates"}
        if round_type in {"attack"}:
            return {"purpose": "counters", "source_role": "adversarial", "evidential_function": "counters"}
        if round_type in {"adjudication", "habermasian"}:
            return {"purpose": "adjudication", "source_role": "primary", "evidential_function": "adjudicates"}
        return {"purpose": "supports", "source_role": "primary", "evidential_function": "supports"}

    def _runner_evidence(self, *, iteration_id: str, plan_id: str | None, call_group_id: str | None, fencing_token: int) -> tuple[dict[str, Any], tuple[str, ...], Mapping[str, Any]]:
        connection = self.repository._connect(read_only=True)
        try:
            plan = connection.execute("SELECT * FROM max_runner_plans WHERE run_id=? AND iteration_id=? ORDER BY sequence_no DESC LIMIT 1", (self._run_id, iteration_id)).fetchone()
            if plan is None or (plan_id is not None and plan["plan_id"] != plan_id):
                raise LongRunAuthorizationError("integrated runner plan is missing or mismatched")
            group = connection.execute("SELECT * FROM max_runner_call_groups WHERE run_id=? AND iteration_id=? ORDER BY created_at DESC LIMIT 1", (self._run_id, iteration_id)).fetchone()
            if group is None or (call_group_id is not None and group["group_id"] != call_group_id):
                raise LongRunAuthorizationError("integrated runner call group is missing or mismatched")
            current = connection.execute("SELECT * FROM max_runner_call_group_current WHERE group_id=?", (group["group_id"],)).fetchone()
            if current is None or current["status"] != "completed":
                raise LongRunAuthorizationError("integrated runner call group is not completed")
            usage = list(connection.execute("SELECT provider_call_id,logical_call_id FROM max_runner_usage_bindings WHERE run_id=? AND project_id=? AND iteration_id=? AND group_id=? ORDER BY created_at,logical_call_id", (self._run_id, self._project_id, iteration_id, group["group_id"])))
            provider_ids = tuple(str(row["provider_call_id"]) for row in usage)
            if not provider_ids:
                raise LongRunAuthorizationError("integrated runner produced no provider-call bindings")
            result = connection.execute("SELECT p.proposal_json FROM max_runner_usage_bindings u JOIN max_provider_call_results p ON p.call_record_id=(SELECT call_record_id FROM max_provider_call_records WHERE provider_call_id=u.provider_call_id) WHERE u.run_id=? AND u.iteration_id=? AND u.group_id=? ORDER BY u.created_at DESC,u.logical_call_id DESC LIMIT 1", (self._run_id, iteration_id, group["group_id"])).fetchone()
            if result is None:
                raise LongRunAuthorizationError("integrated runner produced no provider result")
            proposal = json.loads(result["proposal_json"])
            claim = connection.execute("SELECT * FROM max_runner_invocation_claims WHERE run_id=? AND actor_id=? AND actor_session=? AND fencing_token=? ORDER BY rowid DESC LIMIT 1", (self._run_id, self.actor.actor_id, self.actor.session_id, int(fencing_token))).fetchone()
            if claim is None:
                raise LongRunAuthorizationError("integrated runner invocation claim is missing")
            claim_id = str(claim["claim_id"])
            if claim["status"] == "released":
                claim_id = claim_id.removesuffix(":released")
            execution = {"execution_binding_id": self.execution_binding_id, "iteration_id": iteration_id, "plan_id": plan["plan_id"], "call_group_id": group["group_id"], "invocation_claim_id": claim_id}
            return execution, provider_ids, proposal
        finally:
            connection.close()

    def run_next(self) -> dict[str, Any]:
        return self._run_one_authoritative_tick()

    def _run_one_authoritative_tick(self) -> dict[str, Any]:
        status = self.long_run.status(window_id=self.window_id)["windows"]
        if len(status) != 1:
            raise LongRunAuthorizationError("integrated executor requires exactly one long-run window")
        window = status[0]
        if window["state"] != "active":
            raise LongRunAuthorizationError("integrated executor cannot run a non-active long-run window")
        plan = self.long_run.server_round_plan(window_id=self.window_id)
        permit = self.long_run.mint_permit(
            window_id=self.window_id,
            actor=self.actor,
            current_state_hash=plan["state_hash"],
            checkpoint_id=plan["checkpoint_id"],
            state_version=plan["state_version"],
            round_type=plan["round_type"],
            source_egress_policy_hash=window["source_egress_policy_hash"],
        )
        consumed = self.long_run.consume_permit(window_id=self.window_id, permit_id=permit["permit_id"], actor=self.actor, fencing_token=permit["fencing_token"])
        packet_result = self.source_egress.issue_packet(
            policy_id=self.source_policy_id,
            request={"passage_id": self.passage_id, "context": 1, **self._source_request(plan["round_type"])},
            gateway=self.gateway,
            actor=self.actor,
            window_id=self.window_id,
            permit_id=permit["permit_id"],
        )
        self.source_egress.consume_receipt(receipt_id=packet_result["receipt_id"], actor=self.actor)
        packet = self.source_egress.rehydrate_packet(receipt_id=packet_result["receipt_id"], gateway=self.gateway, actor=self.actor)
        trusted = self.source_egress.provider_wire_typed(packet)
        self._last_source_packet = packet
        bound_gateway = _BoundSourceGateway(self.gateway, packet, trusted)

        def plan_builder(**kwargs: Any) -> RunnerPlan:
            generated = build_plan(**kwargs, forced_round_type=plan["round_type"])
            return replace(
                generated,
                metadata={
                    **generated.metadata,
                    "long_run_integrated": True,
                    "long_run_window_id": self.window_id,
                    "long_run_permit_id": permit["permit_id"],
                },
                plan_id="",
                plan_hash="",
            )

        def plan_validator(candidate: RunnerPlan) -> None:
            public_to_persisted = {"exploration": "exploration", "socratic": "exploration", "source_retrieval": "acquisition_review", "evidence_comparison": "acquisition_review", "adjudication": "adjudication", "habermasian": "adjudication", "attack": "attack", "rehydration": "rehydration"}
            if candidate.sequence != int(plan["iteration_no"]) or candidate.input_state_hash != plan["state_hash"] or candidate.round_type != public_to_persisted[plan["round_type"]] or candidate.metadata.get("long_run_window_id") != self.window_id or candidate.metadata.get("long_run_permit_id") != permit["permit_id"]:
                raise LongRunAuthorizationError("runner plan is not bound to the server long-run permit")

        adapter = LiveAuthorizationPoolAdapter(
            self.profile,
            provider_store=self.provider_store,
            bundle_store=self.bundle_store,
            bundle_id=self.bundle_id,
            actor=self.actor,
            grant_id=self.grant_id,
            fencing_token=int(permit["fencing_token"]),
            transport_factory=self.transport_factory,
            usage_authority=self.usage_authority,
        )
        runner = BoundedRunner(
            self.repository,
            self.actor,
            self.runner_profile,
            adapter,
            gateway=bound_gateway,
            usage_authority=self.usage_authority,
            fixture=False,
            plan_builder=plan_builder,
            plan_validator=plan_validator,
        )
        runner_result = runner.run_next(run_id=window["run_id"])
        if runner_result.get("status") != "completed" or not isinstance(runner_result.get("iteration_id"), str):
            raise LongRunAuthorizationError("integrated BoundedRunner did not complete the permitted iteration")
        self._run_id = str(window["run_id"])
        self._project_id = str(window["project_id"])
        execution, provider_call_ids, proposal = self._runner_evidence(
            iteration_id=str(runner_result["iteration_id"]),
            plan_id=None,
            call_group_id=None,
            fencing_token=int(permit["fencing_token"]),
        )
        self.source_egress.validate_model_handles_authoritative(
            output=proposal,
            project_id=self._project_id,
            run_id=self._run_id,
            window_id=self.window_id,
            permit_id=permit["permit_id"],
            provider_call_ids=provider_call_ids,
            iteration_id=str(runner_result["iteration_id"]),
            policy_hash=window["source_egress_policy_hash"],
        )
        settled = self.long_run.settle_integrated(
            window_id=self.window_id,
            permit_id=permit["permit_id"],
            actor=self.actor,
            fencing_token=int(permit["fencing_token"]),
            execution=execution,
            authority_token=_INTEGRATED_SETTLEMENT_TOKEN,
        )
        return {
            "ok": True,
            "window_id": self.window_id,
            "permit_id": permit["permit_id"],
            "consumption_id": consumed["consumption_id"],
            "round_type": plan["round_type"],
            "iteration_id": runner_result["iteration_id"],
            "provider_call_count": len(provider_call_ids),
            "runner": {key: runner_result[key] for key in ("status", "plan_hash", "output_state_hash") if key in runner_result},
            "settlement": settled,
        }


__all__ = ["AuthoritativeTickPipeline", "LongRunExecutor"]
