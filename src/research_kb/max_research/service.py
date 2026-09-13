"""Python control-plane API; intentionally separate from the MCP research surface."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from ..config import Settings
from ..policy import Actor, PolicyError, require_admin
from .contract import (
    CanonicalObject,
    CanonicalRelation,
    Checkpoint,
    CompletionEvaluationInput,
    CompletionResult,
    MaxResearchCharter,
    ResearchState,
    RunStatus,
)
from .persistence import MaxControlError, MaxControlRepository, MaxResearchSettings
from .persistence.repository import IterationRecordInput
from .persistence.control_models import CanonicalChangeSet, UsageReceipt
from .persistence.runner import RunnerPersistence
from .runner import BoundedRunner, FixtureResearchGateway, FixtureUsageAuthority, RunnerProfile, ScriptedFakeAdapter
from .provider import (
    HermeticTransport,
    LiveAuthorizationBundleStore,
    LiveIterationApprovalStore,
    LiveRunnerExecutor,
    ProviderProfile,
    ProviderStore,
    live_execution_confirmation_hash,
)
from .scheduler import AcquisitionControl, ForegroundScheduler, LongRunningWorker, SchedulerPolicy, WorkerControl
from .long_run import LongRunAuthorizationStore, SourceEgressStore
from .intent_preparer import LiveCanaryIntentPreparer
from .lifetime_separation import PreparationSnapshotStore
from .preparation_handoff import PreparationHandoffStore
from .preparation_execution import NativePreparationStore, PreparationCanaryExecutor
from .dns_attempt import DNSAttemptStore
from .approval_preview import LiveApprovalPreviewStore
from .native_live import NativeLiveCanaryExecutor


def resolve_control_database(*, explicit: str | Path | None = None, config_path: str | Path | None = None) -> Path:
    """Resolve a control DB path without creating it or its parent directory."""

    raw = explicit or os.environ.get("RESEARCH_KB_MAX_DATABASE")
    if raw:
        return MaxResearchSettings.from_path(raw).database
    if config_path is not None:
        settings = Settings.load(Path(config_path))
        return (settings.workspace / "max-research-control.db").resolve()
    return (Path.cwd() / "max-research-control.db").resolve()


class MaxControlService:
    """High-level API with explicit admin authority for control commands."""

    def __init__(self, database: str | Path, actor: Actor, *, clock=None, source_resolver=None, usage_authority=None) -> None:
        self.actor = actor
        self.repository = MaxControlRepository(database, clock=clock, source_resolver=source_resolver, usage_authority=usage_authority)

    def _admin(self) -> None:
        try:
            require_admin(self.actor)
        except PolicyError as exc:
            raise PolicyError("Max control command requires the human admin CLI") from exc

    def initialize(self, *, fixture: bool = False) -> dict[str, Any]:
        self._admin()
        return self.repository.initialize(fixture=fixture)

    def propose(self, *, project_id: str, charter: MaxResearchCharter | Mapping[str, Any]) -> dict[str, Any]:
        self._admin()
        return self.repository.propose(project_id=project_id, charter=charter, actor=self.actor)

    def propose_json_file(self, *, project_id: str, charter_path: str | Path) -> dict[str, Any]:
        self._admin()
        try:
            value = json.loads(Path(charter_path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PolicyError("Charter file is not readable canonical JSON") from exc
        return self.repository.propose(project_id=project_id, charter=value, actor=self.actor)

    def approve(self, *, run_id: str, charter_hash: str, reason: str, ttl_seconds: int = 3600) -> dict[str, Any]:
        self._admin()
        return self.repository.approve(run_id=run_id, charter_hash_value=charter_hash, reason=reason, actor=self.actor, ttl_seconds=ttl_seconds)

    def start(self, *, run_id: str, lease_ttl: int = 60) -> dict[str, Any]:
        self._admin()
        return self.repository.start(run_id=run_id, actor=self.actor, lease_ttl=lease_ttl)

    def pause(self, *, run_id: str, fencing_token: int) -> dict[str, Any]:
        self._admin()
        return self.repository.pause(run_id=run_id, actor=self.actor, fencing_token=fencing_token)

    def resume(self, *, run_id: str, fencing_token: int | None = None, lease_ttl: int = 60, expected_state_version: int | None = None, expected_checkpoint_id: str | None = None, expected_state_hash: str | None = None) -> dict[str, Any]:
        self._admin()
        return self.repository.resume(run_id=run_id, actor=self.actor, fencing_token=fencing_token, lease_ttl=lease_ttl, expected_state_version=expected_state_version, expected_checkpoint_id=expected_checkpoint_id, expected_state_hash=expected_state_hash)

    def cancel(self, *, run_id: str, fencing_token: int | None = None) -> dict[str, Any]:
        self._admin()
        return self.repository.cancel(run_id=run_id, actor=self.actor, fencing_token=fencing_token)

    def acquire_lease(self, *, run_id: str, ttl_seconds: int = 60) -> dict[str, Any]:
        return self.repository.acquire_lease(run_id=run_id, actor=self.actor, ttl_seconds=ttl_seconds)

    def renew_lease(self, *, run_id: str, fencing_token: int, ttl_seconds: int = 60) -> dict[str, Any]:
        return self.repository.renew_lease(run_id=run_id, actor=self.actor, fencing_token=fencing_token, ttl_seconds=ttl_seconds)

    def release_lease(self, *, run_id: str, fencing_token: int) -> dict[str, Any]:
        return self.repository.release_lease(run_id=run_id, actor=self.actor, fencing_token=fencing_token)

    def status(self, *, run_id: str) -> dict[str, Any]:
        return self.repository.status(run_id=run_id)

    def events(self, *, run_id: str, cursor: int = 0, limit: int = 50) -> dict[str, Any]:
        return self.repository.list_events(run_id=run_id, cursor=cursor, limit=limit)

    def verify(self, *, run_id: str) -> dict[str, Any]:
        return self.repository.verify_run(run_id=run_id)

    def verify_database(self) -> dict[str, Any]:
        return self.repository.verify_database()

    # MR-4A is intentionally exposed only through the human-admin/worker
    # service boundary.  These methods do not add MCP tools and never invoke
    # provider, DNS, credential or source-acquisition I/O.
    def long_run_preview(self, *, run_id: str, source_egress_policy_hash: str, caps: Mapping[str, Any], not_before: str, expires_at: str) -> dict[str, Any]:
        return LongRunAuthorizationStore(self.repository).preview(run_id=run_id, source_egress_policy_hash=source_egress_policy_hash, caps=caps, not_before=not_before, expires_at=expires_at)

    def long_run_authorize(self, *, run_id: str, source_egress_policy_hash: str, caps: Mapping[str, Any], not_before: str, expires_at: str, confirmation_hash: str) -> dict[str, Any]:
        return LongRunAuthorizationStore(self.repository).authorize(run_id=run_id, source_egress_policy_hash=source_egress_policy_hash, caps=caps, not_before=not_before, expires_at=expires_at, confirmation_hash=confirmation_hash, actor=self.actor)

    def long_run_status(self, *, run_id: str | None = None, window_id: str | None = None) -> dict[str, Any]:
        return LongRunAuthorizationStore(self.repository).status(run_id=run_id, window_id=window_id)

    def long_run_control(self, *, window_id: str, command: str, reason: str) -> dict[str, Any]:
        return LongRunAuthorizationStore(self.repository).control(window_id=window_id, command=command, actor=self.actor, reason=reason)

    def long_run_renew(self, *, window_id: str, caps: Mapping[str, Any], not_before: str, expires_at: str, confirmation_hash: str, reason: str, source_egress_policy_hash: str | None = None) -> dict[str, Any]:
        return LongRunAuthorizationStore(self.repository).renew(window_id=window_id, caps=caps, not_before=not_before, expires_at=expires_at, confirmation_hash=confirmation_hash, reason=reason, actor=self.actor, source_egress_policy_hash=source_egress_policy_hash)

    def long_run_renew_preview(self, *, window_id: str, caps: Mapping[str, Any], not_before: str, expires_at: str, reason: str, source_egress_policy_hash: str | None = None) -> dict[str, Any]:
        return LongRunAuthorizationStore(self.repository).renew_preview(window_id=window_id, caps=caps, not_before=not_before, expires_at=expires_at, reason=reason, source_egress_policy_hash=source_egress_policy_hash)

    def long_run_verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        return LongRunAuthorizationStore(self.repository).verify(run_id=run_id)

    def source_egress_policy(self, *, run_id: str, policy: Mapping[str, Any]) -> dict[str, Any]:
        return SourceEgressStore(self.repository).create_policy(run_id=run_id, value=policy, actor=self.actor)

    def source_egress_preflight(self, *, policy_id: str, purpose: str, passage_id: str, source_role: str, evidential_function: str) -> dict[str, Any]:
        return SourceEgressStore(self.repository).preflight(policy_id=policy_id, purpose=purpose, passage_id=passage_id, source_role=source_role, evidential_function=evidential_function)

    def source_egress_status(self, *, run_id: str | None = None, policy_id: str | None = None) -> dict[str, Any]:
        return SourceEgressStore(self.repository).status(run_id=run_id, policy_id=policy_id)

    def source_packet_status(self, *, receipt_id: str) -> dict[str, Any]:
        return SourceEgressStore(self.repository).packet_status(receipt_id=receipt_id)

    def source_egress_verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        return SourceEgressStore(self.repository).verify(run_id=run_id)

    def backup(self, *, destination: str | Path) -> dict[str, Any]:
        self._admin()
        return self.repository.backup(destination)

    def restore(self, *, source: str | Path) -> dict[str, Any]:
        self._admin()
        return self.repository.restore(source)

    def append_object(self, *, project_id: str, value: CanonicalObject | Mapping[str, Any], run_id: str | None = None, fencing_token: int | None = None, iteration_id: str | None = None) -> dict[str, Any]:
        return self.repository.append_canonical_object(project_id=project_id, value=value, actor=self.actor, run_id=run_id, fencing_token=fencing_token, iteration_id=iteration_id)

    def append_relation(self, *, project_id: str, value: CanonicalRelation | Mapping[str, Any], run_id: str | None = None, fencing_token: int | None = None, iteration_id: str | None = None) -> dict[str, Any]:
        return self.repository.append_canonical_relation(project_id=project_id, value=value, actor=self.actor, run_id=run_id, fencing_token=fencing_token, iteration_id=iteration_id)

    def save_state(self, *, run_id: str, state: ResearchState | Mapping[str, Any], fencing_token: int | None = None, iteration_id: str | None = None) -> dict[str, Any]:
        return self.repository.save_research_state(run_id=run_id, state=state, actor=self.actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def checkpoint(self, *, run_id: str, checkpoint: Checkpoint | Mapping[str, Any], fencing_token: int) -> dict[str, Any]:
        return self.repository.create_checkpoint(run_id=run_id, checkpoint=checkpoint, actor=self.actor, fencing_token=fencing_token)

    def iteration(self, *, run_id: str, record: IterationRecordInput, fencing_token: int) -> dict[str, Any]:
        return self.repository.record_iteration(run_id=run_id, record=record, actor=self.actor, fencing_token=fencing_token)

    def begin_iteration(self, *, run_id: str, round_type: str, fencing_token: int, input_state_hash: str | None = None, iteration_id: str | None = None) -> dict[str, Any]:
        return self.repository.begin_iteration(run_id=run_id, round_type=round_type, actor=self.actor, fencing_token=fencing_token, input_state_hash=input_state_hash, iteration_id=iteration_id)

    def finish_iteration(self, *, run_id: str, iteration_id: str, fencing_token: int, **kwargs: Any) -> dict[str, Any]:
        return self.repository.finish_iteration(run_id=run_id, iteration_id=iteration_id, actor=self.actor, fencing_token=fencing_token, **kwargs)

    def apply_change_set(self, *, run_id: str, change_set: CanonicalChangeSet | Mapping[str, Any], fencing_token: int) -> dict[str, Any]:
        return self.repository.apply_change_set(run_id=run_id, change_set=change_set, actor=self.actor, fencing_token=fencing_token)

    def rehydrate(self, *, run_id: str, fencing_token: int) -> dict[str, Any]:
        return self.repository.rehydrate_run(run_id=run_id, actor=self.actor, fencing_token=fencing_token)

    def reserve_budget(self, *, run_id: str, amount: Mapping[str, Any], idempotency_key: str, fencing_token: int, iteration_id: str | None = None) -> dict[str, Any]:
        return self.repository.reserve_budget(run_id=run_id, amount=amount, idempotency_key=idempotency_key, actor=self.actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def commit_budget(self, *, run_id: str, reservation_id: str, amount: Mapping[str, Any] | None, idempotency_key: str, fencing_token: int, iteration_id: str | None = None) -> dict[str, Any]:
        return self.repository.commit_budget(run_id=run_id, reservation_id=reservation_id, amount=amount, idempotency_key=idempotency_key, actor=self.actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def release_budget(self, *, run_id: str, reservation_id: str, amount: Mapping[str, Any] | None, idempotency_key: str, fencing_token: int, iteration_id: str | None = None) -> dict[str, Any]:
        return self.repository.release_budget(run_id=run_id, reservation_id=reservation_id, amount=amount, idempotency_key=idempotency_key, actor=self.actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def record_usage(self, *, run_id: str, amount: Mapping[str, Any], provenance: Mapping[str, Any] | None = None, receipt: UsageReceipt | Mapping[str, Any] | None = None, idempotency_key: str, fencing_token: int, iteration_id: str | None = None) -> dict[str, Any]:
        return self.repository.record_authoritative_usage(run_id=run_id, amount=amount, provenance=provenance, receipt=receipt, idempotency_key=idempotency_key, actor=self.actor, fencing_token=fencing_token, iteration_id=iteration_id)

    def evaluate_completion(self, *, run_id: str, fencing_token: int) -> dict[str, Any]:
        return self.repository.evaluate_completion(run_id=run_id, actor=self.actor, fencing_token=fencing_token)

    def persist_completion(self, *, run_id: str, evaluation_input: CompletionEvaluationInput | Mapping[str, Any] | None = None, result: CompletionResult | Mapping[str, Any] | None = None, expected_input_hash: str | None = None, fencing_token: int) -> dict[str, Any]:
        return self.repository.persist_completion(run_id=run_id, evaluation_input=evaluation_input, result=result, expected_input_hash=expected_input_hash, actor=self.actor, fencing_token=fencing_token)


class MaxRunnerService:
    """Runner/admin handoff API; it never exposes a researcher-facing tool."""

    def __init__(self, database: str | Path, actor: Actor, profile: RunnerProfile | Mapping[str, Any] | None = None, *, adapter=None, gateway=None, clock=None, usage_authority=None, lease_ttl: int = 60) -> None:
        self.actor = actor
        self.repository = MaxControlRepository(database, clock=clock, usage_authority=usage_authority)
        self.persistence = RunnerPersistence(self.repository)
        self.profile = profile if isinstance(profile, RunnerProfile) or profile is None else RunnerProfile.from_mapping(profile)
        self.adapter = adapter
        self.gateway = gateway
        self.usage_authority = usage_authority
        self.lease_ttl = lease_ttl

    def register_profile(self, *, profile: RunnerProfile | Mapping[str, Any]) -> dict[str, Any]:
        return self.persistence.register_profile(profile=profile, actor=self.actor)

    def handoff(self, *, run_id: str, profile: RunnerProfile | Mapping[str, Any], runner_actor: Actor, admin_fencing_token: int | None = None, lease_ttl: int | None = None) -> dict[str, Any]:
        return self.persistence.handoff_runner(run_id=run_id, profile=profile, admin_actor=self.actor, runner_actor=runner_actor, admin_fencing_token=admin_fencing_token, lease_ttl=lease_ttl or self.lease_ttl)

    def run_next(self, *, run_id: str, profile: RunnerProfile | Mapping[str, Any] | None = None, runner_actor: Actor | None = None, lease_ttl: int | None = None) -> dict[str, Any]:
        selected_profile = profile or self.profile
        if selected_profile is None:
            raise MaxControlError("run-next requires a registered runner profile")
        if self.adapter is None:
            raise MaxControlError("ADAPTER_NOT_CONFIGURED")
        if self.gateway is None:
            raise MaxControlError("GATEWAY_NOT_CONFIGURED")
        if self.usage_authority is None and self.repository.usage_authority is None:
            raise MaxControlError("USAGE_AUTHORITY_NOT_CONFIGURED")
        selected_actor = runner_actor or self.actor
        runner = BoundedRunner(self.repository, selected_actor, selected_profile, self.adapter, gateway=self.gateway, usage_authority=self.usage_authority, fixture=False, lease_ttl=lease_ttl or self.lease_ttl)
        return runner.run_next(run_id=run_id)

    def live_confirmation_hash(self, *, run_id: str, grant_id: str, bundle_id: str, provider_profile_hash: str, runner_profile: RunnerProfile | Mapping[str, Any] | None = None) -> dict[str, Any]:
        selected = runner_profile or self.profile
        if selected is None:
            raise MaxControlError("live confirmation requires a runner profile")
        runner = selected if isinstance(selected, RunnerProfile) else RunnerProfile.from_mapping(selected)
        return {
            "run_id": run_id,
            "grant_id": grant_id,
            "bundle_id": bundle_id,
            "profile_hash": provider_profile_hash,
            "runner_profile_hash": runner.profile_hash,
            "confirmation_hash": live_execution_confirmation_hash(run_id=run_id, grant_id=grant_id, bundle_id=bundle_id, profile_hash=provider_profile_hash, runner_profile_hash=runner.profile_hash),
        }

    def run_next_live(self, *, run_id: str, grant_id: str, bundle_id: str, live_iteration_approval_id: str, provider_profile: ProviderProfile | Mapping[str, Any], runner_profile: RunnerProfile | Mapping[str, Any] | None = None, gateway: Any | None = None, execute_live: bool = False, confirmation_hash: str = "", lease_ttl: int | None = None, transport_factory=None) -> dict[str, Any]:
        selected = runner_profile or self.profile
        if selected is None:
            raise MaxControlError("live run-next requires a registered runner profile")
        if gateway is None:
            raise MaxControlError("GATEWAY_NOT_CONFIGURED")
        executor = LiveRunnerExecutor(self.repository, self.actor, transport_factory=transport_factory)
        return executor.run_next(run_id=run_id, grant_id=grant_id, bundle_id=bundle_id, live_iteration_approval_id=live_iteration_approval_id, provider_profile=provider_profile, runner_profile=selected, gateway=gateway, execute_live=execute_live, confirmation_hash=confirmation_hash, lease_ttl=lease_ttl or self.lease_ttl)

    def simulate_next(self, *, run_id: str, profile: RunnerProfile | Mapping[str, Any] | None = None, runner_actor: Actor | None = None, lease_ttl: int | None = None, fixture: bool = False) -> dict[str, Any]:
        if not fixture:
            raise MaxControlError("FIXTURE_FLAG_REQUIRED")
        selected_profile = profile or self.profile
        if selected_profile is None:
            raise MaxControlError("simulate-next requires a registered runner profile")
        if self.adapter is None:
            raise MaxControlError("ADAPTER_NOT_CONFIGURED")
        if self.gateway is None:
            raise MaxControlError("GATEWAY_NOT_CONFIGURED")
        authority = self.usage_authority or self.repository.usage_authority
        if authority is None:
            raise MaxControlError("USAGE_AUTHORITY_NOT_CONFIGURED")
        selected_actor = runner_actor or self.actor
        runner = BoundedRunner(self.repository, selected_actor, selected_profile, self.adapter, gateway=self.gateway, usage_authority=authority, fixture=True, lease_ttl=lease_ttl or self.lease_ttl)
        return runner.run_next(run_id=run_id)

    def runner_status(self, *, run_id: str) -> dict[str, Any]:
        return {"run": self.repository.get_run(run_id), "runner": self.persistence.status(run_id=run_id), "history": self.persistence.list_history(run_id=run_id)}

    def ambiguous_decision(self, *, run_id: str, logical_call_id: str, decision: str) -> dict[str, Any]:
        if not self.actor.is_admin:
            raise PolicyError("ambiguous recovery decisions require human admin authority")
        return self.persistence.consume_admin_decision(run_id=run_id, logical_call_id=logical_call_id, decision=decision, admin_actor=self.actor)


class MaxProviderService:
    """Admin/service API for the provider boundary; never an MCP surface."""

    def __init__(self, database: str | Path, actor: Actor, *, clock=None) -> None:
        self.actor = actor
        self.repository = MaxControlRepository(database, clock=clock)
        self.store = ProviderStore(self.repository)
        self.bundles = LiveAuthorizationBundleStore(self.store)
        self.live_iterations = LiveIterationApprovalStore(self.repository)

    def register(self, *, profile: ProviderProfile | Mapping[str, Any]) -> dict[str, Any]:
        return self.store.register_profile(profile=profile, actor=self.actor)

    def register_network_policy(self, *, policy: Mapping[str, Any]) -> dict[str, Any]:
        """Materialize one reviewed policy in the server-owned registry.

        This is an administrative provisioning operation.  Later Preview and
        execution phases accept only the persisted hash; they cannot supply
        policy content to this method or to the transport.
        """

        if not self.actor.is_admin:
            raise MaxControlError("network policy registration requires human admin authority")
        return self.store.register_network_policy(policy=policy, actor=self.actor)

    def profiles(self) -> dict[str, Any]:
        return self.store.list_profiles()

    def show(self, *, profile_hash: str | None = None, profile_id: str | None = None, profile_version: str | None = None) -> dict[str, Any]:
        profile = self.store.get_profile(profile_hash=profile_hash, profile_id=profile_id, profile_version=profile_version)
        value = profile.to_mapping()
        value["endpoint_origin"] = "[redacted]"
        value["credential_ref"] = {"kind": profile.credential_ref.kind, "name": "[redacted]"}
        return {"profile": value, "profile_hash": profile.profile_hash}

    def bind(self, *, run_id: str, profile_hash: str) -> dict[str, Any]:
        if not self.actor.is_admin:
            raise MaxControlError("provider binding requires human admin authority")
        return self.store.bind_run_profile(run_id=run_id, profile_hash=profile_hash, actor=self.actor)

    def grant_live(self, *, run_id: str, profile_hash: str, caps: Mapping[str, Any], reason: str, ttl_seconds: int = 3600) -> dict[str, Any]:
        if not self.actor.is_admin:
            raise MaxControlError("execution grants require human admin authority")
        return self.store.issue_live_execution_grant(run_id=run_id, profile_hash=profile_hash, caps=caps, reason=reason, ttl_seconds=ttl_seconds, actor=self.actor)

    def grant_status(self, *, run_id: str) -> dict[str, Any]:
        return self.store.grant_status(run_id=run_id)

    def consume_live_grant(self, *, run_id: str, grant_id: str) -> dict[str, Any]:
        if not self.actor.is_admin:
            raise MaxControlError("execution grant consumption requires human admin authority")
        binding = self.store.get_run_binding(run_id=run_id)
        profile = self.store.get_profile(profile_hash=str(binding["profile_hash"]))
        return self.store.consume_execution_grant(
            grant_id=grant_id,
            run_id=run_id,
            project_id=str(binding["project_id"]),
            profile_hash=profile.profile_hash,
            model_identity=profile.model_identity,
            network_policy_hash=profile.network_policy_hash,
            pricing_hash=profile.pricing.pricing_hash,
            budget_hash=str(binding["budget_hash"]),
            consumer=self.actor,
        )

    def live_authorization_status(self, *, run_id: str, authorization_id: str | None = None) -> dict[str, Any]:
        return self.store.live_authorization_status(run_id=run_id, authorization_id=authorization_id)

    def authorize_live(self, *, run_id: str, grant_id: str, caps: Mapping[str, Any], network_policy: Mapping[str, Any], reason: str, ttl_seconds: int = 900, profile_hash: str | None = None) -> dict[str, Any]:
        return self.store.issue_live_network_authorization(run_id=run_id, grant_id=grant_id, caps=caps, network_policy=network_policy, reason=reason, actor=self.actor, ttl_seconds=ttl_seconds, profile_hash=profile_hash)

    def create_live_bundle(self, *, run_id: str, grant_id: str, authorization_ids: list[str] | tuple[str, ...]) -> dict[str, Any]:
        return self.bundles.create(run_id=run_id, grant_id=grant_id, authorization_ids=authorization_ids, actor=self.actor)

    def live_bundle_status(self, *, run_id: str, bundle_id: str | None = None) -> dict[str, Any]:
        return self.bundles.status(run_id=run_id, bundle_id=bundle_id)

    def revoke_live_bundle(self, *, bundle_id: str, reason: str) -> dict[str, Any]:
        return self.bundles.revoke(bundle_id=bundle_id, actor=self.actor, reason=reason)

    def approve_live_iteration(self, *, run_id: str, grant_id: str, bundle_id: str, provider_profile_hash: str, runner_profile_hash: str, reason: str, ttl_seconds: int = 900) -> dict[str, Any]:
        return self.live_iterations.issue(run_id=run_id, grant_id=grant_id, bundle_id=bundle_id, provider_profile_hash=provider_profile_hash, runner_profile_hash=runner_profile_hash, reason=reason, actor=self.actor, ttl_seconds=ttl_seconds)

    def live_iteration_approval_status(self, *, run_id: str) -> dict[str, Any]:
        return self.live_iterations.status(run_id=run_id)

    def live_preflight(self, *, run_id: str, authorization_id: str | None = None, grant_id: str | None = None) -> dict[str, Any]:
        return self.store.provider_live_preflight(run_id=run_id, authorization_id=authorization_id, grant_id=grant_id)

    def network_policy_status(self, *, network_policy_hash_value: str) -> dict[str, Any]:
        return self.store.network_policy_status(network_policy_hash_value=network_policy_hash_value)

    def revoke_live_authorization(self, *, authorization_id: str, reason: str) -> dict[str, Any]:
        return self.store.revoke_live_network_authorization(authorization_id=authorization_id, actor=self.actor, reason=reason)

    def expire_live_authorization(self, *, authorization_id: str, reason: str = "expired by admin") -> dict[str, Any]:
        return self.store.expire_live_network_authorization(authorization_id=authorization_id, actor=self.actor, reason=reason)

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        return self.store.verify(run_id=run_id)


class MaxSchedulerService:
    """Explicit foreground scheduler API; no daemon and no live transport."""

    def __init__(self, database: str | Path, actor: Actor, *, worker_actor: Actor | None = None, clock=None) -> None:
        self.actor = actor
        self.worker_actor = worker_actor or actor
        self.repository = MaxControlRepository(database, clock=clock)
        self.store = ProviderStore(self.repository)

    def _scheduler(self) -> ForegroundScheduler:
        return ForegroundScheduler(self.repository, self.worker_actor, provider_store=self.store, admin_actor=self.actor if self.actor.is_admin else None)

    def _read_scheduler(self) -> ForegroundScheduler:
        worker = self.worker_actor
        if worker.is_admin:
            # Read-only status/verify commands are admin-facing, but the
            # scheduler object itself intentionally accepts only a non-admin
            # worker actor for any possible write path.
            worker = Actor("mr2b0-cli-verifier", "mr2b0-cli-verifier-session", "worker", "verifier", "research-kb-cli")
        return ForegroundScheduler(self.repository, worker, provider_store=self.store)

    def persist_policy(self, *, policy: SchedulerPolicy | Mapping[str, Any]) -> dict[str, Any]:
        """Explicit administrator registration of a scheduler policy."""

        if not self.actor.is_admin:
            raise MaxControlError("scheduler policy registration requires human admin authority")
        return self._scheduler().persist_policy(policy=policy, actor=self.actor)

    def tick(self, *, run_id: str, profile: ProviderProfile | Mapping[str, Any], grant_id: str, transport: HermeticTransport, policy: SchedulerPolicy | Mapping[str, Any] | None = None, runner_profile: RunnerProfile | Mapping[str, Any] | None = None, gateway: Any | None = None, lease_ttl: int = 300) -> dict[str, Any]:
        return self._scheduler().tick(run_id=run_id, profile=profile, grant_id=grant_id, transport=transport, policy=policy, runner_profile=runner_profile, gateway=gateway, lease_ttl=lease_ttl)

    def run_bounded(self, *, run_id: str, profile: ProviderProfile | Mapping[str, Any], grant_id: str, transport: HermeticTransport, max_ticks: int, policy: SchedulerPolicy | Mapping[str, Any] | None = None, runner_profile: RunnerProfile | Mapping[str, Any] | None = None, gateway: Any | None = None, lease_ttl: int = 300) -> dict[str, Any]:
        return self._scheduler().run_bounded(run_id=run_id, profile=profile, grant_id=grant_id, transport=transport, max_ticks=max_ticks, policy=policy, runner_profile=runner_profile, gateway=gateway, lease_ttl=lease_ttl)

    def status(self, *, run_id: str) -> dict[str, Any]:
        return self._read_scheduler().status(run_id=run_id)

    def verify(self, *, run_id: str) -> dict[str, Any]:
        return self._read_scheduler().verify(run_id=run_id)


class MaxWorkerService:
    """Admin control and explicit foreground worker facade for MR-3."""

    def __init__(self, database: str | Path, actor: Actor, *, clock=None) -> None:
        self.actor = actor
        self.repository = MaxControlRepository(database, clock=clock)
        self.control = WorkerControl(self.repository)

    def command(self, *, run_id: str, command: str, reason: str) -> dict[str, Any]:
        return self.control.issue_command(run_id=run_id, command=command, reason=reason, actor=self.actor)

    def status(self, *, run_id: str) -> dict[str, Any]:
        return self.control.status(run_id=run_id)

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        return self.control.verify(run_id=run_id)

    def run_bounded(self, *, run_id: str, worker_actor: Actor, runner_profile: RunnerProfile | Mapping[str, Any], step, max_ticks: int, max_wall_clock_seconds: int, interval_seconds: float = 0.0, lease_ttl: int = 300) -> dict[str, Any]:
        worker = LongRunningWorker(self.repository, worker_actor, step=step, control=self.control)
        return worker.run(run_id=run_id, runner_profile=runner_profile, max_ticks=max_ticks, max_wall_clock_seconds=max_wall_clock_seconds, interval_seconds=interval_seconds, lease_ttl=lease_ttl)


class MaxAcquisitionService:
    """Governed acquisition request/validation facade; never ingests files."""

    def __init__(self, database: str | Path, actor: Actor, *, clock=None) -> None:
        self.actor = actor
        self.repository = MaxControlRepository(database, clock=clock)
        self.control = AcquisitionControl(self.repository)

    def propose(self, *, request: Mapping[str, Any]) -> dict[str, Any]:
        return self.control.propose(request=request, actor=self.actor)

    def decide(self, *, request_id: str, decision: str, reason: str, validation_hash: str | None = None, dry_run_manifest_hash: str | None = None) -> dict[str, Any]:
        return self.control.decide(request_id=request_id, decision=decision, reason=reason, validation_hash=validation_hash, dry_run_manifest_hash=dry_run_manifest_hash, actor=self.actor)

    def authorize_worker(self, *, request_id: str, worker_id: str, worker_session: str, max_candidates: int, max_bytes: int, ttl_seconds: int, reason: str) -> dict[str, Any]:
        return self.control.authorize_worker(request_id=request_id, worker_id=worker_id, worker_session=worker_session, max_candidates=max_candidates, max_bytes=max_bytes, ttl_seconds=ttl_seconds, reason=reason, actor=self.actor)

    def claim(self, *, request_id: str, worker_grant_id: str) -> dict[str, Any]:
        return self.control.claim(request_id=request_id, worker_grant_id=worker_grant_id, actor=self.actor)

    def validate_stage(self, *, request_id: str, claim_id: str, staging_run: str | Path, existing_content_hashes: set[str] | frozenset[str] = frozenset()) -> dict[str, Any]:
        return self.control.validate_and_stage(request_id=request_id, claim_id=claim_id, staging_run=staging_run, existing_content_hashes=existing_content_hashes, actor=self.actor)

    def status(self, *, run_id: str, request_id: str | None = None) -> dict[str, Any]:
        return self.control.status(run_id=run_id, request_id=request_id)

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        return self.control.verify(run_id=run_id)


class MaxCanaryService:
    """Human-admin facade for the offline durable-intent prepare boundary."""

    def __init__(self, database: str | Path, actor: Actor, *, clock=None, worker_actor: Actor | None = None) -> None:
        self.actor = actor
        self.repository = MaxControlRepository(database, clock=clock)
        self.worker_actor = worker_actor or Actor(
            "mr4b1b-v10r2-preparer",
            "mr4b1b-v10r2-preparer-session",
            "worker",
            "runner",
            "research-kb-cli",
        )

    def prepare_intent(self, **kwargs: Any) -> dict[str, Any]:
        if not self.actor.is_admin:
            raise MaxControlError("canary intent preparation requires human admin authority")
        return LiveCanaryIntentPreparer(self.repository, worker_actor=self.worker_actor).prepare(**kwargs)

    def preparation_snapshots(self) -> PreparationSnapshotStore:
        """Return the v11R1 lifetime-separated server-owned boundary."""

        if not self.actor.is_admin:
            raise MaxControlError("preparation snapshot operations require human admin authority")
        return PreparationSnapshotStore(self.repository)

    def native_preparation_bridge(
        self,
        *,
        source_database: str | Path | None = None,
        expected_release_identity: Mapping[str, Any] | None = None,
        transport: HermeticTransport | None = None,
    ) -> "NativePreparationService":
        """Return the schema-21 native Preparation-to-JIT service facade.

        The legacy ``preparation_snapshots`` facade remains available for the
        lifetime-separated preparation lifecycle.  This method is the only
        service entrypoint for the native approval/JIT/provider bridge and
        keeps that lifecycle out of the legacy LiveCanaryAuthorityStore.
        """

        if not self.actor.is_admin:
            raise MaxControlError("native preparation bridge requires human admin authority")
        return NativePreparationService(
            self.repository,
            self.actor,
            worker_actor=self.worker_actor,
            source_database=source_database,
            expected_release_identity=expected_release_identity,
            transport=transport,
        )

    def preparation_handoffs(self, *, source_database: str | Path | None = None) -> PreparationHandoffStore:
        """Return the server-owned v13R1 preparation handoff facade."""

        if not self.actor.is_admin:
            raise MaxControlError("preparation handoff operations require human admin authority")
        return PreparationHandoffStore(self.repository, source_database=source_database)

    def handoff_preparation(self, *, source_database: str | Path | None = None, **kwargs: Any) -> dict[str, Any]:
        """Execute the formal atomic preparation-to-human-wait handoff."""

        return self.preparation_handoffs(source_database=source_database).handoff_preparation(**kwargs)

    def dns_attempts(self) -> DNSAttemptStore:
        """Return the server-owned v14R3 DNS attempt boundary."""

        self._admin()
        return DNSAttemptStore(self.repository)


class NativePreparationService:
    """Formal service facade for the schema-21 native bridge.

    This facade intentionally exposes no legacy Live Preview/Authority
    methods.  Provider execution still requires an explicitly injected,
    package-owned hermetic transport; the default service cannot open a
    socket or resolve a credential.
    """

    def __init__(
        self,
        repository: MaxControlRepository,
        actor: Actor,
        *,
        worker_actor: Actor | None = None,
        source_database: str | Path | None = None,
        expected_release_identity: Mapping[str, Any] | None = None,
        transport: HermeticTransport | None = None,
    ) -> None:
        if not actor.is_admin:
            raise MaxControlError("native preparation bridge requires human admin authority")
        self.actor = actor
        self.repository = repository
        self.worker_actor = worker_actor or Actor(
            "mr4b1b-v12r1-native-worker",
            "mr4b1b-v12r1-native-worker-session",
            "worker",
            "runner",
            "research-kb-native-service",
        )
        self.store = NativePreparationStore(
            repository,
            source_database=source_database,
            expected_release_identity=expected_release_identity,
        )
        self.approval_previews = LiveApprovalPreviewStore(
            repository,
            expected_release_identity=expected_release_identity,
        )
        self.executor = PreparationCanaryExecutor(
            repository,
            store=self.store,
            admin_actor=actor,
            worker_actor=self.worker_actor,
            transport=transport,
            source_database=source_database,
            expected_release_identity=expected_release_identity,
        )

    def record_dns_receipt(self, **kwargs: Any) -> dict[str, Any]:
        return self.store.record_dns_receipt(actor=self.actor, **kwargs)

    def authorize(self, **kwargs: Any) -> dict[str, Any]:
        # The formal production boundary is the server-owned Live Approval
        # Preview.  Passing the old Preparation Preview selector is rejected
        # instead of being silently interpreted as human authorization.
        if "approval_preview_id" not in kwargs or "preview_id" in kwargs or "expires_at" in kwargs:
            raise MaxControlError("native authorize requires approval_preview_id and the exact Live Approval Preview phrase")
        return self.approval_previews.authorize(actor=self.actor, **kwargs)

    def create_approval_preview(self, **kwargs: Any) -> dict[str, Any]:
        return self.approval_previews.create_approval_preview(actor=self.actor, **kwargs)

    def approval_preview_status(self, **kwargs: Any) -> dict[str, Any]:
        return self.approval_previews.status(**kwargs)

    def approval_preview_verify(self, **kwargs: Any) -> dict[str, Any]:
        return self.approval_previews.verify(**kwargs)

    def revoke(self, *, approval_id: str, reason: str) -> dict[str, Any]:
        return self.store.revoke_approval(approval_id=approval_id, actor=self.actor, reason=reason)

    def status(self, **kwargs: Any) -> dict[str, Any]:
        return self.store.status(**kwargs)

    def handoff_preparation(self, **kwargs: Any) -> dict[str, Any]:
        return PreparationHandoffStore(self.repository, source_database=self.store.snapshots.source_database).handoff_preparation(**kwargs)

    def execute_from_preview(self, *, preview_id: str, allow_execute: bool = False) -> dict[str, Any]:
        return self.executor.execute_from_preview(preview_id=preview_id, allow_execute=allow_execute)

    def execute(self, *, authority_id: str, allow_execute: bool = False) -> dict[str, Any]:
        return self.executor.execute(authority_id=authority_id, allow_execute=allow_execute)

    def execute_dns(self, **kwargs: Any) -> dict[str, Any]:
        """Execute one explicitly-authorized DNS attempt through v14R3."""

        return DNSAttemptStore(self.repository).execute(actor=self.actor, **kwargs)

    def recover_dns_unknown(self, **kwargs: Any) -> dict[str, Any]:
        return DNSAttemptStore(self.repository).recover_unknown(actor=self.actor, **kwargs)

    def dns_attempt_status(self, **kwargs: Any) -> dict[str, Any]:
        return DNSAttemptStore(self.repository).status(**kwargs)

    def dns_attempt_verify(self, **kwargs: Any) -> dict[str, Any]:
        return DNSAttemptStore(self.repository).verify(**kwargs)


class NativeLiveCanaryService:
    """Formal service facade for the one-shot Native JIT live bridge.

    The facade accepts only server-owned identifiers and hashes.  It never
    accepts a request body, credential, endpoint override, or client transport
    on the production path.
    """

    def __init__(
        self,
        repository: MaxControlRepository,
        actor: Actor,
        *,
        worker_actor: Actor | None = None,
        source_database: str | Path | None = None,
        expected_release_identity: Mapping[str, Any] | None = None,
        transport_factory: Any | None = None,
        usage_authority: Any | None = None,
        live_network_enabled: bool = True,
    ) -> None:
        if not actor.is_admin:
            raise MaxControlError("native live bridge requires human admin authority")
        self.actor = actor
        self.repository = repository
        self.executor = NativeLiveCanaryExecutor(
            repository,
            admin_actor=actor,
            worker_actor=worker_actor,
            source_database=source_database,
            expected_release_identity=expected_release_identity,
            transport_factory=transport_factory,
            usage_authority=usage_authority,
            live_network_enabled=live_network_enabled,
        )

    def create_execution_preview(self, **kwargs: Any) -> dict[str, Any]:
        return self.executor.create_execution_preview(actor=self.actor, **kwargs)

    def authorize_execution(self, **kwargs: Any) -> dict[str, Any]:
        return self.executor.authorize_execution(actor=self.actor, **kwargs)

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        return self.executor.execute(**kwargs)

    def status(self, **kwargs: Any) -> dict[str, Any]:
        return self.executor.status(**kwargs)

    def verify(self, **kwargs: Any) -> dict[str, Any]:
        return self.executor.verify(**kwargs)


__all__ = ["MaxAcquisitionService", "MaxCanaryService", "MaxControlService", "MaxProviderService", "MaxRunnerService", "MaxSchedulerService", "MaxWorkerService", "NativePreparationService", "NativeLiveCanaryService", "PreparationHandoffStore", "PreparationSnapshotStore", "LiveApprovalPreviewStore", "resolve_control_database"]
