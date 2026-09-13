"""Server-owned prepare-only bootstrap for a production-shaped canary.

MR-4B1B-v10R2 closes the gap between an offline Preview and the production
authority re-builder.  The first model-call intent is persisted through the
normal RunnerPersistence boundary before any authority/Preview projection is
allowed to inspect it.  This module deliberately has no adapter, transport,
credential, DNS, or Provider execution dependency.
"""

from __future__ import annotations

from dataclasses import replace
from contextlib import closing
import json
import re
from typing import Any, Callable, Mapping

from ..policy import Actor
from .contract import RunStatus, canonical_sha256
from .long_run import LocalCoreEvidenceGateway
from .persistence.db import MaxControlError
from .persistence.repository import MaxControlRepository, _parse_timestamp, _utc_now
from .persistence.runner import RunnerPersistence
from .provider.store import ProviderStore
from .request_builder import CORE_DATABASE, ServerOwnedRequestBuilder, ServerRequestBuildError
from .runner.contracts import RunnerPlan, RunnerProfile
from .runner.planner import build_plan


class LiveCanaryIntentPreparationError(MaxControlError):
    """A durable prepare-only invariant failed; no network path is implied."""


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_CAP_KEYS = {
    "max_provider_calls", "max_ticks", "max_iterations", "max_acquisition_requests",
    "max_ocr_requests", "max_ingest_operations", "max_input_tokens", "max_output_tokens",
    "max_cache_read_tokens", "max_reasoning_tokens", "max_cost_units",
    "max_wall_clock_seconds", "max_source_passages", "max_source_characters",
}
_CAP_EXACT = {
    "max_provider_calls": 1,
    "max_ticks": 1,
    "max_iterations": 1,
    "max_acquisition_requests": 0,
    "max_ocr_requests": 0,
    "max_ingest_operations": 0,
    "max_source_passages": 1,
    "max_source_characters": 2000,
}
_FORBIDDEN_INPUT_KEYS = {
    "prompt", "messages", "source_text", "passage_text", "citation", "citation_metadata",
    "logical_call_id", "intent_id", "request_hash", "intent_hash", "wire_request_hash",
    "request_manifest_hash", "manifest", "fencing_token", "claim_id", "approval_id",
    "permit_id", "grant_id", "endpoint", "endpoint_origin", "credential", "credential_ref",
    "api_key", "network_policy", "dispatch", "bypass", "skip_verification",
}


def _hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise LiveCanaryIntentPreparationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _stable_text(value: Any, name: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or "\r" in value or "\n" in value:
        raise LiveCanaryIntentPreparationError(f"{name} is invalid")
    lowered = value.casefold()
    if any(fragment in lowered for fragment in ("api_key", "apikey", "authorization", "password", "secret", "token=")):
        raise LiveCanaryIntentPreparationError(f"{name} contains forbidden secret material")
    return value


def _caps(value: Mapping[str, Any]) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise LiveCanaryIntentPreparationError("bounded caps are required")
    if set(str(key) for key in value) != _CAP_KEYS:
        raise LiveCanaryIntentPreparationError("bounded caps contain unsupported or missing fields")
    result: dict[str, int] = {}
    for key, raw in value.items():
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise LiveCanaryIntentPreparationError("bounded caps must be non-negative integers")
        result[str(key)] = int(raw)
    for key, expected in _CAP_EXACT.items():
        if result[key] != expected:
            raise LiveCanaryIntentPreparationError(f"bounded cap {key} must be exactly {expected}")
    if result["max_input_tokens"] < 1 or result["max_output_tokens"] < 1 or result["max_wall_clock_seconds"] < 1:
        raise LiveCanaryIntentPreparationError("input/output/wall-clock caps must be positive")
    return dict(sorted(result.items()))


def _json_column(row: Mapping[str, Any], key: str) -> Any:
    try:
        return json.loads(str(row[key]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LiveCanaryIntentPreparationError(f"durable {key} is invalid") from exc


class LiveCanaryIntentPreparer:
    """Prepare exactly one unfinished, server-owned model-call intent.

    The caller supplies only stable release/policy identifiers and a bounded
    cap vector.  The service obtains the Run state, provider profile, runner
    handoff, source policy, exact local passage, lease, fence, plan and claim
    from the control plane.  ``worker_actor`` is a service-owned actor, not a
    request field.
    """

    def __init__(
        self,
        repository: MaxControlRepository,
        *,
        worker_actor: Actor,
        gateway: LocalCoreEvidenceGateway | None = None,
        failure_injection: str | Callable[[str], bool] | None = None,
    ) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("LiveCanaryIntentPreparer requires a MaxControlRepository")
        if worker_actor.is_admin or worker_actor.actor_kind not in {"runner", "agent", "worker"}:
            raise LiveCanaryIntentPreparationError("prepare worker must be a non-admin runner actor")
        self.repository = repository
        self.worker_actor = worker_actor
        self.gateway = gateway or LocalCoreEvidenceGateway(CORE_DATABASE)
        self.failure_injection = failure_injection
        self.persistence = RunnerPersistence(repository)
        self.providers = ProviderStore(repository)

    def _fail(self, stage: str) -> None:
        current = self.failure_injection
        if current is None:
            return
        hit = bool(current(stage)) if callable(current) else current == stage
        if hit:
            self.failure_injection = None
            raise LiveCanaryIntentPreparationError(f"injected prepare interruption at {stage}")

    def _read_binding(
        self,
        *,
        run_id: str,
        provider_profile_hash: str,
        source_egress_policy_hash: str,
    ) -> tuple[dict[str, Any], Any, RunnerProfile, dict[str, Any], dict[str, Any]]:
        run = self.repository.get_run(run_id=run_id)
        if run["status"] != RunStatus.RUNNING.value:
            raise LiveCanaryIntentPreparationError("prepare requires a RUNNING Run")
        if run["project_id"] != "pilot":
            raise LiveCanaryIntentPreparationError("prepare project binding is outside the governed Pilot")
        with closing(self.repository._connect(read_only=True)) as connection:
            approval_count = int(connection.execute("SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?", (run_id,)).fetchone()[0])
            if approval_count != 1:
                raise LiveCanaryIntentPreparationError("prepare requires exactly one consumed StartApproval")
            provider_binding = connection.execute("SELECT * FROM max_run_provider_bindings WHERE run_id=?", (run_id,)).fetchone()
            source_row = connection.execute("SELECT * FROM max_source_egress_policies WHERE run_id=? AND policy_hash=?", (run_id, source_egress_policy_hash)).fetchone()
            lease = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
            if provider_binding is None:
                raise LiveCanaryIntentPreparationError("the Run has no durable provider binding")
            if source_row is None:
                raise LiveCanaryIntentPreparationError("the requested source-egress policy is not bound to the Run")
            if lease is None or lease["released_at"] is not None:
                raise LiveCanaryIntentPreparationError("an active runner lease is required")
            if lease["owner_id"] != self.worker_actor.actor_id or lease["session_id"] != self.worker_actor.session_id:
                raise LiveCanaryIntentPreparationError("the prepare worker does not own the active runner lease")
            if lease["runner_profile_hash"] is None:
                raise LiveCanaryIntentPreparationError("the active lease has no runner profile")
            runner_row = connection.execute("SELECT profile_json FROM max_runner_profiles WHERE profile_hash=?", (lease["runner_profile_hash"],)).fetchone()
            if runner_row is None:
                raise LiveCanaryIntentPreparationError("the active runner profile is missing")
            try:
                runner_profile = RunnerProfile.from_mapping(json.loads(str(runner_row["profile_json"])))
            except Exception as exc:
                raise LiveCanaryIntentPreparationError("the active runner profile is invalid") from exc
            if runner_profile.profile_hash != lease["runner_profile_hash"]:
                raise LiveCanaryIntentPreparationError("the active runner profile hash drifted")
            source_policy = _json_column(source_row, "policy_json")
            if canonical_sha256(source_policy) != source_row["policy_hash"]:
                raise LiveCanaryIntentPreparationError("the source-egress policy hash projection is invalid")
            if provider_binding["profile_hash"] != provider_profile_hash:
                raise LiveCanaryIntentPreparationError("the provider profile hash is not the bound Run profile")
            if runner_profile.model_identity != run["model_identity"]:
                raise LiveCanaryIntentPreparationError("the runner profile model identity is not the Run model")
            lease_value = {key: lease[key] for key in ("owner_id", "session_id", "fencing_token", "expires_at", "runner_profile_hash")}
        profile = self.providers.get_profile(profile_hash=provider_profile_hash)
        if profile.model_identity != run["model_identity"]:
            raise LiveCanaryIntentPreparationError("the provider profile model identity is not the Run model")
        if profile.profile_hash != provider_profile_hash:
            raise LiveCanaryIntentPreparationError("the provider profile hash projection is invalid")
        binding = {"provider": dict(provider_binding), "source": dict(source_row), "lease": lease_value}
        return run, profile, runner_profile, source_policy, binding

    def _source_allowlist(self, *, run: Mapping[str, Any], source_row: Mapping[str, Any]) -> list[dict[str, Any]]:
        passage_ids = _json_column(source_row, "allow_passage_ids_json")
        if not isinstance(passage_ids, list) or len(passage_ids) != 1 or not isinstance(passage_ids[0], str) or not passage_ids[0]:
            raise LiveCanaryIntentPreparationError("prepare requires exactly one allowlisted source passage")
        role_policy = _json_column(source_row, "source_role_policy_json")
        roles = role_policy.get("allowed_roles", []) if isinstance(role_policy, Mapping) else []
        functions = role_policy.get("allowed_functions", []) if isinstance(role_policy, Mapping) else []
        if not isinstance(roles, list) or len(roles) != 1 or not isinstance(roles[0], str):
            raise LiveCanaryIntentPreparationError("prepare requires one deterministic source role")
        if not isinstance(functions, list) or len(functions) != 1 or not isinstance(functions[0], str):
            raise LiveCanaryIntentPreparationError("prepare requires one deterministic evidential function")
        source = self.gateway.get_packet_source(project_id=str(run["project_id"]), passage_id=passage_ids[0], context=0)
        if not isinstance(source, Mapping):
            raise LiveCanaryIntentPreparationError("the exact Pilot passage is unavailable")
        if source.get("project_id") != run["project_id"] or source.get("passage_id") != passage_ids[0]:
            raise LiveCanaryIntentPreparationError("the exact Pilot passage crosses the project boundary")
        status_values = {str(source.get("verification_status", "")), str(source.get("reliability_status", ""))}
        if not status_values <= {"unverified", "candidate_only"}:
            raise LiveCanaryIntentPreparationError("the exact passage is not candidate/unverified")
        source_version = str(source.get("source_version", ""))
        allowed_versions = _json_column(source_row, "allowed_source_versions_json")
        if source_version not in allowed_versions:
            raise LiveCanaryIntentPreparationError("the exact passage source version is outside the durable policy")
        return [{
            "project_id": str(run["project_id"]),
            "document_id": str(source["document_id"]),
            "document_version_id": source_version,
            "passage_id": str(source["passage_id"]),
            "source_role": roles[0],
            "evidential_function": functions[0],
            "verification_status": str(source["verification_status"]),
            "reliability_status": str(source["reliability_status"]),
        }]

    @staticmethod
    def _reservation_amount(profile: Any, budget: Mapping[str, Any]) -> dict[str, int | float]:
        available = budget.get("available", {})
        if not isinstance(available, Mapping):
            raise LiveCanaryIntentPreparationError("budget availability is invalid")
        amount: dict[str, int | float] = {}
        for unit, value in profile.call_budget.items():
            if unit not in available:
                continue
            if isinstance(available[unit], bool) or not isinstance(available[unit], (int, float)) or available[unit] < value:
                raise LiveCanaryIntentPreparationError("budget is below the frozen per-call reservation")
            amount[str(unit)] = value
        if not amount:
            raise LiveCanaryIntentPreparationError("Run budget has no declared provider reservation units")
        return dict(sorted(amount.items()))

    def _active_claim(self, *, run_id: str, fencing_token: int) -> dict[str, Any] | None:
        now = _utc_now(self.repository.clock)
        with closing(self.repository._connect(read_only=True)) as connection:
            rows = connection.execute(
                "SELECT * FROM max_runner_invocation_claims WHERE run_id=? AND status='active' ORDER BY rowid DESC",
                (run_id,),
            ).fetchall()
            for row in rows:
                released = connection.execute(
                    "SELECT 1 FROM max_runner_invocation_claims WHERE run_id=? AND claim_id=? AND status='released'",
                    (run_id, str(row["claim_id"]) + ":released"),
                ).fetchone()
                expiry = _parse_timestamp(row["expires_at"])
                if released is not None or expiry is None or expiry <= now:
                    continue
                if row["actor_id"] != self.worker_actor.actor_id or row["actor_session"] != self.worker_actor.session_id or int(row["fencing_token"]) != int(fencing_token):
                    raise LiveCanaryIntentPreparationError("another live invocation claim owns the Run")
                return dict(row)
        return None

    @staticmethod
    def _load_plan(row: Mapping[str, Any], *, binding_hash: str, binding: Mapping[str, Any]) -> RunnerPlan:
        try:
            plan = RunnerPlan.from_mapping(json.loads(str(row["plan_json"])))
        except Exception as exc:
            raise LiveCanaryIntentPreparationError("stored prepare plan is invalid") from exc
        if plan.plan_id != row["plan_id"] or plan.plan_hash != row["plan_hash"]:
            raise LiveCanaryIntentPreparationError("stored prepare plan hash is invalid")
        metadata = dict(plan.metadata)
        if metadata.get("prepare_binding_hash") != binding_hash or canonical_sha256(metadata.get("prepare_binding", {})) != binding_hash:
            raise LiveCanaryIntentPreparationError("stored prepare plan is bound to different inputs")
        if metadata.get("prepare_binding") != dict(binding):
            raise LiveCanaryIntentPreparationError("stored prepare plan binding drifted")
        return plan

    def _authority_inputs(
        self,
        *,
        run: Mapping[str, Any],
        profile: Any,
        source_policy: Mapping[str, Any],
        source_allowlist: list[dict[str, Any]],
        runner_profile: RunnerProfile,
        caps: Mapping[str, int],
    ) -> dict[str, Any]:
        return {
            "project_id": run["project_id"],
            "run_id": run["run_id"],
            "model_identity": profile.model_identity,
            "provider_profile_hash": profile.profile_hash,
            "source_egress_policy_hash": source_policy.get("policy_hash", ""),
            "source_policy": dict(source_policy),
            "source_allowlist": list(source_allowlist),
            "runner_profile_hash": runner_profile.profile_hash,
            "caps": dict(caps),
        }

    def prepare(
        self,
        *,
        run_id: str,
        provider_profile_hash: str,
        source_egress_policy_hash: str,
        candidate_wheel_sha256: str,
        source_manifest_sha256: str,
        source_tree_sha256: str,
        engine_version: str,
        caps: Mapping[str, Any],
        request_fields: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create/replay one durable prepare-only intent."""

        if request_fields:
            forbidden = set(str(key).casefold() for key in request_fields) & _FORBIDDEN_INPUT_KEYS
            if forbidden:
                raise LiveCanaryIntentPreparationError("client request fields are not accepted: " + ", ".join(sorted(forbidden)))
            raise LiveCanaryIntentPreparationError("prepare accepts only stable identifiers and bounded caps")
        run_id = _stable_text(run_id, "run_id")
        provider_profile_hash = _hash(provider_profile_hash, "provider_profile_hash")
        source_egress_policy_hash = _hash(source_egress_policy_hash, "source_egress_policy_hash")
        candidate_wheel_sha256 = _hash(candidate_wheel_sha256, "candidate_wheel_sha256")
        source_manifest_sha256 = _hash(source_manifest_sha256, "source_manifest_sha256")
        source_tree_sha256 = _hash(source_tree_sha256, "source_tree_sha256")
        engine_version = _stable_text(engine_version, "engine_version")
        cap_vector = _caps(caps)
        run, profile, runner_profile, source_policy, durable = self._read_binding(
            run_id=run_id, provider_profile_hash=provider_profile_hash, source_egress_policy_hash=source_egress_policy_hash,
        )
        source_allowlist = self._source_allowlist(run=run, source_row=durable["source"])
        authority = self._authority_inputs(
            run=run, profile=profile, source_policy={**source_policy, "policy_hash": source_egress_policy_hash},
            source_allowlist=source_allowlist, runner_profile=runner_profile, caps=cap_vector,
        )
        binding = {
            "engine_version": engine_version,
            "candidate_wheel_sha256": candidate_wheel_sha256,
            "source_manifest_sha256": source_manifest_sha256,
            "source_tree_sha256": source_tree_sha256,
            "provider_profile_hash": provider_profile_hash,
            "source_egress_policy_hash": source_egress_policy_hash,
            "runner_profile_hash": runner_profile.profile_hash,
            "worker_id": self.worker_actor.actor_id,
            "worker_session": self.worker_actor.session_id,
            "source_allowlist_hash": canonical_sha256(source_allowlist),
            "caps": cap_vector,
        }
        binding_hash = canonical_sha256(binding)

        lease = self.persistence.claim_runner_lease(run_id=run_id, profile=runner_profile, actor=self.worker_actor, lease_ttl=7200)
        fencing_token = int(lease["fencing_token"])
        claim = self._active_claim(run_id=run_id, fencing_token=fencing_token)
        if claim is None:
            self._fail("claim_before")
            claim = self.persistence.claim_invocation(run_id=run_id, actor=self.worker_actor, fencing_token=fencing_token, ttl_seconds=7200)
            self._fail("claim_after")
        claim_id = str(claim["claim_id"])

        budget = self.repository.reconstruct_budget(run_id=run_id)
        if not budget.get("ok", True):
            raise LiveCanaryIntentPreparationError("budget ledger cannot be reconstructed")
        state = self.repository.get_state(run_id=run_id)
        history = self.persistence.list_history(run_id=run_id)
        open_iteration = self.persistence.open_iteration(run_id=run_id)
        current = self.persistence.current_work(run_id=run_id)
        latest = self.persistence.latest_plan(run_id=run_id)
        if current is not None:
            plan = self._load_plan(current, binding_hash=binding_hash, binding=binding)
        elif latest is not None:
            plan = self._load_plan(latest, binding_hash=binding_hash, binding=binding)
            if open_iteration is None or open_iteration["iteration_id"] != plan.iteration_id:
                raise LiveCanaryIntentPreparationError("stored prepare plan has no recoverable open iteration")
        else:
            if open_iteration is not None:
                sequence = int(open_iteration["sequence_no"])
                prior_history = [item for item in history if item.get("iteration_id") != open_iteration["iteration_id"]]
            else:
                sequence = max((int(item.get("sequence_no", 0) or 0) for item in history), default=0) + 1
                prior_history = history
            try:
                plan = build_plan(
                    project_id=str(run["project_id"]), run_id=run_id, sequence=sequence, state=state,
                    history=prior_history, profile=runner_profile,
                    policy_triggers=self.persistence.server_policy_triggers(run_id=run_id, state_hash=str(run["current_state_hash"])),
                    budget_snapshot=budget,
                    forced_round_type="exploration" if sequence == 1 else None,
                )
            except Exception as exc:
                raise LiveCanaryIntentPreparationError("server planner could not build the prepare plan") from exc
            if len(plan.role_packets) != 1 or len(plan.call_specs) != 1:
                raise LiveCanaryIntentPreparationError("one-shot prepare requires exactly one server call")
            plan = replace(plan, metadata={**dict(plan.metadata), "prepare_binding_hash": binding_hash, "prepare_binding": binding}, plan_id="", plan_hash="")
        if len(plan.role_packets) != 1 or len(plan.call_specs) != 1:
            raise LiveCanaryIntentPreparationError("one-shot prepare requires exactly one server call")
        self._fail("plan_before")
        if open_iteration is None:
            begun = self.repository.begin_iteration(
                run_id=run_id, round_type=plan.round_type, actor=self.worker_actor, fencing_token=fencing_token,
                input_state_hash=plan.input_state_hash, iteration_id=plan.iteration_id, requested_sequence=plan.sequence,
            )
            open_iteration = begun
            self._fail("begin_after")
        elif open_iteration["iteration_id"] != plan.iteration_id:
            raise LiveCanaryIntentPreparationError("prepare plan is not bound to the open iteration")
        self.persistence.record_plan(run_id=run_id, plan=plan, profile=runner_profile, actor=self.worker_actor, fencing_token=fencing_token)
        self._fail("plan_after")
        self.persistence.bind_plan(run_id=run_id, plan_id=plan.plan_id, iteration_id=plan.iteration_id, actor=self.worker_actor, fencing_token=fencing_token)
        group = self.persistence.record_call_group(run_id=run_id, plan=plan, actor=self.worker_actor, fencing_token=fencing_token)
        group_id = str(group["group_id"])

        spec = plan.call_specs[0]
        idempotency_key = f"mr2a:call:{run_id}:{plan.iteration_id}:0:{spec.call_id}:{plan.plan_hash[:24]}"
        logical_call_id = canonical_sha256({"run_id": run_id, "iteration_id": plan.iteration_id, "idempotency_key": idempotency_key})[:48]
        reservation_key = f"mr2a:reserve:{logical_call_id}"
        existing_reservation = self.persistence.budget_reservation(run_id=run_id, idempotency_key=reservation_key)
        if existing_reservation is None:
            amount = self._reservation_amount(runner_profile, budget)
            self._fail("reserve_before")
            reservation = self.repository.reserve_budget(
                run_id=run_id, amount=amount, idempotency_key=reservation_key, actor=self.worker_actor,
                fencing_token=fencing_token, iteration_id=plan.iteration_id,
            )
            self._fail("reserve_after")
        else:
            reservation = existing_reservation

        unfinished = self.persistence.latest_unfinished(run_id=run_id)
        intent_was_existing = unfinished is not None
        if unfinished is None:
            self._fail("intent_before")
            try:
                built = ServerOwnedRequestBuilder().build_seed_request(
                    authority=authority, plan=plan, runner_profile=runner_profile, provider_profile=profile,
                    logical_call_id=logical_call_id, idempotency_key=idempotency_key,
                )
            except ServerRequestBuildError as exc:
                raise LiveCanaryIntentPreparationError("server-owned seed request could not be built") from exc
            self.persistence.record_intent(
                run_id=run_id, intent=built.intent, plan_id=plan.plan_id, actor=self.worker_actor,
                fencing_token=fencing_token, group_id=group_id, call_index=0, phase=spec.phase,
            )
            self._fail("intent_after")
            unfinished = self.persistence.latest_unfinished(run_id=run_id)
            if unfinished is None:
                raise LiveCanaryIntentPreparationError("durable ModelCallIntent disappeared after persistence")
        else:
            if unfinished["plan_id"] != plan.plan_id or unfinished["idempotency_key"] != idempotency_key or unfinished["logical_call_id"] != logical_call_id:
                raise LiveCanaryIntentPreparationError("an unfinished intent exists for a different prepare identity")

        try:
            with closing(self.repository._connect(read_only=True)) as connection:
                rebuilt = ServerOwnedRequestBuilder().build_from_row(authority=authority, connection=connection, provider_profile=profile)
        except ServerRequestBuildError as exc:
            raise LiveCanaryIntentPreparationError("server-owned durable request round-trip failed") from exc
        checks = {
            "intent_id": rebuilt.intent.intent_id == unfinished["intent_id"],
            "logical_call_id": rebuilt.intent.logical_call_id == unfinished["logical_call_id"],
            "intent_hash": rebuilt.intent.intent_hash == unfinished["intent_hash"],
            "request_hash": rebuilt.intent.request_hash == unfinished["request_hash"],
            "wire_request_hash": bool(rebuilt.manifest.get("wire_request_hash")),
            "manifest_hash": bool(rebuilt.manifest.get("manifest_hash")),
            "provider_profile_hash": rebuilt.manifest.get("provider_profile_hash") == provider_profile_hash,
            "source_policy_hash": rebuilt.manifest.get("source_policy_hash") == source_egress_policy_hash,
            "input_state_hash": rebuilt.manifest.get("input_state_hash") == plan.input_state_hash,
            "plan_binding": dict(plan.metadata).get("prepare_binding_hash") == binding_hash,
        }
        if not all(checks.values()):
            raise LiveCanaryIntentPreparationError("server-owned durable request round-trip drifted")
        with closing(self.repository._connect(read_only=True)) as connection:
            counts = {
                "active_leases": int(connection.execute("SELECT COUNT(*) FROM max_leases WHERE run_id=? AND released_at IS NULL", (run_id,)).fetchone()[0]),
                "active_invocation_claims": int(connection.execute("SELECT COUNT(*) FROM max_runner_invocation_claims c WHERE c.run_id=? AND c.status='active' AND NOT EXISTS (SELECT 1 FROM max_runner_invocation_claims r WHERE r.run_id=c.run_id AND r.claim_id=c.claim_id || ':released' AND r.status='released')", (run_id,)).fetchone()[0]),
                "open_iterations": int(connection.execute("SELECT COUNT(*) FROM max_iterations WHERE run_id=? AND status='started'", (run_id,)).fetchone()[0]),
                "plans": int(connection.execute("SELECT COUNT(*) FROM max_runner_plans WHERE run_id=?", (run_id,)).fetchone()[0]),
                "call_groups": int(connection.execute("SELECT COUNT(*) FROM max_runner_call_groups WHERE run_id=?", (run_id,)).fetchone()[0]),
                "call_bindings": int(connection.execute("SELECT COUNT(*) FROM max_runner_call_bindings WHERE run_id=?", (run_id,)).fetchone()[0]),
                "intents": int(connection.execute("SELECT COUNT(*) FROM max_model_call_intents WHERE run_id=?", (run_id,)).fetchone()[0]),
                "intent_manifests": int(connection.execute("SELECT COUNT(*) FROM max_runner_intent_manifests WHERE run_id=?", (run_id,)).fetchone()[0]),
                "budget_reservations": int(connection.execute("SELECT COUNT(*) FROM max_budget_ledger WHERE run_id=? AND operation='reserve'", (run_id,)).fetchone()[0]),
                "dispatch_acks": int(connection.execute("SELECT COUNT(*) FROM max_model_dispatch_acks WHERE run_id=?", (run_id,)).fetchone()[0]),
                "attempts": int(connection.execute("SELECT COUNT(*) FROM max_model_call_attempts WHERE run_id=?", (run_id,)).fetchone()[0]),
                "results": int(connection.execute("SELECT COUNT(*) FROM max_model_call_results WHERE run_id=?", (run_id,)).fetchone()[0]),
                "usage_bindings": int(connection.execute("SELECT COUNT(*) FROM max_runner_usage_bindings WHERE run_id=?", (run_id,)).fetchone()[0]),
                "iteration_outcomes": int(connection.execute("SELECT COUNT(*) FROM max_iteration_outcomes WHERE run_id=?", (run_id,)).fetchone()[0]),
                "live_approvals": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_approvals WHERE run_id=?", (run_id,)).fetchone()[0]),
                "provider_calls": int(connection.execute("SELECT COUNT(*) FROM max_provider_call_records WHERE run_id=?", (run_id,)).fetchone()[0]),
            }
        expected = {"active_leases": 1, "active_invocation_claims": 1, "open_iterations": 1, "plans": 1, "call_groups": 1, "call_bindings": 1, "intents": 1, "intent_manifests": 1, "budget_reservations": 1}
        if any(counts[key] != value for key, value in expected.items()) or any(counts[key] != 0 for key in ("dispatch_acks", "attempts", "results", "usage_bindings", "iteration_outcomes", "live_approvals", "provider_calls")):
            raise LiveCanaryIntentPreparationError("prepare-only durable state is not exactly one unfinished intent")
        return {
            "ok": True,
            "idempotent": intent_was_existing,
            "run_id": run_id,
            "project_id": run["project_id"],
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "iteration_id": plan.iteration_id,
            "group_id": group_id,
            "claim_id": claim_id,
            "fencing_token": fencing_token,
            "runner_profile_hash": runner_profile.profile_hash,
            "provider_profile_hash": provider_profile_hash,
            "source_egress_policy_hash": source_egress_policy_hash,
            "logical_call_id": rebuilt.intent.logical_call_id,
            "intent_id": rebuilt.intent.intent_id,
            "intent_hash": rebuilt.intent.intent_hash,
            "request_hash": rebuilt.intent.request_hash,
            "wire_request_hash": rebuilt.manifest["wire_request_hash"],
            "request_manifest_hash": rebuilt.manifest["manifest_hash"],
            "request_bytes": int(rebuilt.manifest["request_bytes"]),
            "request_prompt_chars": int(rebuilt.manifest["prompt_chars"]),
            "reservation_id": reservation.get("reservation_id") or reservation.get("entry_id"),
            "reservation_amount": reservation.get("amount", {}),
            "checks": checks,
            "counts": counts,
            "execution": {"provider": 0, "dispatch": 0, "attempt": 0, "usage": 0, "credential": 0, "dns": 0, "tcp": 0, "tls": 0, "https": 0, "cost": 0},
        }


__all__ = ["LiveCanaryIntentPreparationError", "LiveCanaryIntentPreparer"]
