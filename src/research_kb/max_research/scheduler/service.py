"""Foreground, bounded MR-2B0 scheduler.

The scheduler is an explicit service call, not a daemon.  Each tick owns at
most one existing ``BoundedRunner.run_next`` invocation.  The scheduler
tables contain only redacted state pointers and hashes; provider wire bodies,
source text, credentials, and model output are never copied into them.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Any, Mapping

from ...policy import Actor
from ..contract import canonical_json, canonical_sha256, make_stable_id
from ..persistence.db import MaxControlError, control_transaction
from ..persistence.repository import MaxControlRepository, _actor_fields, _parse_timestamp, _timestamp, _utc_now
from ..persistence.runner import RunnerPersistence
from ..runner import BoundedRunner, FixtureResearchGateway, RunnerProfile
from ..runner.contracts import InferenceProfile
from ..provider.adapter import OpenAICompatibleAdapter
from ..provider.contract import ProviderProfile
from ..provider.store import ProviderStore
from ..provider.transport import HermeticTransport, is_injected_hermetic_transport
from ..provider.usage import ProviderUsageAuthority


class SchedulerContractError(MaxControlError):
    """The persisted foreground scheduler policy or pointer is invalid."""


class SchedulerStopReason(str, Enum):
    MAX_TICKS = "max_ticks"
    MAX_ITERATIONS = "max_iterations"
    WALL_CLOCK_LIMIT = "wall_clock_limit"
    RUN_PAUSED = "run_paused"
    RUN_CANCELLED = "run_cancelled"
    GRANT_EXPIRED = "grant_expired"
    BUDGET_EXHAUSTED = "budget_exhausted"
    AMBIGUOUS_RECOVERY = "ambiguous_recovery"
    USAGE_DISPUTE = "usage_dispute"
    REHYDRATION_DRIFT = "rehydration_drift"
    ACQUISITION_REVIEW = "acquisition_review"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    CONFLICT = "conflict"
    COMPLETION_CANDIDATE = "completion_candidate"
    CONTINUOUS_FAILURE = "continuous_failure"
    NO_PROGRESS = "no_progress"
    SCHEDULER_BUSY = "scheduler_busy"
    PROVIDER_DISABLED = "provider_disabled"


@dataclass(frozen=True)
class SchedulerPolicy:
    """Immutable upper bounds for one foreground scheduler session."""

    max_ticks: int = 1
    max_iterations: int = 1
    max_wall_clock_seconds: int = 300
    max_consecutive_failures: int = 3
    max_no_progress: int = 3
    stop_on_completion_candidate: bool = True
    policy_id: str = "mr2b0-default"
    policy_version: str = "1"
    policy_hash: str = ""

    def __post_init__(self) -> None:
        for name in ("max_ticks", "max_iterations", "max_wall_clock_seconds", "max_consecutive_failures", "max_no_progress"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 10_000_000:
                raise SchedulerContractError(f"scheduler policy {name} is outside its bound")
        if not isinstance(self.stop_on_completion_candidate, bool):
            raise SchedulerContractError("scheduler stop_on_completion_candidate must be boolean")
        if not isinstance(self.policy_id, str) or not self.policy_id or len(self.policy_id) > 128:
            raise SchedulerContractError("scheduler policy_id is invalid")
        if not isinstance(self.policy_version, str) or not self.policy_version or len(self.policy_version) > 32:
            raise SchedulerContractError("scheduler policy_version is invalid")
        value = self.to_mapping(include_hash=False)
        expected = canonical_sha256(value)
        if self.policy_hash and self.policy_hash != expected:
            raise SchedulerContractError("scheduler policy hash is not canonical")
        object.__setattr__(self, "policy_hash", expected)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SchedulerPolicy":
        if not isinstance(value, Mapping):
            raise SchedulerContractError("scheduler policy must be an object")
        allowed = {"max_ticks", "max_iterations", "max_wall_clock_seconds", "max_consecutive_failures", "max_no_progress", "stop_on_completion_candidate", "policy_id", "policy_version", "policy_hash"}
        if set(value) - allowed:
            raise SchedulerContractError("scheduler policy contains unsupported fields")
        return cls(**{key: value[key] for key in value if key in allowed})

    def to_mapping(self, *, include_hash: bool = True) -> dict[str, Any]:
        value = {"max_ticks": self.max_ticks, "max_iterations": self.max_iterations, "max_wall_clock_seconds": self.max_wall_clock_seconds, "max_consecutive_failures": self.max_consecutive_failures, "max_no_progress": self.max_no_progress, "stop_on_completion_candidate": self.stop_on_completion_candidate, "policy_id": self.policy_id, "policy_version": self.policy_version}
        if include_hash:
            value["policy_hash"] = self.policy_hash
        return value


def provider_runner_profile(profile: ProviderProfile) -> RunnerProfile:
    """Create the existing runner profile bound to one provider profile."""

    defaults = dict(profile.inference_defaults)
    inference = InferenceProfile(
        temperature=defaults.get("temperature", 0.0),
        top_p=defaults.get("top_p", 1.0),
        max_output_tokens=defaults.get("max_output_tokens", 1024),
        seed=defaults.get("seed", 0),
        response_format="bounded-json",
        timeout_seconds=max(1, int(profile.timeout_policy.get("total_ms", 120_000) // 1000)),
        extra={"provider_profile_hash": profile.profile_hash, "protocol": profile.protocol},
    )
    # This constructor is also used to materialize a legacy fixture profile
    # for migration diagnostics.  It intentionally consumes only explicit
    # fields; the authoritative scheduler preflight below rejects an
    # incomplete profile before any provider dispatch.
    maximum_usage = profile.maximum_usage()
    maximum_cost = profile.pricing.cost_units_for_usage(maximum_usage)
    if not maximum_usage:
        # Legacy registration/handoff diagnostics must remain inspectable so
        # an administrator can see the migration-sized reservation that the
        # old profile would have requested.  ForegroundScheduler.tick and the
        # provider claim path reject this profile before any reservation or
        # send, so this estimate is never execution authority.
        diagnostic_usage = {
            "input_tokens": max(1, int(profile.request_limits.get("max_prompt_chars", 200_000)) // 4),
            "output_tokens": max(1, int(profile.inference_defaults.get("max_output_tokens", 1024))),
        }
        maximum_cost = profile.pricing.cost_units_for_usage(diagnostic_usage)
        maximum_usage = diagnostic_usage
    call_budget = {key: value for key, value in maximum_usage.items() if int(value) > 0}
    input_total = int(maximum_usage.get("input_tokens", 0)) + int(maximum_usage.get("cache_read_tokens", 0))
    output_total = int(maximum_usage.get("output_tokens", 0)) + int(maximum_usage.get("reasoning_tokens", 0))
    if input_total > 0:
        call_budget["input_total_tokens"] = input_total
    if output_total > 0:
        call_budget["output_total_tokens"] = output_total
    # RunnerProfile requires positive declared units.  A zero-priced profile
    # still reserves one explicit control-plane unit so a reservation cannot
    # be mistaken for an unbounded/no-budget call.
    call_budget["cost_units"] = max(1, maximum_cost)
    return RunnerProfile(
        profile_id=f"provider:{profile.profile_id}:{profile.profile_version}",
        model_identity=profile.model_identity,
        inference_profile=inference,
        role_names=("socratic", "attack", "adjudicator", "rehydrator"),
        gateway_name=f"provider:{profile.profile_id}",
        call_budget=call_budget,
    )


class HermeticResearchGateway:
    """Default bounded gateway for MR-2B0; it never reads the corpus."""

    fixture_only = False
    gateway_name = "mr2b0-hermetic-gateway"
    gateway_identity = "mr2b0-hermetic-gateway/v1"
    config_hash = canonical_sha256({"gateway_identity": gateway_identity})

    def context(self, *, project_id: str, run_id: str, state_hash: str, allowed_ids, cold: bool = False) -> Mapping[str, Any]:
        value: dict[str, Any] = {"project_id": project_id, "run_id": run_id, "state_hash": state_hash, "canonical_ids": sorted(set(str(item) for item in allowed_ids)), "source_references": []}
        if cold:
            value["cold"] = True
            value["excluded_sections"] = ["working_summary", "recent_summaries", "working_interpretation", "search_history", "search_history_narrative", "role_discussion_history"]
        return value
def _safe_runner_result(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {"run_id", "project_id", "status", "iteration_id", "iteration_number", "round_type", "cognitive_kind", "plan_hash", "intent_hash", "logical_call_id", "result_hash", "change_set_id", "output_state_hash", "iteration_outcome_id", "usage_entry_id", "recovery_disposition", "reason", "idempotent", "model_call_status", "profile_hash"}
    return {str(key): value[key] for key in value if str(key) in allowed}


def _grant_caps_cover_policy(grant: Mapping[str, Any], policy: SchedulerPolicy) -> None:
    caps = grant.get("caps")
    if not isinstance(caps, Mapping):
        raise MaxControlError("execution grant caps are missing")
    requested = {
        "max_ticks": policy.max_ticks,
        "max_iterations": policy.max_iterations,
        "max_wall_clock_seconds": policy.max_wall_clock_seconds,
        "max_consecutive_failures": policy.max_consecutive_failures,
        "max_no_progress": policy.max_no_progress,
    }
    for name, value in requested.items():
        cap = caps.get(name)
        if isinstance(cap, bool) or not isinstance(cap, int) or value > cap:
            raise MaxControlError("scheduler policy exceeds the execution grant cap")


class ForegroundScheduler:
    """One explicit owner, one grant, and one bounded runner call per tick."""

    def __init__(self, repository: MaxControlRepository, actor: Actor, *, provider_store: ProviderStore | None = None, admin_actor: Actor | None = None) -> None:
        if actor.is_admin or actor.actor_kind not in {"runner", "agent", "worker"}:
            raise MaxControlError("foreground scheduler requires a non-admin worker actor")
        self.repository = repository
        self.actor = actor
        self.admin_actor = admin_actor
        self.provider_store = provider_store or ProviderStore(repository)
        self.runner_persistence = RunnerPersistence(repository)

    def persist_policy(self, *, policy: SchedulerPolicy | Mapping[str, Any], actor: Actor | None = None) -> dict[str, Any]:
        value = policy if isinstance(policy, SchedulerPolicy) else SchedulerPolicy.from_mapping(policy)
        owner = actor or self.admin_actor or self.actor
        if not owner.is_admin:
            raise MaxControlError("scheduler policy registration requires human admin authority")
        now = _timestamp(self.repository.clock)
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                existing = connection.execute("SELECT policy_json FROM max_scheduler_policies WHERE policy_hash=?", (value.policy_hash,)).fetchone()
                if existing is not None:
                    if existing["policy_json"] != canonical_json(value.to_mapping()):
                        raise SchedulerContractError("scheduler policy hash collision")
                    return {"policy_hash": value.policy_hash, "policy": value.to_mapping(), "idempotent": True}
                actor_id, actor_kind, actor_session, _ = _actor_fields(owner)
                connection.execute("INSERT INTO max_scheduler_policies(policy_hash, policy_json, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?)", (value.policy_hash, canonical_json(value.to_mapping()), now, actor_id, actor_kind, actor_session))
            return {"policy_hash": value.policy_hash, "policy": value.to_mapping(), "idempotent": False}
        finally:
            connection.close()

    def _load_policy(self, connection, policy: SchedulerPolicy | Mapping[str, Any] | None) -> SchedulerPolicy:
        if policy is not None:
            value = policy if isinstance(policy, SchedulerPolicy) else SchedulerPolicy.from_mapping(policy)
            return value
        row = connection.execute("SELECT policy_json FROM max_scheduler_policies ORDER BY created_at DESC LIMIT 1").fetchone()
        if row is None:
            raise SchedulerContractError("scheduler policy has not been explicitly authorized")
        try:
            return SchedulerPolicy.from_mapping(json.loads(row["policy_json"]))
        except Exception as exc:
            raise SchedulerContractError("stored scheduler policy is invalid") from exc

    def _preflight_worker_authority(
        self,
        *,
        run_id: str,
        grant_id: str,
        policy: SchedulerPolicy,
        runner_profile: RunnerProfile,
        actor: Actor,
    ) -> None:
        """Validate all mutable scheduler authority through read-only queries.

        Registration, policy approval, and runner handoff are administrator
        actions.  A tick may only consume authority that is already prepared;
        it must never repair that preparation as a side effect of a failed
        or first worker request.
        """

        connection = self.repository._connect(read_only=True)
        try:
            policy_row = connection.execute("SELECT policy_hash, policy_json FROM max_scheduler_policies WHERE policy_hash=?", (policy.policy_hash,)).fetchone()
            if policy_row is None or policy_row["policy_json"] != canonical_json(policy.to_mapping()):
                raise MaxControlError("scheduler policy is not explicitly authorized")
            self.runner_persistence._profile_row(connection, runner_profile.profile_hash)
            lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at, runner_profile_hash FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
            if lease is None or lease["owner_id"] != actor.actor_id or lease["session_id"] != actor.session_id or lease["runner_profile_hash"] != runner_profile.profile_hash or lease["released_at"] is not None:
                raise MaxControlError("scheduler worker does not own the current fenced runner lease")
            expiry = _parse_timestamp(lease["expires_at"])
            if expiry is None or expiry <= _utc_now(self.repository.clock):
                raise MaxControlError("scheduler worker lease has expired; explicit admin handoff is required")
            current = connection.execute("SELECT session_id FROM max_scheduler_current WHERE run_id=?", (run_id,)).fetchone()
            if current is not None:
                session = connection.execute("SELECT grant_id, run_id, project_id, policy_hash, grant_consumption_id FROM max_scheduler_sessions WHERE session_id=?", (current["session_id"],)).fetchone()
                if session is None or session["run_id"] != run_id or session["grant_id"] != grant_id or session["policy_hash"] != policy.policy_hash:
                    raise MaxControlError("scheduler current pointer is not bound to the authorized policy or grant")
            consumption = connection.execute("SELECT consumer_id, consumer_session FROM max_live_execution_grant_consumptions WHERE grant_id=?", (grant_id,)).fetchone()
            if current is None and consumption is not None and (consumption["consumer_id"] != actor.actor_id or consumption["consumer_session"] != actor.session_id):
                raise MaxControlError("execution grant is consumed by another worker")
        finally:
            connection.close()

    def _lease(self, run_id: str) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            row = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at, runner_profile_hash FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise MaxControlError("run lease row is missing")
            return {key: row[key] for key in row.keys()}
        finally:
            connection.close()

    def _ensure_session(self, *, run_id: str, profile: ProviderProfile, grant: Mapping[str, Any], consumption: Mapping[str, Any], policy: SchedulerPolicy, runner_profile: RunnerProfile) -> dict[str, Any]:
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT project_id, status, model_identity FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None:
                    raise MaxControlError("Max run was not found")
                if run["status"] != "RUNNING":
                    raise MaxControlError("scheduler requires a RUNNING Max Run")
                lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at, runner_profile_hash FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if lease is None or lease["owner_id"] != self.actor.actor_id or lease["session_id"] != self.actor.session_id or lease["runner_profile_hash"] != runner_profile.profile_hash:
                    raise MaxControlError("scheduler worker does not own the current fenced runner lease")
                current = connection.execute("SELECT * FROM max_scheduler_current WHERE run_id=?", (run_id,)).fetchone()
                if current is not None:
                    session = connection.execute("SELECT * FROM max_scheduler_sessions WHERE session_id=?", (current["session_id"],)).fetchone()
                    if session is None or session["run_id"] != run_id or session["grant_id"] != grant["grant_id"] or session["policy_hash"] != policy.policy_hash:
                        raise MaxControlError("SCHEDULER_BUSY")
                    if session["owner_id"] == self.actor.actor_id and session["owner_session"] == self.actor.session_id:
                        if int(lease["fencing_token"]) != int(session["fencing_token"]):
                            raise MaxControlError("SCHEDULER_BUSY")
                        return {"session_id": session["session_id"], "fencing_token": int(session["fencing_token"]), "tick_no": int(current["tick_no"]), "status": current["status"], "started_at": session["started_at"], "pointer": json.loads(current["pointer_json"])}
                    # A new worker may take over only after the existing
                    # runner lease has been replaced by the caller's current
                    # fence.  The grant consumption is deliberately reused;
                    # a scheduler restart must never consume it again.
                    if lease["owner_id"] != self.actor.actor_id or lease["session_id"] != self.actor.session_id or int(lease["fencing_token"]) <= int(session["fencing_token"]):
                        raise MaxControlError("SCHEDULER_BUSY")
                    now = _timestamp(self.repository.clock)
                    session_id = make_stable_id("scheduler_session", canonical_sha256({"run_id": run_id, "grant_id": grant["grant_id"], "owner": self.actor.actor_id, "session": self.actor.session_id, "fencing_token": int(lease["fencing_token"]), "prior_session": session["session_id"]})[:64])
                    session_value = {"session_id": session_id, "run_id": run_id, "project_id": run["project_id"], "profile_hash": profile.profile_hash, "grant_id": grant["grant_id"], "grant_consumption_id": session["grant_consumption_id"], "policy_hash": policy.policy_hash, "owner_id": self.actor.actor_id, "owner_kind": self.actor.actor_kind, "owner_session": self.actor.session_id, "fencing_token": int(lease["fencing_token"]), "status": "active", "tick_count": int(current["tick_no"]), "started_at": session["started_at"]}
                    session_hash = canonical_sha256(session_value)
                    connection.execute("INSERT INTO max_scheduler_sessions(session_id, run_id, project_id, profile_hash, grant_id, grant_consumption_id, policy_hash, owner_id, owner_kind, owner_session, fencing_token, status, tick_count, started_at, stopped_at, stop_reason, session_json, session_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL, NULL, ?, ?)", (session_id, run_id, run["project_id"], profile.profile_hash, grant["grant_id"], session["grant_consumption_id"], policy.policy_hash, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id, int(lease["fencing_token"]), int(current["tick_no"]), session["started_at"], canonical_json(session_value), session_hash))
                    pointer = json.loads(current["pointer_json"])
                    pointer["session_id"] = session_id
                    connection.execute("UPDATE max_scheduler_current SET session_id=?, updated_at=?, pointer_json=?, pointer_hash=? WHERE run_id=?", (session_id, now, canonical_json(pointer), canonical_sha256(pointer), run_id))
                    self.repository._append_event(connection, run_id=run_id, event_type="scheduler_session_handoff", payload={"prior_session_id": session["session_id"], "session_id": session_id, "grant_id": grant["grant_id"], "fencing_token": int(lease["fencing_token"])}, actor=self.actor, now=now)
                    return {"session_id": session_id, "fencing_token": int(lease["fencing_token"]), "tick_no": int(current["tick_no"]), "status": current["status"], "started_at": session["started_at"], "pointer": pointer}
                now = _timestamp(self.repository.clock)
                session_id = make_stable_id("scheduler_session", canonical_sha256({"run_id": run_id, "grant_id": grant["grant_id"], "owner": self.actor.actor_id, "session": self.actor.session_id})[:64])
                session_value = {"session_id": session_id, "run_id": run_id, "project_id": run["project_id"], "profile_hash": profile.profile_hash, "grant_id": grant["grant_id"], "grant_consumption_id": consumption["consumption_id"], "policy_hash": policy.policy_hash, "owner_id": self.actor.actor_id, "owner_kind": self.actor.actor_kind, "owner_session": self.actor.session_id, "fencing_token": int(lease["fencing_token"]), "status": "active", "tick_count": 0, "started_at": now}
                session_hash = canonical_sha256(session_value)
                connection.execute("INSERT INTO max_scheduler_sessions(session_id, run_id, project_id, profile_hash, grant_id, grant_consumption_id, policy_hash, owner_id, owner_kind, owner_session, fencing_token, status, tick_count, started_at, stopped_at, stop_reason, session_json, session_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, ?, NULL, NULL, ?, ?)", (session_id, run_id, run["project_id"], profile.profile_hash, grant["grant_id"], consumption["consumption_id"], policy.policy_hash, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id, int(lease["fencing_token"]), now, canonical_json(session_value), session_hash))
                pointer = {"run_id": run_id, "session_id": session_id, "tick_no": 0, "status": "active", "state_hash": "", "consecutive_failures": 0, "no_progress": 0, "next_action": "tick"}
                pointer_hash = canonical_sha256(pointer)
                connection.execute("INSERT INTO max_scheduler_current(run_id, session_id, tick_no, status, updated_at, pointer_json, pointer_hash) VALUES (?, ?, 0, 'active', ?, ?, ?)", (run_id, session_id, now, canonical_json(pointer), pointer_hash))
                self.repository._append_event(connection, run_id=run_id, event_type="scheduler_session_started", payload={"session_id": session_id, "profile_hash": profile.profile_hash, "grant_id": grant["grant_id"], "policy_hash": policy.policy_hash, "fencing_token": int(lease["fencing_token"])}, actor=self.actor, now=now)
            return {"session_id": session_id, "fencing_token": int(lease["fencing_token"]), "tick_no": 0, "status": "active", "started_at": now, "pointer": pointer}
        finally:
            connection.close()

    def _update_stop(self, *, run_id: str, session_id: str, reason: str, status: str = "stopped") -> dict[str, Any]:
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_scheduler_current WHERE run_id=? AND session_id=?", (run_id, session_id)).fetchone()
                if row is None:
                    raise MaxControlError("scheduler current pointer is missing")
                pointer = json.loads(row["pointer_json"])
                pointer["status"] = status
                pointer["stop_reason"] = reason
                pointer["next_action"] = "stop"
                now = _timestamp(self.repository.clock)
                connection.execute("UPDATE max_scheduler_current SET status=?, updated_at=?, pointer_json=?, pointer_hash=? WHERE run_id=? AND session_id=?", (status, now, canonical_json(pointer), canonical_sha256(pointer), run_id, session_id))
                self.repository._append_event(connection, run_id=run_id, event_type="scheduler_stopped", payload={"session_id": session_id, "reason": reason, "tick_no": int(row["tick_no"])}, actor=self.actor, now=now)
            return {"session_id": session_id, "status": status, "stop_reason": reason, "tick_no": int(row["tick_no"])}
        finally:
            connection.close()

    def _append_tick(self, *, run_id: str, session: Mapping[str, Any], prior_state_hash: str, result: Mapping[str, Any], duration_ms: int, policy: SchedulerPolicy) -> dict[str, Any]:
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                current = connection.execute("SELECT * FROM max_scheduler_current WHERE run_id=? AND session_id=?", (run_id, session["session_id"])).fetchone()
                if current is None:
                    raise MaxControlError("scheduler current pointer is missing")
                if int(current["tick_no"]) != int(session["tick_no"]):
                    raise MaxControlError("stale scheduler fencing pointer")
                lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if lease is None or lease["owner_id"] != self.actor.actor_id or lease["session_id"] != self.actor.session_id or int(lease["fencing_token"]) != int(session["fencing_token"]):
                    raise MaxControlError("stale scheduler fencing token")
                pointer = json.loads(current["pointer_json"])
                tick_no = int(current["tick_no"]) + 1
                # Read the state pointer on the same write transaction.  A
                # second connection here could contend with BEGIN IMMEDIATE
                # on Windows and would make the durable tick boundary depend
                # on SQLite's reader/writer timing.
                run_row = connection.execute("SELECT current_state_hash FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run_row is None:
                    raise MaxControlError("Max run was not found while recording scheduler tick")
                resulting = run_row["current_state_hash"] or ""
                clean = _safe_runner_result(result)
                clean.setdefault("status", str(result.get("status", "failed")))
                clean["prior_state_hash"] = prior_state_hash
                clean["resulting_state_hash"] = resulting
                result_hash = canonical_sha256(clean)
                failure_status = clean.get("status") in {"failed", "aborted", "recovery_pending"}
                failures = int(pointer.get("consecutive_failures", 0)) if failure_status else 0
                if failure_status:
                    failures += 1
                no_progress = int(pointer.get("no_progress", 0)) + 1 if resulting == prior_state_hash else 0
                stop_reason: str | None = None
                next_action = "tick"
                if clean.get("reason") in {"budget_exhausted", "provider_call_cap_exhausted"}:
                    stop_reason = SchedulerStopReason.BUDGET_EXHAUSTED.value
                elif clean.get("reason") == "usage_dispute":
                    stop_reason = SchedulerStopReason.USAGE_DISPUTE.value
                elif clean.get("recovery_disposition") == "ambiguous_pause":
                    stop_reason = SchedulerStopReason.AMBIGUOUS_RECOVERY.value
                elif failures >= policy.max_consecutive_failures:
                    stop_reason = SchedulerStopReason.CONTINUOUS_FAILURE.value
                elif no_progress >= policy.max_no_progress:
                    stop_reason = SchedulerStopReason.NO_PROGRESS.value
                elif tick_no >= policy.max_iterations:
                    stop_reason = SchedulerStopReason.MAX_ITERATIONS.value
                elif clean.get("reason") in {"usage_dispute", "ambiguous_pause"}:
                    stop_reason = SchedulerStopReason.USAGE_DISPUTE.value if clean.get("reason") == "usage_dispute" else SchedulerStopReason.AMBIGUOUS_RECOVERY.value
                elif clean.get("reason") == "rehydration_drift":
                    stop_reason = SchedulerStopReason.REHYDRATION_DRIFT.value
                elif clean.get("reason") == "epistemic_conflict_paused":
                    stop_reason = SchedulerStopReason.CONFLICT.value
                elif clean.get("status") == "paused":
                    stop_reason = SchedulerStopReason.RUN_PAUSED.value
                elif clean.get("status") == "completion_candidate" or clean.get("reason") == "completion_candidate":
                    stop_reason = SchedulerStopReason.COMPLETION_CANDIDATE.value
                if stop_reason is not None:
                    next_action = "stop"
                pointer.update({"tick_no": tick_no, "state_hash": resulting, "status": "stopped" if stop_reason else "active", "consecutive_failures": failures, "no_progress": no_progress, "next_action": next_action, "stop_reason": stop_reason})
                now = _timestamp(self.repository.clock)
                tick_id = make_stable_id("scheduler_tick", canonical_sha256({"session_id": session["session_id"], "tick_no": tick_no, "result_hash": result_hash})[:64])
                connection.execute("INSERT INTO max_scheduler_ticks(tick_id, session_id, run_id, project_id, tick_no, prior_state_hash, resulting_state_hash, runner_status, result_json, result_hash, duration_ms, budget_delta_json, next_action, stop_reason, fencing_token, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, (SELECT project_id FROM max_runs WHERE run_id=?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (tick_id, session["session_id"], run_id, run_id, tick_no, prior_state_hash, resulting, clean.get("status", "failed"), canonical_json(clean), result_hash, max(0, int(duration_ms)), canonical_json(result.get("budget_delta", {})) if isinstance(result.get("budget_delta", {}), Mapping) else canonical_json({}), next_action, stop_reason, int(session["fencing_token"]), now, self.actor.actor_id, self.actor.actor_kind, self.actor.session_id))
                connection.execute("UPDATE max_scheduler_current SET tick_no=?, status=?, updated_at=?, pointer_json=?, pointer_hash=? WHERE run_id=? AND session_id=?", (tick_no, pointer["status"], now, canonical_json(pointer), canonical_sha256(pointer), run_id, session["session_id"]))
                self.repository._append_event(connection, run_id=run_id, event_type="scheduler_tick_recorded", payload={"session_id": session["session_id"], "tick_id": tick_id, "tick_no": tick_no, "prior_state_hash": prior_state_hash, "resulting_state_hash": resulting, "result_hash": result_hash, "next_action": next_action, "stop_reason": stop_reason}, actor=self.actor, now=now)
            return {"tick_id": tick_id, "tick_no": tick_no, "session_id": session["session_id"], "status": clean.get("status"), "result": clean, "result_hash": result_hash, "prior_state_hash": prior_state_hash, "resulting_state_hash": resulting, "next_action": next_action, "stop_reason": stop_reason}
        finally:
            connection.close()

    def tick(
        self,
        *,
        run_id: str,
        profile: ProviderProfile | Mapping[str, Any],
        grant_id: str,
        transport: HermeticTransport,
        policy: SchedulerPolicy | Mapping[str, Any] | None = None,
        runner_profile: RunnerProfile | Mapping[str, Any] | None = None,
        gateway: Any | None = None,
        lease_ttl: int = 300,
    ) -> dict[str, Any]:
        if not is_injected_hermetic_transport(transport):
            raise MaxControlError("MR-2B0 scheduler accepts only injected hermetic transport")
        provider = profile if isinstance(profile, ProviderProfile) else ProviderProfile.from_mapping(profile)
        try:
            provider.authority_maximum_usage()
        except Exception as exc:
            raise MaxControlError("scheduler provider profile lacks explicit token caps; migration is required before preflight") from exc
        binding = self.provider_store.get_run_binding(run_id=run_id)
        if binding["profile_hash"] != provider.profile_hash:
            raise MaxControlError("scheduler provider profile does not match the run binding")
        grant_status = self.provider_store.grant_status(run_id=run_id)
        grant = next((item for item in grant_status["grants"] if item["grant_id"] == grant_id), None)
        if grant is None:
            raise MaxControlError("scheduler grant was not found for this run")
        if grant["profile_hash"] != provider.profile_hash:
            raise MaxControlError("scheduler grant profile binding is invalid")
        if not grant.get("active", False):
            current = self._current(run_id)
            if current is not None:
                return self._update_stop(run_id=run_id, session_id=current["session_id"], reason=SchedulerStopReason.GRANT_EXPIRED.value)
            raise MaxControlError("scheduler grant has expired")
        run = self.repository.get_run(run_id)
        if run["status"] != "RUNNING":
            reason = SchedulerStopReason.RUN_PAUSED.value if run["status"] == "PAUSED" else SchedulerStopReason.RUN_CANCELLED.value if run["status"] == "CANCELLED" else SchedulerStopReason.HUMAN_APPROVAL_REQUIRED.value
            current = self._current(run_id)
            if current:
                return self._update_stop(run_id=run_id, session_id=current["session_id"], reason=reason, status="paused" if run["status"] == "PAUSED" else "cancelled" if run["status"] == "CANCELLED" else "stopped")
            raise MaxControlError(f"scheduler cannot tick a {run['status']} run")
        selected_runner_profile = runner_profile if isinstance(runner_profile, RunnerProfile) else RunnerProfile.from_mapping(runner_profile) if runner_profile is not None else provider_runner_profile(provider)
        if selected_runner_profile.model_identity != provider.model_identity:
            raise MaxControlError("runner/provider model identity mismatch")
        # Read-only policy resolution and the complete grant-cap check happen
        # before any authority mutation.  Profile registration, policy
        # authorization, and lease handoff are explicit administrator actions;
        # a scheduler tick never performs them implicitly.
        selected_policy = policy if isinstance(policy, SchedulerPolicy) else SchedulerPolicy.from_mapping(policy) if policy is not None else None
        policy_connection = self.repository._connect(read_only=True)
        try:
            loaded_policy = self._load_policy(policy_connection, selected_policy)
        finally:
            policy_connection.close()
        _grant_caps_cover_policy(grant, loaded_policy)
        self._preflight_worker_authority(run_id=run_id, grant_id=grant_id, policy=loaded_policy, runner_profile=selected_runner_profile, actor=self.actor)
        authority = ProviderUsageAuthority()
        self.repository.usage_authority = authority
        selected_gateway = gateway or HermeticResearchGateway()
        if getattr(selected_gateway, "fixture_only", False):
            # Keep compatibility with callers that pass the old fixture
            # gateway while making the scheduler's safety property explicit
            # to BoundedRunner.  Its context remains bounded and read-only.
            original_gateway = selected_gateway

            class _GatewayProxy:
                fixture_only = False
                gateway_name = getattr(original_gateway, "gateway_name", "mr2b0-hermetic-gateway")
                gateway_identity = getattr(original_gateway, "gateway_identity", gateway_name)
                config_hash = getattr(original_gateway, "config_hash", canonical_sha256({"gateway_identity": gateway_identity}))

                def context(self, **kwargs: Any) -> Mapping[str, Any]:
                    return original_gateway.context(**kwargs)

            selected_gateway = _GatewayProxy()
        current = self._current(run_id)
        usage_projection = self.provider_store.grant_usage(grant_id=grant_id)
        usage = usage_projection["usage"]
        caps = usage_projection["caps"]
        exhausted = (
            int(usage["dispatch_count"]) >= int(caps["max_provider_calls"])
            or int(usage["settled_input_tokens"]) + int(usage["settled_cache_read_tokens"]) + int(usage["reserved_input_tokens"]) + int(usage["reserved_cache_read_tokens"]) >= int(caps["max_input_tokens"])
            or int(usage["settled_output_tokens"]) + int(usage["settled_reasoning_tokens"]) + int(usage["reserved_output_tokens"]) + int(usage["reserved_reasoning_tokens"]) >= int(caps["max_output_tokens"])
            or int(usage["settled_cost_units"]) + int(usage["reserved_cost_units"]) >= int(caps["max_cost_units"])
        )
        if exhausted and current is not None:
            return self._update_stop(run_id=run_id, session_id=current["session_id"], reason=SchedulerStopReason.BUDGET_EXHAUSTED.value)
        if current is None:
            consumption = self.provider_store.consume_execution_grant(grant_id=grant_id, run_id=run_id, project_id=binding["project_id"], profile_hash=provider.profile_hash, model_identity=provider.model_identity, network_policy_hash=provider.network_policy_hash, pricing_hash=provider.pricing.pricing_hash, budget_hash=binding["budget_hash"], consumer=self.actor)
        else:
            connection = self.repository._connect(read_only=True)
            try:
                session_row = connection.execute("SELECT grant_consumption_id, grant_id, run_id, project_id FROM max_scheduler_sessions WHERE session_id=?", (current["session_id"],)).fetchone()
            finally:
                connection.close()
            if session_row is None or session_row["grant_id"] != grant_id or session_row["run_id"] != run_id or session_row["project_id"] != binding["project_id"]:
                raise MaxControlError("scheduler current pointer is not bound to the requested grant")
            consumption = {"consumption_id": session_row["grant_consumption_id"], "grant_id": grant_id, "run_id": run_id, "project_id": binding["project_id"], "idempotent": True}
        session = self._ensure_session(run_id=run_id, profile=provider, grant=grant, consumption=consumption, policy=loaded_policy, runner_profile=selected_runner_profile)
        if session["status"] != "active":
            return {"session_id": session["session_id"], "status": session["status"], "stop_reason": session["pointer"].get("stop_reason"), "tick_no": session["tick_no"], "next_action": "stop"}
        if int(session["tick_no"]) >= loaded_policy.max_ticks:
            return self._update_stop(run_id=run_id, session_id=session["session_id"], reason=SchedulerStopReason.MAX_TICKS.value)
        started_at = _parse_timestamp(session.get("started_at", ""))
        if started_at is not None and _utc_now(self.repository.clock) >= started_at + timedelta(seconds=loaded_policy.max_wall_clock_seconds):
            return self._update_stop(run_id=run_id, session_id=session["session_id"], reason=SchedulerStopReason.WALL_CLOCK_LIMIT.value)
        prior = self.repository.get_run(run_id).get("current_state_hash") or ""
        started = time.monotonic()
        adapter = OpenAICompatibleAdapter(provider, transport, usage_authority=authority, provider_store=self.provider_store, actor=self.actor, grant_id=grant_id, fencing_token=int(session["fencing_token"]))
        runner = BoundedRunner(self.repository, self.actor, selected_runner_profile, adapter, gateway=selected_gateway, usage_authority=authority, fixture=False, lease_ttl=lease_ttl)
        try:
            result = runner.run_next(run_id=run_id)
            clean = _safe_runner_result(result)
        except Exception as exc:
            message = str(exc).casefold()
            code = getattr(exc, "code", None) or (
                "provider_disabled" if "live_provider_disabled" in message else
                "usage_dispute" if any(token in message for token in ("usage", "cost", "reservation exceeds")) else
                "budget_exhausted" if any(token in message for token in ("grant cap", "grant-call", "provider call claim", "budget")) else
                "scheduler_tick_failed"
            )
            clean = {"run_id": run_id, "status": "failed", "reason": code}
        duration_ms = int((time.monotonic() - started) * 1000)
        return self._append_tick(run_id=run_id, session=session, prior_state_hash=prior, result=clean, duration_ms=duration_ms, policy=loaded_policy)

    def run_bounded(self, *, run_id: str, profile: ProviderProfile | Mapping[str, Any], grant_id: str, transport: HermeticTransport, max_ticks: int, policy: SchedulerPolicy | Mapping[str, Any] | None = None, runner_profile: RunnerProfile | Mapping[str, Any] | None = None, gateway: Any | None = None, lease_ttl: int = 300) -> dict[str, Any]:
        if isinstance(max_ticks, bool) or not isinstance(max_ticks, int) or not 1 <= max_ticks <= 10_000:
            raise MaxControlError("scheduler run-bounded max_ticks is invalid")
        values: list[dict[str, Any]] = []
        started = time.monotonic()
        selected = policy if isinstance(policy, SchedulerPolicy) else SchedulerPolicy.from_mapping(policy) if policy is not None else SchedulerPolicy(max_ticks=max_ticks, max_iterations=max_ticks)
        if max_ticks > selected.max_ticks:
            raise MaxControlError("run-bounded exceeds the frozen scheduler policy max_ticks")
        for _ in range(max_ticks):
            if time.monotonic() - started > selected.max_wall_clock_seconds:
                break
            item = self.tick(run_id=run_id, profile=profile, grant_id=grant_id, transport=transport, policy=selected, runner_profile=runner_profile, gateway=gateway, lease_ttl=lease_ttl)
            values.append(item)
            if item.get("stop_reason") or item.get("next_action") == "stop":
                break
        if values and not values[-1].get("stop_reason") and len(values) >= max_ticks:
            values[-1] = {**values[-1], "stop_reason": SchedulerStopReason.MAX_TICKS.value, "next_action": "stop"}
            self._update_stop(run_id=run_id, session_id=str(values[-1]["session_id"]), reason=SchedulerStopReason.MAX_TICKS.value)
        reason = values[-1].get("stop_reason") if values else SchedulerStopReason.WALL_CLOCK_LIMIT.value
        return {"run_id": run_id, "session_id": values[-1].get("session_id") if values else None, "ticks_executed": len(values), "stop_reason": reason, "ticks": values}

    def _current(self, run_id: str) -> dict[str, Any] | None:
        connection = self.repository._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_scheduler_current WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                return None
            return {"run_id": run_id, "session_id": row["session_id"], "tick_no": int(row["tick_no"]), "status": row["status"], "updated_at": row["updated_at"], "pointer": json.loads(row["pointer_json"]), "pointer_hash": row["pointer_hash"]}
        finally:
            connection.close()

    def status(self, *, run_id: str) -> dict[str, Any]:
        current = self._current(run_id)
        connection = self.repository._connect(read_only=True)
        try:
            sessions = []
            for row in connection.execute("SELECT session_id, run_id, profile_hash, grant_id, policy_hash, owner_id, owner_kind, owner_session, fencing_token, status, tick_count, started_at, stopped_at, stop_reason, session_hash FROM max_scheduler_sessions WHERE run_id=? ORDER BY started_at", (run_id,)):
                sessions.append({key: row[key] for key in row.keys() if key != "owner_session"})
            ticks = []
            for row in connection.execute("SELECT tick_id, session_id, tick_no, prior_state_hash, resulting_state_hash, runner_status, result_hash, duration_ms, next_action, stop_reason, fencing_token, created_at FROM max_scheduler_ticks WHERE run_id=? ORDER BY tick_no", (run_id,)):
                ticks.append({key: row[key] for key in row.keys()})
            return {"run_id": run_id, "current": current, "sessions": sessions, "ticks": ticks, "tick_count": len(ticks)}
        finally:
            connection.close()

    def verify(self, *, run_id: str) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        issues: list[str] = []
        try:
            policies = 0
            for row in connection.execute("SELECT policy_json, policy_hash FROM max_scheduler_policies"):
                policies += 1
                try:
                    value = SchedulerPolicy.from_mapping(json.loads(row["policy_json"]))
                    if value.policy_hash != row["policy_hash"]:
                        issues.append("scheduler policy hash mismatch")
                except Exception:
                    issues.append("scheduler policy is invalid")
            sessions = list(connection.execute("SELECT * FROM max_scheduler_sessions WHERE run_id=? ORDER BY started_at", (run_id,)))
            session_ids: set[str] = set()
            for row in sessions:
                session_ids.add(str(row["session_id"]))
                try:
                    session_value = json.loads(row["session_json"])
                    if canonical_sha256(session_value) != row["session_hash"]:
                        issues.append("scheduler session hash mismatch")
                    for key, expected in (("session_id", row["session_id"]), ("run_id", row["run_id"]), ("profile_hash", row["profile_hash"]), ("grant_id", row["grant_id"]), ("policy_hash", row["policy_hash"]), ("owner_id", row["owner_id"]), ("owner_session", row["owner_session"]), ("fencing_token", int(row["fencing_token"])), ("status", row["status"]), ("tick_count", int(row["tick_count"])), ("started_at", row["started_at"])):
                        if session_value.get(key) != expected:
                            issues.append("scheduler session binding mismatch")
                            break
                except Exception:
                    issues.append("scheduler session is invalid")
            current = connection.execute("SELECT * FROM max_scheduler_current WHERE run_id=?", (run_id,)).fetchone()
            ticks = list(connection.execute("SELECT * FROM max_scheduler_ticks WHERE run_id=? ORDER BY tick_no", (run_id,)))
            if current is not None:
                pointer = json.loads(current["pointer_json"])
                if canonical_sha256(pointer) != current["pointer_hash"] or int(current["tick_no"]) != len(ticks) or current["session_id"] not in session_ids or pointer.get("session_id") != current["session_id"]:
                    issues.append("scheduler current pointer is inconsistent")
                if current["status"] in {"stopped", "paused", "cancelled", "completed"} and not pointer.get("stop_reason"):
                    issues.append("scheduler stopped pointer lacks a stop reason")
                previous = 0
                for row in ticks:
                    if int(row["tick_no"]) != previous + 1 or int(row["fencing_token"]) < 1 or row["session_id"] not in session_ids or row["run_id"] != run_id:
                        issues.append("scheduler tick sequence is not continuous")
                    previous = int(row["tick_no"])
                    try:
                        result = json.loads(row["result_json"])
                        if canonical_sha256(result) != row["result_hash"]:
                            issues.append("scheduler tick result hash mismatch")
                    except Exception:
                        issues.append("scheduler tick result is invalid")
            return {"ok": not issues, "run_id": run_id, "policy_count": policies, "tick_count": len(ticks), "issues": sorted(set(issues))}
        finally:
            connection.close()


__all__ = ["ForegroundScheduler", "SchedulerContractError", "SchedulerPolicy", "SchedulerStopReason", "provider_runner_profile"]
