"""Persistence boundary for the MR-2A bounded runner.

This module adds no research database tables.  It uses the already-authorized
Max control repository and keeps all model-facing work outside SQLite
transactions.  Historical call records are append-only; current pointers are
small, replaceable indexes used only to find deterministic recovery work.
"""

from __future__ import annotations

from contextlib import nullcontext
from datetime import timedelta
from typing import Any, Mapping, Sequence
import uuid

from ..contract import AttackRecord, DiscussionSession, EpistemicConflictRecord, RehydrationOutput, RunStatus, canonical_sha256, model_to_dict, validate_epistemic_conflict_record
from ...policy import Actor
from ..runner.contracts import (
    DeliberationCallSpec,
    ModelCallIntent,
    ModelCallResult,
    ModelCallStatus,
    ModelResponseEnvelope,
    RecoveryDisposition,
    RunnerPlan,
    RunnerProfile,
)
from .control_models import UsageReceipt
from .schema_manifest import verify_schema_manifest
from .db import MaxControlError, control_transaction
from .repository import (
    MaxControlRepository,
    _ISO,
    _json,
    _loads,
    _parse_timestamp,
    _reject_untrusted_payload,
    _timestamp,
    _utc_now,
    _hash,
    normalize_budget_amount,
)
from ..preparation_handoff import PreparationHandoffStore, PREPARATION_CLAIM_HELD, PREPARED, JIT_EXECUTING, TERMINAL_HANDOFF_STATES


class RunnerPersistence:
    """Small persistence facade used by :class:`BoundedRunner`."""

    def __init__(self, repository: MaxControlRepository) -> None:
        self.repository = repository

    def _connect(self, *, read_only: bool, verify_schema: bool = True):
        return self.repository._connect(read_only=read_only, verify_schema=verify_schema)

    @staticmethod
    def _profile(value: RunnerProfile | Mapping[str, Any]) -> RunnerProfile:
        try:
            return value if isinstance(value, RunnerProfile) else RunnerProfile.from_mapping(value)
        except Exception as exc:
            raise MaxControlError("runner profile is invalid") from exc

    def register_profile(self, *, profile: RunnerProfile | Mapping[str, Any], actor: Actor) -> dict[str, Any]:
        if not actor.is_admin:
            raise MaxControlError("runner profile registration requires human admin authority")
        value = self._profile(profile)
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                existing = connection.execute("SELECT profile_json FROM max_runner_profiles WHERE profile_hash=?", (value.profile_hash,)).fetchone()
                if existing is not None:
                    if existing["profile_json"] != _json(value):
                        raise MaxControlError("runner profile hash collision")
                    return {"profile_id": value.profile_id, "profile_hash": value.profile_hash, "registered": False}
                connection.execute(
                    "INSERT INTO max_runner_profiles(profile_hash, profile_id, profile_json, model_identity, inference_profile_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (value.profile_hash, value.profile_id, _json(value), value.model_identity, value.inference_profile.inference_profile_hash, now, actor.actor_id, actor.actor_kind, actor.session_id),
                )
            return {"profile_id": value.profile_id, "profile_hash": value.profile_hash, "registered": True}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner profile registration failed") from exc
        finally:
            connection.close()

    def _profile_row(self, connection, profile_hash: str):
        row = connection.execute("SELECT * FROM max_runner_profiles WHERE profile_hash=?", (profile_hash,)).fetchone()
        if row is None:
            raise MaxControlError("runner profile is not registered")
        try:
            value = RunnerProfile.from_mapping(_loads(row["profile_json"]))
        except Exception as exc:
            raise MaxControlError("stored runner profile is invalid") from exc
        if value.profile_hash != profile_hash:
            raise MaxControlError("stored runner profile hash mismatch")
        return row, value

    def handoff_runner(
        self,
        *,
        run_id: str,
        profile: RunnerProfile | Mapping[str, Any],
        admin_actor: Actor,
        runner_actor: Actor,
        admin_fencing_token: int | None = None,
        lease_ttl: int = 60,
    ) -> dict[str, Any]:
        if not admin_actor.is_admin:
            raise MaxControlError("runner handoff requires human admin authority")
        if runner_actor.is_admin or runner_actor.actor_kind not in {"runner", "agent", "worker"}:
            raise MaxControlError("runner handoff target must be a non-admin runner actor")
        value = self._profile(profile)
        if lease_ttl < 1 or lease_ttl > 86_400:
            raise MaxControlError("lease TTL is outside the supported range")
        now_dt = _utc_now(self.repository.clock)
        now = _timestamp(self.repository.clock)
        expires = (now_dt + timedelta(seconds=lease_ttl)).strftime(_ISO)[:-3] + "Z"
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                _, stored_profile = self._profile_row(connection, value.profile_hash)
                row = self.repository._run_row(connection, run_id)
                current = self.repository._run_state(row)
                used_profiles = {
                    item[0]
                    for item in connection.execute(
                        "SELECT DISTINCT p.profile_hash FROM max_model_call_intents i JOIN max_runner_plans p ON p.plan_id=i.plan_id WHERE i.run_id=?",
                        (run_id,),
                    )
                }
                if used_profiles and used_profiles != {value.profile_hash}:
                    raise MaxControlError("runner profile is frozen after the first model call")
                if current.model_identity != stored_profile.model_identity:
                    raise MaxControlError("runner profile model identity differs from the approved Charter")
                lease = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if lease is None:
                    raise MaxControlError("run lease row is missing")
                status = current.status
                if status == RunStatus.APPROVED:
                    lease_info = self.repository._acquire_lease_connection(connection, run_id=run_id, actor=runner_actor, ttl_seconds=lease_ttl, now=now, allowed_statuses={RunStatus.APPROVED})
                    transition = __import__("research_kb.max_research.contract", fromlist=["transition_run_state"]).transition_run_state(current, RunStatus.RUNNING)
                    self.repository._update_run(connection, transition.new_state, now=now)
                    transition_record = self.repository._record_transition_result(connection, prior=current, transition=transition, actor=admin_actor, now=now)
                    prior_token = 0
                elif status == RunStatus.RUNNING:
                    expiry = _parse_timestamp(lease["expires_at"])
                    if expiry is None:
                        raise MaxControlError("running-run handoff found an invalid lease expiry")
                    if expiry <= now_dt:
                        # Expired takeover is an explicit admin action.  The
                        # repository increments the fence for the temporary
                        # admin owner; the subsequent runner transfer
                        # increments it once more, fencing the stale worker.
                        recovered = self.repository._acquire_lease_connection(connection, run_id=run_id, actor=admin_actor, ttl_seconds=lease_ttl, now=now, allowed_statuses={RunStatus.RUNNING})
                        self.repository._append_event(connection, run_id=run_id, event_type="lease_acquired", payload={"owner_id": admin_actor.actor_id, "session_id": admin_actor.session_id, "fencing_token": recovered["fencing_token"], "expires_at": recovered["expires_at"], "reason": "expired_admin_takeover"}, actor=admin_actor, now=now)
                        prior_token = int(recovered["fencing_token"])
                    else:
                        if admin_fencing_token is None:
                            raise MaxControlError("running-run handoff requires the current admin fencing token")
                        self.repository._assert_fence(connection, run_id=run_id, actor=admin_actor, fencing_token=admin_fencing_token, now=now)
                        if lease["owner_id"] != admin_actor.actor_id or lease["session_id"] != admin_actor.session_id:
                            raise MaxControlError("only the current admin lease owner may hand off the Run")
                        prior_token = int(lease["fencing_token"])
                    new_token = prior_token + 1
                    connection.execute("UPDATE max_leases SET owner_id=?, session_id=?, fencing_token=?, expires_at=?, renewed_at=?, released_at=NULL, runner_profile_hash=? WHERE run_id=?", (runner_actor.actor_id, runner_actor.session_id, new_token, expires, now, value.profile_hash, run_id))
                    lease_info = {"run_id": run_id, "owner_id": runner_actor.actor_id, "session_id": runner_actor.session_id, "fencing_token": new_token, "expires_at": expires}
                    transition_record = None
                else:
                    raise MaxControlError("runner handoff is not allowed in the current Run state")
                if status == RunStatus.APPROVED:
                    connection.execute("UPDATE max_leases SET runner_profile_hash=? WHERE run_id=?", (value.profile_hash, run_id))
                handoff_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_handoff", current.project_id, {"run_id": run_id, "profile_hash": value.profile_hash, "runner_actor_id": runner_actor.actor_id, "runner_session": runner_actor.session_id, "fencing_token": lease_info["fencing_token"], "nonce": uuid.uuid4().hex})
                handoff_payload = {"handoff_id": handoff_id, "run_id": run_id, "project_id": current.project_id, "profile_hash": value.profile_hash, "runner_actor_id": runner_actor.actor_id, "runner_session": runner_actor.session_id, "prior_fencing_token": prior_token, "fencing_token": lease_info["fencing_token"], "admin_actor_id": admin_actor.actor_id}
                connection.execute("INSERT INTO max_runner_handoffs(handoff_id, run_id, project_id, profile_hash, admin_actor_id, admin_actor_kind, admin_session, runner_actor_id, runner_actor_kind, runner_session, prior_fencing_token, fencing_token, handoff_json, handoff_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (handoff_id, run_id, current.project_id, value.profile_hash, admin_actor.actor_id, admin_actor.actor_kind, admin_actor.session_id, runner_actor.actor_id, runner_actor.actor_kind, runner_actor.session_id, prior_token, lease_info["fencing_token"], _json(handoff_payload), _hash(handoff_payload), now))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_handoff", payload={"handoff_id": handoff_id, "profile_hash": value.profile_hash, "runner_actor_id": runner_actor.actor_id, "runner_session": runner_actor.session_id, "prior_fencing_token": prior_token, "fencing_token": lease_info["fencing_token"]}, actor=admin_actor, now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="lease_acquired", payload={"owner_id": runner_actor.actor_id, "session_id": runner_actor.session_id, "fencing_token": lease_info["fencing_token"], "expires_at": expires, "reason": "admin_runner_handoff"}, actor=admin_actor, now=now)
                if transition_record is not None:
                    self.repository._append_event(connection, run_id=run_id, event_type="run_transition", payload={"from": current.status.value, "to": transition.new_state.status.value, "state_version": transition.new_state.state_version, "reason": "admin_runner_handoff"}, actor=admin_actor, now=now)
            return {"handoff_id": handoff_id, "profile_hash": value.profile_hash, "runner_actor_id": runner_actor.actor_id, "runner_session": runner_actor.session_id, "lease": lease_info, "transition_result": transition_record}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner handoff failed") from exc
        finally:
            connection.close()

    def claim_runner_lease(self, *, run_id: str, profile: RunnerProfile | Mapping[str, Any], actor: Actor, lease_ttl: int = 60) -> dict[str, Any]:
        if actor.is_admin:
            raise MaxControlError("runner lease cannot be claimed by an admin actor")
        value = self._profile(profile)
        if lease_ttl < 1 or lease_ttl > 86_400:
            raise MaxControlError("lease TTL is outside the supported range")
        now_dt = _utc_now(self.repository.clock)
        now = _timestamp(self.repository.clock)
        expires = (now_dt + timedelta(seconds=lease_ttl)).strftime(_ISO)[:-3] + "Z"
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                _, stored = self._profile_row(connection, value.profile_hash)
                row = self.repository._run_row(connection, run_id)
                current = self.repository._run_state(row)
                if current.status != RunStatus.RUNNING or current.model_identity != stored.model_identity:
                    raise MaxControlError("runner lease requires a matching RUNNING Run")
                lease = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if lease is None or lease["runner_profile_hash"] != value.profile_hash:
                    raise MaxControlError("Run has not been handed off to this runner profile")
                expiry = _parse_timestamp(lease["expires_at"])
                if lease["owner_id"] != actor.actor_id or lease["session_id"] != actor.session_id:
                    raise MaxControlError("Run is owned by another runner actor/session")
                if expiry is None or expiry <= now_dt:
                    raise MaxControlError("runner lease expired; a new explicit admin handoff is required")
                token = int(lease["fencing_token"])
                connection.execute("UPDATE max_leases SET expires_at=?, renewed_at=? WHERE run_id=?", (expires, now, run_id))
                self.repository._append_event(connection, run_id=run_id, event_type="lease_renewed", payload={"fencing_token": token, "expires_at": expires, "reason": "runner_claim"}, actor=actor, now=now)
            return {"run_id": run_id, "owner_id": actor.actor_id, "session_id": actor.session_id, "fencing_token": token, "expires_at": expires}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner lease claim failed") from exc
        finally:
            connection.close()

    def claim_invocation(self, *, run_id: str, actor: Actor, fencing_token: int, ttl_seconds: int = 60) -> dict[str, Any]:
        if ttl_seconds < 1 or ttl_seconds > 86_400:
            raise MaxControlError("runner invocation TTL is outside the supported range")
        now_dt = _utc_now(self.repository.clock)
        now = _timestamp(self.repository.clock)
        expires = (now_dt + timedelta(seconds=ttl_seconds)).strftime(_ISO)[:-3] + "Z"
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                latest = connection.execute("SELECT * FROM max_runner_invocation_claims WHERE run_id=? ORDER BY rowid DESC LIMIT 1", (run_id,)).fetchone()
                if latest is not None and latest["status"] == "active":
                    expiry = _parse_timestamp(latest["expires_at"])
                    if expiry is None:
                        raise MaxControlError("runner invocation claim expiry is invalid")
                    if expiry is not None and expiry > now_dt:
                        raise MaxControlError("RUN_NEXT_BUSY")
                attempt_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_invocation", run["project_id"], {"run_id": run_id, "actor_id": actor.actor_id, "session": actor.session_id, "fencing_token": fencing_token, "nonce": uuid.uuid4().hex})
                payload = {"claim_id": attempt_id, "run_id": run_id, "actor_id": actor.actor_id, "actor_session": actor.session_id, "fencing_token": fencing_token, "attempt_id": attempt_id, "expires_at": expires, "status": "active"}
                connection.execute("INSERT INTO max_runner_invocation_claims(claim_id, run_id, actor_id, actor_session, fencing_token, attempt_id, expires_at, status, claim_json, claim_hash, created_at, released_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, NULL)", (attempt_id, run_id, actor.actor_id, actor.session_id, fencing_token, attempt_id, expires, _json(payload), _hash(payload), now))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_invocation_claimed", payload={"claim_id": attempt_id, "attempt_id": attempt_id, "fencing_token": fencing_token, "expires_at": expires}, actor=actor, now=now)
            return {"claim_id": attempt_id, "attempt_id": attempt_id, "expires_at": expires, "fencing_token": fencing_token}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner invocation claim failed") from exc
        finally:
            connection.close()

    def release_invocation(self, *, run_id: str, claim_id: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self.repository._run_row(connection, run_id)
                prior = connection.execute("SELECT * FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=?", (claim_id, run_id)).fetchone()
                if prior is None:
                    raise MaxControlError("runner invocation claim is unknown")
                if prior["actor_id"] != actor.actor_id or prior["actor_session"] != actor.session_id or int(prior["fencing_token"]) != int(fencing_token):
                    raise MaxControlError("runner invocation claim binding is invalid")
                if prior["status"] != "active":
                    if prior["status"] == "released":
                        return {"claim_id": claim_id, "released": True}
                    raise MaxControlError("runner invocation claim is not releasable")
                # pause/cancel deliberately releases the run lease before this
                # finally-block runs.  The invocation must still be releasable
                # by the owner that created it, using the claim's original fence.
                # For a live RUNNING run, retain the stronger current-lease check.
                if run["status"] not in {RunStatus.PAUSED.value, RunStatus.CANCELLED.value}:
                    self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                released_attempt = f"{claim_id}:released"
                already_released = connection.execute("SELECT 1 FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=?", (released_attempt, run_id)).fetchone()
                if already_released is not None:
                    return {"claim_id": claim_id, "released": True}
                payload = {"claim_id": claim_id, "run_id": run_id, "actor_id": actor.actor_id, "actor_session": actor.session_id, "fencing_token": fencing_token, "attempt_id": released_attempt, "expires_at": now, "status": "released", "released_claim_id": claim_id}
                connection.execute("INSERT INTO max_runner_invocation_claims(claim_id, run_id, actor_id, actor_session, fencing_token, attempt_id, expires_at, status, claim_json, claim_hash, created_at, released_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'released', ?, ?, ?, ?)", (released_attempt, run_id, actor.actor_id, actor.session_id, fencing_token, released_attempt, now, _json(payload), _hash(payload), now, now))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_invocation_released", payload={"claim_id": claim_id, "fencing_token": fencing_token}, actor=actor, now=now)
            return {"claim_id": claim_id, "released": True}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner invocation release failed") from exc
        finally:
            connection.close()

    def record_plan(self, *, run_id: str, plan: RunnerPlan | Mapping[str, Any], profile: RunnerProfile | Mapping[str, Any], actor: Actor, fencing_token: int) -> dict[str, Any]:
        value = plan if isinstance(plan, RunnerPlan) else RunnerPlan.from_mapping(plan)
        runner_profile = self._profile(profile)
        if value.run_id != run_id:
            raise MaxControlError("runner plan Run binding is invalid")
        if value.model_identity != runner_profile.model_identity or value.inference_profile_hash != runner_profile.inference_profile.inference_profile_hash:
            raise MaxControlError("runner plan profile binding is invalid")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self.repository._run_row(connection, run_id); current = self.repository._run_state(row)
                if current.status != RunStatus.RUNNING or value.project_id != current.project_id or value.input_state_hash != current.current_state_hash:
                    raise MaxControlError("runner plan is outside the current Run state")
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                _, stored = self._profile_row(connection, runner_profile.profile_hash)
                if stored.model_identity != current.model_identity:
                    raise MaxControlError("runner profile model identity differs from Run")
                lease = connection.execute("SELECT owner_id, session_id, runner_profile_hash FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if lease is None or lease["owner_id"] != actor.actor_id or lease["session_id"] != actor.session_id or lease["runner_profile_hash"] != runner_profile.profile_hash:
                    raise MaxControlError("runner plan is not authorized by the current handoff")
                prior = connection.execute("SELECT MAX(sequence_no) AS sequence_no FROM max_runner_plans WHERE run_id=?", (run_id,)).fetchone()["sequence_no"]
                if value.sequence != int(prior or 0) + 1:
                    existing = connection.execute("SELECT plan_json FROM max_runner_plans WHERE run_id=? AND plan_hash=?", (run_id, value.plan_hash)).fetchone()
                    if existing is None:
                        raise MaxControlError("runner plan sequence is not contiguous")
                existing = connection.execute("SELECT plan_json, plan_id FROM max_runner_plans WHERE run_id=? AND plan_hash=?", (run_id, value.plan_hash)).fetchone()
                if existing is not None:
                    return {"plan_id": existing["plan_id"], "plan_hash": value.plan_hash, "idempotent": True}
                if connection.execute("SELECT 1 FROM max_runner_plan_current WHERE run_id=?", (run_id,)).fetchone() is not None:
                    raise MaxControlError("another runner plan is already current")
                connection.execute("INSERT INTO max_runner_plans(plan_id, run_id, project_id, sequence_no, iteration_id, input_state_hash, round_type, cognitive_kind, profile_hash, plan_json, plan_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (value.plan_id, run_id, value.project_id, value.sequence, value.iteration_id, value.input_state_hash, value.round_type, value.cognitive_kind, runner_profile.profile_hash, _json(value), value.plan_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_plan_created", payload={"plan_id": value.plan_id, "plan_hash": value.plan_hash, "sequence_no": value.sequence, "round_type": value.round_type, "cognitive_kind": value.cognitive_kind, "profile_hash": runner_profile.profile_hash}, actor=actor, now=now)
            return {"plan_id": value.plan_id, "plan_hash": value.plan_hash, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner plan persistence failed") from exc
        finally:
            connection.close()

    def bind_plan(self, *, run_id: str, plan_id: str, iteration_id: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self.repository._run_row(connection, run_id); current = self.repository._run_state(row)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                plan = connection.execute("SELECT * FROM max_runner_plans WHERE plan_id=? AND run_id=?", (plan_id, run_id)).fetchone()
                iteration = connection.execute("SELECT * FROM max_iterations WHERE iteration_id=? AND run_id=?", (iteration_id, run_id)).fetchone()
                if plan is None or iteration is None or plan["iteration_id"] != iteration_id:
                    raise MaxControlError("runner plan and iteration are not bound")
                current_plan = connection.execute("SELECT * FROM max_runner_plan_current WHERE run_id=?", (run_id,)).fetchone()
                if current_plan is not None:
                    if current_plan["plan_id"] == plan_id and current_plan["iteration_id"] == iteration_id:
                        return {"plan_id": plan_id, "iteration_id": iteration_id, "idempotent": True}
                    raise MaxControlError("a different runner plan is already current")
                connection.execute("INSERT INTO max_runner_plan_current(run_id, plan_id, iteration_id, active_logical_call_id, set_at) VALUES (?, ?, ?, NULL, ?)", (run_id, plan_id, iteration_id, now))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_plan_bound", payload={"plan_id": plan_id, "iteration_id": iteration_id, "state_hash": current.current_state_hash}, actor=actor, now=now)
            return {"plan_id": plan_id, "iteration_id": iteration_id, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner plan binding failed") from exc
        finally:
            connection.close()

    def record_call_group(self, *, run_id: str, plan: RunnerPlan | Mapping[str, Any], actor: Actor, fencing_token: int) -> dict[str, Any]:
        value = plan if isinstance(plan, RunnerPlan) else RunnerPlan.from_mapping(plan)
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                iteration = connection.execute("SELECT * FROM max_iterations WHERE iteration_id=? AND run_id=?", (value.iteration_id, run_id)).fetchone()
                if iteration is None or iteration["status"] != "started":
                    raise MaxControlError("runner call group is outside the current iteration")
                group_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_call_group", run["project_id"], {"run_id": run_id, "iteration_id": value.iteration_id, "plan_hash": value.plan_hash})
                group_payload = {"group_id": group_id, "run_id": run_id, "project_id": run["project_id"], "iteration_id": value.iteration_id, "plan_id": value.plan_id, "phase": value.round_type, "roles": [packet.role for packet in value.role_packets], "role_packet_ids": [packet.packet_id for packet in value.role_packets], "call_count": len(value.role_packets), "call_specs": [model_to_dict(spec) for spec in value.call_specs]}
                existing = connection.execute("SELECT group_id, group_hash FROM max_runner_call_groups WHERE group_id=?", (group_id,)).fetchone()
                if existing is not None:
                    if existing["group_hash"] != _hash(group_payload):
                        raise MaxControlError("runner call group hash collision")
                    return {"group_id": group_id, "call_count": len(value.role_packets), "idempotent": True}
                connection.execute("INSERT INTO max_runner_call_groups(group_id, run_id, project_id, iteration_id, plan_id, phase, call_count, group_json, group_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (group_id, run_id, run["project_id"], value.iteration_id, value.plan_id, value.round_type, len(value.role_packets), _json(group_payload), _hash(group_payload), now, actor.actor_id, actor.actor_kind, actor.session_id))
                for call_index, spec in enumerate(value.call_specs):
                    spec_value = model_to_dict(spec)
                    spec_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_call_spec", run["project_id"], {"group_id": group_id, "call_index": call_index, "spec": spec_value})
                    connection.execute("INSERT INTO max_runner_call_specs(spec_id, group_id, run_id, iteration_id, call_index, call_id, phase, role, upstream_call_ids_json, input_mode, artifact_type, spec_json, spec_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (spec_id, group_id, run_id, value.iteration_id, call_index, spec.call_id, spec.phase, spec.role, _json(spec.upstream_call_ids), spec.input_mode, spec.artifact_type, _json(spec_value), _hash(spec_value), now, actor.actor_id, actor.actor_kind, actor.session_id))
                connection.execute("INSERT INTO max_runner_call_group_current(group_id, run_id, current_index, status, current_logical_call_id, updated_at, updated_by) VALUES (?, ?, 0, 'open', NULL, ?, ?)", (group_id, run_id, now, actor.actor_id))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_call_group_created", payload={"group_id": group_id, "iteration_id": value.iteration_id, "plan_id": value.plan_id, "call_count": len(value.role_packets), "phase": value.round_type}, actor=actor, now=now)
            return {"group_id": group_id, "call_count": len(value.role_packets), "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner call group persistence failed") from exc
        finally:
            connection.close()

    def current_group(self, *, run_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT g.*, c.current_index, c.status AS group_status, c.current_logical_call_id FROM max_runner_call_groups g JOIN max_runner_call_group_current c ON c.group_id=g.group_id WHERE g.run_id=? AND c.status='open' ORDER BY g.created_at DESC LIMIT 1", (run_id,)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def group_binding(self, *, run_id: str, group_id: str, call_index: int) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT b.*, i.intent_id, i.intent_hash, i.intent_json, r.result_id, r.result_json FROM max_runner_call_bindings b JOIN max_model_call_intents i ON i.logical_call_id=b.logical_call_id LEFT JOIN max_model_call_results r ON r.logical_call_id=b.logical_call_id WHERE b.run_id=? AND b.group_id=? AND b.call_index=?", (run_id, group_id, call_index)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def finalize_call_group(self, *, run_id: str, group_id: str, status: str, actor: Actor, fencing_token: int, _connection=None) -> dict[str, Any]:
        if status not in {"completed", "aborted", "paused"}:
            raise MaxControlError("runner call group status is invalid")
        now = _timestamp(self.repository.clock)
        connection = _connection or self._connect(read_only=False)
        try:
            with (control_transaction(connection) if _connection is None else nullcontext(connection)):
                self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                row = connection.execute("SELECT * FROM max_runner_call_groups WHERE group_id=? AND run_id=?", (group_id, run_id)).fetchone()
                if row is None:
                    raise MaxControlError("runner call group is unknown")
                current = connection.execute("SELECT status FROM max_runner_call_group_current WHERE group_id=? AND run_id=?", (group_id, run_id)).fetchone()
                if current is None:
                    raise MaxControlError("runner call group current pointer is missing")
                if current["status"] == status:
                    return {"group_id": group_id, "status": status, "idempotent": True}
                if current["status"] != "open":
                    raise MaxControlError("runner call group is already finalized")
                connection.execute("UPDATE max_runner_call_group_current SET status=?, current_index=(SELECT call_count FROM max_runner_call_groups WHERE group_id=?), current_logical_call_id=NULL, updated_at=?, updated_by=? WHERE group_id=?", (status, group_id, now, actor.actor_id, group_id))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_call_group_finished", payload={"group_id": group_id, "status": status, "call_count": row["call_count"]}, actor=actor, now=now)
            return {"group_id": group_id, "status": status}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner call group finalization failed") from exc
        finally:
            if _connection is None:
                connection.close()

    def record_intent(self, *, run_id: str, intent: ModelCallIntent | Mapping[str, Any], plan_id: str, actor: Actor, fencing_token: int, group_id: str | None = None, call_index: int | None = None, phase: str | None = None) -> dict[str, Any]:
        value = intent if isinstance(intent, ModelCallIntent) else ModelCallIntent.from_mapping(intent)
        if value.run_id != run_id:
            raise MaxControlError("model intent Run binding is invalid")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self.repository._run_row(connection, run_id); current = self.repository._run_state(row)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                pointer = connection.execute("SELECT * FROM max_runner_plan_current WHERE run_id=?", (run_id,)).fetchone()
                open_iteration = self.repository._open_iteration(connection, run_id=run_id)
                if pointer is None or pointer["plan_id"] != plan_id or pointer["iteration_id"] != value.iteration_id or open_iteration["iteration_id"] != value.iteration_id:
                    raise MaxControlError("model intent is outside the current runner plan/iteration")
                plan = connection.execute("SELECT * FROM max_runner_plans WHERE plan_id=?", (plan_id,)).fetchone()
                profile_row = connection.execute("SELECT inference_profile_hash FROM max_runner_profiles WHERE profile_hash=?", (plan["profile_hash"],)).fetchone() if plan is not None else None
                if plan is None or profile_row is None or plan["input_state_hash"] != value.input_state_hash or value.model_identity != current.model_identity or value.inference_profile_hash != profile_row["inference_profile_hash"]:
                    raise MaxControlError("model intent binding is invalid")
                existing = connection.execute("SELECT intent_id, intent_hash FROM max_model_call_intents WHERE run_id=? AND idempotency_key=?", (run_id, value.idempotency_key)).fetchone()
                if existing is not None:
                    if existing["intent_hash"] != value.intent_hash:
                        raise MaxControlError("idempotency key is bound to a different model intent")
                    return {"intent_id": existing["intent_id"], "logical_call_id": value.logical_call_id, "intent_hash": value.intent_hash, "idempotent": True}
                if pointer["active_logical_call_id"] is not None and pointer["active_logical_call_id"] != value.logical_call_id:
                    if group_id is None or connection.execute("SELECT 1 FROM max_runner_call_groups WHERE group_id=? AND run_id=? AND iteration_id=?", (group_id, run_id, value.iteration_id)).fetchone() is None:
                        raise MaxControlError("the open iteration already has an active logical model call")
                manifest = dict(value.durable_mapping())
                _reject_untrusted_payload(manifest)
                manifest_json = _json(manifest)
                connection.execute("INSERT INTO max_model_call_intents(intent_id, logical_call_id, run_id, project_id, iteration_id, plan_id, input_state_hash, role_packet_id, round_type, model_identity, inference_profile_hash, request_hash, idempotency_key, intent_json, intent_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (value.intent_id, value.logical_call_id, run_id, current.project_id, value.iteration_id, plan_id, value.input_state_hash, value.role_packet_id, value.round_type, value.model_identity, value.inference_profile_hash, value.request_hash, value.idempotency_key, manifest_json, value.intent_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                connection.execute("INSERT INTO max_runner_intent_manifests(intent_id, logical_call_id, run_id, project_id, iteration_id, plan_id, manifest_json, manifest_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (value.intent_id, value.logical_call_id, run_id, current.project_id, value.iteration_id, plan_id, manifest_json, _hash(manifest), now, actor.actor_id, actor.actor_kind, actor.session_id))
                if group_id is not None:
                    if call_index is None or call_index < 0:
                        raise MaxControlError("runner call index is required for grouped intents")
                    group = connection.execute("SELECT * FROM max_runner_call_groups WHERE group_id=? AND run_id=? AND iteration_id=?", (group_id, run_id, value.iteration_id)).fetchone()
                    if group is None or call_index >= int(group["call_count"]):
                        raise MaxControlError("runner intent is outside its call group")
                    packet_hash = str(manifest.get("packet_hash", ""))
                    binding_payload = {"binding_id": value.logical_call_id, "group_id": group_id, "run_id": run_id, "iteration_id": value.iteration_id, "logical_call_id": value.logical_call_id, "call_index": call_index, "role": manifest.get("role", ""), "phase": phase or value.round_type, "packet_hash": packet_hash, "intent_hash": value.intent_hash, "status": "planned"}
                    connection.execute("INSERT INTO max_runner_call_bindings(binding_id, group_id, run_id, iteration_id, logical_call_id, call_index, role, phase, packet_hash, intent_hash, result_id, status, binding_json, binding_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'planned', ?, ?, ?, ?, ?, ?)", (value.logical_call_id, group_id, run_id, value.iteration_id, value.logical_call_id, call_index, manifest.get("role", ""), phase or value.round_type, packet_hash, value.intent_hash, _json(binding_payload), _hash(binding_payload), now, actor.actor_id, actor.actor_kind, actor.session_id))
                    connection.execute("UPDATE max_runner_call_group_current SET current_index=?, current_logical_call_id=?, updated_at=?, updated_by=? WHERE group_id=?", (call_index, value.logical_call_id, now, actor.actor_id, group_id))
                connection.execute("UPDATE max_runner_plan_current SET active_logical_call_id=?, set_at=? WHERE run_id=?", (value.logical_call_id, now, run_id))
                self.repository._append_event(connection, run_id=run_id, event_type="model_call_intent_persisted", payload={"intent_id": value.intent_id, "logical_call_id": value.logical_call_id, "intent_hash": value.intent_hash, "iteration_id": value.iteration_id, "request_hash": value.request_hash}, actor=actor, now=now)
            return {"intent_id": value.intent_id, "logical_call_id": value.logical_call_id, "intent_hash": value.intent_hash, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("model intent persistence failed") from exc
        finally:
            connection.close()

    def record_dispatch_ack(self, *, run_id: str, logical_call_id: str, status: str, dispatch_known: bool, provider_call_id: str | None, actor: Actor, fencing_token: int, preserve_existing: bool = False) -> dict[str, Any]:
        if status not in {"dispatched", "unknown", "not_dispatched"}:
            raise MaxControlError("dispatch acknowledgement status is invalid")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE logical_call_id=? AND run_id=?", (logical_call_id, run_id)).fetchone()
                if intent is None:
                    raise MaxControlError("dispatch acknowledgement references an unknown model intent")
                existing = connection.execute("SELECT ack_id, ack_hash FROM max_model_dispatch_acks WHERE logical_call_id=?", (logical_call_id,)).fetchone()
                payload = {"logical_call_id": logical_call_id, "run_id": run_id, "dispatch_status": status, "dispatch_known": bool(dispatch_known), "provider_call_id": provider_call_id}
                if existing is not None:
                    if existing["ack_hash"] != _hash(payload):
                        if preserve_existing:
                            # The first acknowledgement is immutable.  A
                            # later provider query/retry may resolve an
                            # earlier ``unknown`` observation, but it must
                            # not rewrite that historical fact.  The
                            # authoritative result and recovery record carry
                            # the later resolution.
                            return {"ack_id": existing["ack_id"], "logical_call_id": logical_call_id, "idempotent": True, "preserved": True}
                        raise MaxControlError("dispatch acknowledgement is not idempotent")
                    return {"ack_id": existing["ack_id"], "logical_call_id": logical_call_id, "idempotent": True}
                ack_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("dispatch_ack", intent["project_id"], {"logical_call_id": logical_call_id, "status": status})
                connection.execute("INSERT INTO max_model_dispatch_acks(ack_id, logical_call_id, run_id, dispatch_status, dispatch_known, provider_call_id, ack_json, ack_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (ack_id, logical_call_id, run_id, status, int(bool(dispatch_known)), provider_call_id, _json(payload), _hash(payload), now, actor.actor_id, actor.actor_kind, actor.session_id))
                self.repository._append_event(connection, run_id=run_id, event_type="model_dispatch_ack", payload={"ack_id": ack_id, "logical_call_id": logical_call_id, "dispatch_status": status, "dispatch_known": bool(dispatch_known)}, actor=actor, now=now)
            return {"ack_id": ack_id, "logical_call_id": logical_call_id, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("dispatch acknowledgement persistence failed") from exc
        finally:
            connection.close()

    def record_attempt(
        self,
        *,
        run_id: str,
        logical_call_id: str,
        stage: str,
        detail: Mapping[str, Any] | None,
        actor: Actor,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Append one server-observed dispatch attempt.

        ``dispatching`` is deliberately written before the adapter call.  If
        the process disappears after that point, recovery can distinguish a
        first call from a call whose external outcome is unknown without
        guessing that a provider response was received.
        """
        if stage not in {"dispatching", "dispatched", "unknown", "failed"}:
            raise MaxControlError("model call attempt stage is invalid")
        normalized_detail = dict(detail or {})
        _reject_untrusted_payload(normalized_detail)
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                intent = connection.execute("SELECT project_id FROM max_model_call_intents WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                if intent is None:
                    raise MaxControlError("model call attempt references an unknown logical call")
                prior = connection.execute("SELECT MAX(attempt_no) AS attempt_no FROM max_model_call_attempts WHERE logical_call_id=?", (logical_call_id,)).fetchone()
                attempt_no = int(prior["attempt_no"] or 0) + 1
                payload = {"run_id": run_id, "logical_call_id": logical_call_id, "attempt_no": attempt_no, "stage": stage, "detail": normalized_detail}
                attempt_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("model_attempt", intent["project_id"], payload)
                connection.execute(
                    "INSERT INTO max_model_call_attempts(attempt_id, logical_call_id, run_id, attempt_no, stage, attempt_json, attempt_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (attempt_id, logical_call_id, run_id, attempt_no, stage, _json(payload), _hash(payload), now, actor.actor_id, actor.actor_kind, actor.session_id),
                )
                self.repository._append_event(connection, run_id=run_id, event_type="model_call_attempt", payload={"attempt_id": attempt_id, "logical_call_id": logical_call_id, "attempt_no": attempt_no, "stage": stage, "detail_hash": _hash(normalized_detail)}, actor=actor, now=now)
            return {"attempt_id": attempt_id, "attempt_no": attempt_no, "stage": stage}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("model call attempt persistence failed") from exc
        finally:
            connection.close()

    def record_result(self, *, run_id: str, result: ModelCallResult | Mapping[str, Any], actor: Actor, fencing_token: int, _connection=None) -> dict[str, Any]:
        value = result if isinstance(result, ModelCallResult) else ModelCallResult.from_mapping(result)
        now = _timestamp(self.repository.clock)
        connection = _connection or self._connect(read_only=False)
        try:
            with (control_transaction(connection) if _connection is None else nullcontext(connection)):
                self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE logical_call_id=? AND run_id=?", (value.logical_call_id, run_id)).fetchone()
                if intent is None or intent["intent_hash"] != value.intent_hash:
                    raise MaxControlError("model result does not bind a stored intent")
                response = value.response
                if response.model_identity != intent["model_identity"] or response.inference_profile_hash != intent["inference_profile_hash"]:
                    raise MaxControlError("model result model/profile binding is invalid")
                if response.status != value.status:
                    raise MaxControlError("model result status differs from its response envelope")
                receipt = None
                # A provider failure can still be billable.  Validate and
                # authorize a non-empty receipt for either terminal status;
                # only a failed result with no receipt is explicitly
                # non-billable and may be released by the abort path.
                if value.status == ModelCallStatus.SUCCEEDED.value or response.usage_receipt:
                    try:
                        receipt = UsageReceipt.from_mapping(response.usage_receipt)
                    except Exception as exc:
                        raise MaxControlError("model result usage receipt is invalid") from exc
                    if receipt.run_id != run_id or receipt.iteration_id != intent["iteration_id"] or receipt.model_identity != intent["model_identity"] or receipt.computed_payload_hash() != receipt.payload_hash or (receipt.receipt_hash and receipt.computed_receipt_hash() != receipt.receipt_hash):
                        raise MaxControlError("model usage receipt is not bound to the intent")
                    expected_binding = {
                        "logical_call_id": value.logical_call_id,
                        "intent_hash": value.intent_hash,
                        "request_hash": intent["request_hash"],
                        "provider_call_id": response.provider_call_id,
                        "inference_profile_hash": intent["inference_profile_hash"],
                    }
                    if any(getattr(receipt, key, "") != expected for key, expected in expected_binding.items()) or not all(getattr(receipt, key, "") for key in expected_binding):
                        raise MaxControlError("model usage receipt call binding is invalid")
                    previous_receipt = connection.execute("SELECT logical_call_id, intent_hash, request_hash, provider_call_id, amount_hash FROM max_runner_usage_bindings WHERE receipt_id=?", (receipt.receipt_id,)).fetchone()
                    if previous_receipt is not None and (previous_receipt["logical_call_id"] != value.logical_call_id or previous_receipt["intent_hash"] != value.intent_hash or previous_receipt["request_hash"] != intent["request_hash"] or previous_receipt["provider_call_id"] != response.provider_call_id):
                        raise MaxControlError("usage receipt replay is bound to a different logical call")
                    authority = self.repository.usage_authority
                    if authority is None:
                        raise MaxControlError("USAGE_AUTHORITY_NOT_CONFIGURED")
                    try:
                        verification = authority.verify_usage_receipt(
                            receipt,
                            run_id=run_id,
                            iteration_id=intent["iteration_id"],
                            model_identity=intent["model_identity"],
                            logical_call_id=value.logical_call_id,
                            intent_hash=value.intent_hash,
                            request_hash=intent["request_hash"],
                            provider_call_id=response.provider_call_id,
                            inference_profile_hash=intent["inference_profile_hash"],
                        )
                    except Exception as exc:
                        raise MaxControlError("usage receipt authority rejected the receipt") from exc
                    if verification is False or verification is None:
                        raise MaxControlError("usage receipt authority rejected the receipt")
                existing = connection.execute("SELECT result_id, result_hash FROM max_model_call_results WHERE logical_call_id=?", (value.logical_call_id,)).fetchone()
                if existing is not None:
                    if existing["result_hash"] != value.result_hash:
                        raise MaxControlError("a different authoritative model result already exists")
                    return {"result_id": existing["result_id"], "logical_call_id": value.logical_call_id, "result_hash": value.result_hash, "idempotent": True}
                result_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("model_result", intent["project_id"], {"logical_call_id": value.logical_call_id, "result_hash": value.result_hash})
                usage = model_to_dict(response.usage_receipt)
                durable = dict(value.durable_mapping())
                _reject_untrusted_payload(durable)
                connection.execute("INSERT INTO max_model_call_results(result_id, logical_call_id, intent_id, run_id, project_id, iteration_id, intent_hash, result_status, result_json, result_hash, usage_json, usage_hash, authoritative, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)", (result_id, value.logical_call_id, intent["intent_id"], run_id, intent["project_id"], intent["iteration_id"], value.intent_hash, value.status, _json(durable), value.result_hash, _json(usage), _hash(usage), now, actor.actor_id, actor.actor_kind, actor.session_id))
                binding = connection.execute("SELECT group_id, call_index FROM max_runner_call_bindings WHERE logical_call_id=? AND run_id=?", (value.logical_call_id, run_id)).fetchone()
                call_binding = connection.execute("SELECT role, phase, packet_hash FROM max_runner_call_bindings WHERE logical_call_id=? AND run_id=?", (value.logical_call_id, run_id)).fetchone()
                manifest = _loads(intent["intent_json"])
                result_binding_payload = {
                    "run_id": run_id,
                    "project_id": intent["project_id"],
                    "iteration_id": intent["iteration_id"],
                    "group_id": binding["group_id"] if binding else None,
                    "logical_call_id": value.logical_call_id,
                    "result_id": result_id,
                    "call_index": int(binding["call_index"]) if binding and binding["call_index"] is not None else None,
                    "role": call_binding["role"] if call_binding else manifest.get("role", ""),
                    "phase": call_binding["phase"] if call_binding else manifest.get("phase", value.status),
                    "intent_hash": value.intent_hash,
                    "request_hash": intent["request_hash"],
                }
                _reject_untrusted_payload(result_binding_payload)
                result_binding_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_result_call_binding", intent["project_id"], {"result_id": result_id, "logical_call_id": value.logical_call_id})
                connection.execute("INSERT INTO max_runner_result_call_bindings(binding_id, run_id, project_id, iteration_id, group_id, logical_call_id, result_id, call_index, role, phase, intent_hash, request_hash, binding_json, binding_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (result_binding_id, run_id, intent["project_id"], intent["iteration_id"], binding["group_id"] if binding else None, value.logical_call_id, result_id, int(binding["call_index"]) if binding and binding["call_index"] is not None else None, result_binding_payload["role"], result_binding_payload["phase"], value.intent_hash, intent["request_hash"], _json(result_binding_payload), _hash(result_binding_payload), now, actor.actor_id, actor.actor_kind, actor.session_id))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_result_call_bound", payload={"binding_id": result_binding_id, "result_id": result_id, "logical_call_id": value.logical_call_id}, actor=actor, now=now)
                if binding is not None:
                    connection.execute("UPDATE max_runner_call_group_current SET current_index=?, current_logical_call_id=?, updated_at=?, updated_by=? WHERE group_id=?", (int(binding["call_index"]) + 1, value.logical_call_id, now, actor.actor_id, binding["group_id"]))
                self.repository._append_event(connection, run_id=run_id, event_type="model_call_result_persisted", payload={"result_id": result_id, "logical_call_id": value.logical_call_id, "intent_hash": value.intent_hash, "result_hash": value.result_hash, "status": value.status, "usage_hash": _hash(usage)}, actor=actor, now=now)
            return {"result_id": result_id, "logical_call_id": value.logical_call_id, "result_hash": value.result_hash, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("model result persistence failed") from exc
        finally:
            if _connection is None:
                connection.close()

    def record_usage_binding(
        self,
        *,
        run_id: str,
        result_id: str,
        receipt: UsageReceipt | Mapping[str, Any],
        usage_entry_id: str,
        actor: Actor,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Bind one verified provider receipt to exactly one result and ledger row."""

        try:
            receipt_value = receipt if isinstance(receipt, UsageReceipt) else UsageReceipt.from_mapping(receipt)
        except Exception as exc:
            raise MaxControlError("usage binding receipt is invalid") from exc
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                result = connection.execute("SELECT * FROM max_model_call_results WHERE result_id=? AND run_id=?", (result_id, run_id)).fetchone()
                if result is None:
                    raise MaxControlError("usage binding result is unknown")
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE logical_call_id=? AND run_id=?", (result["logical_call_id"], run_id)).fetchone()
                if intent is None or result["intent_id"] != intent["intent_id"]:
                    raise MaxControlError("usage binding intent is orphaned")
                durable = _loads(result["result_json"])
                try:
                    stored_receipt = UsageReceipt.from_mapping(durable.get("usage_receipt", {}))
                except Exception as exc:
                    raise MaxControlError("usage binding result receipt is invalid") from exc
                expected = {"logical_call_id": result["logical_call_id"], "intent_hash": result["intent_hash"], "request_hash": intent["request_hash"], "provider_call_id": durable.get("provider_call_id", ""), "model_identity": intent["model_identity"], "inference_profile_hash": intent["inference_profile_hash"], "run_id": run_id, "iteration_id": intent["iteration_id"]}
                if any(getattr(receipt_value, key, None) != expected_value for key, expected_value in expected.items() if key not in {"model_identity", "run_id", "iteration_id"}) or receipt_value.model_identity != expected["model_identity"] or receipt_value.run_id != expected["run_id"] or receipt_value.iteration_id != expected["iteration_id"]:
                    raise MaxControlError("usage binding context is invalid")
                stored_receipt_hash = stored_receipt.receipt_hash or stored_receipt.computed_receipt_hash()
                provided_receipt_hash = receipt_value.receipt_hash or receipt_value.computed_receipt_hash()
                if (stored_receipt.receipt_id != receipt_value.receipt_id or stored_receipt.payload_hash != receipt_value.payload_hash or stored_receipt_hash != provided_receipt_hash or result["usage_hash"] != _hash(_loads(result["usage_json"]))):
                    raise MaxControlError("usage binding receipt does not match the persisted result")
                ledger = connection.execute("SELECT * FROM max_budget_ledger WHERE entry_id=? AND run_id=? AND operation='usage'", (usage_entry_id, run_id)).fetchone()
                if ledger is None or normalize_budget_amount(_loads(ledger["amount_json"])) != normalize_budget_amount(receipt_value.amount) or ledger["iteration_id"] != intent["iteration_id"]:
                    raise MaxControlError("usage binding ledger entry is invalid")
                group = connection.execute("SELECT group_id FROM max_runner_call_bindings WHERE logical_call_id=? AND run_id=?", (result["logical_call_id"], run_id)).fetchone()
                binding = {
                    "result_id": result_id,
                    "logical_call_id": result["logical_call_id"],
                    "intent_id": intent["intent_id"],
                    "run_id": run_id,
                    "project_id": run["project_id"],
                    "iteration_id": intent["iteration_id"],
                    "group_id": group["group_id"] if group else None,
                    "intent_hash": result["intent_hash"],
                    "request_hash": intent["request_hash"],
                    "provider_call_id": expected["provider_call_id"],
                    "model_identity": intent["model_identity"],
                    "inference_profile_hash": intent["inference_profile_hash"],
                    "receipt_id": receipt_value.receipt_id,
                    "receipt_hash": receipt_value.receipt_hash or receipt_value.computed_receipt_hash(),
                    "usage_entry_id": usage_entry_id,
                    "amount": normalize_budget_amount(receipt_value.amount),
                    "status": "settled",
                }
                existing = connection.execute("SELECT binding_id, binding_hash FROM max_runner_usage_bindings WHERE result_id=? OR logical_call_id=? OR receipt_id=?", (result_id, result["logical_call_id"], receipt_value.receipt_id)).fetchone()
                binding_hash = _hash(binding)
                if existing is not None:
                    if existing["binding_hash"] != binding_hash:
                        raise MaxControlError("usage binding is not idempotent")
                    return {"binding_id": existing["binding_id"], "usage_entry_id": usage_entry_id, "idempotent": True}
                binding_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_usage_binding", run["project_id"], {"result_id": result_id, "receipt_hash": binding["receipt_hash"]})
                connection.execute("INSERT INTO max_runner_usage_bindings(binding_id, result_id, logical_call_id, intent_id, run_id, project_id, iteration_id, group_id, intent_hash, request_hash, provider_call_id, model_identity, inference_profile_hash, receipt_id, receipt_hash, usage_entry_id, amount_json, amount_hash, binding_json, binding_hash, status, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (binding_id, result_id, result["logical_call_id"], intent["intent_id"], run_id, run["project_id"], intent["iteration_id"], group["group_id"] if group else None, result["intent_hash"], intent["request_hash"], expected["provider_call_id"], intent["model_identity"], intent["inference_profile_hash"], receipt_value.receipt_id, binding["receipt_hash"], usage_entry_id, _json(binding["amount"]), _hash(binding["amount"]), _json(binding), binding_hash, "settled", now, actor.actor_id, actor.actor_kind, actor.session_id))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_usage_bound", payload={"binding_id": binding_id, "result_id": result_id, "logical_call_id": result["logical_call_id"], "usage_entry_id": usage_entry_id, "receipt_hash": binding["receipt_hash"]}, actor=actor, now=now)
            return {"binding_id": binding_id, "usage_entry_id": usage_entry_id, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("usage binding persistence failed") from exc
        finally:
            connection.close()

    def record_artifact_binding(
        self,
        *,
        run_id: str,
        iteration_id: str,
        artifact_type: str,
        artifact_id: str,
        artifact_hash: str,
        logical_call_id: str,
        result_id: str,
        actor: Actor,
        fencing_token: int,
    ) -> dict[str, Any]:
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                result = connection.execute("SELECT * FROM max_model_call_results WHERE run_id=? AND result_id=? AND logical_call_id=?", (run_id, result_id, logical_call_id)).fetchone()
                if intent is None or result is None or intent["iteration_id"] != iteration_id:
                    raise MaxControlError("artifact binding call is invalid")
                group = connection.execute("SELECT group_id FROM max_runner_call_bindings WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                payload = {"run_id": run_id, "project_id": run["project_id"], "iteration_id": iteration_id, "group_id": group["group_id"] if group else None, "logical_call_id": logical_call_id, "result_id": result_id, "artifact_type": artifact_type, "artifact_id": artifact_id, "artifact_hash": artifact_hash, "intent_hash": intent["intent_hash"], "request_hash": intent["request_hash"]}
                binding_hash = _hash(payload)
                existing = connection.execute("SELECT binding_id, binding_hash FROM max_runner_artifact_bindings WHERE iteration_id=? AND artifact_type=? AND artifact_id=?", (iteration_id, artifact_type, artifact_id)).fetchone()
                if existing is not None:
                    if existing["binding_hash"] != binding_hash:
                        raise MaxControlError("artifact binding is not idempotent")
                    return {"binding_id": existing["binding_id"], "idempotent": True}
                binding_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_artifact_binding", run["project_id"], {"iteration_id": iteration_id, "artifact_type": artifact_type, "artifact_id": artifact_id})
                connection.execute("INSERT INTO max_runner_artifact_bindings(binding_id, run_id, project_id, iteration_id, group_id, logical_call_id, result_id, artifact_type, artifact_id, artifact_hash, intent_hash, request_hash, binding_json, binding_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (binding_id, run_id, run["project_id"], iteration_id, group["group_id"] if group else None, logical_call_id, result_id, artifact_type, artifact_id, artifact_hash, intent["intent_hash"], intent["request_hash"], _json(payload), binding_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_artifact_bound", payload={"binding_id": binding_id, "iteration_id": iteration_id, "artifact_type": artifact_type, "artifact_id": artifact_id, "logical_call_id": logical_call_id}, actor=actor, now=now)
            return {"binding_id": binding_id, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("artifact binding persistence failed") from exc
        finally:
            connection.close()

    def record_epistemic_conflict(
        self,
        *,
        run_id: str,
        iteration_id: str,
        logical_call_id: str,
        intent_hash: str,
        request_hash: str,
        proposal_hash: str,
        validator_hash: str,
        canonical_state_hash: str,
        canonical_version_hashes: Sequence[str],
        issue_codes: Sequence[str],
        conflict_type: str,
        canonical_basis: Mapping[str, Any],
        fingerprint: str,
        actor: Actor,
        fencing_token: int,
    ) -> dict[str, Any]:
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                if intent is None or intent["iteration_id"] != iteration_id or intent["intent_hash"] != intent_hash or intent["request_hash"] != request_hash:
                    raise MaxControlError("epistemic conflict call binding is invalid")
                state_row = connection.execute("SELECT state_hash FROM max_research_states WHERE run_id=?", (run_id,)).fetchone()
                if state_row is None or state_row["state_hash"] != canonical_state_hash:
                    raise MaxControlError("epistemic conflict state binding is invalid")
                version_rows = connection.execute(
                    "SELECT v.object_json FROM max_canonical_object_versions v JOIN max_run_object_memberships m ON m.version_id=v.version_id WHERE m.run_id=? AND m.project_id=? ORDER BY v.version_id",
                    (run_id, run["project_id"]),
                ).fetchall()
                expected_version_hashes = tuple(sorted(_hash(_loads(row["object_json"])) for row in version_rows))
                if tuple(sorted(canonical_version_hashes)) != expected_version_hashes:
                    raise MaxControlError("epistemic conflict canonical version binding is invalid")
                # A crash after the append but before the caller receives the
                # response must not turn a retry of the same semantic finding
                # into an extra escalation level.  A new intent/proposal for
                # the same fingerprint remains a genuine repeat and advances
                # the persisted resolution ladder.
                exact = connection.execute(
                    "SELECT * FROM max_epistemic_conflicts WHERE run_id=? AND fingerprint=? AND intent_hash=? AND request_hash=? AND proposal_hash=? AND validator_hash=? AND canonical_state_hash=? ORDER BY repeat_count DESC LIMIT 1",
                    (run_id, fingerprint, intent_hash, request_hash, proposal_hash, validator_hash, canonical_state_hash),
                ).fetchone()
                if exact is not None:
                    try:
                        normalized_existing = _loads(exact["conflict_json"])
                    except Exception as exc:
                        raise MaxControlError("existing epistemic conflict record is invalid") from exc
                    return {"conflict_id": exact["conflict_id"], "repeat_count": int(exact["repeat_count"]), "resolution": exact["resolution"], "record": normalized_existing, "idempotent": True}
                prior = connection.execute("SELECT MAX(repeat_count) AS repeat_count FROM max_epistemic_conflicts WHERE run_id=? AND fingerprint=?", (run_id, fingerprint)).fetchone()
                repeat_count = int(prior["repeat_count"] or 0) + 1
                resolution = "rejected" if repeat_count == 1 else "rehydration_required" if repeat_count == 2 else "paused"
                record = EpistemicConflictRecord(run["project_id"], run_id, iteration_id, logical_call_id, intent_hash, request_hash, proposal_hash, validator_hash, canonical_state_hash, tuple(canonical_version_hashes), tuple(issue_codes), conflict_type, canonical_basis, fingerprint, repeat_count, resolution, actor.actor_id, now)
                validate_epistemic_conflict_record(record).raise_if_invalid()
                normalized = model_to_dict(record)
                _reject_untrusted_payload({"conflict": normalized})
                connection.execute("INSERT INTO max_epistemic_conflicts(conflict_id, run_id, project_id, iteration_id, logical_call_id, intent_hash, request_hash, proposal_hash, validator_hash, canonical_state_hash, canonical_version_hashes_json, issue_codes_json, conflict_type, canonical_basis_json, fingerprint, repeat_count, resolution, conflict_json, conflict_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (record.conflict_id, run_id, run["project_id"], iteration_id, logical_call_id, intent_hash, request_hash, proposal_hash, validator_hash, canonical_state_hash, _json(record.canonical_version_hashes), _json(record.issue_codes), conflict_type, _json(record.canonical_basis), fingerprint, repeat_count, resolution, _json(normalized), _hash(normalized), now, actor.actor_id, actor.actor_kind, actor.session_id))
                self.repository._append_event(connection, run_id=run_id, event_type="epistemic_conflict_recorded", payload={"conflict_id": record.conflict_id, "iteration_id": iteration_id, "logical_call_id": logical_call_id, "conflict_type": conflict_type, "fingerprint": fingerprint, "repeat_count": repeat_count, "resolution": resolution}, actor=actor, now=now)
            return {"conflict_id": record.conflict_id, "repeat_count": repeat_count, "resolution": resolution, "record": normalized}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("epistemic conflict persistence failed") from exc
        finally:
            connection.close()

    def record_recovery(self, *, run_id: str, logical_call_id: str, disposition: RecoveryDisposition | str, decision: Mapping[str, Any], actor: Actor, fencing_token: int | None = None) -> dict[str, Any]:
        value = getattr(disposition, "value", disposition)
        if value not in {item.value for item in RecoveryDisposition}:
            raise MaxControlError("recovery disposition is invalid")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                self.repository._run_row(connection, run_id)
                if fencing_token is not None:
                    self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                elif not actor.is_admin:
                    raise MaxControlError("runner recovery decision requires a current fencing token")
                intent = connection.execute("SELECT project_id FROM max_model_call_intents WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                if intent is None:
                    raise MaxControlError("recovery decision references an unknown logical call")
                _reject_untrusted_payload(decision)
                normalized = {"run_id": run_id, "logical_call_id": logical_call_id, "disposition": value, "decision": dict(decision)}
                recovery_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("recovery", intent["project_id"], {**normalized, "nonce": uuid.uuid4().hex})
                connection.execute("INSERT INTO max_runner_recovery_decisions(recovery_id, logical_call_id, run_id, disposition, decision_json, decision_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (recovery_id, logical_call_id, run_id, value, _json(normalized), _hash(normalized), now, actor.actor_id, actor.actor_kind, actor.session_id))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_recovery_decision", payload={"recovery_id": recovery_id, "logical_call_id": logical_call_id, "disposition": value, "decision_hash": _hash(normalized)}, actor=actor, now=now)
            return {"recovery_id": recovery_id, "logical_call_id": logical_call_id, "disposition": value}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("recovery decision persistence failed") from exc
        finally:
            connection.close()

    def recovery_consumption(self, *, run_id: str, logical_call_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_runner_recovery_consumptions WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def consume_admin_decision(self, *, run_id: str, logical_call_id: str, decision: str, admin_actor: Actor) -> dict[str, Any]:
        if not admin_actor.is_admin:
            raise MaxControlError("ambiguous recovery decisions require human admin authority")
        value = str(decision).strip().lower()
        if value not in {"retry", "abort", "accept"}:
            raise MaxControlError("ambiguous recovery decision is invalid")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self.repository._run_row(connection, run_id)
                if run["status"] != "PAUSED":
                    raise MaxControlError("ambiguous recovery decision requires a PAUSED Run")
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                if intent is None:
                    raise MaxControlError("recovery decision references the wrong Run or intent")
                existing = connection.execute("SELECT * FROM max_runner_recovery_consumptions WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                if existing is not None:
                    if existing["decision"] == value:
                        return {"consumption_id": existing["consumption_id"], "run_id": run_id, "logical_call_id": logical_call_id, "decision": value, "idempotent": True}
                    raise MaxControlError("recovery decision has already been consumed")
                recovery = connection.execute("SELECT * FROM max_runner_recovery_decisions WHERE run_id=? AND logical_call_id=? AND disposition=? ORDER BY created_at DESC LIMIT 1", (run_id, logical_call_id, RecoveryDisposition.AMBIGUOUS_PAUSE.value)).fetchone()
                if recovery is None:
                    raise MaxControlError("no pending ambiguous recovery decision exists")
                if value == "accept":
                    result = connection.execute("SELECT result_id, result_hash, authoritative FROM max_model_call_results WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                    if result is None or not int(result["authoritative"]):
                        raise MaxControlError("accept requires an existing authoritative provider result")
                    result_binding = {"result_id": result["result_id"], "result_hash": result["result_hash"]}
                else:
                    result_binding = {"result_id": None, "result_hash": None}
                payload = {"run_id": run_id, "logical_call_id": logical_call_id, "recovery_id": recovery["recovery_id"], "intent_hash": intent["intent_hash"], "decision": value, "admin_actor_id": admin_actor.actor_id, "admin_session": admin_actor.session_id, "fencing_token": None, "result": result_binding}
                consumption_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("recovery_consumption", run["project_id"], {**payload, "nonce": uuid.uuid4().hex})
                result_json = _json(payload)
                connection.execute("INSERT INTO max_runner_recovery_consumptions(consumption_id, recovery_id, run_id, logical_call_id, intent_hash, decision, admin_actor_id, admin_session, consumed_at, fencing_token, result_json, result_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (consumption_id, recovery["recovery_id"], run_id, logical_call_id, intent["intent_hash"], value, admin_actor.actor_id, admin_actor.session_id, now, None, result_json, _hash(payload)))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_recovery_consumed", payload={"consumption_id": consumption_id, "recovery_id": recovery["recovery_id"], "logical_call_id": logical_call_id, "decision": value, "result_hash": result_binding["result_hash"]}, actor=admin_actor, now=now)
            return {"consumption_id": consumption_id, "run_id": run_id, "logical_call_id": logical_call_id, "decision": value, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("recovery decision consumption failed") from exc
        finally:
            connection.close()

    def record_outcome(self, *, run_id: str, logical_call_id: str, status: str, iteration_id: str, outcome: Mapping[str, Any], actor: Actor, fencing_token: int, links: Sequence[Mapping[str, Any]] = (), _connection=None) -> dict[str, Any]:
        if status not in {"completed", "aborted", "paused"}:
            raise MaxControlError("runner outcome status is invalid")
        now = _timestamp(self.repository.clock)
        connection = _connection or self._connect(read_only=False)
        try:
            with (control_transaction(connection) if _connection is None else nullcontext(connection)):
                row = self.repository._run_row(connection, run_id)
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                if intent is None or intent["iteration_id"] != iteration_id:
                    raise MaxControlError("runner outcome is outside the intent iteration")
                existing = connection.execute("SELECT outcome_id, outcome_hash FROM max_runner_attempt_outcomes WHERE logical_call_id=?", (logical_call_id,)).fetchone()
                normalized = {"run_id": run_id, "logical_call_id": logical_call_id, "iteration_id": iteration_id, "status": status, "outcome": dict(outcome)}
                if existing is not None:
                    if existing["outcome_hash"] != _hash(normalized):
                        raise MaxControlError("runner outcome is not idempotent")
                    return {"outcome_id": existing["outcome_id"], "status": status, "idempotent": True}
                _reject_untrusted_payload(outcome)
                outcome_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_outcome", row["project_id"], {"logical_call_id": logical_call_id, "status": status})
                change_set_id = outcome.get("change_set_id") if isinstance(outcome.get("change_set_id"), str) else None
                iteration_outcome_id = outcome.get("iteration_outcome_id") if isinstance(outcome.get("iteration_outcome_id"), str) else None
                usage_entry_id = outcome.get("usage_entry_id") if isinstance(outcome.get("usage_entry_id"), str) else None
                connection.execute("INSERT INTO max_runner_attempt_outcomes(outcome_id, logical_call_id, run_id, project_id, iteration_id, status, change_set_id, iteration_outcome_id, usage_entry_id, outcome_json, outcome_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (outcome_id, logical_call_id, run_id, row["project_id"], iteration_id, status, change_set_id, iteration_outcome_id, usage_entry_id, _json(normalized), _hash(normalized), now, actor.actor_id, actor.actor_kind, actor.session_id))
                for link in links:
                    if not isinstance(link, Mapping) or set(link) - {"link_type", "target_id", "target_hash"} or not isinstance(link.get("link_type"), str) or not isinstance(link.get("target_id"), str) or not isinstance(link.get("target_hash"), str):
                        raise MaxControlError("runner outcome link is invalid")
                    link_id = __import__("research_kb.max_research.contract", fromlist=["make_event_id"]).make_event_id("runner_link", row["project_id"], {"logical_call_id": logical_call_id, "link_type": link["link_type"], "target_id": link["target_id"]})
                    connection.execute("INSERT INTO max_runner_links(link_id, logical_call_id, run_id, link_type, target_id, target_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (link_id, logical_call_id, run_id, link["link_type"], link["target_id"], link["target_hash"], now, actor.actor_id, actor.actor_kind, actor.session_id))
                if status in {"completed", "aborted"}:
                    connection.execute("DELETE FROM max_runner_plan_current WHERE run_id=?", (run_id,))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_attempt_outcome", payload={"outcome_id": outcome_id, "logical_call_id": logical_call_id, "iteration_id": iteration_id, "status": status, "change_set_id": change_set_id, "iteration_outcome_id": iteration_outcome_id, "usage_entry_id": usage_entry_id}, actor=actor, now=now)
            return {"outcome_id": outcome_id, "status": status, "idempotent": False}
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("runner outcome persistence failed") from exc
        finally:
            if _connection is None:
                connection.close()

    def abort_pre_send(
        self,
        *,
        run_id: str,
        actor: Actor,
        fencing_token: int,
        failure_stage: str,
        error_code: str,
        logical_call_id: str | None = None,
    ) -> dict[str, Any]:
        """Atomically close runner state when durable evidence proves no send.

        This writes only a server-owned failed model envelope with
        ``dispatch_known=False``.  It never creates a provider call, usage
        receipt, attestation, or response payload.
        """

        if not isinstance(failure_stage, str) or not failure_stage or len(failure_stage) > 128:
            raise MaxControlError("pre-send runner closure failure stage is invalid")
        if not isinstance(error_code, str) or not error_code or len(error_code) > 128 or not error_code.replace("_", "").isalnum():
            raise MaxControlError("pre-send runner closure error code is invalid")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self.repository._run_row(connection, run_id)
                open_groups = connection.execute(
                    "SELECT g.*, c.status AS group_status FROM max_runner_call_groups g JOIN max_runner_call_group_current c ON c.group_id=g.group_id WHERE g.run_id=? AND c.status='open' ORDER BY g.created_at",
                    (run_id,),
                ).fetchall()
                existing_iteration = connection.execute(
                    "SELECT o.outcome_id, o.iteration_id FROM max_iteration_outcomes o WHERE o.run_id=? AND o.status='aborted' ORDER BY o.finished_at DESC LIMIT 1",
                    (run_id,),
                ).fetchone()
                current_plan = connection.execute("SELECT 1 FROM max_runner_plan_current WHERE run_id=?", (run_id,)).fetchone()
                if run["status"] != RunStatus.RUNNING.value:
                    if existing_iteration is not None and not open_groups and current_plan is None:
                        return {"run_id": run_id, "iteration_id": existing_iteration["iteration_id"], "outcome_id": existing_iteration["outcome_id"], "status": "aborted", "idempotent": True}
                    raise MaxControlError("pre-send runner closure requires a RUNNING Run")
                self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=now)
                begin = self.repository._open_iteration(connection, run_id=run_id)
                iteration_id = str(begin["iteration_id"])
                groups = [row for row in open_groups if row["iteration_id"] == iteration_id]
                bindings = list(connection.execute(
                    "SELECT b.*, i.intent_hash, i.model_identity, i.inference_profile_hash, i.project_id, i.iteration_id AS intent_iteration_id FROM max_runner_call_bindings b JOIN max_model_call_intents i ON i.logical_call_id=b.logical_call_id AND i.run_id=b.run_id WHERE b.run_id=? AND b.iteration_id=? ORDER BY b.call_index",
                    (run_id, iteration_id),
                ))
                if logical_call_id is not None and not any(row["logical_call_id"] == logical_call_id for row in bindings):
                    raise MaxControlError("pre-send runner closure logical call is outside the current iteration")

                result_count = 0
                for binding in bindings:
                    logical = str(binding["logical_call_id"])
                    existing_result = connection.execute(
                        "SELECT result_id, result_status, result_json FROM max_model_call_results WHERE run_id=? AND logical_call_id=?",
                        (run_id, logical),
                    ).fetchone()
                    if existing_result is None:
                        response = ModelResponseEnvelope(
                            logical_call_id=logical,
                            intent_hash=str(binding["intent_hash"]),
                            model_identity=str(binding["model_identity"]),
                            inference_profile_hash=str(binding["inference_profile_hash"]),
                            status=ModelCallStatus.FAILED.value,
                            proposal={},
                            usage_receipt={},
                            provider_call_id="not-sent",
                            dispatch_known=False,
                            error_code=error_code,
                        )
                        controlled = ModelCallResult(
                            logical_call_id=logical,
                            intent_hash=str(binding["intent_hash"]),
                            status=ModelCallStatus.FAILED.value,
                            response=response,
                        )
                        self.record_result(
                            run_id=run_id,
                            result=controlled,
                            actor=actor,
                            fencing_token=fencing_token,
                            _connection=connection,
                        )
                        result_count += 1
                    else:
                        try:
                            durable = _loads(existing_result["result_json"])
                        except Exception as exc:
                            raise MaxControlError("pre-send runner closure found an invalid result") from exc
                        if existing_result["result_status"] == ModelCallStatus.SUCCEEDED.value or durable.get("usage_receipt"):
                            raise MaxControlError("pre-send runner closure cannot replace a billable model result")

                    reservation = connection.execute(
                        "SELECT entry_id FROM max_budget_ledger WHERE run_id=? AND idempotency_key=? AND operation='reserve'",
                        (run_id, f"mr2a:reserve:{logical}"),
                    ).fetchone()
                    if reservation is not None:
                        remaining = self.repository._reservation_remaining(connection, run_id=run_id, reservation_id=reservation["entry_id"])
                        if remaining:
                            self.repository._budget_write(
                                run_id=run_id,
                                operation="release",
                                amount=remaining,
                                reservation_id=reservation["entry_id"],
                                idempotency_key=f"mr2a:release:{logical}",
                                actor=actor,
                                fencing_token=fencing_token,
                                iteration_id=iteration_id,
                                _connection=connection,
                            )

                self.repository.record_server_usage(
                    run_id=run_id,
                    amount={"iteration_count": 1},
                    idempotency_key=f"mr2a:iteration:service:{iteration_id}",
                    actor=actor,
                    fencing_token=fencing_token,
                    iteration_id=iteration_id,
                    charge_kind="iteration",
                    _connection=connection,
                )
                budget_delta = self.repository._budget_delta_for_iteration(connection, run_id=run_id, iteration_id=iteration_id)
                finished = self.repository.finish_iteration(
                    run_id=run_id,
                    iteration_id=iteration_id,
                    actor=actor,
                    fencing_token=fencing_token,
                    status="aborted",
                    output_state_hash=None,
                    budget_delta=budget_delta,
                    outcome_metadata={
                        "provider_usage": {},
                        "provider_cost_units": 0,
                        "provider_result_count": 0,
                        "failure_stage": failure_stage,
                        "error_code": error_code,
                    },
                    _connection=connection,
                )
                attempt_outcome_count = 0
                for binding in bindings:
                    self.record_outcome(
                        run_id=run_id,
                        logical_call_id=str(binding["logical_call_id"]),
                        status="aborted",
                        iteration_id=iteration_id,
                        outcome={
                            "status": "aborted",
                            "dispatch_known": False,
                            "provider_usage": {},
                            "provider_cost_units": 0,
                            "failure_stage": failure_stage,
                            "error_code": error_code,
                            "iteration_outcome_id": finished["outcome_id"],
                        },
                        actor=actor,
                        fencing_token=fencing_token,
                        _connection=connection,
                    )
                    attempt_outcome_count += 1
                connection.execute("DELETE FROM max_runner_plan_current WHERE run_id=?", (run_id,))
                for group in groups:
                    self.finalize_call_group(
                        run_id=run_id,
                        group_id=str(group["group_id"]),
                        status="aborted",
                        actor=actor,
                        fencing_token=fencing_token,
                        _connection=connection,
                    )
                self.repository._append_event(
                    connection,
                    run_id=run_id,
                    event_type="runner_pre_send_abort_closed",
                    payload={
                        "iteration_id": iteration_id,
                        "outcome_id": finished["outcome_id"],
                        "group_count": len(groups),
                        "result_count": result_count,
                        "attempt_outcome_count": attempt_outcome_count,
                        "provider_usage": {},
                        "provider_cost_units": 0,
                        "failure_stage": failure_stage,
                        "error_code": error_code,
                    },
                    actor=actor,
                    now=now,
                )
            return {
                "run_id": run_id,
                "iteration_id": iteration_id,
                "outcome_id": finished["outcome_id"],
                "status": "aborted",
                "result_count": result_count,
                "attempt_outcome_count": attempt_outcome_count,
                "idempotent": False,
            }
        except MaxControlError:
            raise
        except Exception as exc:
            raise MaxControlError("pre-send runner closure failed") from exc
        finally:
            connection.close()

    def current_work(self, *, run_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT p.*, i.intent_json, i.intent_hash, i.logical_call_id FROM max_runner_plan_current c JOIN max_runner_plans p ON p.plan_id=c.plan_id LEFT JOIN max_model_call_intents i ON i.logical_call_id=c.active_logical_call_id WHERE c.run_id=?", (run_id,)).fetchone()
            if row is None:
                return None
            return dict(row)
        finally:
            connection.close()

    def list_history(self, *, run_id: str) -> list[dict[str, Any]]:
        connection = self._connect(read_only=True)
        try:
            rows = [dict(row) for row in connection.execute("SELECT i.sequence_no, i.iteration_id, i.round_type, i.input_state_hash, COALESCE(o.output_state_hash, i.output_state_hash) AS output_state_hash, COALESCE(o.status, i.status) AS status, i.started_at, COALESCE(o.finished_at, i.finished_at) AS finished_at, o.outcome_id, o.outcome_hash, o.strategy_ledger_json, o.record_refs_json, o.artifact_summary_json FROM max_iterations i LEFT JOIN max_iteration_outcomes o ON o.iteration_id=i.iteration_id AND o.run_id=i.run_id WHERE i.run_id=? ORDER BY i.sequence_no", (run_id,))]
            for row in rows:
                row["history_hash"] = _hash({key: row[key] for key in sorted(row) if key != "history_hash"})
            return rows
        finally:
            connection.close()

    def server_policy_triggers(self, *, run_id: str, state_hash: str) -> tuple[str, ...]:
        """Derive rehydration triggers from immutable facts, never payload claims."""

        connection = self._connect(read_only=True)
        try:
            triggers: set[str] = set()
            latest = connection.execute("SELECT i.round_type, COALESCE(o.output_state_hash, i.output_state_hash) AS final_state_hash, o.counterevidence_snapshots_json, o.artifact_summary_json FROM max_iterations i LEFT JOIN max_iteration_outcomes o ON o.iteration_id=i.iteration_id AND o.run_id=i.run_id WHERE i.run_id=? ORDER BY i.sequence_no DESC LIMIT 1", (run_id,)).fetchone()
            if latest is not None:
                if latest["final_state_hash"] and latest["final_state_hash"] != state_hash:
                    triggers.add("leading_hypothesis_changed")
                try:
                    if latest["counterevidence_snapshots_json"] and _loads(latest["counterevidence_snapshots_json"]):
                        triggers.add("major_counterevidence")
                except Exception:
                    triggers.add("major_counterevidence")
                try:
                    artifacts = _loads(latest["artifact_summary_json"] or "[]")
                    if any(isinstance(item, Mapping) and item.get("artifact_type") == "drift_finding" for item in artifacts):
                        triggers.add("recovery")
                except Exception:
                    triggers.add("recovery")
            return tuple(sorted(triggers))
        finally:
            connection.close()

    def latest_plan(self, *, run_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_runner_plans WHERE run_id=? ORDER BY sequence_no DESC LIMIT 1", (run_id,)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def open_iteration(self, *, run_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT i.* FROM max_iterations i JOIN max_iteration_current c ON c.iteration_id=i.iteration_id WHERE c.run_id=? AND i.run_id=?", (run_id, run_id)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def stored_result(self, *, run_id: str, logical_call_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT r.*, i.intent_json FROM max_model_call_results r JOIN max_model_call_intents i ON i.logical_call_id=r.logical_call_id WHERE r.run_id=? AND r.logical_call_id=?", (run_id, logical_call_id)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def usage_binding(self, *, run_id: str, logical_call_id: str) -> dict[str, Any] | None:
        """Return the single immutable usage binding for a logical call."""

        connection = self._connect(read_only=True)
        try:
            row = connection.execute(
                "SELECT * FROM max_runner_usage_bindings WHERE run_id=? AND logical_call_id=?",
                (run_id, logical_call_id),
            ).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def stored_outcome(self, *, run_id: str, logical_call_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_runner_attempt_outcomes WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def find_change_set(self, *, run_id: str, iteration_id: str, input_state_hash: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_canonical_change_sets WHERE run_id=? AND iteration_id=? AND input_state_hash=? ORDER BY created_at DESC LIMIT 1", (run_id, iteration_id, input_state_hash)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def latest_unfinished(self, *, run_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT i.*, a.dispatch_status, a.dispatch_known, r.result_id, r.result_json, r.result_hash FROM max_model_call_intents i LEFT JOIN max_model_dispatch_acks a ON a.logical_call_id=i.logical_call_id LEFT JOIN max_model_call_results r ON r.logical_call_id=i.logical_call_id WHERE i.run_id=? AND NOT EXISTS (SELECT 1 FROM max_runner_attempt_outcomes o WHERE o.logical_call_id=i.logical_call_id) ORDER BY i.created_at DESC LIMIT 1", (run_id,)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def latest_attempt(self, *, run_id: str, logical_call_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_model_call_attempts WHERE run_id=? AND logical_call_id=? ORDER BY attempt_no DESC LIMIT 1", (run_id, logical_call_id)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def iteration_budget_delta(self, *, run_id: str, iteration_id: str) -> dict[str, int | float]:
        connection = self._connect(read_only=True)
        try:
            delta: dict[str, int | float] = {}
            for row in connection.execute("SELECT operation, amount_json FROM max_budget_ledger WHERE run_id=? AND iteration_id=? ORDER BY sequence_no", (run_id, iteration_id)):
                values = normalize_budget_amount(_loads(row["amount_json"]), allow_empty=True)
                sign = -1 if row["operation"] in {"release", "refund"} else 1
                for unit, value in values.items():
                    delta[unit] = delta.get(unit, 0) + sign * value
            return {key: value for key, value in sorted(delta.items()) if value}
        finally:
            connection.close()

    def budget_reservation(self, *, run_id: str, idempotency_key: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT entry_id, amount_json, reservation_id, iteration_id FROM max_budget_ledger WHERE run_id=? AND idempotency_key=? AND operation='reserve'", (run_id, idempotency_key)).fetchone()
            if row is None:
                return None
            return {"entry_id": row["entry_id"], "amount": _loads(row["amount_json"]), "reservation_id": row["reservation_id"], "iteration_id": row["iteration_id"]}
        finally:
            connection.close()

    def iteration_outcome(self, *, run_id: str, iteration_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT outcome_id, outcome_hash, status, outcome_json FROM max_iteration_outcomes WHERE run_id=? AND iteration_id=?", (run_id, iteration_id)).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def _verify_mr2a2_closure(
        self,
        connection: Any,
        *,
        run_id: str,
        run: Mapping[str, Any],
        intent_rows: Sequence[Mapping[str, Any]],
        result_rows: Sequence[Mapping[str, Any]],
        outcome_rows: Sequence[Mapping[str, Any]],
        groups: Sequence[Mapping[str, Any]],
        bindings: Sequence[Mapping[str, Any]],
        issues: list[str],
    ) -> None:
        """Recompute the MR-2A.2 call/usage/artifact closure from SQLite."""

        json_module = __import__("json")
        specs = list(connection.execute("SELECT * FROM max_runner_call_specs WHERE run_id=? ORDER BY group_id, call_index", (run_id,)))
        result_call_bindings = list(connection.execute("SELECT * FROM max_runner_result_call_bindings WHERE run_id=? ORDER BY created_at", (run_id,)))
        usage_bindings = list(connection.execute("SELECT * FROM max_runner_usage_bindings WHERE run_id=? ORDER BY created_at", (run_id,)))
        artifact_bindings = list(connection.execute("SELECT * FROM max_runner_artifact_bindings WHERE run_id=? ORDER BY created_at", (run_id,)))
        conflicts = list(connection.execute("SELECT * FROM max_epistemic_conflicts WHERE run_id=? ORDER BY fingerprint, repeat_count", (run_id,)))
        # MR-1 and older MR-2A.1 databases may contain legacy runner rows but
        # no MR-2A.2 authority records.  Preserve their existing verification
        # contract; once a run has any v2 authority row, the checks below are
        # fail-closed and complete.
        if not (specs or result_call_bindings or usage_bindings or artifact_bindings or conflicts):
            return
        ledger_rows = list(connection.execute("SELECT * FROM max_budget_ledger WHERE run_id=? ORDER BY sequence_no", (run_id,)))
        ledger_by_id = {row["entry_id"]: row for row in ledger_rows}
        receipts = {row["receipt_id"]: row for row in connection.execute("SELECT * FROM max_usage_receipts WHERE run_id=?", (run_id,))}
        recovery_rows = list(connection.execute("SELECT * FROM max_runner_recovery_decisions WHERE run_id=? ORDER BY created_at", (run_id,)))
        intent_by_logical = {row["logical_call_id"]: row for row in intent_rows}
        result_by_logical = {row["logical_call_id"]: row for row in result_rows}
        result_by_id = {row["result_id"]: row for row in result_rows}
        result_call_by_logical: dict[str, list[Mapping[str, Any]]] = {}
        result_call_by_result: dict[str, list[Mapping[str, Any]]] = {}
        for row in result_call_bindings:
            result_call_by_logical.setdefault(row["logical_call_id"], []).append(row)
            result_call_by_result.setdefault(row["result_id"], []).append(row)
        call_by_logical = {row["logical_call_id"]: row for row in bindings}
        group_by_id = {row["group_id"]: row for row in groups}
        group_projection = {row["group_id"]: row for row in connection.execute("SELECT * FROM max_runner_call_group_current WHERE run_id=?", (run_id,))}
        group_status = {group_id: row["status"] for group_id, row in group_projection.items()}
        lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
        now_dt = _utc_now(self.repository.clock)
        lease_expiry = _parse_timestamp(lease["expires_at"]) if lease is not None else None
        lease_live = bool(
            run["status"] == RunStatus.RUNNING.value
            and lease is not None
            and lease["owner_id"]
            and lease["session_id"]
            and lease_expiry is not None
            and lease_expiry > now_dt
        )
        live_invocation_claim = False
        if lease_live:
            for claim in connection.execute(
                "SELECT c.actor_id, c.actor_session, c.fencing_token, c.expires_at "
                "FROM max_runner_invocation_claims c "
                "WHERE c.run_id=? AND c.status='active' "
                "AND NOT EXISTS (SELECT 1 FROM max_runner_invocation_claims r "
                "WHERE r.run_id=c.run_id AND r.status='released' "
                "AND r.claim_id=c.claim_id || ':released')",
                (run_id,),
            ):
                claim_expiry = _parse_timestamp(claim["expires_at"])
                if (
                    claim_expiry is not None
                    and claim_expiry > now_dt
                    and claim["actor_id"] == lease["owner_id"]
                    and claim["actor_session"] == lease["session_id"]
                    and int(claim["fencing_token"]) == int(lease["fencing_token"])
                ):
                    live_invocation_claim = True
                    break

        expected_adjudication = (
            ("lead_position", "lead_position", "lead", ()),
            ("rival_position", "rival_position", "rival", ()),
            ("rival_cross_examination", "rival_cross_examination", "rival", ("lead_position", "rival_position")),
            ("lead_cross_examination_response", "lead_cross_examination_response", "lead", ("lead_position", "rival_position", "rival_cross_examination")),
            ("adjudicator", "adjudicator", "adjudicator", ("lead_position", "rival_position", "rival_cross_examination", "lead_cross_examination_response")),
        )
        specs_by_group: dict[str, list[tuple[int, DeliberationCallSpec]]] = {}
        for row in specs:
            try:
                raw = json_module.loads(row["spec_json"])
                value = DeliberationCallSpec.from_mapping(raw)
                upstream = tuple(json_module.loads(row["upstream_call_ids_json"]))
                valid = (
                    row["spec_hash"] == _hash(raw)
                    and row["call_id"] == value.call_id
                    and row["phase"] == value.phase
                    and row["role"] == value.role
                    and upstream == tuple(value.upstream_call_ids)
                    and row["input_mode"] == value.input_mode
                    and row["artifact_type"] == value.artifact_type
                )
                group = group_by_id.get(row["group_id"])
                if group is None or row["iteration_id"] != group["iteration_id"] or int(row["call_index"]) >= int(group["call_count"]) or not valid:
                    issues.append("runner call spec binding or hash mismatch")
                specs_by_group.setdefault(row["group_id"], []).append((int(row["call_index"]), value))
            except Exception:
                issues.append("runner call spec JSON is invalid")
        for group in groups:
            group_specs = sorted(specs_by_group.get(group["group_id"], ()), key=lambda item: item[0])
            if len(group_specs) != int(group["call_count"]):
                issues.append("runner call group spec count is incomplete")
            if [item[0] for item in group_specs] != list(range(len(group_specs))):
                issues.append("runner call spec sequence is not contiguous")
            if group["phase"] == "adjudication":
                actual = tuple((item[1].call_id, item[1].phase, item[1].role, tuple(item[1].upstream_call_ids)) for item in group_specs)
                if actual != expected_adjudication:
                    issues.append("adjudication call topology is not the frozen five-call contract")

        usage_by_result: dict[str, list[Mapping[str, Any]]] = {}
        usage_by_logical: dict[str, list[Mapping[str, Any]]] = {}
        for row in usage_bindings:
            usage_by_result.setdefault(row["result_id"], []).append(row)
            usage_by_logical.setdefault(row["logical_call_id"], []).append(row)
        for row in result_rows:
            intent = intent_by_logical.get(row["logical_call_id"])
            call = call_by_logical.get(row["logical_call_id"])
            if intent is None or call is None or row["intent_id"] != intent["intent_id"] or row["intent_hash"] != intent["intent_hash"] or call["intent_hash"] != intent["intent_hash"]:
                issues.append("model result intent/call binding is incomplete")
            call_results = result_call_by_result.get(row["result_id"], [])
            if len(call_results) != 1 or len(result_call_by_logical.get(row["logical_call_id"], [])) != 1:
                issues.append("model result has no unique immutable call binding")
            else:
                result_call = call_results[0]
                try:
                    result_call_payload = json_module.loads(result_call["binding_json"])
                    if _hash(result_call_payload) != result_call["binding_hash"]:
                        issues.append("model result call binding hash mismatch")
                    if result_call["logical_call_id"] != row["logical_call_id"] or result_call["result_id"] != row["result_id"] or result_call["intent_hash"] != row["intent_hash"] or intent is None or result_call["request_hash"] != intent["request_hash"]:
                        issues.append("model result call binding context mismatch")
                    if call is not None and (result_call["group_id"] != call["group_id"] or result_call["call_index"] != call["call_index"] or result_call["role"] != call["role"] or result_call["phase"] != call["phase"]):
                        issues.append("model result call binding does not match its planned call")
                except Exception:
                    issues.append("model result call binding JSON is invalid")
            rows = usage_by_result.get(row["result_id"], [])
            try:
                durable = json_module.loads(row["result_json"])
                has_receipt = bool(durable.get("usage_receipt"))
                billable_result = row["result_status"] == ModelCallStatus.SUCCEEDED.value or has_receipt
                if billable_result and len(rows) != 1:
                    issues.append("billable model result does not have exactly one usage binding")
                if not billable_result and rows:
                    issues.append("non-billable failed model result has an unexpected settled usage binding")
                if row["result_status"] == ModelCallStatus.SUCCEEDED.value and durable.get("result_manifest_version") != "mr-2a.2/v1":
                    issues.append("MR-2A.2 result manifest version is missing")
                for usage in rows:
                    receipt_row = receipts.get(usage["receipt_id"])
                    ledger = ledger_by_id.get(usage["usage_entry_id"])
                    receipt = UsageReceipt.from_mapping(json_module.loads(receipt_row["receipt_json"])) if receipt_row is not None else None
                    expected_provider = str(durable.get("provider_call_id", ""))
                    exact = (
                        receipt is not None
                        and ledger is not None
                        and ledger["operation"] == "usage"
                        and receipt.receipt_id == usage["receipt_id"]
                        and receipt.receipt_hash == usage["receipt_hash"]
                        and receipt.run_id == run_id
                        and intent is not None
                        and receipt.iteration_id == intent["iteration_id"]
                        and receipt.model_identity == intent["model_identity"]
                        and receipt.logical_call_id == row["logical_call_id"]
                        and receipt.intent_hash == row["intent_hash"]
                        and receipt.request_hash == intent["request_hash"]
                        and receipt.provider_call_id == expected_provider
                        and receipt.inference_profile_hash == intent["inference_profile_hash"]
                        and normalize_budget_amount(json_module.loads(ledger["amount_json"])) == normalize_budget_amount(json_module.loads(usage["amount_json"]))
                        and receipt.payload_hash == receipt.computed_payload_hash()
                        and receipt.receipt_hash == receipt.computed_receipt_hash()
                    )
                    if not exact:
                        issues.append("usage receipt/ledger/result binding mismatch")
                    if ledger is not None:
                        provenance = json_module.loads(ledger["provenance_json"])
                        if not isinstance(provenance, Mapping) or provenance.get("receipt_hash") != usage["receipt_hash"]:
                            issues.append("usage ledger reverse mapping is missing")
            except Exception:
                issues.append("model result usage closure is invalid")

        for row in usage_bindings:
            try:
                payload = json_module.loads(row["binding_json"])
                if _hash(payload) != row["binding_hash"] or _hash(payload.get("amount", {})) != row["amount_hash"]:
                    issues.append("runner usage binding hash mismatch")
                result = result_by_id.get(row["result_id"])
                intent = intent_by_logical.get(row["logical_call_id"])
                if result is None or intent is None or result["logical_call_id"] != row["logical_call_id"] or result["run_id"] != run_id or intent["intent_id"] != row["intent_id"] or intent["iteration_id"] != row["iteration_id"] or row["project_id"] != run["project_id"]:
                    issues.append("runner usage binding is orphaned")
            except Exception:
                issues.append("runner usage binding JSON is invalid")

        for row in result_call_bindings:
            if row["result_id"] not in result_by_id or row["logical_call_id"] not in intent_by_logical:
                issues.append("model result call binding is orphaned")

        for ledger in ledger_rows:
            if ledger["operation"] != "usage":
                continue
            try:
                provenance = json_module.loads(ledger["provenance_json"])
            except Exception:
                provenance = {}
                issues.append("budget usage provenance is invalid")
            if isinstance(provenance, Mapping) and provenance.get("server_owned") is True:
                if provenance.get("charge_kind") != "iteration" or normalize_budget_amount(json_module.loads(ledger["amount_json"])) != {"iteration_count": 1}:
                    issues.append("server usage charge is not the single iteration unit")
            elif not any(row["usage_entry_id"] == ledger["entry_id"] for row in usage_bindings):
                issues.append("provider usage ledger entry has no reverse binding")

        iteration_rows = list(connection.execute("SELECT iteration_id FROM max_iterations WHERE run_id=?", (run_id,)))
        for iteration in iteration_rows:
            outcome = connection.execute("SELECT status FROM max_iteration_outcomes WHERE run_id=? AND iteration_id=?", (run_id, iteration["iteration_id"])).fetchone()
            charges = []
            for ledger in ledger_rows:
                if ledger["iteration_id"] != iteration["iteration_id"] or ledger["operation"] != "usage":
                    continue
                try:
                    provenance = json_module.loads(ledger["provenance_json"])
                except Exception:
                    provenance = {}
                if isinstance(provenance, Mapping) and provenance.get("server_owned") is True and provenance.get("charge_kind") == "iteration":
                    charges.append(ledger)
            if outcome is not None and outcome["status"] in {"completed", "aborted"} and len(charges) != 1:
                issues.append("terminal iteration does not have exactly one service iteration charge")
            if outcome is None and charges:
                issues.append("open iteration has a premature service iteration charge")

        for group in groups:
            status = group_status.get(group["group_id"], "")
            projection = group_projection.get(group["group_id"])
            lifecycle_state = projection["lifecycle_state"] if projection is not None and "lifecycle_state" in projection.keys() else PREPARATION_CLAIM_HELD
            group_bindings = [row for row in bindings if row["group_id"] == group["group_id"]]
            declared_count = int(group["call_count"])
            declared_indices = sorted(int(row["call_index"]) for row in group_bindings)
            all_declared_bindings = declared_indices == list(range(declared_count))
            all_calls_terminal = all_declared_bindings
            for call in group_bindings:
                result = result_by_logical.get(call["logical_call_id"])
                result_usage = usage_by_logical.get(call["logical_call_id"], [])
                if result is None or len(result_call_by_logical.get(call["logical_call_id"], [])) != 1:
                    all_calls_terminal = False
                    continue
                try:
                    durable = json_module.loads(result["result_json"])
                    billable = result["result_status"] == ModelCallStatus.SUCCEEDED.value or bool(durable.get("usage_receipt"))
                    if billable:
                        call_terminal = len(result_usage) == 1
                    else:
                        call_terminal = not result_usage
                    reservation = connection.execute(
                        "SELECT entry_id FROM max_budget_ledger WHERE run_id=? AND idempotency_key=? AND operation='reserve'",
                        (run_id, f"mr2a:reserve:{call['logical_call_id']}"),
                    ).fetchone()
                    if reservation is not None:
                        call_terminal = call_terminal and not bool(self.repository._reservation_remaining(connection, run_id=run_id, reservation_id=reservation["entry_id"]))
                    all_calls_terminal = all_calls_terminal and call_terminal
                except Exception:
                    all_calls_terminal = False
            iteration_outcome = connection.execute(
                "SELECT outcome_id, status FROM max_iteration_outcomes WHERE run_id=? AND iteration_id=?",
                (run_id, group["iteration_id"]),
            ).fetchone()
            group_logical_ids = {row["logical_call_id"] for row in group_bindings}
            group_recoveries = [row for row in recovery_rows if row["logical_call_id"] in group_logical_ids]
            controlled_pause = run["status"] == RunStatus.PAUSED.value and any(
                row["disposition"] in {RecoveryDisposition.AMBIGUOUS_PAUSE.value, RecoveryDisposition.ADMIN_DECISION_REQUIRED.value}
                for row in group_recoveries
            )
            if status == "open":
                handoff_issues: list[str] = []
                if lifecycle_state in {PREPARED, JIT_EXECUTING, *TERMINAL_HANDOFF_STATES}:
                    handoff_issues = PreparationHandoffStore.verify_group_handoff(
                        connection,
                        run_id=run_id,
                        group_id=group["group_id"],
                        now=now_dt,
                    )
                    issues.extend(handoff_issues)
                # An open pointer is valid only while this run has a live,
                # fencing-consistent invocation.  In particular, a group
                # whose every declared call already has terminal result and
                # usage cannot remain open after the worker has released its
                # claim.
                handoff_wait_is_valid = lifecycle_state in {PREPARED, JIT_EXECUTING, *TERMINAL_HANDOFF_STATES} and not handoff_issues
                if not live_invocation_claim and not controlled_pause and not handoff_wait_is_valid:
                    issues.append("open_group_without_live_invocation_claim")
                    if all_calls_terminal:
                        issues.append("terminal_ready_group_not_finalized")
                elif iteration_outcome is not None and not all_calls_terminal:
                    issues.append("open_group_has_terminal_iteration_outcome")
            elif status == "completed":
                if iteration_outcome is None or iteration_outcome["status"] != "completed":
                    issues.append("completed_group_missing_completed_iteration_outcome")
                if not all_calls_terminal:
                    issues.append("completed_group_has_nonterminal_call")
            elif status == "aborted":
                if iteration_outcome is None or iteration_outcome["status"] != "aborted":
                    issues.append("aborted_group_missing_aborted_iteration_outcome")
            elif status == "paused":
                if run["status"] != RunStatus.PAUSED.value:
                    issues.append("paused_group_run_is_not_paused")
                if not any(row["disposition"] in {RecoveryDisposition.AMBIGUOUS_PAUSE.value, RecoveryDisposition.ADMIN_DECISION_REQUIRED.value} for row in group_recoveries):
                    issues.append("paused_group_missing_recovery_authority")
            if status == "completed":
                if len(group_bindings) != int(group["call_count"]) or any(row["logical_call_id"] not in result_by_logical for row in group_bindings):
                    issues.append("completed runner call group is incomplete")
                if group["phase"] == "adjudication":
                    deliberation_rows = [row for row in artifact_bindings if row["group_id"] == group["group_id"] and str(row["artifact_type"]).startswith("deliberation_")]
                    expected_artifact_types = {
                        "lead_position": "deliberation_position",
                        "rival_position": "deliberation_position",
                        "rival_cross_examination": "deliberation_cross_examination",
                        "lead_cross_examination_response": "deliberation_correction",
                        "adjudicator": "deliberation_adjudication",
                    }
                    actual_counts: dict[str, int] = {}
                    for row in deliberation_rows:
                        actual_counts[str(row["artifact_type"])] = actual_counts.get(str(row["artifact_type"]), 0) + 1
                        intent = intent_by_logical.get(row["logical_call_id"])
                        call_id = ""
                        if intent is not None:
                            try:
                                call_id = str(json_module.loads(intent["intent_json"]).get("call_spec_id", ""))
                            except Exception:
                                issues.append("deliberation artifact intent manifest is invalid")
                        if expected_artifact_types.get(call_id) != row["artifact_type"]:
                            issues.append("deliberation artifact is bound to the wrong logical call")
                    if len(group_bindings) != 5 or actual_counts != {"deliberation_position": 2, "deliberation_cross_examination": 1, "deliberation_correction": 1, "deliberation_adjudication": 1}:
                        issues.append("completed adjudication group lacks all five call artifacts")
            if status in {"completed", "aborted"}:
                for call in group_bindings:
                    if connection.execute("SELECT 1 FROM max_runner_attempt_outcomes WHERE run_id=? AND logical_call_id=?", (run_id, call["logical_call_id"])).fetchone() is None:
                        issues.append("closed runner call has no terminal outcome")
                    reserve = connection.execute("SELECT entry_id FROM max_budget_ledger WHERE run_id=? AND idempotency_key=? AND operation='reserve'", (run_id, f"mr2a:reserve:{call['logical_call_id']}")).fetchone()
                    if reserve is not None:
                        try:
                            if self.repository._reservation_remaining(connection, run_id=run_id, reservation_id=reserve["entry_id"]):
                                issues.append("closed runner call has an open budget reservation")
                        except Exception:
                            issues.append("runner reservation lineage cannot be reconstructed")

        for row in artifact_bindings:
            try:
                payload = json_module.loads(row["binding_json"])
                if _hash(payload) != row["binding_hash"] or row["intent_hash"] != payload.get("intent_hash") or row["request_hash"] != payload.get("request_hash"):
                    issues.append("runner artifact binding hash mismatch")
                intent = intent_by_logical.get(row["logical_call_id"])
                result = result_by_id.get(row["result_id"])
                if intent is None or result is None or intent["intent_hash"] != row["intent_hash"] or intent["request_hash"] != row["request_hash"] or result["logical_call_id"] != row["logical_call_id"]:
                    issues.append("runner artifact binding is orphaned")
                if str(row["artifact_type"]).startswith("deliberation_") and result is not None:
                    durable = json_module.loads(result["result_json"])
                    artifact = durable.get("proposal", {}).get("deliberation")
                    if artifact is None or canonical_sha256(artifact) != row["artifact_hash"]:
                        issues.append("deliberation artifact is not produced by its result")
                elif connection.execute("SELECT 1 FROM max_iteration_artifact_links WHERE run_id=? AND iteration_id=? AND artifact_id=? AND artifact_hash=?", (run_id, row["iteration_id"], row["artifact_id"], row["artifact_hash"])).fetchone() is None:
                    issues.append("runner artifact output has no immutable iteration link")
            except Exception:
                issues.append("runner artifact binding JSON is invalid")

        conflict_counts: dict[str, list[int]] = {}
        for row in conflicts:
            try:
                payload = json_module.loads(row["conflict_json"])
                record = EpistemicConflictRecord.from_mapping(payload)
                expected_state = connection.execute("SELECT state_hash FROM max_research_states WHERE run_id=?", (run_id,)).fetchone()
                expected_versions = tuple(sorted(_hash(_loads(item["object_json"])) for item in connection.execute("SELECT v.object_json FROM max_canonical_object_versions v JOIN max_run_object_memberships m ON m.version_id=v.version_id WHERE m.run_id=? AND m.project_id=? ORDER BY v.version_id", (run_id, run["project_id"]))))
                if _hash(payload) != row["conflict_hash"] or not validate_epistemic_conflict_record(record).ok or record.conflict_id != row["conflict_id"] or record.run_id != run_id or record.project_id != run["project_id"] or record.intent_hash != row["intent_hash"] or record.request_hash != row["request_hash"] or expected_state is None or record.canonical_state_hash != expected_state["state_hash"] or tuple(sorted(record.canonical_version_hashes)) != expected_versions:
                    issues.append("epistemic conflict binding or hash mismatch")
                conflict_counts.setdefault(row["fingerprint"], []).append(int(row["repeat_count"]))
            except Exception:
                issues.append("epistemic conflict record is invalid")
        for fingerprint, counts in conflict_counts.items():
            if sorted(counts) != list(range(1, len(counts) + 1)):
                issues.append("epistemic conflict repeat sequence is not contiguous")

    def verify_run(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True, verify_schema=False)
        try:
            try:
                schema_manifest = verify_schema_manifest(connection)
            except Exception:
                schema_manifest = {
                    "ok": False,
                    "issues": ["Max schema manifest verification failed"],
                }
            issues: list[str] = list(schema_manifest.get("issues", ()))
            run = self.repository._run_row(connection, run_id)
            plan_rows = list(connection.execute("SELECT * FROM max_runner_plans WHERE run_id=? ORDER BY sequence_no", (run_id,)))
            intent_rows = list(connection.execute("SELECT * FROM max_model_call_intents WHERE run_id=? ORDER BY created_at", (run_id,)))
            result_rows = list(connection.execute("SELECT * FROM max_model_call_results WHERE run_id=? ORDER BY created_at", (run_id,)))
            attempt_rows = list(connection.execute("SELECT * FROM max_model_call_attempts WHERE run_id=? ORDER BY logical_call_id, attempt_no", (run_id,)))
            recovery_rows = list(connection.execute("SELECT * FROM max_runner_recovery_decisions WHERE run_id=? ORDER BY created_at", (run_id,)))
            outcome_rows = list(connection.execute("SELECT * FROM max_runner_attempt_outcomes WHERE run_id=? ORDER BY created_at", (run_id,)))
            profile_hashes = {row["profile_hash"] for row in plan_rows}
            expected_plan_sequence = 1
            for row in plan_rows:
                if int(row["sequence_no"]) != expected_plan_sequence:
                    issues.append("runner plan sequence is not contiguous")
                expected_plan_sequence += 1
            last_attempt_no: dict[str, int] = {}
            for row in attempt_rows:
                try:
                    payload = __import__("json").loads(row["attempt_json"])
                    if _hash(payload) != row["attempt_hash"] or payload.get("logical_call_id") != row["logical_call_id"] or int(payload.get("attempt_no")) != int(row["attempt_no"]) or int(row["attempt_no"]) != last_attempt_no.get(row["logical_call_id"], 0) + 1:
                        issues.append("model call attempt sequence or hash mismatch")
                    if connection.execute("SELECT 1 FROM max_model_call_intents WHERE logical_call_id=? AND run_id=?", (row["logical_call_id"], run_id)).fetchone() is None:
                        issues.append("model call attempt is orphaned")
                    last_attempt_no[row["logical_call_id"]] = int(row["attempt_no"])
                except Exception:
                    issues.append("model call attempt JSON is invalid")
            for row in plan_rows:
                try:
                    plan = RunnerPlan.from_mapping(__import__("json").loads(row["plan_json"]))
                    profile = connection.execute("SELECT profile_hash, profile_json, model_identity, inference_profile_hash FROM max_runner_profiles WHERE profile_hash=?", (row["profile_hash"],)).fetchone()
                    stored_profile = RunnerProfile.from_mapping(__import__("json").loads(profile["profile_json"])) if profile is not None else None
                    profile_ok = stored_profile is not None and stored_profile.profile_hash == profile["profile_hash"] and plan.model_identity == profile["model_identity"] and plan.inference_profile_hash == profile["inference_profile_hash"]
                    if plan.plan_hash != row["plan_hash"] or plan.plan_id != row["plan_id"] or plan.project_id != run["project_id"] or plan.input_state_hash != row["input_state_hash"] or not profile_ok:
                        issues.append("runner plan hash or binding mismatch")
                    iteration = connection.execute("SELECT run_id, project_id FROM max_iterations WHERE iteration_id=?", (row["iteration_id"],)).fetchone()
                    if iteration is not None and (iteration["run_id"] != run_id or iteration["project_id"] != run["project_id"]):
                        issues.append("runner plan iteration crosses Run boundary")
                except Exception:
                    issues.append("runner plan JSON is invalid")
            for row in intent_rows:
                try:
                    manifest = __import__("json").loads(row["intent_json"])
                    manifest_row = connection.execute("SELECT manifest_json, manifest_hash FROM max_runner_intent_manifests WHERE intent_id=? AND logical_call_id=?", (row["intent_id"], row["logical_call_id"])).fetchone()
                    iteration_row = connection.execute("SELECT run_id, project_id, input_state_hash FROM max_iterations WHERE iteration_id=?", (row["iteration_id"],)).fetchone()
                    manifest_ok = manifest_row is not None and manifest_row["manifest_json"] == row["intent_json"] and _hash(manifest) == manifest_row["manifest_hash"]
                    expected = {"project_id": row["project_id"], "run_id": run_id, "iteration_id": row["iteration_id"], "input_state_hash": row["input_state_hash"], "role_packet_id": row["role_packet_id"], "round_type": row["round_type"], "model_identity": row["model_identity"], "inference_profile_hash": row["inference_profile_hash"], "request_hash": row["request_hash"], "idempotency_key": row["idempotency_key"], "logical_call_id": row["logical_call_id"], "intent_id": row["intent_id"], "intent_hash": row["intent_hash"]}
                    fields_ok = all(manifest.get(key) == value for key, value in expected.items())
                    if not manifest_ok or not fields_ok or row["run_id"] != run_id or row["project_id"] != run["project_id"] or iteration_row is None or iteration_row["run_id"] != run_id or iteration_row["project_id"] != run["project_id"] or row["input_state_hash"] != iteration_row["input_state_hash"]:
                        issues.append("model intent binding mismatch")
                    if connection.execute("SELECT 1 FROM max_runner_plans WHERE plan_id=? AND run_id=?", (row["plan_id"], run_id)).fetchone() is None:
                        issues.append("model intent plan is missing")
                except Exception:
                    issues.append("model intent JSON is invalid")
                ack = connection.execute("SELECT * FROM max_model_dispatch_acks WHERE logical_call_id=?", (row["logical_call_id"],)).fetchone()
                result = connection.execute("SELECT * FROM max_model_call_results WHERE logical_call_id=?", (row["logical_call_id"],)).fetchone()
                if result is not None:
                    try:
                        durable = __import__("json").loads(result["result_json"])
                        response = {"logical_call_id": durable["logical_call_id"], "intent_hash": durable["intent_hash"], "model_identity": durable["model_identity"], "inference_profile_hash": durable["inference_profile_hash"], "status": durable["status"], "proposal": durable.get("proposal", {}), "usage_receipt": durable.get("usage_receipt", {}), "provider_call_id": durable.get("provider_call_id", "fixture-call"), "dispatch_known": durable.get("dispatch_known", True), "error_code": durable.get("error_code"), "response_hash": durable.get("response_hash", "")}
                        parsed = ModelCallResult.from_mapping({"logical_call_id": durable["logical_call_id"], "intent_hash": durable["intent_hash"], "status": durable["status"], "response": response, "authoritative": durable.get("authoritative", True), "result_hash": durable.get("result_hash", "")})
                        if parsed.result_hash != result["result_hash"] or parsed.intent_hash != row["intent_hash"] or result["intent_id"] != row["intent_id"] or durable.get("result_manifest_version") not in {"mr-2a.1/v1", "mr-2a.2/v1"}:
                            issues.append("model result binding or hash mismatch")
                        if result["usage_hash"] != _hash(__import__("json").loads(result["usage_json"])):
                            issues.append("model usage hash mismatch")
                    except Exception:
                        issues.append("model result JSON is invalid")
                if ack is not None and ack["logical_call_id"] != row["logical_call_id"]:
                    issues.append("dispatch acknowledgement is orphaned")
            for row in connection.execute("SELECT * FROM max_model_dispatch_acks WHERE run_id=?", (run_id,)):
                if connection.execute("SELECT 1 FROM max_model_call_intents WHERE logical_call_id=? AND run_id=?", (row["logical_call_id"], run_id)).fetchone() is None:
                    issues.append("dispatch acknowledgement is orphaned")
                try:
                    if _hash(__import__("json").loads(row["ack_json"])) != row["ack_hash"]:
                        issues.append("dispatch acknowledgement hash mismatch")
                except Exception:
                    issues.append("dispatch acknowledgement JSON is invalid")
            for row in recovery_rows:
                try:
                    if _hash(__import__("json").loads(row["decision_json"])) != row["decision_hash"]:
                        issues.append("runner recovery decision hash mismatch")
                    if connection.execute("SELECT 1 FROM max_model_call_intents WHERE logical_call_id=? AND run_id=?", (row["logical_call_id"], run_id)).fetchone() is None:
                        issues.append("runner recovery decision is orphaned")
                except Exception:
                    issues.append("runner recovery decision JSON is invalid")
            current = connection.execute("SELECT * FROM max_runner_plan_current WHERE run_id=?", (run_id,)).fetchone()
            if current is not None:
                if connection.execute("SELECT 1 FROM max_runner_plans WHERE plan_id=? AND run_id=?", (current["plan_id"], run_id)).fetchone() is None:
                    issues.append("current runner plan is orphaned")
                if current["active_logical_call_id"] is not None and connection.execute("SELECT 1 FROM max_model_call_intents WHERE logical_call_id=? AND run_id=?", (current["active_logical_call_id"], run_id)).fetchone() is None:
                    issues.append("current logical call is orphaned")
            for row in outcome_rows:
                try:
                    payload = __import__("json").loads(row["outcome_json"])
                    if _hash(payload) != row["outcome_hash"] or payload.get("run_id") != run_id or payload.get("logical_call_id") != row["logical_call_id"] or payload.get("iteration_id") != row["iteration_id"]:
                        issues.append("runner outcome hash or binding mismatch")
                except Exception:
                    issues.append("runner outcome JSON is invalid")
                if row["change_set_id"] is not None and connection.execute("SELECT 1 FROM max_canonical_change_sets WHERE change_set_id=? AND run_id=?", (row["change_set_id"], run_id)).fetchone() is None:
                    issues.append("runner outcome change-set link is orphaned")
                if row["iteration_outcome_id"] is not None and connection.execute("SELECT 1 FROM max_iteration_outcomes WHERE outcome_id=? AND run_id=?", (row["iteration_outcome_id"], run_id)).fetchone() is None:
                    issues.append("runner outcome iteration link is orphaned")
            for row in connection.execute("SELECT * FROM max_runner_links WHERE run_id=?", (run_id,)):
                if connection.execute("SELECT 1 FROM max_model_call_intents WHERE logical_call_id=? AND run_id=?", (row["logical_call_id"], run_id)).fetchone() is None:
                    issues.append("runner link intent is orphaned")
                    continue
                target_hash: str | None = None
                link_type = row["link_type"]
                if link_type == "change_set":
                    target = connection.execute("SELECT change_set_hash FROM max_canonical_change_sets WHERE change_set_id=? AND run_id=?", (row["target_id"], run_id)).fetchone()
                    target_hash = target["change_set_hash"] if target is not None else None
                elif link_type == "iteration_outcome":
                    target = connection.execute("SELECT outcome_hash FROM max_iteration_outcomes WHERE outcome_id=? AND run_id=?", (row["target_id"], run_id)).fetchone()
                    target_hash = target["outcome_hash"] if target is not None else None
                elif link_type == "budget_entry":
                    target = connection.execute("SELECT entry_id FROM max_budget_ledger WHERE entry_id=? AND run_id=?", (row["target_id"], run_id)).fetchone()
                    target_hash = canonical_sha256({"entry_id": row["target_id"], "logical_call_id": row["logical_call_id"]}) if target is not None else None
                elif link_type == "artifact":
                    target = connection.execute("SELECT artifact_hash FROM max_iteration_artifact_links WHERE artifact_id=? AND run_id=? ORDER BY created_at DESC LIMIT 1", (row["target_id"], run_id)).fetchone()
                    target_hash = target["artifact_hash"] if target is not None else None
                elif link_type == "checkpoint":
                    target = connection.execute("SELECT checkpoint_json FROM max_checkpoints WHERE checkpoint_id=? AND run_id=?", (row["target_id"], run_id)).fetchone()
                    if target is not None:
                        try:
                            target_hash = canonical_sha256(_loads(target["checkpoint_json"]))
                        except Exception:
                            target_hash = None
                if target_hash is None or target_hash != row["target_hash"]:
                    issues.append("runner link target hash or binding mismatch")
            groups = list(connection.execute("SELECT * FROM max_runner_call_groups WHERE run_id=? ORDER BY created_at", (run_id,)))
            bindings = list(connection.execute("SELECT * FROM max_runner_call_bindings WHERE run_id=? ORDER BY group_id, call_index", (run_id,)))
            for group in groups:
                try:
                    payload = __import__("json").loads(group["group_json"])
                    if _hash(payload) != group["group_hash"] or payload.get("group_id") != group["group_id"] or payload.get("run_id") != run_id or int(payload.get("call_count", -1)) != int(group["call_count"]):
                        issues.append("runner call group hash or binding mismatch")
                    indices = [int(item["call_index"]) for item in bindings if item["group_id"] == group["group_id"]]
                    if indices and indices != list(range(max(indices) + 1)):
                        issues.append("runner call group index is not contiguous")
                    if max(indices, default=-1) >= int(group["call_count"]):
                        issues.append("runner call group index exceeds its declared count")
                except Exception:
                    issues.append("runner call group JSON is invalid")
            for binding in bindings:
                try:
                    payload = __import__("json").loads(binding["binding_json"])
                    if _hash(payload) != binding["binding_hash"] or payload.get("logical_call_id") != binding["logical_call_id"] or payload.get("intent_hash") != binding["intent_hash"]:
                        issues.append("runner call binding hash mismatch")
                    intent = connection.execute("SELECT run_id, iteration_id, intent_hash FROM max_model_call_intents WHERE logical_call_id=?", (binding["logical_call_id"],)).fetchone()
                    if intent is None or intent["run_id"] != run_id or intent["iteration_id"] != binding["iteration_id"] or intent["intent_hash"] != binding["intent_hash"]:
                        issues.append("runner call binding intent is orphaned")
                except Exception:
                    issues.append("runner call binding JSON is invalid")
            for row in connection.execute("SELECT * FROM max_runner_invocation_claims WHERE run_id=?", (run_id,)):
                try:
                    payload = __import__("json").loads(row["claim_json"])
                    claim_binding_ok = payload.get("claim_id") == row["claim_id"] if row["status"] == "active" else payload.get("released_claim_id") is not None
                    if row["status"] == "released":
                        released_claim = connection.execute("SELECT actor_id, actor_session, fencing_token FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=? AND status='active'", (payload.get("released_claim_id"), run_id)).fetchone()
                        if released_claim is None or released_claim["actor_id"] != row["actor_id"] or released_claim["actor_session"] != row["actor_session"] or int(released_claim["fencing_token"]) != int(row["fencing_token"]):
                            claim_binding_ok = False
                    if _hash(payload) != row["claim_hash"] or not claim_binding_ok or payload.get("run_id") != run_id or payload.get("fencing_token") != row["fencing_token"]:
                        issues.append("runner invocation claim hash or binding mismatch")
                except Exception:
                    issues.append("runner invocation claim JSON is invalid")
            for row in connection.execute("SELECT * FROM max_runner_recovery_consumptions WHERE run_id=?", (run_id,)):
                try:
                    payload = __import__("json").loads(row["result_json"])
                    if _hash(payload) != row["result_hash"] or payload.get("run_id") != run_id or payload.get("logical_call_id") != row["logical_call_id"] or payload.get("intent_hash") != row["intent_hash"] or connection.execute("SELECT 1 FROM max_runner_recovery_decisions WHERE recovery_id=? AND run_id=?", (row["recovery_id"], run_id)).fetchone() is None:
                        issues.append("recovery consumption binding or hash mismatch")
                except Exception:
                    issues.append("recovery consumption JSON is invalid")
            cognitive_rows = list(connection.execute("SELECT * FROM max_runner_cognitive_artifacts WHERE run_id=?", (run_id,)))
            for row in cognitive_rows:
                try:
                    artifact = __import__("json").loads(row["artifact_json"])
                    if _hash(artifact) != row["artifact_hash"]:
                        issues.append("cognitive artifact hash mismatch")
                    if row["artifact_type"] in {"attack_record", "attack"}:
                        typed = AttackRecord.from_mapping(artifact)
                        if typed.run_id != run_id or typed.project_id != run["project_id"] or typed.iteration_id != row["iteration_id"]:
                            issues.append("AttackRecord binding mismatch")
                    elif row["artifact_type"] in {"discussion_session", "adjudication"}:
                        typed = DiscussionSession.from_mapping(artifact)
                        if typed.run_id != run_id or typed.project_id != run["project_id"]:
                            issues.append("DiscussionSession binding mismatch")
                    elif row["artifact_type"] == "rehydration_output":
                        typed = RehydrationOutput.from_mapping(artifact)
                        if not typed.accepted or typed.state is None or typed.state.run_id != run_id:
                            issues.append("RehydrationOutput binding mismatch")
                except Exception:
                    issues.append("cognitive artifact is invalid")
            self._verify_mr2a2_closure(
                connection,
                run_id=run_id,
                run=run,
                intent_rows=intent_rows,
                result_rows=result_rows,
                outcome_rows=outcome_rows,
                groups=groups,
                bindings=bindings,
                issues=issues,
            )
            current_group_rows = list(connection.execute("SELECT * FROM max_runner_call_group_current WHERE run_id=?", (run_id,)))
            for current_group in current_group_rows:
                if connection.execute("SELECT 1 FROM max_runner_call_groups WHERE group_id=? AND run_id=?", (current_group["group_id"], run_id)).fetchone() is None:
                    issues.append("current runner call group is orphaned")
            return {"ok": not issues and bool(schema_manifest.get("ok", False)), "schema_manifest": schema_manifest, "plan_count": len(plan_rows), "intent_count": len(intent_rows), "attempt_count": len(attempt_rows), "result_count": len(result_rows), "recovery_count": len(recovery_rows), "outcome_count": len(outcome_rows), "profile_count": len(profile_hashes), "call_group_count": len(groups), "call_binding_count": len(bindings), "cognitive_artifact_count": len(cognitive_rows), "issues": sorted(set(issues))}
        finally:
            connection.close()

    def status(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            current = connection.execute("SELECT plan_id, iteration_id, active_logical_call_id FROM max_runner_plan_current WHERE run_id=?", (run_id,)).fetchone()
            lease = connection.execute("SELECT runner_profile_hash, owner_id, session_id, fencing_token, expires_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
            return {"current_plan_id": current["plan_id"] if current else None, "current_iteration_id": current["iteration_id"] if current else None, "active_logical_call_id": current["active_logical_call_id"] if current else None, "runner_profile_hash": lease["runner_profile_hash"] if lease else None, "runner_owner_id": lease["owner_id"] if lease else None, "runner_session": lease["session_id"] if lease else None, "runner_lease_active": bool(lease and lease["runner_profile_hash"] and _parse_timestamp(lease["expires_at"]) and _parse_timestamp(lease["expires_at"]) > _utc_now(self.repository.clock)), "plan_count": connection.execute("SELECT COUNT(*) FROM max_runner_plans WHERE run_id=?", (run_id,)).fetchone()[0], "intent_count": connection.execute("SELECT COUNT(*) FROM max_model_call_intents WHERE run_id=?", (run_id,)).fetchone()[0], "attempt_count": connection.execute("SELECT COUNT(*) FROM max_model_call_attempts WHERE run_id=?", (run_id,)).fetchone()[0], "result_count": connection.execute("SELECT COUNT(*) FROM max_model_call_results WHERE run_id=?", (run_id,)).fetchone()[0]}
        finally:
            connection.close()


__all__ = ["RunnerPersistence"]
