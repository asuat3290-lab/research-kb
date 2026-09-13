"""MR-3 restartable foreground worker orchestration.

The worker is deliberately not a hidden daemon.  One explicit process calls
``run``; an operating-system supervisor may restart that process.  Durable
commands, heartbeats, the fenced lease, scheduler state and runner state are
the recovery authority.  Recent model summaries are never used as authority.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Callable, Mapping

from ...policy import Actor
from ..contract import canonical_json, canonical_sha256, make_stable_id
from ..persistence.db import MaxControlError, control_transaction
from ..persistence.repository import MaxControlRepository, _actor_fields, _parse_timestamp, _timestamp, _utc_now


_COMMANDS = {"pause", "drain", "stop"}
_STATES = {"starting", "running", "draining", "paused", "stopped", "failed"}


def _reason(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 2_000 or "\r" in value or "\n" in value:
        raise MaxControlError("worker command reason is invalid")
    return value.strip()


class WorkerControl:
    """Append-only commands and heartbeats with one mutable projection."""

    def __init__(self, repository: MaxControlRepository) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("WorkerControl requires MaxControlRepository")
        self.repository = repository

    @staticmethod
    def _current_value(*, run_id: str, project_id: str, worker_id: str, worker_session: str, fencing_token: int, state: str, tick_count: int, last_heartbeat_id: str | None, stop_reason: str | None) -> dict[str, Any]:
        return {"run_id": run_id, "project_id": project_id, "worker_id": worker_id, "worker_session": worker_session, "fencing_token": int(fencing_token), "state": state, "tick_count": int(tick_count), "last_heartbeat_id": last_heartbeat_id, "stop_reason": stop_reason}

    def issue_command(self, *, run_id: str, command: str, reason: str, actor: Actor) -> dict[str, Any]:
        if not actor.is_admin or command not in _COMMANDS:
            raise MaxControlError("worker command requires human admin authority")
        reason_hash = canonical_sha256(_reason(reason))
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT project_id, status, state_version FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None or run["status"] not in {"RUNNING", "PAUSED"}:
                    raise MaxControlError("worker command run is not active")
                value = {"run_id": run_id, "project_id": run["project_id"], "command": command, "reason_hash": reason_hash, "run_state_version": int(run["state_version"])}
                command_hash = canonical_sha256(value); command_id = make_stable_id("worker_command", command_hash[:64])
                existing = connection.execute("SELECT command_json, command_hash FROM max_worker_commands WHERE command_id=?", (command_id,)).fetchone()
                if existing is not None:
                    if existing["command_hash"] != command_hash or json.loads(existing["command_json"]) != value:
                        raise MaxControlError("worker command ID collision")
                    consumed = connection.execute("SELECT consumption_id FROM max_worker_command_consumptions WHERE command_id=?", (command_id,)).fetchone()
                    return {"command_id": command_id, "command_hash": command_hash, "command": command, "consumed": consumed is not None, "idempotent": True}
                pending = connection.execute(
                    "SELECT c.command_id FROM max_worker_commands c "
                    "LEFT JOIN max_worker_command_consumptions x ON x.command_id=c.command_id "
                    "WHERE c.run_id=? AND x.command_id IS NULL LIMIT 1",
                    (run_id,),
                ).fetchone()
                if pending is not None:
                    raise MaxControlError("worker run already has a pending command")
                now = _timestamp(self.repository.clock); actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                connection.execute("INSERT INTO max_worker_commands(command_id, run_id, project_id, command, reason_hash, issued_at, command_json, command_hash, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (command_id, run_id, run["project_id"], command, reason_hash, now, canonical_json(value), command_hash, actor_id, actor_kind, actor_session))
                self.repository._append_event(connection, run_id=run_id, event_type="worker_command_issued", payload={"command_id": command_id, "command_hash": command_hash, "command": command}, actor=actor, now=now)
            return {"command_id": command_id, "command_hash": command_hash, "command": command, "consumed": False, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("worker command conflicts with immutable history") from exc
        finally:
            connection.close()

    def pending_command(self, *, run_id: str) -> dict[str, Any] | None:
        connection = self.repository._connect(read_only=True)
        try:
            row = connection.execute("SELECT c.* FROM max_worker_commands c LEFT JOIN max_worker_command_consumptions x ON x.command_id=c.command_id WHERE c.run_id=? AND x.command_id IS NULL ORDER BY c.issued_at, c.command_id LIMIT 1", (run_id,)).fetchone()
            if row is None:
                return None
            value = json.loads(row["command_json"])
            if canonical_sha256(value) != row["command_hash"] or value.get("command") != row["command"] or value.get("run_id") != row["run_id"]:
                raise MaxControlError("worker command hash is invalid")
            return {"command_id": row["command_id"], "command_hash": row["command_hash"], "command": row["command"], "issued_at": row["issued_at"]}
        finally:
            connection.close()

    def consume_command(self, *, command_id: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        if actor.is_admin or actor.actor_kind not in {"worker", "runner", "agent"}:
            raise MaxControlError("worker command consumption requires a non-admin worker")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                command = connection.execute("SELECT * FROM max_worker_commands WHERE command_id=?", (command_id,)).fetchone()
                if command is None:
                    raise MaxControlError("worker command was not found")
                existing = connection.execute("SELECT * FROM max_worker_command_consumptions WHERE command_id=?", (command_id,)).fetchone()
                if existing is not None:
                    if existing["worker_id"] != actor.actor_id or existing["worker_session"] != actor.session_id or int(existing["fencing_token"]) != fencing_token:
                        raise MaxControlError("worker command was consumed by another worker")
                    return {"consumption_id": existing["consumption_id"], "command_id": command_id, "command": command["command"], "idempotent": True}
                now = _timestamp(self.repository.clock)
                self.repository._assert_fence(connection, run_id=command["run_id"], actor=actor, fencing_token=fencing_token, now=now)
                value = {"command_id": command_id, "run_id": command["run_id"], "worker_id": actor.actor_id, "worker_session": actor.session_id, "fencing_token": fencing_token, "consumed_at": now}
                consumption_hash = canonical_sha256(value); consumption_id = make_stable_id("worker_command_consumption", consumption_hash[:64])
                connection.execute("INSERT INTO max_worker_command_consumptions(consumption_id, command_id, run_id, worker_id, worker_session, fencing_token, consumed_at, consumption_json, consumption_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (consumption_id, command_id, command["run_id"], actor.actor_id, actor.session_id, fencing_token, now, canonical_json(value), consumption_hash))
                self.repository._append_event(connection, run_id=command["run_id"], event_type="worker_command_consumed", payload={"command_id": command_id, "consumption_id": consumption_id, "command": command["command"]}, actor=actor, now=now)
            return {"consumption_id": consumption_id, "command_id": command_id, "command": command["command"], "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("worker command was concurrently consumed") from exc
        finally:
            connection.close()

    def heartbeat(self, *, run_id: str, actor: Actor, fencing_token: int, state: str, tick_count: int, stop_reason: str | None = None) -> dict[str, Any]:
        if state not in _STATES or actor.is_admin or isinstance(tick_count, bool) or not isinstance(tick_count, int) or tick_count < 0:
            raise MaxControlError("worker heartbeat fields are invalid")
        if stop_reason is not None and (not isinstance(stop_reason, str) or not stop_reason or len(stop_reason) > 256 or "\r" in stop_reason or "\n" in stop_reason):
            raise MaxControlError("worker stop reason is invalid")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT project_id, current_state_hash, status FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None:
                    raise MaxControlError("worker heartbeat run was not found")
                # A final heartbeat may follow a worker-owned pause, which
                # releases the run lease.  Otherwise require the current fence.
                if not (state == "paused" and run["status"] == "PAUSED"):
                    self.repository._assert_fence(connection, run_id=run_id, actor=actor, fencing_token=fencing_token, now=_timestamp(self.repository.clock))
                current = connection.execute("SELECT * FROM max_worker_current WHERE run_id=?", (run_id,)).fetchone()
                if current is not None:
                    if int(current["fencing_token"]) > fencing_token:
                        raise MaxControlError("stale worker cannot append a heartbeat")
                    if int(current["fencing_token"]) == fencing_token and (current["worker_id"] != actor.actor_id or current["worker_session"] != actor.session_id):
                        raise MaxControlError("worker heartbeat actor differs at the current fence")
                    if tick_count < int(current["tick_count"]):
                        raise MaxControlError("worker heartbeat tick count regressed")
                sequence = int(connection.execute("SELECT COALESCE(MAX(sequence_no),0)+1 FROM max_worker_heartbeats WHERE run_id=?", (run_id,)).fetchone()[0])
                now = _timestamp(self.repository.clock)
                value = {"run_id": run_id, "project_id": run["project_id"], "sequence_no": sequence, "worker_id": actor.actor_id, "worker_session": actor.session_id, "fencing_token": fencing_token, "worker_state": state, "tick_count": tick_count, "state_hash": run["current_state_hash"], "stop_reason": stop_reason, "created_at": now}
                heartbeat_hash = canonical_sha256(value); heartbeat_id = make_stable_id("worker_heartbeat", heartbeat_hash[:64])
                connection.execute("INSERT INTO max_worker_heartbeats(heartbeat_id, run_id, project_id, sequence_no, worker_id, worker_session, fencing_token, worker_state, tick_count, state_hash, heartbeat_json, heartbeat_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (heartbeat_id, run_id, run["project_id"], sequence, actor.actor_id, actor.session_id, fencing_token, state, tick_count, run["current_state_hash"], canonical_json(value), heartbeat_hash, now))
                current_value = self._current_value(run_id=run_id, project_id=run["project_id"], worker_id=actor.actor_id, worker_session=actor.session_id, fencing_token=fencing_token, state=state, tick_count=tick_count, last_heartbeat_id=heartbeat_id, stop_reason=stop_reason)
                connection.execute("INSERT INTO max_worker_current(run_id, project_id, worker_id, worker_session, fencing_token, state, tick_count, last_heartbeat_id, stop_reason, current_json, current_hash, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET project_id=excluded.project_id, worker_id=excluded.worker_id, worker_session=excluded.worker_session, fencing_token=excluded.fencing_token, state=excluded.state, tick_count=excluded.tick_count, last_heartbeat_id=excluded.last_heartbeat_id, stop_reason=excluded.stop_reason, current_json=excluded.current_json, current_hash=excluded.current_hash, updated_at=excluded.updated_at", (run_id, run["project_id"], actor.actor_id, actor.session_id, fencing_token, state, tick_count, heartbeat_id, stop_reason, canonical_json(current_value), canonical_sha256(current_value), now))
                self.repository._append_event(connection, run_id=run_id, event_type="worker_heartbeat", payload={"heartbeat_id": heartbeat_id, "heartbeat_hash": heartbeat_hash, "sequence_no": sequence, "worker_state": state, "tick_count": tick_count, "state_hash": run["current_state_hash"], "stop_reason": stop_reason}, actor=actor, now=now)
            return {"heartbeat_id": heartbeat_id, "heartbeat_hash": heartbeat_hash, "sequence_no": sequence, "state": state, "tick_count": tick_count}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("worker heartbeat conflicted with another process") from exc
        finally:
            connection.close()

    def status(self, *, run_id: str) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            current = connection.execute("SELECT * FROM max_worker_current WHERE run_id=?", (run_id,)).fetchone()
            pending = connection.execute("SELECT COUNT(*) FROM max_worker_commands c LEFT JOIN max_worker_command_consumptions x ON x.command_id=c.command_id WHERE c.run_id=? AND x.command_id IS NULL", (run_id,)).fetchone()[0]
            if current is None:
                return {"run_id": run_id, "current": None, "pending_command_count": int(pending), "heartbeat_count": 0}
            value = json.loads(current["current_json"]); expected = self._current_value(run_id=current["run_id"], project_id=current["project_id"], worker_id=current["worker_id"], worker_session=current["worker_session"], fencing_token=int(current["fencing_token"]), state=current["state"], tick_count=int(current["tick_count"]), last_heartbeat_id=current["last_heartbeat_id"], stop_reason=current["stop_reason"])
            if value != expected or canonical_sha256(value) != current["current_hash"]:
                raise MaxControlError("worker current projection is invalid")
            public = {key: value[key] for key in ("run_id", "project_id", "worker_id", "state", "tick_count", "last_heartbeat_id", "stop_reason")}
            return {"run_id": run_id, "current": public, "pending_command_count": int(pending), "heartbeat_count": int(connection.execute("SELECT COUNT(*) FROM max_worker_heartbeats WHERE run_id=?", (run_id,)).fetchone()[0])}
        finally:
            connection.close()

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        issues: list[str] = []; counts = {"commands": 0, "command_consumptions": 0, "heartbeats": 0, "current": 0}
        connection = self.repository._connect(read_only=True)
        try:
            parameters = ((run_id,) if run_id is not None else ())
            where = " WHERE run_id=?" if run_id is not None else ""
            for row in connection.execute("SELECT * FROM max_worker_commands" + where, parameters):
                counts["commands"] += 1
                try:
                    value = json.loads(row["command_json"])
                    if canonical_sha256(value) != row["command_hash"] or value.get("run_id") != row["run_id"] or value.get("command") != row["command"]: issues.append("worker command hash mismatch")
                except Exception: issues.append("worker command is invalid")
            for row in connection.execute("SELECT * FROM max_worker_command_consumptions" + where, parameters):
                counts["command_consumptions"] += 1
                try:
                    value = json.loads(row["consumption_json"])
                    if canonical_sha256(value) != row["consumption_hash"] or value.get("command_id") != row["command_id"]: issues.append("worker command consumption hash mismatch")
                except Exception: issues.append("worker command consumption is invalid")
            run_ids = [row[0] for row in connection.execute("SELECT DISTINCT run_id FROM max_worker_heartbeats" + where, parameters)]
            pending_rows = list(connection.execute(
                "SELECT c.run_id, COUNT(*) AS pending_count FROM max_worker_commands c "
                "LEFT JOIN max_worker_command_consumptions x ON x.command_id=c.command_id "
                + ("WHERE c.run_id=? AND x.command_id IS NULL " if run_id is not None else "WHERE x.command_id IS NULL ")
                + "GROUP BY c.run_id",
                parameters,
            ))
            if any(int(row["pending_count"]) > 1 for row in pending_rows):
                issues.append("worker run has conflicting pending commands")
            for selected_run in run_ids:
                heartbeats = list(connection.execute("SELECT * FROM max_worker_heartbeats WHERE run_id=? ORDER BY sequence_no", (selected_run,))); counts["heartbeats"] += len(heartbeats)
                last_tick = -1
                for sequence, row in enumerate(heartbeats, 1):
                    try:
                        value = json.loads(row["heartbeat_json"])
                        if int(row["sequence_no"]) != sequence or canonical_sha256(value) != row["heartbeat_hash"] or int(row["tick_count"]) < last_tick: issues.append("worker heartbeat sequence/hash mismatch")
                        last_tick = int(row["tick_count"])
                    except Exception: issues.append("worker heartbeat is invalid")
                current = connection.execute("SELECT * FROM max_worker_current WHERE run_id=?", (selected_run,)).fetchone()
                if current is None: issues.append("worker heartbeat history lacks current projection")
                else:
                    counts["current"] += 1
                    try:
                        value = json.loads(current["current_json"]); expected = self._current_value(run_id=current["run_id"], project_id=current["project_id"], worker_id=current["worker_id"], worker_session=current["worker_session"], fencing_token=int(current["fencing_token"]), state=current["state"], tick_count=int(current["tick_count"]), last_heartbeat_id=current["last_heartbeat_id"], stop_reason=current["stop_reason"])
                        if value != expected or canonical_sha256(value) != current["current_hash"] or not heartbeats or current["last_heartbeat_id"] != heartbeats[-1]["heartbeat_id"]: issues.append("worker current projection mismatch")
                    except Exception: issues.append("worker current projection is invalid")
            return {"ok": not issues, "run_id": run_id, "counts": counts, "issues": sorted(set(issues))}
        finally:
            connection.close()


class LongRunningWorker:
    """Explicit bounded process loop around an already governed one-tick call."""

    def __init__(self, repository: MaxControlRepository, actor: Actor, *, step: Callable[[], Mapping[str, Any]], control: WorkerControl | None = None, sleeper: Callable[[float], None] = time.sleep, monotonic: Callable[[], float] = time.monotonic) -> None:
        if actor.is_admin or actor.actor_kind not in {"worker", "runner", "agent"} or not callable(step):
            raise MaxControlError("long-running worker dependencies are invalid")
        self.repository = repository; self.actor = actor; self.step = step; self.control = control or WorkerControl(repository); self.sleeper = sleeper; self.monotonic = monotonic

    def run(self, *, run_id: str, runner_profile: Any, max_ticks: int, max_wall_clock_seconds: int, interval_seconds: float = 0.0, lease_ttl: int = 300) -> dict[str, Any]:
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 10_000_000 for value in (max_ticks, max_wall_clock_seconds, lease_ttl)) or not isinstance(interval_seconds, (int, float)) or isinstance(interval_seconds, bool) or interval_seconds < 0 or interval_seconds > 3_600:
            raise MaxControlError("long-running worker bounds are invalid")
        from ..persistence.runner import RunnerPersistence

        persistence = RunnerPersistence(self.repository)
        lease = persistence.claim_runner_lease(run_id=run_id, profile=runner_profile, actor=self.actor, lease_ttl=lease_ttl)
        fence = int(lease["fencing_token"]); tick_count = int((self.control.status(run_id=run_id).get("current") or {}).get("tick_count", 0)); started = self.monotonic()
        self.control.heartbeat(run_id=run_id, actor=self.actor, fencing_token=fence, state="starting", tick_count=tick_count)
        stop_reason = "max_ticks"; recent_results: list[dict[str, Any]] = []; ticks_executed = 0
        for _ in range(max_ticks):
            if self.monotonic() - started >= max_wall_clock_seconds:
                stop_reason = "wall_clock_limit"; break
            command = self.control.pending_command(run_id=run_id)
            if command is not None:
                consumed = self.control.consume_command(command_id=command["command_id"], actor=self.actor, fencing_token=fence)
                action = consumed["command"]
                if action == "pause":
                    self.repository.pause(run_id=run_id, actor=self.actor, fencing_token=fence)
                    self.control.heartbeat(run_id=run_id, actor=self.actor, fencing_token=fence, state="paused", tick_count=tick_count, stop_reason="admin_pause")
                    return {"run_id": run_id, "ticks_executed": ticks_executed, "stop_reason": "admin_pause", "recent_results": recent_results}
                state = "draining" if action == "drain" else "stopped"
                reason = "admin_drain" if action == "drain" else "admin_stop"
                self.control.heartbeat(run_id=run_id, actor=self.actor, fencing_token=fence, state=state, tick_count=tick_count, stop_reason=reason)
                return {"run_id": run_id, "ticks_executed": ticks_executed, "stop_reason": reason, "recent_results": recent_results}
            lease = persistence.claim_runner_lease(run_id=run_id, profile=runner_profile, actor=self.actor, lease_ttl=lease_ttl)
            fence = int(lease["fencing_token"])
            self.control.heartbeat(run_id=run_id, actor=self.actor, fencing_token=fence, state="running", tick_count=tick_count)
            try:
                raw = self.step()
                result = {str(key): raw[key] for key in raw if str(key) in {"run_id", "project_id", "status", "iteration_id", "iteration_number", "round_type", "cognitive_kind", "plan_hash", "intent_hash", "logical_call_id", "result_hash", "change_set_id", "output_state_hash", "iteration_outcome_id", "usage_entry_id", "recovery_disposition", "reason", "idempotent", "model_call_status", "profile_hash"}}
            except Exception as exc:
                reason = getattr(exc, "code", None) or "worker_step_failed"
                self.control.heartbeat(run_id=run_id, actor=self.actor, fencing_token=fence, state="failed", tick_count=tick_count, stop_reason=str(reason)[:256])
                return {"run_id": run_id, "ticks_executed": ticks_executed, "stop_reason": str(reason)[:256], "recent_results": recent_results}
            # Durable state lives in SQLite.  Keep only a bounded redacted tail
            # so a multi-day process cannot grow its return object without end.
            recent_results.append(result)
            if len(recent_results) > 100:
                del recent_results[0]
            ticks_executed += 1; tick_count += 1
            stop = result.get("status") in {"paused", "completion_candidate", "budget_exhausted", "recovery_pending"} or result.get("reason") in {"budget_exhausted", "provider_call_cap_exhausted", "usage_dispute", "rehydration_drift", "epistemic_conflict_paused"}
            if stop:
                stop_reason = str(result.get("reason") or result.get("status"))[:256]
                self.control.heartbeat(run_id=run_id, actor=self.actor, fencing_token=fence, state="stopped", tick_count=tick_count, stop_reason=stop_reason)
                return {"run_id": run_id, "ticks_executed": ticks_executed, "stop_reason": stop_reason, "recent_results": recent_results}
            if interval_seconds:
                self.sleeper(float(interval_seconds))
        self.control.heartbeat(run_id=run_id, actor=self.actor, fencing_token=fence, state="stopped", tick_count=tick_count, stop_reason=stop_reason)
        return {"run_id": run_id, "ticks_executed": ticks_executed, "stop_reason": stop_reason, "recent_results": recent_results}


__all__ = ["LongRunningWorker", "WorkerControl"]
