"""Server-owned protocol for already-running external research Agents.

This module is intentionally independent from provider execution.  A trusted
host integration injects an authenticated :class:`~research_kb.policy.Actor`,
the service issues a bounded work packet, and the Agent reads source material
through the ordinary research gateway before submitting a candidate result.
The control store keeps identifiers, hashes, claims, and bounded metadata; it
does not become a second source-text transport or a provider billing ledger.
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol, Sequence

from ..policy import Actor, PolicyError, require_admin
from .contract import canonical_json, is_project_id, make_event_id, is_stable_id
from .persistence.db import CONTROL_SCHEMA_VERSION, control_transaction
from .persistence.repository import (
    MaxControlError,
    MaxControlRepository,
    _hash,
    _json,
    _loads,
    _parse_timestamp,
    _reject_untrusted_payload,
    _timestamp,
    _utc_now,
)


EXTERNAL_AGENT_PROTOCOL = "research-kb/external-agent/v1"
EXTERNAL_AGENT_SCHEMA = "research-kb/external-agent-work/v1"
_MAX_SESSION_TTL = 86_400
_MAX_PACKET_TTL = 86_400
_MAX_CLAIM_TTL = 3_600
_MAX_SOURCE_REFS = 64
_MAX_RESULT_BYTES = 256_000
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALLOWED_SOURCE_KEYS = frozenset(
    {
        "project_id",
        "document_id",
        "document_version_id",
        "passage_id",
        "verified_evidence_id",
        "verified_source_version_id",
    }
)
_ALLOWED_SOURCE_RESULT_KEYS = _ALLOWED_SOURCE_KEYS | {"reference_hash"}
_ALLOWED_OPERATIONS = frozenset(
    {"read_source", "read_canonical", "submit_candidate", "release_work", "recover_work"}
)
_RESULT_KEYS = frozenset(
    {"candidate_claims", "evidence_links", "objections", "unresolved_questions", "next_steps", "usage"}
)
_DEFAULT_RESULT_CONTRACT = {
    "schema": "research-kb/external-agent-candidate/v1",
    "status": "candidate_only",
    "required": ["candidate_claims", "evidence_links", "objections", "unresolved_questions", "next_steps", "usage"],
    "forbidden_statuses": ["verified", "accepted", "completed", "reported"],
}


class ExternalAgentSourceResolver(Protocol):
    """Resolve a stable source reference without returning source body text."""

    def resolve_reference(self, *, project_id: str, reference: Mapping[str, Any]) -> Mapping[str, Any] | None:
        ...


def _bounded_text(value: Any, *, name: str, maximum: int, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise MaxControlError(f"{name} must be a string")
    clean = value.strip()
    if required and not clean:
        raise MaxControlError(f"{name} must not be empty")
    if len(clean) > maximum or "\x00" in clean:
        raise MaxControlError(f"{name} exceeds the bounded protocol limit")
    return clean


def _bounded_ttl(value: Any, *, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum:
        raise MaxControlError(f"{name} is outside the supported TTL range")
    return value


def _utc(value: str) -> datetime:
    parsed = _parse_timestamp(value)
    if parsed is None:
        raise MaxControlError("stored external-Agent timestamp is invalid")
    return parsed


def _event_hash(*, event_id: str, sequence_no: int, event_type: str, payload_hash: str, previous_event_hash: str, event_json: str, actor_id: str, actor_kind: str, actor_session: str, created_at: str) -> str:
    return _hash(
        {
            "event_id": event_id,
            "sequence_no": sequence_no,
            "event_type": event_type,
            "payload_hash": payload_hash,
            "previous_event_hash": previous_event_hash,
            "event_json": event_json,
            "actor_id": actor_id,
            "actor_kind": actor_kind,
            "actor_session": actor_session,
            "created_at": created_at,
        }
    )


class ExternalAgentService:
    """The server-owned external-Agent work protocol.

    ``server_actor`` is required for packet issuance and next-round creation.
    Agent methods never accept caller-supplied authenticated identity fields;
    they resolve those fields from the server-created session row.
    """

    def __init__(
        self,
        repository: MaxControlRepository,
        server_actor: Actor | None = None,
        *,
        source_resolver: ExternalAgentSourceResolver | Any | None = None,
        clock=None,
    ) -> None:
        self.repository = repository
        self.server_actor = server_actor
        self.source_resolver = source_resolver if source_resolver is not None else repository.source_resolver
        self.clock = clock if clock is not None else repository.clock

    @staticmethod
    def discover() -> dict[str, Any]:
        """Return a stable, non-sensitive capability document."""

        return {
            "protocol": EXTERNAL_AGENT_PROTOCOL,
            "operations": [
                "discover", "open_session", "close_session", "issue_work_packet",
                "claim_work", "get_work_packet", "recover_work", "submit_candidate",
                "release_work", "issue_next_round", "verify",
            ],
            "required_fields": {
                "session": ["project_id", "authenticated_connection", "claimed_agent_id"],
                "work_packet": ["project_id", "run_id", "iteration_id", "question", "role", "source_refs", "result_contract"],
                "candidate": ["work_packet_id", "claim_id", "expected_state_version", "expected_state_hash", "idempotency_key", "result"],
            },
            "limits": {
                "max_session_ttl_seconds": _MAX_SESSION_TTL,
                "max_packet_ttl_seconds": _MAX_PACKET_TTL,
                "max_claim_ttl_seconds": _MAX_CLAIM_TTL,
                "max_source_references": _MAX_SOURCE_REFS,
                "max_candidate_bytes": _MAX_RESULT_BYTES,
                "candidate_status": "candidate_only",
            },
            "identity": {
                "authenticated_connection": "server_injected_actor_identity",
                "claimed_agent_and_model": "self_reported_metadata",
                "client_identity_cannot_replace_authenticated_identity": True,
            },
            "usage": {
                "accepted_statuses": ["unknown", "self_reported"],
                "provider_receipt": "not available in external-agent mode unless independently verified",
                "cost": "never inferred from self-reported usage",
            },
            "external_actions": {"provider": 0, "network": 0, "credential_reads": 0},
        }

    def _require_server_admin(self) -> Actor:
        if self.server_actor is None:
            raise MaxControlError("server-owned operation requires a configured control-plane actor")
        try:
            require_admin(self.server_actor)
        except PolicyError as exc:
            raise MaxControlError("server-owned packet operation requires the human control-plane authority") from exc
        return self.server_actor

    def _connect(self, *, read_only: bool) -> sqlite3.Connection:
        return self.repository._connect(read_only=read_only)

    def _session_row(self, connection: sqlite3.Connection, session_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM max_external_agent_sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if row is None:
            raise MaxControlError("external-Agent session was not found")
        return row

    def _session_event_state(self, connection: sqlite3.Connection, session_id: str) -> str:
        row = connection.execute(
            "SELECT event_type FROM max_external_agent_session_events WHERE session_id=? ORDER BY sequence_no DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        return str(row[0]) if row is not None else "invalid"

    def _require_session(
        self,
        connection: sqlite3.Connection,
        *,
        session_id: str,
        project_id: str | None = None,
        now: datetime | None = None,
        require_active: bool = True,
    ) -> sqlite3.Row:
        row = self._session_row(connection, session_id)
        if project_id is not None and row["project_id"] != project_id:
            raise MaxControlError("external-Agent session is outside the project boundary")
        state = self._session_event_state(connection, session_id)
        current = now or _utc_now(self.clock)
        expired = _utc(row["expires_at"]) <= current
        if require_active and (state != "opened" or expired):
            raise MaxControlError("external-Agent session is not active")
        return row

    @staticmethod
    def _assert_actor_session(row: sqlite3.Row, actor: Actor) -> None:
        if not isinstance(actor, Actor) or actor.actor_id != row["authenticated_actor_id"] or actor.session_id != row["authenticated_actor_session"]:
            raise MaxControlError("authenticated connection identity does not match the server session")

    def _append_session_event(self, connection: sqlite3.Connection, *, row: sqlite3.Row, event_type: str, actor: Actor, now: str, detail: Mapping[str, Any] | None = None) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence_no,event_hash FROM max_external_agent_session_events WHERE session_id=? ORDER BY sequence_no DESC LIMIT 1",
            (row["session_id"],),
        ).fetchone()
        sequence = int(previous["sequence_no"]) + 1 if previous else 1
        payload = {"schema": EXTERNAL_AGENT_SCHEMA, "session_id": row["session_id"], "event_type": event_type, **dict(detail or {})}
        _reject_untrusted_payload(payload)
        payload_hash = _hash(payload)
        event_id = make_event_id(
            "external_agent_session_event",
            row["project_id"],
            {"session_id": row["session_id"], "sequence_no": sequence, "event_type": event_type, "payload_hash": payload_hash},
        )
        event_json = _json(payload)
        previous_hash = str(previous["event_hash"]) if previous else ""
        event_hash = _event_hash(
            event_id=event_id, sequence_no=sequence, event_type=event_type,
            payload_hash=payload_hash, previous_event_hash=previous_hash,
            event_json=event_json, actor_id=actor.actor_id, actor_kind=actor.actor_kind,
            actor_session=actor.session_id, created_at=now,
        )
        connection.execute(
            "INSERT INTO max_external_agent_session_events(event_id,session_id,sequence_no,event_type,event_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, row["session_id"], sequence, event_type, event_json, payload_hash, previous_hash, event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id),
        )
        return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "event_type": event_type}

    def _append_claim_event(self, connection: sqlite3.Connection, *, claim_id: str, packet: sqlite3.Row, event_type: str, actor: Actor, now: str, detail: Mapping[str, Any] | None = None) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence_no,event_hash FROM max_external_agent_work_claim_events WHERE claim_id=? ORDER BY sequence_no DESC LIMIT 1",
            (claim_id,),
        ).fetchone()
        sequence = int(previous["sequence_no"]) + 1 if previous else 1
        payload = {"schema": EXTERNAL_AGENT_SCHEMA, "claim_id": claim_id, "work_packet_id": packet["work_packet_id"], "event_type": event_type, **dict(detail or {})}
        _reject_untrusted_payload(payload)
        payload_hash = _hash(payload)
        event_id = make_event_id(
            "external_agent_claim_event", packet["project_id"],
            {"claim_id": claim_id, "sequence_no": sequence, "event_type": event_type, "payload_hash": payload_hash},
        )
        event_json = _json(payload)
        previous_hash = str(previous["event_hash"]) if previous else ""
        event_hash = _event_hash(
            event_id=event_id, sequence_no=sequence, event_type=event_type,
            payload_hash=payload_hash, previous_event_hash=previous_hash,
            event_json=event_json, actor_id=actor.actor_id, actor_kind=actor.actor_kind,
            actor_session=actor.session_id, created_at=now,
        )
        connection.execute(
            "INSERT INTO max_external_agent_work_claim_events(event_id,claim_id,sequence_no,event_type,event_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, claim_id, sequence, event_type, event_json, payload_hash, previous_hash, event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id),
        )
        return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "event_type": event_type}

    def _append_run_event(self, connection: sqlite3.Connection, *, packet: sqlite3.Row, event_type: str, actor: Actor, now: str, detail: Mapping[str, Any] | None = None) -> dict[str, Any]:
        stream_key = f"run:{packet['run_id']}"
        previous = connection.execute(
            "SELECT sequence_no,event_hash FROM max_external_agent_events WHERE stream_key=? ORDER BY sequence_no DESC LIMIT 1",
            (stream_key,),
        ).fetchone()
        sequence = int(previous["sequence_no"]) + 1 if previous else 1
        payload = {"schema": EXTERNAL_AGENT_SCHEMA, "stream_key": stream_key, "work_packet_id": packet["work_packet_id"], "event_type": event_type, **dict(detail or {})}
        _reject_untrusted_payload(payload)
        payload_hash = _hash(payload)
        event_id = make_event_id(
            "external_agent_event", packet["project_id"],
            {"stream_key": stream_key, "sequence_no": sequence, "event_type": event_type, "payload_hash": payload_hash},
        )
        event_json = _json(payload)
        previous_hash = str(previous["event_hash"]) if previous else ""
        event_hash = _event_hash(
            event_id=event_id, sequence_no=sequence, event_type=event_type,
            payload_hash=payload_hash, previous_event_hash=previous_hash,
            event_json=event_json, actor_id=actor.actor_id, actor_kind=actor.actor_kind,
            actor_session=actor.session_id, created_at=now,
        )
        connection.execute(
            "INSERT INTO max_external_agent_events(event_id,stream_key,sequence_no,run_id,project_id,event_type,event_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, stream_key, sequence, packet["run_id"], packet["project_id"], event_type, event_json, payload_hash, previous_hash, event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id),
        )
        return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "event_type": event_type}

    def open_session(
        self,
        *,
        project_id: str,
        authenticated_actor: Actor,
        claimed_agent_id: str,
        claimed_model: str | None = None,
        ttl_seconds: int = 3_600,
    ) -> dict[str, Any]:
        if not is_project_id(project_id):
            raise MaxControlError("project_id is not valid")
        if not isinstance(authenticated_actor, Actor) or authenticated_actor.is_admin:
            raise MaxControlError("an external-Agent session requires a non-admin authenticated actor")
        agent_id = _bounded_text(claimed_agent_id, name="claimed_agent_id", maximum=160)
        model = _bounded_text(claimed_model, name="claimed_model", maximum=160, required=False) or None
        ttl = _bounded_ttl(ttl_seconds, name="session_ttl_seconds", maximum=_MAX_SESSION_TTL)
        actor_id = _bounded_text(authenticated_actor.actor_id, name="authenticated_actor_id", maximum=200)
        actor_session = _bounded_text(authenticated_actor.session_id, name="authenticated_actor_session", maximum=200)
        now_dt = _utc_now(self.clock)
        now = _timestamp(self.clock)
        expires = (now_dt + timedelta(seconds=ttl)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        connection_id = f"conn:{uuid.uuid4().hex}"
        session_id = make_event_id("external_agent_session", project_id, {"connection_id": connection_id, "actor_id": actor_id, "created_at": now})
        value = {
            "schema": EXTERNAL_AGENT_SCHEMA, "session_id": session_id, "connection_id": connection_id,
            "project_id": project_id, "authenticated_actor_id": actor_id,
            "authenticated_actor_kind": authenticated_actor.actor_kind, "authenticated_actor_role": authenticated_actor.role,
            "authenticated_actor_framework": authenticated_actor.framework, "authenticated_actor_session": actor_session,
            "authenticated_model": authenticated_actor.model, "claimed_agent_id": agent_id,
            "claimed_model": model, "auth_method": "server_injected", "created_at": now, "expires_at": expires,
        }
        _reject_untrusted_payload(value)
        session_hash = _hash(value)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                connection.execute(
                    "INSERT INTO max_external_agent_sessions(session_id,connection_id,project_id,authenticated_actor_id,authenticated_actor_kind,authenticated_actor_role,authenticated_actor_framework,authenticated_actor_session,authenticated_model,claimed_agent_id,claimed_model,auth_method,created_at,expires_at,session_json,session_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (session_id, connection_id, project_id, actor_id, authenticated_actor.actor_kind, authenticated_actor.role, authenticated_actor.framework, actor_session, authenticated_actor.model, agent_id, model, "server_injected", now, expires, _json(value), session_hash),
                )
                row = self._session_row(connection, session_id)
                event = self._append_session_event(connection, row=row, event_type="opened", actor=authenticated_actor, now=now)
            return {"session_id": session_id, "connection_id": connection_id, "project_id": project_id, "expires_at": expires, "session_hash": session_hash, "event": event, "authenticated_identity": {"actor_id": actor_id, "actor_kind": authenticated_actor.actor_kind, "framework": authenticated_actor.framework, "session_id": actor_session}, "claimed_identity": {"agent_id": agent_id, "model": model}}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("external-Agent session creation conflicted with an immutable record") from exc
        finally:
            connection.close()

    def close_session(self, *, session_id: str, authenticated_actor: Actor) -> dict[str, Any]:
        now = _timestamp(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._require_session(connection, session_id=session_id, now=_utc_now(self.clock), require_active=True)
                self._assert_actor_session(row, authenticated_actor)
                event = self._append_session_event(connection, row=row, event_type="closed", actor=authenticated_actor, now=now)
            return {"session_id": session_id, "state": "closed", "event": event}
        finally:
            connection.close()

    def _normalize_source_refs(self, *, project_id: str, source_refs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        if not isinstance(source_refs, (list, tuple)) or len(source_refs) > _MAX_SOURCE_REFS:
            raise MaxControlError("source_refs must be a bounded list")
        if self.source_resolver is None and source_refs:
            raise MaxControlError("a server-owned source resolver is required for work packets with sources")
        resolved: list[dict[str, Any]] = []
        for supplied in source_refs:
            if not isinstance(supplied, Mapping):
                raise MaxControlError("source_refs must contain objects")
            if set(str(key) for key in supplied) - _ALLOWED_SOURCE_KEYS:
                raise MaxControlError("source reference contains client citation metadata")
            if supplied.get("project_id") not in (None, project_id):
                raise MaxControlError("source reference crosses project boundary")
            identifiers = [supplied.get(key) for key in _ALLOWED_SOURCE_KEYS - {"project_id"}]
            if not any(isinstance(item, str) and is_stable_id(item) for item in identifiers):
                raise MaxControlError("source reference must contain a server-owned stable ID")
            try:
                if hasattr(self.source_resolver, "resolve_reference"):
                    answer = self.source_resolver.resolve_reference(project_id=project_id, reference=dict(supplied))  # type: ignore[attr-defined]
                else:
                    answer = self.source_resolver(project_id=project_id, reference=dict(supplied))  # type: ignore[misc]
            except Exception as exc:
                raise MaxControlError("server source reference validation failed") from exc
            if not isinstance(answer, Mapping) or answer.get("project_id") != project_id:
                raise MaxControlError("source reference was not validated for this project")
            if set(str(key) for key in answer) - _ALLOWED_SOURCE_RESULT_KEYS:
                raise MaxControlError("source resolver returned unsupported or body-bearing metadata")
            normalized = {key: answer[key] for key in answer if key in _ALLOWED_SOURCE_KEYS}
            if not any(isinstance(normalized.get(key), str) and is_stable_id(normalized[key]) for key in _ALLOWED_SOURCE_KEYS - {"project_id"}):
                raise MaxControlError("source resolver did not return a stable source identity")
            normalized["project_id"] = project_id
            normalized["reference_hash"] = _hash({"project_id": project_id, "reference": normalized})
            _reject_untrusted_payload(normalized)
            resolved.append(normalized)
        return sorted(resolved, key=canonical_json)

    @staticmethod
    def _source_identifier_set(source_refs: Sequence[Mapping[str, Any]]) -> set[str]:
        identifiers: set[str] = set()
        for reference in source_refs:
            identifiers.update(
                str(value)
                for key, value in reference.items()
                if key not in {"project_id", "reference_hash"} and isinstance(value, str)
            )
        return identifiers

    @staticmethod
    def _validate_operations(operations: Sequence[str] | None) -> list[str]:
        values = list(operations or sorted(_ALLOWED_OPERATIONS))
        if not values or len(values) > len(_ALLOWED_OPERATIONS) or any(not isinstance(item, str) or item not in _ALLOWED_OPERATIONS for item in values):
            raise MaxControlError("allowed_operations contains an unsupported operation")
        if len(set(values)) != len(values):
            raise MaxControlError("allowed_operations must be unique")
        return sorted(values)

    def _issue_packet(
        self,
        *,
        connection: sqlite3.Connection,
        project_id: str,
        run_id: str,
        iteration_id: str,
        question: str,
        role: str,
        task_kind: str,
        source_refs: list[dict[str, Any]],
        allowed_operations: list[str],
        result_contract: Mapping[str, Any],
        ttl_seconds: int,
        checkpoint_id: str | None,
        prior_result_id: str | None,
        round_no: int,
        now: str,
    ) -> dict[str, Any]:
        run = self.repository._run_row(connection, run_id)
        self.repository._require_project_run(run, project_id)
        if run["status"] != "RUNNING":
            raise MaxControlError("external work packets require a RUNNING Max Run")
        iteration = connection.execute("SELECT * FROM max_iterations WHERE iteration_id=? AND run_id=?", (iteration_id, run_id)).fetchone()
        if iteration is None or iteration["project_id"] != project_id or iteration["status"] != "started":
            raise MaxControlError("external work packet requires the current started iteration")
        if checkpoint_id is not None:
            checkpoint = connection.execute("SELECT 1 FROM max_checkpoints WHERE checkpoint_id=? AND run_id=?", (checkpoint_id, run_id)).fetchone()
            if checkpoint is None:
                raise MaxControlError("checkpoint is outside the Run")
        if prior_result_id is not None:
            prior = connection.execute("SELECT * FROM max_external_agent_results WHERE result_id=?", (prior_result_id,)).fetchone()
            if prior is None or prior["run_id"] != run_id or prior["project_id"] != project_id or prior["result_status"] != "candidate":
                raise MaxControlError("prior external-Agent result is not a candidate in this Run")
        state_hash = str(run["current_state_hash"])
        state_version = int(run["state_version"])
        now_dt = _utc(now)
        expires = (now_dt + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        question_value = {"question": _bounded_text(question, name="question", maximum=8_000)}
        role_value = _bounded_text(role, name="role", maximum=160)
        task_value = _bounded_text(task_kind, name="task_kind", maximum=160)
        contract_value = dict(result_contract)
        _reject_untrusted_payload(contract_value)
        if len(canonical_json(contract_value).encode("utf-8")) > 32_000:
            raise MaxControlError("result_contract is too large")
        packet_value = {
            "schema": EXTERNAL_AGENT_SCHEMA, "work_packet_id": "pending", "run_id": run_id, "project_id": project_id,
            "iteration_id": iteration_id, "round_no": round_no, "task_kind": task_value, "role": role_value,
            "state_version": state_version, "state_hash": state_hash, "checkpoint_id": checkpoint_id,
            "prior_result_id": prior_result_id, "question": question_value, "allowed_operations": allowed_operations,
            "source_refs": source_refs, "result_contract": contract_value, "created_at": now, "expires_at": expires,
            "server_owned": True,
        }
        packet_id = make_event_id("external_agent_work_packet", project_id, {"run_id": run_id, "round_no": round_no, "nonce": uuid.uuid4().hex})
        packet_value["work_packet_id"] = packet_id
        packet_hash = _hash(packet_value)
        question_json = _json(question_value)
        operations_json = _json(allowed_operations)
        source_json = _json(source_refs)
        contract_json = _json(contract_value)
        connection.execute(
            "INSERT INTO max_external_agent_work_packets(work_packet_id,run_id,project_id,iteration_id,round_no,task_kind,role,state_version,state_hash,checkpoint_id,prior_result_id,question_json,question_hash,allowed_operations_json,allowed_operations_hash,source_refs_json,source_refs_hash,result_contract_json,result_contract_hash,packet_json,packet_hash,created_at,expires_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (packet_id, run_id, project_id, iteration_id, round_no, task_value, role_value, state_version, state_hash, checkpoint_id, prior_result_id, question_json, _hash(question_value), operations_json, _hash(allowed_operations), source_json, _hash(source_refs), contract_json, _hash(contract_value), _json(packet_value), packet_hash, now, expires, self._require_server_admin().actor_id, self.server_actor.actor_kind, self.server_actor.session_id),
        )
        current = {"schema": EXTERNAL_AGENT_SCHEMA, "work_packet_id": packet_id, "run_id": run_id, "project_id": project_id, "state": "available", "generation": 0, "claim_id": None, "result_id": None, "updated_at": now}
        connection.execute(
            "INSERT INTO max_external_agent_work_current(work_packet_id,run_id,project_id,state,generation,claim_id,result_id,updated_at,current_json,current_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (packet_id, run_id, project_id, "available", 0, None, None, now, _json(current), _hash(current)),
        )
        packet_row = connection.execute("SELECT * FROM max_external_agent_work_packets WHERE work_packet_id=?", (packet_id,)).fetchone()
        event = self._append_run_event(connection, packet=packet_row, event_type="packet_issued", actor=self.server_actor, now=now, detail={"packet_hash": packet_hash, "round_no": round_no})
        return {"packet": self._packet_output(connection, packet_row), "idempotent": False, "event": event}

    def issue_work_packet(
        self,
        *,
        project_id: str,
        run_id: str,
        iteration_id: str,
        question: str,
        role: str,
        source_refs: Sequence[Mapping[str, Any]],
        task_kind: str = "research",
        allowed_operations: Sequence[str] | None = None,
        result_contract: Mapping[str, Any] | None = None,
        ttl_seconds: int = 3_600,
        checkpoint_id: str | None = None,
        round_no: int | None = None,
    ) -> dict[str, Any]:
        self._require_server_admin()
        if not is_project_id(project_id):
            raise MaxControlError("project_id is not valid")
        ttl = _bounded_ttl(ttl_seconds, name="packet_ttl_seconds", maximum=_MAX_PACKET_TTL)
        operations = self._validate_operations(allowed_operations)
        contract = dict(result_contract or _DEFAULT_RESULT_CONTRACT)
        normalized_refs = self._normalize_source_refs(project_id=project_id, source_refs=source_refs)
        now = _timestamp(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                selected_round = round_no
                if selected_round is None:
                    selected_round = int(connection.execute("SELECT COALESCE(MAX(round_no),0)+1 FROM max_external_agent_work_packets WHERE run_id=?", (run_id,)).fetchone()[0])
                if isinstance(selected_round, bool) or not isinstance(selected_round, int) or selected_round < 1:
                    raise MaxControlError("round_no must be a positive integer")
                existing = connection.execute("SELECT * FROM max_external_agent_work_packets WHERE run_id=? AND round_no=?", (run_id, selected_round)).fetchone()
                if existing is not None:
                    expected = {
                        "run_id": run_id, "project_id": project_id, "iteration_id": iteration_id,
                        "question_hash": _hash({"question": _bounded_text(question, name="question", maximum=8_000)}),
                        "role": _bounded_text(role, name="role", maximum=160), "task_kind": _bounded_text(task_kind, name="task_kind", maximum=160),
                        "source_refs_hash": _hash(normalized_refs), "allowed_operations_hash": _hash(operations), "result_contract_hash": _hash(contract),
                    }
                    if any(existing[key] != value for key, value in expected.items()):
                        raise MaxControlError("a different immutable work packet already uses this Run round")
                    return {"packet": self._packet_output(connection, existing), "idempotent": True}
                return self._issue_packet(connection=connection, project_id=project_id, run_id=run_id, iteration_id=iteration_id, question=question, role=role, task_kind=task_kind, source_refs=normalized_refs, allowed_operations=operations, result_contract=contract, ttl_seconds=ttl, checkpoint_id=checkpoint_id, prior_result_id=None, round_no=selected_round, now=now)
        finally:
            connection.close()

    def issue_next_round(
        self,
        *,
        prior_result_id: str,
        question: str,
        role: str,
        ttl_seconds: int = 3_600,
        task_kind: str = "revision",
    ) -> dict[str, Any]:
        self._require_server_admin()
        ttl = _bounded_ttl(ttl_seconds, name="packet_ttl_seconds", maximum=_MAX_PACKET_TTL)
        now = _timestamp(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                prior = connection.execute(
                    "SELECT p.* FROM max_external_agent_work_packets p JOIN max_external_agent_results r ON r.work_packet_id=p.work_packet_id WHERE r.result_id=?",
                    (prior_result_id,),
                ).fetchone()
                if prior is None:
                    raise MaxControlError("prior external-Agent candidate result was not found")
                source_refs = _loads(prior["source_refs_json"])
                operations = _loads(prior["allowed_operations_json"])
                contract = _loads(prior["result_contract_json"])
                next_round = int(connection.execute("SELECT COALESCE(MAX(round_no),0)+1 FROM max_external_agent_work_packets WHERE run_id=?", (prior["run_id"],)).fetchone()[0])
                existing = connection.execute("SELECT * FROM max_external_agent_work_packets WHERE run_id=? AND round_no=?", (prior["run_id"], next_round)).fetchone()
                if existing is not None:
                    return {"packet": self._packet_output(connection, existing), "idempotent": True}
                return self._issue_packet(connection=connection, project_id=prior["project_id"], run_id=prior["run_id"], iteration_id=prior["iteration_id"], question=question, role=role, task_kind=task_kind, source_refs=source_refs, allowed_operations=operations, result_contract=contract, ttl_seconds=ttl, checkpoint_id=prior["checkpoint_id"], prior_result_id=prior_result_id, round_no=next_round, now=now)
        finally:
            connection.close()

    def _packet_output(self, connection: sqlite3.Connection, packet: sqlite3.Row, *, current: sqlite3.Row | None = None, claim: sqlite3.Row | None = None) -> dict[str, Any]:
        current = current or connection.execute("SELECT * FROM max_external_agent_work_current WHERE work_packet_id=?", (packet["work_packet_id"],)).fetchone()
        output = {
            "work_packet_id": packet["work_packet_id"], "packet_hash": packet["packet_hash"], "project_id": packet["project_id"], "run_id": packet["run_id"], "iteration_id": packet["iteration_id"], "round_no": int(packet["round_no"]), "task_kind": packet["task_kind"], "role": packet["role"], "state_version": int(packet["state_version"]), "state_hash": packet["state_hash"], "checkpoint_id": packet["checkpoint_id"], "prior_result_id": packet["prior_result_id"], "question": _loads(packet["question_json"]), "allowed_operations": _loads(packet["allowed_operations_json"]), "source_refs": _loads(packet["source_refs_json"]), "result_contract": _loads(packet["result_contract_json"]), "created_at": packet["created_at"], "expires_at": packet["expires_at"], "state": current["state"] if current is not None else "unknown", "generation": int(current["generation"]) if current is not None else 0, "claim_id": current["claim_id"] if current is not None else None, "result_id": current["result_id"] if current is not None else None,
        }
        if claim is not None:
            output["claim"] = {"claim_id": claim["claim_id"], "generation": int(claim["generation"]), "expires_at": claim["expires_at"], "fencing_token_hash": claim["fencing_token_hash"], "authenticated_identity": {"actor_id": claim["authenticated_actor_id"], "claimed_agent_id": claim["claimed_agent_id"]}}
        return output

    def claim_work(self, *, session_id: str, work_packet_id: str, claim_ttl_seconds: int = 600) -> dict[str, Any]:
        ttl = _bounded_ttl(claim_ttl_seconds, name="claim_ttl_seconds", maximum=_MAX_CLAIM_TTL)
        now_dt = _utc_now(self.clock); now = _timestamp(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                session = self._require_session(connection, session_id=session_id, now=now_dt)
                packet = connection.execute("SELECT * FROM max_external_agent_work_packets WHERE work_packet_id=?", (work_packet_id,)).fetchone()
                if packet is None:
                    raise MaxControlError("external-Agent work packet was not found")
                if packet["project_id"] != session["project_id"]:
                    raise MaxControlError("work packet is outside the authenticated project boundary")
                current = connection.execute("SELECT * FROM max_external_agent_work_current WHERE work_packet_id=?", (work_packet_id,)).fetchone()
                if current is None:
                    raise MaxControlError("work packet current projection is missing")
                if current["state"] == "submitted":
                    raise MaxControlError("work packet already has a candidate result")
                if _utc(packet["expires_at"]) <= now_dt:
                    raise MaxControlError("work packet has expired")
                if current["state"] == "claimed" and current["claim_id"]:
                    active_claim = connection.execute("SELECT c.*, cc.state AS claim_state FROM max_external_agent_work_claims c JOIN max_external_agent_work_claim_current cc ON cc.claim_id=c.claim_id WHERE c.claim_id=?", (current["claim_id"],)).fetchone()
                    if active_claim is not None and active_claim["claim_state"] == "active" and _utc(active_claim["expires_at"]) > now_dt:
                        if active_claim["session_id"] == session_id:
                            return {"packet": self._packet_output(connection, packet, current=current, claim=active_claim), "claim": {"claim_id": active_claim["claim_id"], "idempotent": True}, "idempotent": True}
                        raise MaxControlError("work packet is currently claimed by another session")
                    if active_claim is not None and active_claim["claim_state"] == "active":
                        self._append_claim_event(connection, claim_id=active_claim["claim_id"], packet=packet, event_type="expired", actor=self.server_actor or Actor("server", "server"), now=now, detail={"reason": "claim_ttl_elapsed"})
                        expired_current = {"claim_id": active_claim["claim_id"], "work_packet_id": work_packet_id, "session_id": active_claim["session_id"], "state": "expired", "updated_at": now}
                        connection.execute("UPDATE max_external_agent_work_claim_current SET state=?,updated_at=?,current_json=?,current_hash=? WHERE claim_id=?", ("expired", now, _json(expired_current), _hash(expired_current), active_claim["claim_id"]))
                    current = connection.execute("SELECT * FROM max_external_agent_work_current WHERE work_packet_id=?", (work_packet_id,)).fetchone()
                generation = int(connection.execute("SELECT COALESCE(MAX(generation),0)+1 FROM max_external_agent_work_claims WHERE work_packet_id=?", (work_packet_id,)).fetchone()[0])
                claim_id = make_event_id("external_agent_work_claim", packet["project_id"], {"work_packet_id": work_packet_id, "session_id": session_id, "generation": generation, "nonce": uuid.uuid4().hex})
                claim_expiry = min(now_dt + timedelta(seconds=ttl), _utc(packet["expires_at"]), _utc(session["expires_at"]))
                claim_expires = claim_expiry.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
                fencing_hash = _hash({"claim_id": claim_id, "work_packet_id": work_packet_id, "generation": generation})
                claim_value = {"schema": EXTERNAL_AGENT_SCHEMA, "claim_id": claim_id, "work_packet_id": work_packet_id, "run_id": packet["run_id"], "project_id": packet["project_id"], "generation": generation, "session_id": session_id, "authenticated_actor_id": session["authenticated_actor_id"], "claimed_agent_id": session["claimed_agent_id"], "fencing_token_hash": fencing_hash, "created_at": now, "expires_at": claim_expires}
                claim_hash = _hash(claim_value)
                connection.execute("INSERT INTO max_external_agent_work_claims(claim_id,work_packet_id,run_id,project_id,generation,session_id,authenticated_actor_id,claimed_agent_id,fencing_token_hash,created_at,expires_at,claim_json,claim_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (claim_id, work_packet_id, packet["run_id"], packet["project_id"], generation, session_id, session["authenticated_actor_id"], session["claimed_agent_id"], fencing_hash, now, claim_expires, _json(claim_value), claim_hash))
                claim_current = {"claim_id": claim_id, "work_packet_id": work_packet_id, "session_id": session_id, "state": "active", "updated_at": now}
                connection.execute("INSERT INTO max_external_agent_work_claim_current(claim_id,work_packet_id,session_id,state,updated_at,current_json,current_hash) VALUES (?,?,?,?,?,?,?)", (claim_id, work_packet_id, session_id, "active", now, _json(claim_current), _hash(claim_current)))
                work_current = {"schema": EXTERNAL_AGENT_SCHEMA, "work_packet_id": work_packet_id, "run_id": packet["run_id"], "project_id": packet["project_id"], "state": "claimed", "generation": generation, "claim_id": claim_id, "result_id": None, "updated_at": now}
                connection.execute("UPDATE max_external_agent_work_current SET state=?,generation=?,claim_id=?,result_id=NULL,updated_at=?,current_json=?,current_hash=? WHERE work_packet_id=?", ("claimed", generation, claim_id, now, _json(work_current), _hash(work_current), work_packet_id))
                claim_event = self._append_claim_event(connection, claim_id=claim_id, packet=packet, event_type="claimed", actor=Actor(session["authenticated_actor_id"], session["authenticated_actor_session"], session["authenticated_actor_kind"], session["authenticated_actor_role"], session["authenticated_actor_framework"], session["authenticated_model"]), now=now, detail={"generation": generation})
                run_event = self._append_run_event(connection, packet=packet, event_type="packet_claimed", actor=Actor(session["authenticated_actor_id"], session["authenticated_actor_session"], session["authenticated_actor_kind"], session["authenticated_actor_role"], session["authenticated_actor_framework"], session["authenticated_model"]), now=now, detail={"claim_id": claim_id, "generation": generation})
            return {"packet": self._packet_output(connection, packet, current=connection.execute("SELECT * FROM max_external_agent_work_current WHERE work_packet_id=?", (work_packet_id,)).fetchone(), claim=connection.execute("SELECT * FROM max_external_agent_work_claims WHERE claim_id=?", (claim_id,)).fetchone()), "claim": {"claim_id": claim_id, "claim_hash": claim_hash, "generation": generation, "expires_at": claim_expires, "fencing_token_hash": fencing_hash, "event": claim_event}, "event": run_event, "idempotent": False}
        finally:
            connection.close()

    def get_work_packet(self, *, session_id: str, work_packet_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            session = self._require_session(connection, session_id=session_id, now=_utc_now(self.clock))
            packet = connection.execute("SELECT * FROM max_external_agent_work_packets WHERE work_packet_id=?", (work_packet_id,)).fetchone()
            current = connection.execute("SELECT * FROM max_external_agent_work_current WHERE work_packet_id=?", (work_packet_id,)).fetchone()
            if packet is None or current is None or packet["project_id"] != session["project_id"]:
                raise MaxControlError("work packet is not available to this session")
            claim = None
            if current["state"] == "claimed":
                claim = connection.execute("SELECT c.*,cc.state AS claim_state FROM max_external_agent_work_claims c JOIN max_external_agent_work_claim_current cc ON cc.claim_id=c.claim_id WHERE c.claim_id=?", (current["claim_id"],)).fetchone()
                if claim is None or claim["session_id"] != session_id or claim["claim_state"] != "active" or _utc(claim["expires_at"]) <= _utc_now(self.clock):
                    raise MaxControlError("work packet is actively claimed by another session")
            return {"packet": self._packet_output(connection, packet, current=current, claim=claim)}
        finally:
            connection.close()

    def recover_work(self, *, session_id: str, work_packet_id: str | None = None) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            session = self._require_session(connection, session_id=session_id, now=_utc_now(self.clock))
            params: list[Any] = [session["project_id"]]
            query = "SELECT p.*,c.* FROM max_external_agent_work_packets p JOIN max_external_agent_work_current c ON c.work_packet_id=p.work_packet_id WHERE p.project_id=? AND c.state<> 'submitted'"
            if work_packet_id is not None:
                query += " AND p.work_packet_id=?"; params.append(work_packet_id)
            query += " ORDER BY p.round_no"
            packets = []
            for row in connection.execute(query, params):
                claim = None
                if row["claim_id"] is not None:
                    claim = connection.execute("SELECT c.*,cc.state AS claim_state FROM max_external_agent_work_claims c JOIN max_external_agent_work_claim_current cc ON cc.claim_id=c.claim_id WHERE c.claim_id=?", (row["claim_id"],)).fetchone()
                    if claim is not None and claim["claim_state"] == "active" and _utc(claim["expires_at"]) > _utc_now(self.clock):
                        continue
                packets.append(self._packet_output(connection, row, current=row, claim=None))
            return {"project_id": session["project_id"], "recoverable": packets, "count": len(packets)}
        finally:
            connection.close()

    def release_work(self, *, session_id: str, work_packet_id: str, claim_id: str, reason: str) -> dict[str, Any]:
        reason_value = _bounded_text(reason, name="release_reason", maximum=500)
        now = _timestamp(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                session = self._require_session(connection, session_id=session_id, now=_utc_now(self.clock))
                packet = connection.execute("SELECT * FROM max_external_agent_work_packets WHERE work_packet_id=?", (work_packet_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_external_agent_work_current WHERE work_packet_id=?", (work_packet_id,)).fetchone()
                claim = connection.execute("SELECT c.*,cc.state AS claim_state FROM max_external_agent_work_claims c JOIN max_external_agent_work_claim_current cc ON cc.claim_id=c.claim_id WHERE c.claim_id=?", (claim_id,)).fetchone()
                if packet is None or current is None or claim is None or packet["project_id"] != session["project_id"] or current["claim_id"] != claim_id or claim["session_id"] != session_id or claim["claim_state"] != "active":
                    raise MaxControlError("claim is not owned by this active session")
                agent = Actor(session["authenticated_actor_id"], session["authenticated_actor_session"], session["authenticated_actor_kind"], session["authenticated_actor_role"], session["authenticated_actor_framework"], session["authenticated_model"])
                claim_event = self._append_claim_event(connection, claim_id=claim_id, packet=packet, event_type="released", actor=agent, now=now, detail={"reason": reason_value})
                claim_current = {"claim_id": claim_id, "work_packet_id": work_packet_id, "session_id": session_id, "state": "released", "updated_at": now, "reason": reason_value}
                connection.execute("UPDATE max_external_agent_work_claim_current SET state=?,updated_at=?,current_json=?,current_hash=? WHERE claim_id=?", ("released", now, _json(claim_current), _hash(claim_current), claim_id))
                work_current = {"schema": EXTERNAL_AGENT_SCHEMA, "work_packet_id": work_packet_id, "run_id": packet["run_id"], "project_id": packet["project_id"], "state": "released", "generation": int(current["generation"]), "claim_id": None, "result_id": None, "updated_at": now}
                connection.execute("UPDATE max_external_agent_work_current SET state=?,claim_id=NULL,updated_at=?,current_json=?,current_hash=? WHERE work_packet_id=?", ("released", now, _json(work_current), _hash(work_current), work_packet_id))
                run_event = self._append_run_event(connection, packet=packet, event_type="packet_released", actor=agent, now=now, detail={"claim_id": claim_id, "reason": reason_value})
            return {"work_packet_id": work_packet_id, "claim_id": claim_id, "state": "released", "claim_event": claim_event, "event": run_event}
        finally:
            connection.close()

    def _validate_candidate(self, *, result: Mapping[str, Any], source_refs: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        if not isinstance(result, Mapping) or set(str(key) for key in result) != _RESULT_KEYS:
            raise MaxControlError("candidate result does not match the external-Agent result contract")
        candidate = dict(result)
        _reject_untrusted_payload(candidate)
        if len(canonical_json(candidate).encode("utf-8")) > _MAX_RESULT_BYTES:
            raise MaxControlError("candidate result exceeds the bounded size")
        allowed_ids = self._source_identifier_set(source_refs)
        claims = candidate["candidate_claims"]
        if not isinstance(claims, list) or len(claims) > 256:
            raise MaxControlError("candidate_claims must be a bounded list")
        normalized_claims = []
        for claim in claims:
            if not isinstance(claim, Mapping) or set(str(key) for key in claim) - {"text", "epistemic_status", "source_refs", "rationale"}:
                raise MaxControlError("candidate claim contains unsupported fields")
            if claim.get("epistemic_status") != "candidate":
                raise MaxControlError("external-Agent claims must remain candidate")
            text = _bounded_text(claim.get("text"), name="candidate_claim.text", maximum=4_000)
            refs = claim.get("source_refs", [])
            if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in allowed_ids for ref in refs):
                raise MaxControlError("candidate claim cites an unauthorized source reference")
            normalized_claims.append({"text": text, "epistemic_status": "candidate", "source_refs": list(refs), **({"rationale": _bounded_text(claim["rationale"], name="candidate_claim.rationale", maximum=2_000)} if "rationale" in claim else {})})
        links = candidate["evidence_links"]
        if not isinstance(links, list) or len(links) > 256:
            raise MaxControlError("evidence_links must be a bounded list")
        normalized_links = []
        for link in links:
            if not isinstance(link, Mapping) or set(str(key) for key in link) != {"source_ref", "relation"} or link["source_ref"] not in allowed_ids or link["relation"] not in {"supports", "counters", "qualifies"}:
                raise MaxControlError("evidence link is outside the packet source allowance")
            normalized_links.append({"source_ref": link["source_ref"], "relation": link["relation"]})
        objections = candidate["objections"]
        if not isinstance(objections, list) or len(objections) > 256:
            raise MaxControlError("objections must be a bounded list")
        normalized_objections = []
        for objection in objections:
            if not isinstance(objection, Mapping) or set(str(key) for key in objection) - {"text", "source_refs"}:
                raise MaxControlError("objection contains unsupported fields")
            refs = objection.get("source_refs", [])
            if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in allowed_ids for ref in refs):
                raise MaxControlError("objection cites an unauthorized source reference")
            normalized_objections.append({"text": _bounded_text(objection.get("text"), name="objection.text", maximum=4_000), "source_refs": list(refs)})
        def bounded_list(value: Any, name: str) -> list[str]:
            if not isinstance(value, list) or len(value) > 256 or any(not isinstance(item, str) or len(item.strip()) > 2_000 or not item.strip() for item in value):
                raise MaxControlError(f"{name} must be a bounded list of text")
            return [item.strip() for item in value]
        usage = candidate["usage"]
        if not isinstance(usage, Mapping):
            raise MaxControlError("usage must declare unknown or self_reported status")
        usage_keys = set(str(key) for key in usage)
        status = usage.get("status")
        if status == "unknown":
            if usage_keys != {"status"}:
                raise MaxControlError("unknown usage must not carry unverified measurements")
            normalized_usage = {"status": "unknown"}
        elif status == "self_reported":
            allowed_usage = {"status", "input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens", "wall_clock_seconds"}
            if usage_keys - allowed_usage:
                raise MaxControlError("self-reported usage contains unsupported billing fields")
            normalized_usage = {"status": "self_reported"}
            for key in sorted(usage_keys - {"status"}):
                value = usage[key]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise MaxControlError("self-reported usage measurements must be non-negative integers")
                normalized_usage[key] = value
        else:
            raise MaxControlError("usage status must be unknown or self_reported")
        normalized = {"candidate_claims": normalized_claims, "evidence_links": normalized_links, "objections": normalized_objections, "unresolved_questions": bounded_list(candidate["unresolved_questions"], "unresolved_questions"), "next_steps": bounded_list(candidate["next_steps"], "next_steps"), "usage": normalized_usage}
        return normalized, normalized_usage

    def submit_candidate(
        self,
        *,
        session_id: str,
        work_packet_id: str,
        claim_id: str,
        expected_state_version: int,
        expected_state_hash: str,
        idempotency_key: str,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(expected_state_version, int) or isinstance(expected_state_version, bool):
            raise MaxControlError("expected_state_version must be an integer")
        if not isinstance(expected_state_hash, str) or len(expected_state_hash) != 64:
            raise MaxControlError("expected_state_hash is invalid")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY_RE.fullmatch(idempotency_key) is None:
            raise MaxControlError("idempotency_key is invalid")
        now_dt = _utc_now(self.clock); now = _timestamp(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                packet = connection.execute("SELECT * FROM max_external_agent_work_packets WHERE work_packet_id=?", (work_packet_id,)).fetchone()
                if packet is None:
                    raise MaxControlError("external-Agent work packet was not found")
                source_refs = _loads(packet["source_refs_json"])
                normalized, usage = self._validate_candidate(result=result, source_refs=source_refs)
                result_hash = _hash({"work_packet_id": work_packet_id, "idempotency_key": idempotency_key, "result": normalized})
                session = self._require_session(connection, session_id=session_id, project_id=packet["project_id"], now=now_dt)
                existing = connection.execute("SELECT * FROM max_external_agent_results WHERE work_packet_id=? AND idempotency_key=?", (work_packet_id, idempotency_key)).fetchone()
                if existing is not None:
                    if existing["result_hash"] != result_hash:
                        raise MaxControlError("idempotency key was replayed with a different candidate")
                    return {"result_id": existing["result_id"], "result_hash": existing["result_hash"], "usage_status": existing["usage_status"], "status": "candidate", "idempotent": True}
                current = connection.execute("SELECT * FROM max_external_agent_work_current WHERE work_packet_id=?", (work_packet_id,)).fetchone()
                claim = connection.execute("SELECT c.*,cc.state AS claim_state FROM max_external_agent_work_claims c JOIN max_external_agent_work_claim_current cc ON cc.claim_id=c.claim_id WHERE c.claim_id=?", (claim_id,)).fetchone()
                run = self.repository._run_row(connection, packet["run_id"])
                if current is None or current["state"] != "claimed" or current["claim_id"] != claim_id or claim is None or claim["session_id"] != session_id or claim["claim_state"] != "active":
                    raise MaxControlError("candidate submission does not own the active claim")
                if _utc(claim["expires_at"]) <= now_dt or _utc(packet["expires_at"]) <= now_dt:
                    raise MaxControlError("candidate claim or packet is expired")
                if expected_state_version != int(packet["state_version"]) or expected_state_hash != packet["state_hash"] or int(run["state_version"]) != int(packet["state_version"]) or run["current_state_hash"] != packet["state_hash"]:
                    raise MaxControlError("candidate submission carries a stale Run state version")
                result_id = make_event_id("external_agent_result", packet["project_id"], {"work_packet_id": work_packet_id, "idempotency_key": idempotency_key, "result_hash": result_hash})
                result_json = _json({key: value for key, value in normalized.items() if key != "usage"})
                usage_json = _json(usage)
                connection.execute("INSERT INTO max_external_agent_results(result_id,work_packet_id,run_id,project_id,iteration_id,session_id,authenticated_actor_id,claimed_agent_id,claimed_model,claim_id,state_version,state_hash,idempotency_key,result_json,result_hash,usage_json,usage_hash,usage_status,result_status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (result_id, work_packet_id, packet["run_id"], packet["project_id"], packet["iteration_id"], session_id, session["authenticated_actor_id"], session["claimed_agent_id"], session["claimed_model"], claim_id, int(packet["state_version"]), packet["state_hash"], idempotency_key, result_json, result_hash, usage_json, _hash(usage), usage["status"], "candidate", now))
                agent = Actor(session["authenticated_actor_id"], session["authenticated_actor_session"], session["authenticated_actor_kind"], session["authenticated_actor_role"], session["authenticated_actor_framework"], session["authenticated_model"])
                claim_event = self._append_claim_event(connection, claim_id=claim_id, packet=packet, event_type="released", actor=agent, now=now, detail={"reason": "candidate_submitted", "result_id": result_id, "result_hash": result_hash})
                claim_current = {"claim_id": claim_id, "work_packet_id": work_packet_id, "session_id": session_id, "state": "released", "updated_at": now, "reason": "candidate_submitted"}
                connection.execute("UPDATE max_external_agent_work_claim_current SET state=?,updated_at=?,current_json=?,current_hash=? WHERE claim_id=?", ("released", now, _json(claim_current), _hash(claim_current), claim_id))
                work_current = {"schema": EXTERNAL_AGENT_SCHEMA, "work_packet_id": work_packet_id, "run_id": packet["run_id"], "project_id": packet["project_id"], "state": "submitted", "generation": int(current["generation"]), "claim_id": None, "result_id": result_id, "updated_at": now}
                connection.execute("UPDATE max_external_agent_work_current SET state=?,claim_id=NULL,result_id=?,updated_at=?,current_json=?,current_hash=? WHERE work_packet_id=?", ("submitted", result_id, now, _json(work_current), _hash(work_current), work_packet_id))
                run_event = self._append_run_event(connection, packet=packet, event_type="candidate_submitted", actor=agent, now=now, detail={"claim_id": claim_id, "result_id": result_id, "result_hash": result_hash, "usage_status": usage["status"]})
            return {"result_id": result_id, "result_hash": result_hash, "usage_status": usage["status"], "status": "candidate", "idempotent": False, "claim_event": claim_event, "event": run_event}
        finally:
            connection.close()

    def get_submission_status(
        self,
        *,
        session_id: str,
        work_packet_id: str,
        idempotency_key: str,
        authenticated_actor: Actor,
    ) -> dict[str, Any]:
        """Read the bounded status of one candidate submission.

        The result envelope is intentionally not returned here.  A worker can
        recover the server-owned status and hashes without turning this query
        into a second source/result transport.
        """

        connection = self._connect(read_only=True)
        try:
            packet = connection.execute(
                "SELECT * FROM max_external_agent_work_packets WHERE work_packet_id=?",
                (work_packet_id,),
            ).fetchone()
            if packet is None:
                raise MaxControlError("external-Agent work packet was not found")
            session = self._require_session(
                connection,
                session_id=session_id,
                project_id=packet["project_id"],
                now=_utc_now(self.clock),
                require_active=True,
            )
            self._assert_actor_session(session, authenticated_actor)
            if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
                raise MaxControlError("idempotency_key is invalid")
            current = connection.execute(
                "SELECT state,generation,result_id,updated_at,current_hash FROM max_external_agent_work_current WHERE work_packet_id=?",
                (work_packet_id,),
            ).fetchone()
            row = connection.execute(
                "SELECT result_id,result_hash,usage_status,result_status,created_at,idempotency_key FROM max_external_agent_results WHERE work_packet_id=? AND idempotency_key=?",
                (work_packet_id, idempotency_key),
            ).fetchone()
            if row is None:
                return {
                    "work_packet_id": work_packet_id,
                    "idempotency_key": idempotency_key,
                    "status": "not_submitted",
                    "work_state": current["state"] if current is not None else "unknown",
                    "generation": int(current["generation"]) if current is not None else 0,
                    "current_hash": current["current_hash"] if current is not None else None,
                }
            return {
                "work_packet_id": work_packet_id,
                "idempotency_key": row["idempotency_key"],
                "status": row["result_status"],
                "result_id": row["result_id"],
                "result_hash": row["result_hash"],
                "usage_status": row["usage_status"],
                "created_at": row["created_at"],
                "work_state": current["state"] if current is not None else "unknown",
                "generation": int(current["generation"]) if current is not None else 0,
                "current_hash": current["current_hash"] if current is not None else None,
            }
        finally:
            connection.close()

    def _verify_event_chain(self, rows: Sequence[sqlite3.Row], *, key_field: str) -> list[str]:
        issues: list[str] = []
        expected_sequence = 1
        previous_hash = ""
        for row in rows:
            if int(row["sequence_no"]) != expected_sequence:
                issues.append(f"event sequence gap in {key_field}={row[key_field]}")
            if row["previous_event_hash"] != previous_hash:
                issues.append(f"event predecessor mismatch in {key_field}={row[key_field]}")
            try:
                payload = _loads(row["event_json"])
            except Exception:
                issues.append(f"event payload invalid in {key_field}={row[key_field]}")
                payload = None
            if payload is not None and row["payload_hash"] != _hash(payload):
                issues.append(f"event payload hash mismatch in {key_field}={row[key_field]}")
            expected = _event_hash(event_id=row["event_id"], sequence_no=int(row["sequence_no"]), event_type=row["event_type"], payload_hash=row["payload_hash"], previous_event_hash=row["previous_event_hash"], event_json=row["event_json"], actor_id=row["actor_id"], actor_kind=row["actor_kind"], actor_session=row["actor_session"], created_at=row["created_at"])
            if row["event_hash"] != expected:
                issues.append(f"event hash mismatch in {key_field}={row[key_field]}")
            previous_hash = row["event_hash"]
            expected_sequence += 1
        return issues

    def verify(
        self,
        *,
        run_id: str | None = None,
        session_id: str | None = None,
        authenticated_actor: Actor | None = None,
    ) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        issues: list[str] = []
        try:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
            foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
            session_rows = list(connection.execute("SELECT * FROM max_external_agent_sessions ORDER BY session_id"))
            packet_rows = list(connection.execute("SELECT * FROM max_external_agent_work_packets ORDER BY run_id,round_no"))
            scoped_project_id: str | None = None
            if session_id is not None:
                if authenticated_actor is None:
                    raise MaxControlError("authenticated actor is required for session-scoped verification")
                scoped_session = self._require_session(
                    connection,
                    session_id=session_id,
                    now=_utc_now(self.clock),
                    require_active=True,
                )
                self._assert_actor_session(scoped_session, authenticated_actor)
                scoped_project_id = str(scoped_session["project_id"])
                session_rows = [row for row in session_rows if row["project_id"] == scoped_project_id]
            if run_id is not None:
                run_row = connection.execute("SELECT project_id FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run_row is None:
                    raise MaxControlError("Max run was not found")
                if scoped_project_id is not None and run_row["project_id"] != scoped_project_id:
                    raise MaxControlError("run is outside the external-Agent project boundary")
                packet_rows = [row for row in packet_rows if row["run_id"] == run_id]
            elif scoped_project_id is not None:
                packet_rows = [row for row in packet_rows if row["project_id"] == scoped_project_id]
            for row in session_rows:
                try:
                    value = _loads(row["session_json"])
                    if row["session_hash"] != _hash(value) or value.get("session_id") != row["session_id"] or value.get("project_id") != row["project_id"]:
                        issues.append(f"session hash/binding mismatch: {row['session_id']}")
                except Exception:
                    issues.append(f"session JSON invalid: {row['session_id']}")
                issues.extend(self._verify_event_chain(list(connection.execute("SELECT * FROM max_external_agent_session_events WHERE session_id=? ORDER BY sequence_no", (row["session_id"],))), key_field="session_id"))
            for packet in packet_rows:
                try:
                    packet_value = _loads(packet["packet_json"])
                    if packet["packet_hash"] != _hash(packet_value) or packet_value.get("work_packet_id") != packet["work_packet_id"]:
                        issues.append(f"work packet hash mismatch: {packet['work_packet_id']}")
                    if packet["question_hash"] != _hash(_loads(packet["question_json"])) or packet["allowed_operations_hash"] != _hash(_loads(packet["allowed_operations_json"])) or packet["source_refs_hash"] != _hash(_loads(packet["source_refs_json"])) or packet["result_contract_hash"] != _hash(_loads(packet["result_contract_json"])):
                        issues.append(f"work packet component hash mismatch: {packet['work_packet_id']}")
                except Exception:
                    issues.append(f"work packet JSON invalid: {packet['work_packet_id']}")
                current = connection.execute("SELECT * FROM max_external_agent_work_current WHERE work_packet_id=?", (packet["work_packet_id"],)).fetchone()
                if current is None:
                    issues.append(f"work current projection missing: {packet['work_packet_id']}")
                    continue
                try:
                    current_value = _loads(current["current_json"])
                    if current["current_hash"] != _hash(current_value):
                        issues.append(f"work current hash mismatch: {packet['work_packet_id']}")
                except Exception:
                    issues.append(f"work current JSON invalid: {packet['work_packet_id']}")
                claims = list(connection.execute("SELECT * FROM max_external_agent_work_claims WHERE work_packet_id=? ORDER BY generation", (packet["work_packet_id"],)))
                generations = [int(item["generation"]) for item in claims]
                if generations != list(range(1, len(generations) + 1)):
                    issues.append(f"claim generation lineage is not contiguous: {packet['work_packet_id']}")
                active = 0
                for claim in claims:
                    try:
                        if claim["claim_hash"] != _hash(_loads(claim["claim_json"])):
                            issues.append(f"claim hash mismatch: {claim['claim_id']}")
                    except Exception:
                        issues.append(f"claim JSON invalid: {claim['claim_id']}")
                    claim_current = connection.execute("SELECT * FROM max_external_agent_work_claim_current WHERE claim_id=?", (claim["claim_id"],)).fetchone()
                    if claim_current is None:
                        issues.append(f"claim current missing: {claim['claim_id']}")
                    elif claim_current["state"] == "active":
                        active += 1
                        if current["state"] != "claimed" or current["claim_id"] != claim["claim_id"]:
                            issues.append(f"active claim is not the work current claim: {claim['claim_id']}")
                    issues.extend(self._verify_event_chain(list(connection.execute("SELECT * FROM max_external_agent_work_claim_events WHERE claim_id=? ORDER BY sequence_no", (claim["claim_id"],))), key_field="claim_id"))
                if active > 1:
                    issues.append(f"multiple active external-Agent claims: {packet['work_packet_id']}")
                if current["state"] == "claimed" and active != 1:
                    issues.append(f"claimed work has no single active claim: {packet['work_packet_id']}")
                if current["state"] == "submitted":
                    if current["result_id"] is None or connection.execute("SELECT 1 FROM max_external_agent_results WHERE result_id=? AND work_packet_id=?", (current["result_id"], packet["work_packet_id"])).fetchone() is None:
                        issues.append(f"submitted work has no bound candidate result: {packet['work_packet_id']}")
                    if active:
                        issues.append(f"submitted work still has an active claim: {packet['work_packet_id']}")
                issues.extend(self._verify_event_chain(list(connection.execute("SELECT * FROM max_external_agent_events WHERE stream_key=? ORDER BY sequence_no", (f"run:{packet['run_id']}",))), key_field="stream_key"))
            result_filters: list[str] = []
            result_parameters: list[str] = []
            if run_id is not None:
                result_filters.append("run_id=?")
                result_parameters.append(run_id)
            if scoped_project_id is not None:
                result_filters.append("project_id=?")
                result_parameters.append(scoped_project_id)
            result_query = "SELECT * FROM max_external_agent_results" + (" WHERE " + " AND ".join(result_filters) if result_filters else "")
            result_rows = list(connection.execute(result_query, tuple(result_parameters)))
            for result in result_rows:
                try:
                    candidate = _loads(result["result_json"])
                    usage = _loads(result["usage_json"])
                    normalized = {**candidate, "usage": usage}
                    expected_hash = _hash({"work_packet_id": result["work_packet_id"], "idempotency_key": result["idempotency_key"], "result": normalized})
                    if result["result_hash"] != expected_hash or result["usage_hash"] != _hash(usage) or result["result_status"] != "candidate":
                        issues.append(f"candidate result hash/status mismatch: {result['result_id']}")
                    packet = connection.execute("SELECT source_refs_json FROM max_external_agent_work_packets WHERE work_packet_id=?", (result["work_packet_id"],)).fetchone()
                    if packet is not None:
                        allowed = self._source_identifier_set(_loads(packet["source_refs_json"]))
                        for claim in candidate.get("candidate_claims", []):
                            if any(ref not in allowed for ref in claim.get("source_refs", [])):
                                issues.append(f"candidate source binding mismatch: {result['result_id']}")
                except Exception:
                    issues.append(f"candidate result JSON invalid: {result['result_id']}")
            event_filter: list[str] = []
            event_parameters: list[str] = []
            if run_id is not None:
                event_filter.append("run_id=?")
                event_parameters.append(run_id)
            elif scoped_project_id is not None:
                event_filter.append("project_id=?")
                event_parameters.append(scoped_project_id)
            event_query = "SELECT COUNT(*) FROM max_external_agent_events" + (" WHERE " + " AND ".join(event_filter) if event_filter else "")
            return {
                "ok": not issues and quick_check == "ok" and not foreign_keys,
                "protocol": EXTERNAL_AGENT_PROTOCOL,
                "schema_version": CONTROL_SCHEMA_VERSION,
                "quick_check": quick_check == "ok",
                "foreign_keys": not foreign_keys,
                "counts": {"sessions": len(session_rows), "packets": len(packet_rows), "claims": sum(int(connection.execute("SELECT COUNT(*) FROM max_external_agent_work_claims WHERE work_packet_id=?", (p["work_packet_id"],)).fetchone()[0]) for p in packet_rows), "results": len(result_rows), "events": int(connection.execute(event_query, tuple(event_parameters)).fetchone()[0])},
                "issues": sorted(set(issues)),
                "external_actions": {"provider": 0, "network": 0, "credential_reads": 0},
            }
        finally:
            connection.close()


class ExternalAgentError(MaxControlError):
    """Named error for integrations that want to distinguish protocol failures."""


__all__ = ["EXTERNAL_AGENT_PROTOCOL", "EXTERNAL_AGENT_SCHEMA", "ExternalAgentError", "ExternalAgentService", "ExternalAgentSourceResolver"]
