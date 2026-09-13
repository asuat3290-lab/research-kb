"""MR-4B1B-v13R1 durable preparation handoff control plane.

Preparation authority is short-lived build authority.  The immutable handoff
and its current projection are server-owned, hash-bound, and contain only
stable identifiers and digests.  This module never performs DNS, credential,
network, or Provider work.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .contract import canonical_json, canonical_sha256, make_stable_id
from .persistence.db import MaxControlError, control_transaction
from .persistence.repository import (
    MaxControlRepository,
    _parse_timestamp,
    _timestamp,
)
from ..policy import Actor


PREPARED = "PREPARED_AWAITING_AUTHORIZATION"
JIT_EXECUTING = "JIT_EXECUTING"
TERMINAL_HANDOFF_STATES = {"SUCCEEDED", "FAILED", "UNKNOWN", "CANCELLED", "EXPIRED", "CLOSED"}
PREPARATION_CLAIM_HELD = "OPEN_WITH_PREPARATION_CLAIM"


class PreparationHandoffError(MaxControlError):
    """A durable preparation handoff invariant failed closed."""


def _json_hash(value: str, name: str) -> tuple[dict[str, Any], str]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PreparationHandoffError(f"{name} JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise PreparationHandoffError(f"{name} JSON is not an object")
    return parsed, canonical_sha256(parsed)


_DNS_REQUEST_BINDING_KEYS = (
    "schema", "hostname", "port", "scheme", "snapshot_id", "snapshot_hash",
    "preview_id", "preview_hash", "endpoint_origin_hash", "network_policy_hash",
    "max_getaddrinfo_calls", "max_dns_candidates", "credential_reads",
    "tcp_connections", "tls_https_calls", "provider_calls", "cost_units",
)


def _dns_request_binding_hash(value: Mapping[str, Any]) -> str:
    """Recompute the request hash over the immutable request binding only.

    The server adds authority ID/hash, expiry, and status to the persisted
    request JSON after calculating the request hash.  Hashing the whole
    serialized row would therefore reject every valid request and would also
    make those server-owned projections part of the client binding.
    """

    if set(value) != set(_DNS_REQUEST_BINDING_KEYS) | {"authority_id", "authority_hash", "expires_at", "status"}:
        raise PreparationHandoffError("DNS request serialized shape is invalid")
    return canonical_sha256({key: value.get(key) for key in _DNS_REQUEST_BINDING_KEYS})


def _reservation_hash(row: sqlite3.Row) -> str:
    return canonical_sha256(
        {
            "entry_id": row["entry_id"],
            "run_id": row["run_id"],
            "sequence_no": int(row["sequence_no"]),
            "operation": row["operation"],
            "idempotency_key": row["idempotency_key"],
            "amount_json": row["amount_json"],
            "provenance_json": row["provenance_json"],
        }
    )


def _effective_claims(connection: sqlite3.Connection, run_id: str, now: datetime) -> list[sqlite3.Row]:
    result: list[sqlite3.Row] = []
    for row in connection.execute(
        "SELECT c.* FROM max_runner_invocation_claims c "
        "WHERE c.run_id=? AND c.status='active' "
        "AND NOT EXISTS (SELECT 1 FROM max_runner_invocation_claims r "
        "WHERE r.run_id=c.run_id AND r.status='released' "
        "AND r.claim_id=c.claim_id || ':released')",
        (run_id,),
    ):
        expiry = _parse_timestamp(row["expires_at"])
        if expiry is not None and expiry > now:
            result.append(row)
    return result


class PreparationHandoffStore:
    """Formal persistence facade for handoff, verifier, and JIT transitions."""

    def __init__(self, repository: MaxControlRepository, *, source_database: str | Path | None = None) -> None:
        from .lifetime_separation import PreparationSnapshotStore

        self.repository = repository
        self.snapshots = PreparationSnapshotStore(repository, source_database=source_database)

    def _connect(self, *, read_only: bool) -> sqlite3.Connection:
        return self.repository._connect(read_only=read_only)

    def _chain(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        snapshot_id: str,
        preview_id: str,
        dns_authority_id: str,
        dns_request_id: str,
    ) -> dict[str, Any]:
        snapshot = connection.execute(
            "SELECT * FROM max_live_canary_preparation_snapshots WHERE snapshot_id=? AND run_id=?",
            (snapshot_id, run_id),
        ).fetchone()
        preview = connection.execute(
            "SELECT * FROM max_live_canary_preparation_previews WHERE preview_id=? AND snapshot_id=? AND run_id=?",
            (preview_id, snapshot_id, run_id),
        ).fetchone()
        authority = connection.execute(
            "SELECT * FROM max_live_canary_preparation_dns_authorities "
            "WHERE authority_id=? AND preview_id=? AND snapshot_id=?",
            (dns_authority_id, preview_id, snapshot_id),
        ).fetchone()
        request = connection.execute(
            "SELECT * FROM max_live_canary_preparation_dns_requests "
            "WHERE request_id=? AND authority_id=?",
            (dns_request_id, dns_authority_id),
        ).fetchone()
        if snapshot is None or preview is None or authority is None or request is None:
            raise PreparationHandoffError("preparation handoff chain is incomplete")

        snapshot_value, snapshot_hash = _json_hash(snapshot["snapshot_json"], "Snapshot")
        preview_value, preview_hash = _json_hash(preview["preview_json"], "Preview")
        authority_value, authority_hash = _json_hash(authority["authority_json"], "DNS Authority")
        request_value, _request_serialized_hash = _json_hash(request["request_json"], "DNS request")
        request_hash = _dns_request_binding_hash(request_value)
        if snapshot_hash != snapshot["snapshot_hash"] or preview_hash != preview["preview_hash"]:
            raise PreparationHandoffError("Snapshot or Preview hash is invalid")
        if authority_hash != authority["authority_hash"] or request_hash != request["request_hash"]:
            raise PreparationHandoffError("DNS Authority or Request hash is invalid")
        if preview["snapshot_hash"] != snapshot["snapshot_hash"]:
            raise PreparationHandoffError("Preview is not bound to the Snapshot")
        if request["snapshot_hash"] != snapshot["snapshot_hash"] or request["preview_hash"] != preview["preview_hash"]:
            raise PreparationHandoffError("DNS Request is not bound to the Snapshot/Preview")
        if authority["request_hash"] != request["request_hash"] or request_value.get("authority_id") != authority["authority_id"]:
            raise PreparationHandoffError("DNS Authority/Request binding drifted")
        if authority["status"] != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION" or request["status"] != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION":
            raise PreparationHandoffError("DNS Request is not in the preparation wait state")
        if authority_value.get("status") != request_value.get("status") or authority_value.get("status") != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION":
            raise PreparationHandoffError("DNS Request serialized state drifted")
        snapshot_issues = self.snapshots._verify_event_chain(connection, snapshot_id)
        snapshot_issues += self.snapshots._drift(connection, snapshot)
        if snapshot_issues:
            raise PreparationHandoffError("preparation binding drifted: " + ", ".join(sorted(set(snapshot_issues))))
        return {
            "snapshot": snapshot,
            "preview": preview,
            "authority": authority,
            "request": request,
            "snapshot_value": snapshot_value,
            "preview_value": preview_value,
            "authority_value": authority_value,
            "request_value": request_value,
        }

    @staticmethod
    def _manifest_and_reservation(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        intent_id: str,
        logical_call_id: str,
        reservation_id: str | None,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        manifest = connection.execute(
            "SELECT * FROM max_runner_intent_manifests "
            "WHERE intent_id=? AND run_id=? AND logical_call_id=?",
            (intent_id, run_id, logical_call_id),
        ).fetchone()
        if manifest is None:
            raise PreparationHandoffError("durable request manifest is missing")
        if reservation_id is None:
            reservation = connection.execute(
                "SELECT * FROM max_budget_ledger WHERE run_id=? AND operation='reserve' "
                "AND idempotency_key=? ORDER BY sequence_no DESC LIMIT 1",
                (run_id, f"mr2a:reserve:{logical_call_id}"),
            ).fetchone()
        else:
            reservation = connection.execute(
                "SELECT * FROM max_budget_ledger "
                "WHERE entry_id=? AND run_id=? AND operation='reserve'",
                (reservation_id, run_id),
            ).fetchone()
        if reservation is None:
            raise PreparationHandoffError("budget reservation binding is missing")
        return manifest, reservation

    @staticmethod
    def _append_handoff_event(
        connection: sqlite3.Connection,
        *,
        handoff: Mapping[str, Any],
        state: str,
        payload: Mapping[str, Any],
        actor: Actor,
        now: str,
    ) -> dict[str, Any]:
        if state not in {PREPARED, JIT_EXECUTING, *TERMINAL_HANDOFF_STATES}:
            raise PreparationHandoffError("invalid preparation handoff state")
        payload_value = dict(payload)
        payload_json = canonical_json(payload_value)
        payload_hash = canonical_sha256(payload_value)
        prior = connection.execute(
            "SELECT sequence_no,event_hash FROM max_runner_preparation_handoff_events "
            "WHERE handoff_id=? ORDER BY sequence_no DESC LIMIT 1",
            (handoff["handoff_id"],),
        ).fetchone()
        sequence = int(prior["sequence_no"]) + 1 if prior is not None else 1
        previous_hash = prior["event_hash"] if prior is not None else None
        identity = {
            "handoff_id": handoff["handoff_id"],
            "run_id": handoff["run_id"],
            "call_group_id": handoff["call_group_id"],
            "sequence_no": sequence,
            "state": state,
            "payload_hash": payload_hash,
            "previous_event_hash": previous_hash,
            "created_at": now,
        }
        event_hash = canonical_sha256(
            {
                **identity,
                "payload_json": payload_json,
                "actor_id": actor.actor_id,
                "actor_kind": actor.actor_kind,
                "actor_session": actor.session_id,
            }
        )
        event_id = make_stable_id("preparation_handoff_event", event_hash[:64])
        connection.execute(
            "INSERT INTO max_runner_preparation_handoff_events("
            "event_id,handoff_id,project_id,run_id,call_group_id,sequence_no,state,"
            "payload_json,payload_hash,previous_event_hash,event_hash,created_at,"
            "actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                handoff["handoff_id"],
                handoff["project_id"],
                handoff["run_id"],
                handoff["call_group_id"],
                sequence,
                state,
                payload_json,
                payload_hash,
                previous_hash,
                event_hash,
                now,
                actor.actor_id,
                actor.actor_kind,
                actor.session_id,
            ),
        )
        current_value = {
            "schema": "research-kb/mr4b1b-v13r1-preparation-handoff-current/v1",
            "handoff_id": handoff["handoff_id"],
            "project_id": handoff["project_id"],
            "run_id": handoff["run_id"],
            "call_group_id": handoff["call_group_id"],
            "state": state,
            "event_hash": event_hash,
            **payload_value,
        }
        current_json = canonical_json(current_value)
        current_hash = canonical_sha256(current_value)
        exists = connection.execute(
            "SELECT 1 FROM max_runner_preparation_handoff_current WHERE handoff_id=?",
            (handoff["handoff_id"],),
        ).fetchone()
        if exists is None:
            connection.execute(
                "INSERT INTO max_runner_preparation_handoff_current("
                "handoff_id,project_id,run_id,call_group_id,state,current_event_sequence,"
                "current_event_hash,current_json,current_hash,updated_at,updated_by)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    handoff["handoff_id"],
                    handoff["project_id"],
                    handoff["run_id"],
                    handoff["call_group_id"],
                    state,
                    sequence,
                    event_hash,
                    current_json,
                    current_hash,
                    now,
                    actor.actor_id,
                ),
            )
        else:
            connection.execute(
                "UPDATE max_runner_preparation_handoff_current SET state=?,"
                "current_event_sequence=?,current_event_hash=?,current_json=?,"
                "current_hash=?,updated_at=?,updated_by=? WHERE handoff_id=?",
                (
                    state,
                    sequence,
                    event_hash,
                    current_json,
                    current_hash,
                    now,
                    actor.actor_id,
                    handoff["handoff_id"],
                ),
            )
        return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "current_hash": current_hash}

    @staticmethod
    def _release_claim_and_lease(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        claim: sqlite3.Row,
        actor: Actor,
        fencing_token: int,
        now: str,
    ) -> tuple[str, str]:
        released_claim_id = f"{claim['claim_id']}:released"
        if connection.execute(
            "SELECT 1 FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=?",
            (released_claim_id, run_id),
        ).fetchone() is None:
            payload = {
                "claim_id": claim["claim_id"],
                "run_id": run_id,
                "actor_id": actor.actor_id,
                "actor_session": actor.session_id,
                "fencing_token": int(fencing_token),
                "attempt_id": released_claim_id,
                "expires_at": now,
                "status": "released",
                "released_claim_id": claim["claim_id"],
            }
            connection.execute(
                "INSERT INTO max_runner_invocation_claims("
                "claim_id,run_id,actor_id,actor_session,fencing_token,attempt_id,"
                "expires_at,status,claim_json,claim_hash,created_at,released_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    released_claim_id,
                    run_id,
                    actor.actor_id,
                    actor.session_id,
                    int(fencing_token),
                    released_claim_id,
                    now,
                    "released",
                    canonical_json(payload),
                    canonical_sha256(payload),
                    now,
                    now,
                ),
            )
        lease = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
        if lease is None or lease["owner_id"] != actor.actor_id or lease["session_id"] != actor.session_id or int(lease["fencing_token"]) != int(fencing_token):
            raise PreparationHandoffError("preparation lease binding is invalid")
        connection.execute(
            "UPDATE max_leases SET expires_at=?,released_at=? WHERE run_id=?",
            (now, now, run_id),
        )
        return released_claim_id, f"run-lease:{run_id}:released"

    def handoff_preparation(
        self,
        *,
        run_id: str,
        snapshot_id: str,
        preview_id: str,
        dns_authority_id: str,
        dns_request_id: str,
        preparation_claim_id: str,
        fencing_token: int,
        worker: Actor,
        reservation_id: str | None = None,
    ) -> dict[str, Any]:
        """Atomically enter PREPARED_AWAITING_AUTHORIZATION."""

        if worker.is_admin or worker.actor_kind not in {"worker", "runner", "agent"}:
            raise PreparationHandoffError("preparation handoff requires a non-admin worker actor")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                group_row = connection.execute(
                    "SELECT g.*,c.status AS group_status,c.lifecycle_state "
                    "FROM max_runner_call_groups g "
                    "JOIN max_runner_call_group_current c ON c.group_id=g.group_id "
                    "WHERE g.run_id=? ORDER BY g.created_at DESC LIMIT 1",
                    (run_id,),
                ).fetchone()
                if group_row is None:
                    raise PreparationHandoffError("durable call group is missing")
                existing = connection.execute(
                    "SELECT h.*,c.state AS current_state "
                    "FROM max_runner_preparation_handoffs h "
                    "JOIN max_runner_preparation_handoff_current c ON c.handoff_id=h.handoff_id "
                    "WHERE h.call_group_id=?",
                    (group_row["group_id"],),
                ).fetchone()
                if existing is not None:
                    if existing["current_state"] != PREPARED:
                        raise PreparationHandoffError("preparation handoff is already beyond the human-wait state")
                    if existing["preparation_claim_id"] != preparation_claim_id or int(existing["last_fencing_token"]) != int(fencing_token):
                        raise PreparationHandoffError("preparation handoff replay/stale claim rejected")
                    return {"ok": True, "idempotent": True, "handoff_id": existing["handoff_id"], "state": PREPARED, "released_claim_id": existing["released_claim_id"], "released_lease_id": existing["released_lease_id"]}
                if group_row["group_status"] != "open" or group_row["lifecycle_state"] not in {PREPARATION_CLAIM_HELD, "OPEN_WITH_LIVE_CLAIM"}:
                    raise PreparationHandoffError("call group is not in the claim-held preparation state")
                claim = connection.execute(
                    "SELECT * FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=? AND status='active'",
                    (preparation_claim_id, run_id),
                ).fetchone()
                if claim is None or claim["actor_id"] != worker.actor_id or claim["actor_session"] != worker.session_id or int(claim["fencing_token"]) != int(fencing_token):
                    raise PreparationHandoffError("preparation invocation claim is not current")
                self.repository._assert_fence(connection, run_id=run_id, actor=worker, fencing_token=fencing_token, now=now)
                chain = self._chain(connection, run_id=run_id, snapshot_id=snapshot_id, preview_id=preview_id, dns_authority_id=dns_authority_id, dns_request_id=dns_request_id)
                snapshot = chain["snapshot"]
                if snapshot["group_id"] != group_row["group_id"]:
                    raise PreparationHandoffError("Snapshot is bound to another call group")
                intent = connection.execute(
                    "SELECT * FROM max_model_call_intents WHERE intent_id=? AND run_id=? AND logical_call_id=?",
                    (snapshot["intent_id"], run_id, snapshot["logical_call_id"]),
                ).fetchone()
                if intent is None or intent["iteration_id"] != snapshot["iteration_id"]:
                    raise PreparationHandoffError("durable intent binding is invalid")
                manifest, reservation = self._manifest_and_reservation(connection, run_id=run_id, intent_id=intent["intent_id"], logical_call_id=intent["logical_call_id"], reservation_id=reservation_id)
                for table, column in (("max_model_call_attempts", "logical_call_id"), ("max_model_call_results", "logical_call_id"), ("max_provider_call_records", "run_id"), ("max_provider_call_results", "run_id"), ("max_provider_dispatch_attempts", "run_id"), ("max_live_canary_native_jit_authorities", "run_id")):
                    value = intent["logical_call_id"] if column == "logical_call_id" else run_id
                    if int(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (value,)).fetchone()[0]) != 0:
                        raise PreparationHandoffError("preparation handoff crossed the send boundary")
                source_binding_hash = canonical_sha256(chain["snapshot_value"]["source_binding"])
                lease_id = f"run-lease:{run_id}"
                released_claim_id, released_lease_id = self._release_claim_and_lease(connection, run_id=run_id, claim=claim, actor=worker, fencing_token=fencing_token, now=now)
                binding = {
                    "schema": "research-kb/mr4b1b-v13r1-preparation-handoff/v1",
                    "server_owned": True,
                    "project_id": snapshot["project_id"], "run_id": run_id, "iteration_id": snapshot["iteration_id"], "call_group_id": group_row["group_id"],
                    "intent_id": intent["intent_id"], "request_manifest_id": manifest["intent_id"], "request_manifest_hash": manifest["manifest_hash"],
                    "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"], "preview_id": chain["preview"]["preview_id"], "preview_hash": chain["preview"]["preview_hash"],
                    "dns_authority_id": chain["authority"]["authority_id"], "dns_authority_hash": chain["authority"]["authority_hash"], "dns_request_id": chain["request"]["request_id"], "dns_request_hash": chain["request"]["request_hash"],
                    "source_binding_hash": source_binding_hash, "release_identity_hash": snapshot["release_identity_hash"], "provider_profile_hash": snapshot["provider_profile_hash"], "model_identity": snapshot["model_identity"],
                    "pricing_hash": snapshot["pricing_hash"], "network_policy_hash": snapshot["network_policy_hash"], "source_policy_hash": snapshot["source_policy_hash"], "credential_reference_hash": snapshot["credential_reference_hash"], "budget_hash": snapshot["budget_hash"],
                    "reservation_id": reservation["entry_id"], "reservation_hash": _reservation_hash(reservation), "preparation_claim_id": preparation_claim_id, "released_claim_id": released_claim_id,
                    "preparation_lease_id": lease_id, "released_lease_id": released_lease_id, "last_fencing_token": int(fencing_token), "handoff_state": PREPARED, "created_at": now,
                }
                handoff_hash = canonical_sha256(binding)
                handoff_id = make_stable_id("preparation_handoff", handoff_hash[:64])
                handoff_row = {**binding, "handoff_id": handoff_id, "handoff_hash": handoff_hash}
                columns = "handoff_id,project_id,run_id,iteration_id,call_group_id,intent_id,request_manifest_id,request_manifest_hash,snapshot_id,snapshot_hash,preview_id,preview_hash,dns_authority_id,dns_authority_hash,dns_request_id,dns_request_hash,source_binding_hash,release_identity_hash,provider_profile_hash,model_identity,pricing_hash,network_policy_hash,source_policy_hash,credential_reference_hash,budget_hash,reservation_id,reservation_hash,preparation_claim_id,released_claim_id,preparation_lease_id,released_lease_id,last_fencing_token,handoff_state,handoff_json,handoff_hash,created_at,actor_id,actor_kind,actor_session"
                values = (handoff_id, snapshot["project_id"], run_id, snapshot["iteration_id"], group_row["group_id"], intent["intent_id"], manifest["intent_id"], manifest["manifest_hash"], snapshot["snapshot_id"], snapshot["snapshot_hash"], chain["preview"]["preview_id"], chain["preview"]["preview_hash"], chain["authority"]["authority_id"], chain["authority"]["authority_hash"], chain["request"]["request_id"], chain["request"]["request_hash"], source_binding_hash, snapshot["release_identity_hash"], snapshot["provider_profile_hash"], snapshot["model_identity"], snapshot["pricing_hash"], snapshot["network_policy_hash"], snapshot["source_policy_hash"], snapshot["credential_reference_hash"], snapshot["budget_hash"], reservation["entry_id"], _reservation_hash(reservation), preparation_claim_id, released_claim_id, lease_id, released_lease_id, int(fencing_token), PREPARED, canonical_json(binding), handoff_hash, now, worker.actor_id, worker.actor_kind, worker.session_id)
                connection.execute(f"INSERT INTO max_runner_preparation_handoffs({columns}) VALUES ({','.join('?' for _ in values)})", values)
                event = self._append_handoff_event(connection, handoff=handoff_row, state=PREPARED, payload={"handoff_hash": handoff_hash, "released_claim_id": released_claim_id, "released_lease_id": released_lease_id, "last_fencing_token": int(fencing_token), "send_boundary_reached": False}, actor=worker, now=now)
                connection.execute("UPDATE max_runner_call_group_current SET lifecycle_state=?,updated_at=?,updated_by=? WHERE group_id=? AND run_id=? AND status='open'", (PREPARED, now, worker.actor_id, group_row["group_id"], run_id))
                self.repository._append_event(connection, run_id=run_id, event_type="runner_invocation_released", payload={"claim_id": preparation_claim_id, "fencing_token": int(fencing_token), "reason": "preparation_handoff"}, actor=worker, now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="lease_released", payload={"fencing_token": int(fencing_token), "reason": "preparation_handoff"}, actor=worker, now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="preparation_handoff_created", payload={"handoff_id": handoff_id, "call_group_id": group_row["group_id"], "snapshot_id": snapshot["snapshot_id"], "preview_id": chain["preview"]["preview_id"], "dns_request_id": chain["request"]["request_id"], "event_hash": event["event_hash"]}, actor=worker, now=now)
                return {"ok": True, "idempotent": False, "handoff_id": handoff_id, "handoff_hash": handoff_hash, "state": PREPARED, "call_group_id": group_row["group_id"], "released_claim_id": released_claim_id, "released_lease_id": released_lease_id, "last_fencing_token": int(fencing_token), "event_hash": event["event_hash"]}
        except PreparationHandoffError:
            raise
        except sqlite3.IntegrityError as exc:
            raise PreparationHandoffError("preparation handoff conflicted with an immutable record") from exc
        finally:
            connection.close()

    def close_waiting_handoff(
        self,
        *,
        run_id: str,
        state: str,
        actor: Actor,
        handoff_id: str | None = None,
        reason: str = "explicit cancellation or expiry",
    ) -> dict[str, Any]:
        """Close a waiting handoff without reviving a claim or creating authority."""

        if not actor.is_admin:
            raise PreparationHandoffError("closing a preparation handoff requires human admin authority")
        if state not in {"CANCELLED", "EXPIRED", "CLOSED"}:
            raise PreparationHandoffError("invalid waiting handoff terminal state")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                selector = "h.handoff_id=?" if handoff_id is not None else "h.run_id=?"
                value = handoff_id if handoff_id is not None else run_id
                row = connection.execute(
                    "SELECT h.*,c.state FROM max_runner_preparation_handoffs h "
                    "JOIN max_runner_preparation_handoff_current c ON c.handoff_id=h.handoff_id "
                    f"WHERE {selector} ORDER BY h.created_at DESC LIMIT 1",
                    (value,),
                ).fetchone()
                if row is None or row["run_id"] != run_id:
                    raise PreparationHandoffError("preparation handoff was not found")
                if row["state"] == state:
                    return {"ok": True, "idempotent": True, "handoff_id": row["handoff_id"], "state": state}
                if row["state"] != PREPARED:
                    raise PreparationHandoffError("only a waiting preparation handoff can be closed")
                issues = self.verify_group_handoff(connection, run_id=run_id, group_id=row["call_group_id"], now=self.repository.clock())
                if issues:
                    raise PreparationHandoffError("cannot close an invalid preparation handoff: " + ", ".join(issues))
                event = self._append_handoff_event(
                    connection,
                    handoff=row,
                    state=state,
                    payload={"reason": reason, "send_boundary_reached": False, "budget_action": "reservation remains conservatively bound"},
                    actor=actor,
                    now=now,
                )
                connection.execute(
                    "UPDATE max_runner_call_group_current SET lifecycle_state=?,updated_at=?,updated_by=? WHERE group_id=? AND run_id=?",
                    (state, now, actor.actor_id, row["call_group_id"], run_id),
                )
                self.repository._append_event(
                    connection,
                    run_id=run_id,
                    event_type="preparation_handoff_closed",
                    payload={"handoff_id": row["handoff_id"], "state": state, "reason": reason, "event_hash": event["event_hash"]},
                    actor=actor,
                    now=now,
                )
                return {"ok": True, "idempotent": False, "handoff_id": row["handoff_id"], "state": state, "event_hash": event["event_hash"], "budget_action": "reservation remains conservatively bound"}
        except PreparationHandoffError:
            raise
        except sqlite3.IntegrityError as exc:
            raise PreparationHandoffError("preparation handoff close conflicted with an immutable record") from exc
        finally:
            connection.close()

    def status(self, *, run_id: str | None = None, group_id: str | None = None, handoff_id: str | None = None) -> dict[str, Any]:
        selectors = [item for item in (run_id, group_id, handoff_id) if item is not None]
        if len(selectors) != 1:
            raise PreparationHandoffError("exactly one handoff selector is required")
        connection = self._connect(read_only=True)
        try:
            if handoff_id is not None:
                row = connection.execute("SELECT h.*,c.state,c.current_event_hash,c.current_hash FROM max_runner_preparation_handoffs h JOIN max_runner_preparation_handoff_current c ON c.handoff_id=h.handoff_id WHERE h.handoff_id=?", (handoff_id,)).fetchone()
            elif group_id is not None:
                row = connection.execute("SELECT h.*,c.state,c.current_event_hash,c.current_hash FROM max_runner_preparation_handoffs h JOIN max_runner_preparation_handoff_current c ON c.handoff_id=h.handoff_id WHERE h.call_group_id=?", (group_id,)).fetchone()
            else:
                row = connection.execute("SELECT h.*,c.state,c.current_event_hash,c.current_hash FROM max_runner_preparation_handoffs h JOIN max_runner_preparation_handoff_current c ON c.handoff_id=h.handoff_id WHERE h.run_id=? ORDER BY h.created_at DESC LIMIT 1", (run_id,)).fetchone()
            if row is None:
                raise PreparationHandoffError("preparation handoff was not found")
            return {"ok": True, "handoff_id": row["handoff_id"], "handoff_hash": row["handoff_hash"], "run_id": row["run_id"], "call_group_id": row["call_group_id"], "state": row["state"], "current_event_hash": row["current_event_hash"], "current_hash": row["current_hash"], "preparation_claim_released": True, "preparation_lease_released": True}
        finally:
            connection.close()

    @staticmethod
    def _static_issues(handoff: sqlite3.Row, current: sqlite3.Row) -> list[str]:
        issues: list[str] = []
        value, value_hash = _json_hash(handoff["handoff_json"], "handoff")
        if value_hash != handoff["handoff_hash"]:
            issues.append("prepared_group_binding_drift")
        fields = ("project_id", "run_id", "iteration_id", "call_group_id", "intent_id", "request_manifest_id", "request_manifest_hash", "snapshot_id", "snapshot_hash", "preview_id", "preview_hash", "dns_authority_id", "dns_authority_hash", "dns_request_id", "dns_request_hash", "source_binding_hash", "release_identity_hash", "provider_profile_hash", "model_identity", "pricing_hash", "network_policy_hash", "source_policy_hash", "credential_reference_hash", "budget_hash", "reservation_id", "reservation_hash", "preparation_claim_id", "released_claim_id", "preparation_lease_id", "released_lease_id", "last_fencing_token", "handoff_state")
        if any(value.get(key) != handoff[key] for key in fields):
            issues.append("prepared_group_binding_drift")
        current_value, current_hash = _json_hash(current["current_json"], "handoff current")
        if current_hash != current["current_hash"] or current_value.get("state") != current["state"] or current_value.get("event_hash") != current["current_event_hash"]:
            issues.append("prepared_group_binding_drift")
        return sorted(set(issues))

    @classmethod
    def verify_group_handoff(cls, connection: sqlite3.Connection, *, run_id: str, group_id: str, now: datetime) -> list[str]:
        current_group = connection.execute("SELECT * FROM max_runner_call_group_current WHERE group_id=? AND run_id=?", (group_id, run_id)).fetchone()
        if current_group is None:
            return ["prepared_group_missing_handoff"]
        lifecycle = current_group["lifecycle_state"] if "lifecycle_state" in current_group.keys() else "OPEN_WITH_LIVE_CLAIM"
        handoff_current = connection.execute("SELECT * FROM max_runner_preparation_handoff_current WHERE call_group_id=? AND run_id=?", (group_id, run_id)).fetchone()
        handoff = None if handoff_current is None else connection.execute("SELECT * FROM max_runner_preparation_handoffs WHERE handoff_id=?", (handoff_current["handoff_id"],)).fetchone()
        if handoff is None or handoff_current is None:
            return ["prepared_group_missing_handoff"]
        issues = cls._static_issues(handoff, handoff_current)
        events = list(connection.execute("SELECT * FROM max_runner_preparation_handoff_events WHERE handoff_id=? ORDER BY sequence_no", (handoff["handoff_id"],)))
        previous_hash: str | None = None
        for index, event in enumerate(events, 1):
            try:
                payload, payload_hash = _json_hash(event["payload_json"], "handoff event")
                if event["sequence_no"] != index or payload_hash != event["payload_hash"] or event["previous_event_hash"] != previous_hash:
                    issues.append("prepared_group_binding_drift")
                expected_hash = canonical_sha256({"handoff_id": event["handoff_id"], "run_id": event["run_id"], "call_group_id": event["call_group_id"], "sequence_no": int(event["sequence_no"]), "state": event["state"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"], "payload_json": event["payload_json"], "actor_id": event["actor_id"], "actor_kind": event["actor_kind"], "actor_session": event["actor_session"]})
                if expected_hash != event["event_hash"]:
                    issues.append("prepared_group_binding_drift")
                previous_hash = event["event_hash"]
            except Exception:
                issues.append("prepared_group_binding_drift")
        if not events or handoff_current["current_event_sequence"] != events[-1]["sequence_no"] or handoff_current["current_event_hash"] != events[-1]["event_hash"]:
            issues.append("prepared_group_binding_drift")
        if handoff_current["state"] != lifecycle:
            issues.append("prepared_group_binding_drift")

        snapshot = connection.execute("SELECT * FROM max_live_canary_preparation_snapshots WHERE snapshot_id=? AND run_id=?", (handoff["snapshot_id"], run_id)).fetchone()
        preview = connection.execute("SELECT * FROM max_live_canary_preparation_previews WHERE preview_id=? AND snapshot_id=? AND run_id=?", (handoff["preview_id"], handoff["snapshot_id"], run_id)).fetchone()
        authority = connection.execute("SELECT * FROM max_live_canary_preparation_dns_authorities WHERE authority_id=? AND preview_id=?", (handoff["dns_authority_id"], handoff["preview_id"])).fetchone()
        request = connection.execute("SELECT * FROM max_live_canary_preparation_dns_requests WHERE request_id=? AND authority_id=?", (handoff["dns_request_id"], handoff["dns_authority_id"])).fetchone()
        if snapshot is None or preview is None or authority is None or request is None:
            issues.append("prepared_group_binding_drift")
        else:
            try:
                snapshot_value, snapshot_hash = _json_hash(snapshot["snapshot_json"], "Snapshot")
                if snapshot_hash != snapshot["snapshot_hash"] or canonical_sha256(snapshot_value.get("source_binding", {})) != handoff["source_binding_hash"] or snapshot["release_identity_hash"] != handoff["release_identity_hash"] or snapshot["provider_profile_hash"] != handoff["provider_profile_hash"] or snapshot["pricing_hash"] != handoff["pricing_hash"] or snapshot["network_policy_hash"] != handoff["network_policy_hash"] or snapshot["source_policy_hash"] != handoff["source_policy_hash"] or snapshot["credential_reference_hash"] != handoff["credential_reference_hash"] or snapshot["budget_hash"] != handoff["budget_hash"]:
                    issues.append("prepared_group_binding_drift")
                request_value, _ = _json_hash(request["request_json"], "DNS request")
                if preview["preview_hash"] != handoff["preview_hash"] or preview["snapshot_hash"] != handoff["snapshot_hash"] or authority["authority_hash"] != handoff["dns_authority_hash"] or request["request_hash"] != handoff["dns_request_hash"] or _dns_request_binding_hash(request_value) != request["request_hash"] or request["preview_hash"] != handoff["preview_hash"] or request["snapshot_hash"] != handoff["snapshot_hash"]:
                    issues.append("prepared_group_binding_drift")
                manifest = connection.execute("SELECT manifest_hash FROM max_runner_intent_manifests WHERE intent_id=? AND run_id=?", (handoff["request_manifest_id"], run_id)).fetchone()
                if manifest is None or manifest["manifest_hash"] != handoff["request_manifest_hash"]:
                    issues.append("prepared_group_binding_drift")
                reservation = connection.execute("SELECT * FROM max_budget_ledger WHERE entry_id=? AND run_id=? AND operation='reserve'", (handoff["reservation_id"], run_id)).fetchone()
                if reservation is None or _reservation_hash(reservation) != handoff["reservation_hash"]:
                    issues.append("prepared_group_budget_inconsistent")
            except Exception:
                issues.append("prepared_group_binding_drift")

        claims = _effective_claims(connection, run_id, now)
        lease = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
        lease_expiry = _parse_timestamp(lease["expires_at"]) if lease is not None else None
        active_lease = bool(lease is not None and lease["released_at"] is None and lease_expiry is not None and lease_expiry > now)
        if lifecycle == PREPARED:
            if claims:
                issues.append("prepared_group_has_live_claim")
            if active_lease:
                issues.append("prepared_group_has_active_lease")
            claim = connection.execute("SELECT * FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=?", (handoff["preparation_claim_id"], run_id)).fetchone()
            released = connection.execute("SELECT * FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=? AND status='released'", (handoff["released_claim_id"], run_id)).fetchone()
            released_value: dict[str, Any] = {}
            if released is not None:
                try:
                    released_value = json.loads(released["claim_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    released_value = {}
            if claim is None or released is None or released_value.get("released_claim_id") != handoff["preparation_claim_id"] or int(released["fencing_token"]) != int(handoff["last_fencing_token"]):
                issues.append("prepared_group_claim_release_missing")
            logical_ids = [row["logical_call_id"] for row in connection.execute("SELECT logical_call_id FROM max_runner_call_bindings WHERE group_id=?", (group_id,))]
            for table in ("max_model_call_attempts", "max_model_call_results"):
                if logical_ids:
                    placeholders = ",".join("?" for _ in logical_ids)
                    if int(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE logical_call_id IN ({placeholders})", logical_ids).fetchone()[0]) != 0:
                        issues.append("prepared_group_after_send")
            for table in ("max_provider_call_records", "max_provider_call_results", "max_provider_dispatch_attempts", "max_provider_usage_attestations", "max_live_canary_native_jit_authorities"):
                if int(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?", (run_id,)).fetchone()[0]) != 0:
                    issues.append("prepared_group_after_send")
        elif lifecycle == JIT_EXECUTING:
            current_value, _ = _json_hash(handoff_current["current_json"], "handoff current")
            fresh_claim_id = current_value.get("claim_id")
            fresh = [row for row in claims if row["claim_id"] == fresh_claim_id and int(row["fencing_token"]) > int(handoff["last_fencing_token"])]
            if not active_lease or not fresh:
                issues.append("jit_group_missing_fresh_claim")
        return sorted(set(issues))

    def transition_to_jit_connection(self, connection: sqlite3.Connection, *, preview_id: str, worker: Actor, claim_id: str, fencing_token: int, now: str) -> dict[str, Any]:
        row = connection.execute("SELECT h.*,c.state FROM max_runner_preparation_handoffs h JOIN max_runner_preparation_handoff_current c ON c.handoff_id=h.handoff_id WHERE h.preview_id=?", (preview_id,)).fetchone()
        if row is None or row["state"] != PREPARED:
            raise PreparationHandoffError("JIT requires PREPARED_AWAITING_AUTHORIZATION")
        group = connection.execute("SELECT * FROM max_runner_call_group_current WHERE group_id=? AND run_id=?", (row["call_group_id"], row["run_id"])).fetchone()
        lease = connection.execute("SELECT * FROM max_leases WHERE run_id=?", (row["run_id"],)).fetchone()
        claim = connection.execute("SELECT * FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=? AND status='active'", (claim_id, row["run_id"])).fetchone()
        if group is None or group["lifecycle_state"] != PREPARED or lease is None or lease["owner_id"] != worker.actor_id or lease["session_id"] != worker.session_id or int(lease["fencing_token"]) != int(fencing_token) or claim is None or int(fencing_token) <= int(row["last_fencing_token"]):
            raise PreparationHandoffError("JIT lease/claim/fencing binding is not fresh")
        event = self._append_handoff_event(connection, handoff=row, state=JIT_EXECUTING, payload={"claim_id": claim_id, "fencing_token": int(fencing_token), "lease_id": f"run-lease:{row['run_id']}", "send_boundary_reached": False}, actor=worker, now=now)
        connection.execute("UPDATE max_runner_call_group_current SET lifecycle_state=?,updated_at=?,updated_by=? WHERE group_id=? AND run_id=?", (JIT_EXECUTING, now, worker.actor_id, row["call_group_id"], row["run_id"]))
        return {"handoff_id": row["handoff_id"], "state": JIT_EXECUTING, "event_hash": event["event_hash"], "current_hash": event["current_hash"]}

    def transition_terminal(self, *, preview_id: str, state: str, actor: Actor, claim_id: str, fencing_token: int) -> dict[str, Any]:
        if state not in TERMINAL_HANDOFF_STATES:
            raise PreparationHandoffError("invalid terminal handoff state")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT h.*,c.state FROM max_runner_preparation_handoffs h JOIN max_runner_preparation_handoff_current c ON c.handoff_id=h.handoff_id WHERE h.preview_id=?", (preview_id,)).fetchone()
                if row is None:
                    raise PreparationHandoffError("preparation handoff was not found")
                if row["state"] not in {JIT_EXECUTING, state}:
                    raise PreparationHandoffError("terminal handoff transition is not legal")
                event = self._append_handoff_event(connection, handoff=row, state=state, payload={"claim_id": claim_id, "fencing_token": int(fencing_token), "send_boundary_reached": state in {"SUCCEEDED", "UNKNOWN"}}, actor=actor, now=now)
                connection.execute("UPDATE max_runner_call_group_current SET lifecycle_state=?,updated_at=?,updated_by=? WHERE group_id=? AND run_id=?", (state, now, actor.actor_id, row["call_group_id"], row["run_id"]))
                return {"ok": True, "handoff_id": row["handoff_id"], "state": state, "event_hash": event["event_hash"]}
        finally:
            connection.close()


__all__ = ["JIT_EXECUTING", "PREPARATION_CLAIM_HELD", "PREPARED", "PreparationHandoffError", "PreparationHandoffStore"]
