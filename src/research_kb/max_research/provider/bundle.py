"""MR-2B2 durable live-authorization bundles and runner adapter.

Each :class:`~research_kb.max_research.provider.live.LiveNetworkAuthorization`
remains single-use.  A bundle merely gives a bounded runner a deterministic,
append-only sequence of such authorities.  Assignment is durable before any
permit, credential read, DNS lookup, or network call, so process recovery does
not silently select a different authority.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Mapping, Sequence

from ...policy import Actor
from ..contract import canonical_json, canonical_sha256, make_stable_id
from ..persistence.db import MaxControlError, control_transaction
from ..persistence.repository import _actor_fields, _parse_timestamp, _timestamp, _utc_now
from ..runner.contracts import AdapterCapabilities, ModelRequestEnvelope, ModelResponseEnvelope
from .contract import ProviderProfile
from .live import LiveProviderTransportFactory
from .live_adapter import LiveOpenAICompatibleAdapter
from .store import ProviderStore
from .transport import ProviderTransportError
from .usage import ProviderUsageAuthority


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _text(value: Any, name: str, *, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or "\r" in value or "\n" in value:
        raise MaxControlError(f"{name} is invalid")
    return value


def _hash(value: Any, name: str) -> str:
    result = _text(value, name, limit=64).lower()
    if not _HASH_RE.fullmatch(result):
        raise MaxControlError(f"{name} is not a SHA-256 hash")
    return result


def _require_admin(actor: Actor) -> None:
    if not isinstance(actor, Actor) or not actor.is_admin:
        raise MaxControlError("live authorization bundle mutation requires human admin authority")


class LiveAuthorizationBundleStore:
    """Append-only authority bundle repository over the Max control DB."""

    def __init__(self, provider_store: ProviderStore) -> None:
        if not isinstance(provider_store, ProviderStore):
            raise TypeError("LiveAuthorizationBundleStore requires ProviderStore")
        self.provider_store = provider_store
        self.repository = provider_store.repository

    @staticmethod
    def _current_value(*, bundle_id: str, run_id: str, project_id: str, state: str, next_ordinal: int) -> dict[str, Any]:
        return {
            "bundle_id": bundle_id,
            "run_id": run_id,
            "project_id": project_id,
            "state": state,
            "next_ordinal": int(next_ordinal),
        }

    @staticmethod
    def _event(connection: sqlite3.Connection, *, bundle_id: str, run_id: str, project_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise MaxControlError("bundle event payload must be an object")
        payload_value = dict(payload)
        payload_json = canonical_json(payload_value)
        if len(payload_json.encode("utf-8")) > 50_000:
            raise MaxControlError("bundle event payload exceeds its byte limit")
        previous = connection.execute(
            "SELECT sequence_no, event_hash FROM max_live_authorization_bundle_events WHERE bundle_id=? ORDER BY sequence_no DESC LIMIT 1",
            (bundle_id,),
        ).fetchone()
        sequence_no = int(previous["sequence_no"]) + 1 if previous is not None else 1
        payload_hash = canonical_sha256(payload_value)
        event_value = {
            "bundle_id": bundle_id,
            "run_id": run_id,
            "project_id": project_id,
            "sequence_no": sequence_no,
            "event_type": event_type,
            "payload_hash": payload_hash,
            "previous_event_hash": previous["event_hash"] if previous is not None else None,
            "created_at": now,
        }
        event_hash = canonical_sha256(event_value)
        event_id = make_stable_id("live_authorization_bundle_event", event_hash[:64])
        actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
        connection.execute(
            "INSERT INTO max_live_authorization_bundle_events(bundle_event_id, bundle_id, run_id, project_id, sequence_no, event_type, payload_json, payload_hash, previous_event_hash, event_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, bundle_id, run_id, project_id, sequence_no, event_type, payload_json, payload_hash, event_value["previous_event_hash"], event_hash, now, actor_id, actor_kind, actor_session),
        )
        return {"bundle_event_id": event_id, **event_value, "event_hash": event_hash}

    def create(self, *, run_id: str, grant_id: str, authorization_ids: Sequence[str], actor: Actor) -> dict[str, Any]:
        """Create one immutable ordered bundle from active authorities."""

        _require_admin(actor)
        run_id = _text(run_id, "run_id")
        grant_id = _text(grant_id, "grant_id")
        if isinstance(authorization_ids, (str, bytes, bytearray)) or not isinstance(authorization_ids, Sequence):
            raise MaxControlError("authorization_ids must be an ordered list")
        members = tuple(_text(value, "authorization_id") for value in authorization_ids)
        if not 1 <= len(members) <= 256 or len(set(members)) != len(members):
            raise MaxControlError("authorization bundle must contain 1..256 unique authorities")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT project_id, model_identity, budget_hash, status FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                if run is None or grant is None or run["status"] not in {"APPROVED", "RUNNING"}:
                    raise MaxControlError("bundle run or execution grant is not eligible")
                if grant["run_id"] != run_id or grant["project_id"] != run["project_id"] or grant["model_identity"] != run["model_identity"] or grant["budget_hash"] != run["budget_hash"]:
                    raise MaxControlError("bundle execution grant binding mismatch")
                try:
                    grant_caps = json.loads(grant["caps_json"])
                except Exception as exc:
                    raise MaxControlError("bundle execution grant caps are invalid") from exc
                if not isinstance(grant_caps, Mapping) or len(members) > int(grant_caps.get("max_provider_calls", 0)):
                    raise MaxControlError("authorization bundle exceeds the execution-grant provider-call cap")
                authorization_rows: list[sqlite3.Row] = []
                now_dt = _utc_now(self.repository.clock)
                for authorization_id in members:
                    row = connection.execute(
                        "SELECT a.*, c.state, c.consumption_id FROM max_live_network_authorizations a JOIN max_live_network_authorization_current c ON c.authorization_id=a.authorization_id WHERE a.authorization_id=?",
                        (authorization_id,),
                    ).fetchone()
                    if row is None or row["state"] != "active" or row["consumption_id"] is not None:
                        raise MaxControlError("bundle member is missing, consumed, revoked, or expired")
                    if _parse_timestamp(row["expires_at"]) is None or _parse_timestamp(row["expires_at"]) <= now_dt:
                        raise MaxControlError("bundle member authorization has expired")
                    expected = {
                        "run_id": run_id,
                        "project_id": run["project_id"],
                        "grant_id": grant_id,
                        "profile_hash": grant["profile_hash"],
                        "model_identity": grant["model_identity"],
                        "pricing_hash": grant["pricing_hash"],
                        "budget_hash": grant["budget_hash"],
                    }
                    if any(row[key] != value for key, value in expected.items()):
                        raise MaxControlError("bundle member authority binding mismatch")
                    authorization_rows.append(row)
                now = _timestamp(self.repository.clock)
                expires_at = min(str(row["expires_at"]) for row in authorization_rows)
                bundle_value = {
                    "run_id": run_id,
                    "project_id": run["project_id"],
                    "grant_id": grant_id,
                    "profile_hash": grant["profile_hash"],
                    "model_identity": grant["model_identity"],
                    "pricing_hash": grant["pricing_hash"],
                    "budget_hash": grant["budget_hash"],
                    "member_count": len(members),
                    "member_authorization_hashes": [str(row["authorization_hash"]) for row in authorization_rows],
                    "issued_at": now,
                    "expires_at": expires_at,
                }
                # issued_at is intentionally excluded from identity so an exact
                # retry reaches the same immutable bundle.
                identity = {key: value for key, value in bundle_value.items() if key != "issued_at"}
                bundle_hash = canonical_sha256(identity)
                bundle_id = make_stable_id("live_authorization_bundle", bundle_hash[:64])
                existing = connection.execute("SELECT bundle_json, bundle_hash FROM max_live_authorization_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
                if existing is not None:
                    existing_value = json.loads(existing["bundle_json"])
                    if existing["bundle_hash"] != bundle_hash or {key: value for key, value in existing_value.items() if key != "issued_at"} != identity:
                        raise MaxControlError("live authorization bundle ID collision")
                    current = connection.execute("SELECT state FROM max_live_authorization_bundle_current WHERE bundle_id=?", (bundle_id,)).fetchone()
                    if current is None:
                        raise MaxControlError("live authorization bundle lacks its current projection")
                    return {"bundle_id": bundle_id, "bundle_hash": bundle_hash, "member_count": len(members), "state": current["state"], "idempotent": True}
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                connection.execute(
                    "INSERT INTO max_live_authorization_bundles(bundle_id, run_id, project_id, grant_id, profile_hash, model_identity, pricing_hash, budget_hash, member_count, issued_at, expires_at, bundle_json, bundle_hash, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (bundle_id, run_id, run["project_id"], grant_id, grant["profile_hash"], grant["model_identity"], grant["pricing_hash"], grant["budget_hash"], len(members), now, expires_at, canonical_json(bundle_value), bundle_hash, actor_id, actor_kind, actor_session),
                )
                for ordinal, row in enumerate(authorization_rows):
                    member_value = {
                        "bundle_id": bundle_id,
                        "ordinal": ordinal,
                        "authorization_id": row["authorization_id"],
                        "authorization_hash": row["authorization_hash"],
                    }
                    member_hash = canonical_sha256(member_value)
                    member_id = make_stable_id("live_authorization_bundle_member", member_hash[:64])
                    connection.execute(
                        "INSERT INTO max_live_authorization_bundle_members(member_id, bundle_id, ordinal, authorization_id, authorization_hash, member_json, member_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (member_id, bundle_id, ordinal, row["authorization_id"], row["authorization_hash"], canonical_json(member_value), member_hash),
                    )
                current = self._current_value(bundle_id=bundle_id, run_id=run_id, project_id=run["project_id"], state="active", next_ordinal=0)
                connection.execute(
                    "INSERT INTO max_live_authorization_bundle_current(bundle_id, run_id, project_id, state, next_ordinal, current_json, current_hash, updated_at) VALUES (?, ?, ?, 'active', 0, ?, ?, ?)",
                    (bundle_id, run_id, run["project_id"], canonical_json(current), canonical_sha256(current), now),
                )
                self._event(connection, bundle_id=bundle_id, run_id=run_id, project_id=run["project_id"], event_type="created", payload={"bundle_hash": bundle_hash, "member_count": len(members)}, actor=actor, now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="live_authorization_bundle_created", payload={"bundle_id": bundle_id, "bundle_hash": bundle_hash, "member_count": len(members), "grant_id": grant_id}, actor=actor, now=now)
            return {"bundle_id": bundle_id, "bundle_hash": bundle_hash, "member_count": len(members), "state": "active", "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live authorization bundle conflicts with an immutable record") from exc
        finally:
            connection.close()

    def assign(self, *, bundle_id: str, run_id: str, iteration_id: str, logical_call_id: str, intent_hash: str, idempotency_key: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        """Assign the next authority to one durable model-call intent."""

        for value, name in ((bundle_id, "bundle_id"), (run_id, "run_id"), (iteration_id, "iteration_id"), (logical_call_id, "logical_call_id"), (idempotency_key, "idempotency_key")):
            _text(value, name)
        intent_hash = _hash(intent_hash, "intent_hash")
        if actor.is_admin or actor.actor_kind not in {"runner", "worker", "agent"}:
            raise MaxControlError("bundle assignment requires a non-admin runner actor")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise MaxControlError("bundle assignment fencing token is invalid")
        idempotency_hash = canonical_sha256(idempotency_key)
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                bundle = connection.execute("SELECT * FROM max_live_authorization_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_authorization_bundle_current WHERE bundle_id=?", (bundle_id,)).fetchone()
                if bundle is None or current is None or bundle["run_id"] != run_id:
                    raise MaxControlError("live authorization bundle was not found for this run")
                existing = connection.execute(
                    "SELECT * FROM max_live_authorization_assignments WHERE bundle_id=? AND idempotency_key_hash=?",
                    (bundle_id, idempotency_hash),
                ).fetchone()
                if existing is not None:
                    expected = {"run_id": run_id, "iteration_id": iteration_id, "logical_call_id": logical_call_id, "intent_hash": intent_hash}
                    if any(existing[key] != value for key, value in expected.items()):
                        raise MaxControlError("bundle assignment replay binding mismatch")
                    value = json.loads(existing["assignment_json"])
                    if canonical_sha256(value) != existing["assignment_hash"]:
                        raise MaxControlError("bundle assignment hash is invalid")
                    return {**value, "assignment_hash": existing["assignment_hash"], "bundle_state": current["state"], "idempotent": True}
                if current["state"] != "active":
                    raise MaxControlError("live authorization bundle is not active")
                now_dt = _utc_now(self.repository.clock)
                if _parse_timestamp(bundle["expires_at"]) is None or _parse_timestamp(bundle["expires_at"]) <= now_dt:
                    raise MaxControlError("live authorization bundle has expired")
                run = connection.execute("SELECT project_id, status FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if run is None or run["status"] != "RUNNING" or run["project_id"] != bundle["project_id"]:
                    raise MaxControlError("bundle assignment requires a running bound run")
                if lease is None or lease["owner_id"] != actor.actor_id or lease["session_id"] != actor.session_id or int(lease["fencing_token"]) != fencing_token or lease["released_at"] is not None or _parse_timestamp(lease["expires_at"]) is None or _parse_timestamp(lease["expires_at"]) <= now_dt:
                    raise MaxControlError("bundle assignment uses a stale or missing runner fence")
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE logical_call_id=?", (logical_call_id,)).fetchone()
                manifest = connection.execute("SELECT manifest_hash FROM max_runner_intent_manifests WHERE logical_call_id=?", (logical_call_id,)).fetchone()
                if intent is None or manifest is None:
                    raise MaxControlError("bundle assignment requires a durable runner intent manifest")
                expected_intent = {"run_id": run_id, "project_id": bundle["project_id"], "iteration_id": iteration_id, "intent_hash": intent_hash, "idempotency_key": idempotency_key}
                if any(intent[key] != value for key, value in expected_intent.items()):
                    raise MaxControlError("bundle assignment intent binding mismatch")
                ordinal = int(current["next_ordinal"])
                member = connection.execute("SELECT * FROM max_live_authorization_bundle_members WHERE bundle_id=? AND ordinal=?", (bundle_id, ordinal)).fetchone()
                if member is None:
                    raise MaxControlError("live authorization bundle has no remaining member")
                authorization = connection.execute(
                    "SELECT a.*, c.state, c.consumption_id FROM max_live_network_authorizations a JOIN max_live_network_authorization_current c ON c.authorization_id=a.authorization_id WHERE a.authorization_id=?",
                    (member["authorization_id"],),
                ).fetchone()
                if authorization is None or authorization["state"] != "active" or authorization["consumption_id"] is not None or authorization["authorization_hash"] != member["authorization_hash"]:
                    raise MaxControlError("assigned bundle authority is no longer active")
                expected_authority = {"run_id": run_id, "project_id": bundle["project_id"], "grant_id": bundle["grant_id"], "profile_hash": bundle["profile_hash"], "model_identity": bundle["model_identity"], "pricing_hash": bundle["pricing_hash"], "budget_hash": bundle["budget_hash"]}
                if any(authorization[key] != value for key, value in expected_authority.items()):
                    raise MaxControlError("assigned bundle authority binding mismatch")
                now = _timestamp(self.repository.clock)
                assignment_value = {
                    "bundle_id": bundle_id,
                    "member_id": member["member_id"],
                    "ordinal": ordinal,
                    "authorization_id": member["authorization_id"],
                    "run_id": run_id,
                    "project_id": bundle["project_id"],
                    "iteration_id": iteration_id,
                    "logical_call_id": logical_call_id,
                    "intent_hash": intent_hash,
                    "idempotency_key_hash": idempotency_hash,
                    "assigned_at": now,
                }
                assignment_hash = canonical_sha256(assignment_value)
                assignment_id = make_stable_id("live_authorization_assignment", assignment_hash[:64])
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                connection.execute(
                    "INSERT INTO max_live_authorization_assignments(assignment_id, bundle_id, member_id, ordinal, authorization_id, run_id, project_id, iteration_id, logical_call_id, intent_hash, idempotency_key_hash, assigned_at, assignment_json, assignment_hash, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (assignment_id, bundle_id, member["member_id"], ordinal, member["authorization_id"], run_id, bundle["project_id"], iteration_id, logical_call_id, intent_hash, idempotency_hash, now, canonical_json(assignment_value), assignment_hash, actor_id, actor_kind, actor_session),
                )
                next_ordinal = ordinal + 1
                state = "exhausted" if next_ordinal >= int(bundle["member_count"]) else "active"
                current_value = self._current_value(bundle_id=bundle_id, run_id=run_id, project_id=bundle["project_id"], state=state, next_ordinal=next_ordinal)
                connection.execute(
                    "UPDATE max_live_authorization_bundle_current SET state=?, next_ordinal=?, current_json=?, current_hash=?, updated_at=? WHERE bundle_id=?",
                    (state, next_ordinal, canonical_json(current_value), canonical_sha256(current_value), now, bundle_id),
                )
                self._event(connection, bundle_id=bundle_id, run_id=run_id, project_id=bundle["project_id"], event_type="assigned", payload={"assignment_id": assignment_id, "assignment_hash": assignment_hash, "ordinal": ordinal, "logical_call_id": logical_call_id, "intent_hash": intent_hash}, actor=actor, now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="live_authorization_assigned", payload={"bundle_id": bundle_id, "assignment_id": assignment_id, "assignment_hash": assignment_hash, "ordinal": ordinal, "logical_call_id": logical_call_id}, actor=actor, now=now)
            return {"assignment_id": assignment_id, **assignment_value, "assignment_hash": assignment_hash, "bundle_state": state, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live authorization bundle assignment conflicted with another worker") from exc
        finally:
            connection.close()

    def revoke(self, *, bundle_id: str, actor: Actor, reason: str) -> dict[str, Any]:
        _require_admin(actor)
        bundle_id = _text(bundle_id, "bundle_id")
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 2_000 or "\r" in reason or "\n" in reason:
            raise MaxControlError("bundle revocation reason is invalid")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                bundle = connection.execute("SELECT * FROM max_live_authorization_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_authorization_bundle_current WHERE bundle_id=?", (bundle_id,)).fetchone()
                if bundle is None or current is None:
                    raise MaxControlError("live authorization bundle was not found")
                if current["state"] == "revoked":
                    return {"bundle_id": bundle_id, "state": "revoked", "idempotent": True}
                if current["state"] not in {"active", "exhausted"}:
                    raise MaxControlError("live authorization bundle cannot be revoked from its current state")
                now = _timestamp(self.repository.clock)
                value = self._current_value(bundle_id=bundle_id, run_id=bundle["run_id"], project_id=bundle["project_id"], state="revoked", next_ordinal=int(current["next_ordinal"]))
                connection.execute("UPDATE max_live_authorization_bundle_current SET state='revoked', current_json=?, current_hash=?, updated_at=? WHERE bundle_id=?", (canonical_json(value), canonical_sha256(value), now, bundle_id))
                self._event(connection, bundle_id=bundle_id, run_id=bundle["run_id"], project_id=bundle["project_id"], event_type="revoked", payload={"reason_hash": canonical_sha256(reason.strip())}, actor=actor, now=now)
                self.repository._append_event(connection, run_id=bundle["run_id"], event_type="live_authorization_bundle_revoked", payload={"bundle_id": bundle_id, "reason_hash": canonical_sha256(reason.strip())}, actor=actor, now=now)
            return {"bundle_id": bundle_id, "state": "revoked", "idempotent": False}
        finally:
            connection.close()

    def status(self, *, run_id: str, bundle_id: str | None = None) -> dict[str, Any]:
        run_id = _text(run_id, "run_id")
        connection = self.repository._connect(read_only=True)
        try:
            if bundle_id is None:
                rows = list(connection.execute("SELECT b.*, c.state, c.next_ordinal, c.current_json, c.current_hash, c.updated_at FROM max_live_authorization_bundles b JOIN max_live_authorization_bundle_current c ON c.bundle_id=b.bundle_id WHERE b.run_id=? ORDER BY b.issued_at, b.bundle_id", (run_id,)))
            else:
                bundle_id = _text(bundle_id, "bundle_id")
                rows = list(connection.execute("SELECT b.*, c.state, c.next_ordinal, c.current_json, c.current_hash, c.updated_at FROM max_live_authorization_bundles b JOIN max_live_authorization_bundle_current c ON c.bundle_id=b.bundle_id WHERE b.run_id=? AND b.bundle_id=?", (run_id, bundle_id)))
            bundles: list[dict[str, Any]] = []
            for row in rows:
                current = json.loads(row["current_json"])
                expected = self._current_value(bundle_id=row["bundle_id"], run_id=row["run_id"], project_id=row["project_id"], state=row["state"], next_ordinal=int(row["next_ordinal"]))
                if current != expected or canonical_sha256(current) != row["current_hash"]:
                    raise MaxControlError("live authorization bundle projection hash is invalid")
                bundles.append({
                    "bundle_id": row["bundle_id"],
                    "bundle_hash": row["bundle_hash"],
                    "run_id": row["run_id"],
                    "project_id": row["project_id"],
                    "grant_id": row["grant_id"],
                    "profile_hash": row["profile_hash"],
                    "member_count": int(row["member_count"]),
                    "assigned_count": int(row["next_ordinal"]),
                    "remaining_count": max(0, int(row["member_count"]) - int(row["next_ordinal"])),
                    "state": row["state"],
                    "expires_at": row["expires_at"],
                    "updated_at": row["updated_at"],
                })
            return {"run_id": run_id, "bundles": bundles, "count": len(bundles)}
        finally:
            connection.close()

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        issues: list[str] = []
        counts = {"bundles": 0, "members": 0, "assignments": 0, "events": 0}
        connection = self.repository._connect(read_only=True)
        try:
            query = "SELECT b.*, c.state, c.next_ordinal, c.current_json, c.current_hash FROM max_live_authorization_bundles b JOIN max_live_authorization_bundle_current c ON c.bundle_id=b.bundle_id"
            rows = list(connection.execute(query + (" WHERE b.run_id=?" if run_id is not None else "") + " ORDER BY b.issued_at, b.bundle_id", ((run_id,) if run_id is not None else ())))
            for row in rows:
                counts["bundles"] += 1
                try:
                    bundle = json.loads(row["bundle_json"])
                    identity = {key: value for key, value in bundle.items() if key != "issued_at"}
                    current = json.loads(row["current_json"])
                    expected_current = self._current_value(bundle_id=row["bundle_id"], run_id=row["run_id"], project_id=row["project_id"], state=row["state"], next_ordinal=int(row["next_ordinal"]))
                    if canonical_sha256(identity) != row["bundle_hash"] or current != expected_current or canonical_sha256(current) != row["current_hash"]:
                        issues.append("live authorization bundle hash mismatch")
                except Exception:
                    issues.append("live authorization bundle is invalid")
                members = list(connection.execute("SELECT * FROM max_live_authorization_bundle_members WHERE bundle_id=? ORDER BY ordinal", (row["bundle_id"],)))
                counts["members"] += len(members)
                if len(members) != int(row["member_count"]) or [int(member["ordinal"]) for member in members] != list(range(int(row["member_count"]))):
                    issues.append("live authorization bundle member sequence mismatch")
                for member in members:
                    try:
                        value = json.loads(member["member_json"])
                        authority = connection.execute("SELECT authorization_hash, run_id, grant_id, profile_hash FROM max_live_network_authorizations WHERE authorization_id=?", (member["authorization_id"],)).fetchone()
                        if canonical_sha256(value) != member["member_hash"] or authority is None or authority["authorization_hash"] != member["authorization_hash"] or authority["run_id"] != row["run_id"] or authority["grant_id"] != row["grant_id"] or authority["profile_hash"] != row["profile_hash"]:
                            issues.append("live authorization bundle member binding mismatch")
                    except Exception:
                        issues.append("live authorization bundle member is invalid")
                assignments = list(connection.execute("SELECT * FROM max_live_authorization_assignments WHERE bundle_id=? ORDER BY ordinal", (row["bundle_id"],)))
                counts["assignments"] += len(assignments)
                if len(assignments) != int(row["next_ordinal"]):
                    issues.append("live authorization bundle assignment count mismatch")
                for assignment in assignments:
                    try:
                        value = json.loads(assignment["assignment_json"])
                        intent = connection.execute("SELECT run_id, project_id, iteration_id, intent_hash, idempotency_key FROM max_model_call_intents WHERE logical_call_id=?", (assignment["logical_call_id"],)).fetchone()
                        if canonical_sha256(value) != assignment["assignment_hash"] or intent is None or intent["run_id"] != assignment["run_id"] or intent["project_id"] != assignment["project_id"] or intent["iteration_id"] != assignment["iteration_id"] or intent["intent_hash"] != assignment["intent_hash"] or canonical_sha256(intent["idempotency_key"]) != assignment["idempotency_key_hash"]:
                            issues.append("live authorization assignment binding mismatch")
                    except Exception:
                        issues.append("live authorization assignment is invalid")
                events = list(connection.execute("SELECT * FROM max_live_authorization_bundle_events WHERE bundle_id=? ORDER BY sequence_no", (row["bundle_id"],)))
                counts["events"] += len(events)
                previous = None
                for expected_sequence, event in enumerate(events, 1):
                    try:
                        payload = json.loads(event["payload_json"])
                        event_value = {"bundle_id": event["bundle_id"], "run_id": event["run_id"], "project_id": event["project_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if int(event["sequence_no"]) != expected_sequence or canonical_sha256(payload) != event["payload_hash"] or event["previous_event_hash"] != previous or canonical_sha256(event_value) != event["event_hash"]:
                            issues.append("live authorization bundle event chain mismatch")
                        previous = event["event_hash"]
                    except Exception:
                        issues.append("live authorization bundle event is invalid")
            return {"ok": not issues, "run_id": run_id, "counts": counts, "issues": sorted(set(issues))}
        finally:
            connection.close()


class LiveAuthorizationPoolAdapter:
    """Bounded-runner adapter that consumes one bundle member per call."""

    fixture_only = False

    def __init__(self, profile: ProviderProfile, *, provider_store: ProviderStore, bundle_store: LiveAuthorizationBundleStore, bundle_id: str, actor: Actor, grant_id: str, fencing_token: int, transport_factory: LiveProviderTransportFactory, usage_authority: ProviderUsageAuthority | None = None) -> None:
        if not isinstance(profile, ProviderProfile) or not isinstance(provider_store, ProviderStore) or not isinstance(bundle_store, LiveAuthorizationBundleStore):
            raise TypeError("live authorization pool adapter dependencies are invalid")
        # Production accepts the exact package factory.  A subclass is allowed
        # only for a database explicitly created as a fixture.
        if type(transport_factory) is not LiveProviderTransportFactory:
            if not (provider_store.repository.is_fixture_database() and isinstance(transport_factory, LiveProviderTransportFactory) and getattr(transport_factory, "fixture_only", False) is True):
                raise ProviderTransportError("LIVE_TRANSPORT_FACTORY_INVALID", "live authorization pool requires the package transport factory")
        self.profile = profile
        self.provider_store = provider_store
        self.bundle_store = bundle_store
        self.bundle_id = _text(bundle_id, "bundle_id")
        self.actor = actor
        self.grant_id = _text(grant_id, "grant_id")
        self.fencing_token = int(fencing_token)
        self.transport_factory = transport_factory
        self.usage_authority = usage_authority or ProviderUsageAuthority()
        self._children: dict[str, LiveOpenAICompatibleAdapter] = {}

    @property
    def capabilities(self) -> AdapterCapabilities:
        # Live result-query endpoints are intentionally unsupported. Durable
        # idempotent dispatch replay is the only automatic recovery path.
        return AdapterCapabilities(
            provider_name=self.profile.provider_name,
            supports_provider_idempotency=self.profile.capabilities.idempotency,
            supports_result_query=False,
            supports_usage_receipt=self.profile.capabilities.usage_reporting,
            max_request_chars=int(self.profile.request_limits.get("max_request_bytes", 1_000_000)),
        )

    def dispatch(self, request: ModelRequestEnvelope, *, idempotency_key: str) -> ModelResponseEnvelope:
        if not isinstance(request, ModelRequestEnvelope):
            raise ProviderTransportError("INVALID_PROVIDER_REQUEST", "live pool request is invalid")
        logical_call_id = str(request.request_payload.get("logical_call_id", ""))
        if not logical_call_id:
            raise ProviderTransportError("INVALID_PROVIDER_REQUEST", "live pool request lacks a logical call")
        assignment = self.bundle_store.assign(
            bundle_id=self.bundle_id,
            run_id=request.run_id,
            iteration_id=request.iteration_id,
            logical_call_id=logical_call_id,
            intent_hash=request.intent_hash or request.request_hash,
            idempotency_key=idempotency_key,
            actor=self.actor,
            fencing_token=self.fencing_token,
        )
        durable = self.provider_store.provider_call(run_id=request.run_id, idempotency_key=idempotency_key)
        if assignment.get("bundle_state") in {"revoked", "expired"} and not (durable is not None and durable.get("terminal_status") == "succeeded"):
            raise ProviderTransportError("LIVE_AUTHORIZATION_BUNDLE_INACTIVE", "live authorization bundle is no longer active")
        child = LiveOpenAICompatibleAdapter(
            self.profile,
            transport_factory=self.transport_factory,
            provider_store=self.provider_store,
            actor=self.actor,
            grant_id=self.grant_id,
            authorization_id=str(assignment["authorization_id"]),
            fencing_token=self.fencing_token,
            usage_authority=self.usage_authority,
            live_bundle_id=self.bundle_id,
            live_assignment_id=str(assignment["assignment_id"]),
        )
        self._children[idempotency_key] = child
        return child.dispatch(request, idempotency_key=idempotency_key)

    def query(self, *, idempotency_key: str) -> ModelResponseEnvelope | None:
        child = self._children.get(idempotency_key)
        if child is None:
            return None
        return child.query(idempotency_key=idempotency_key)


__all__ = ["LiveAuthorizationBundleStore", "LiveAuthorizationPoolAdapter"]
