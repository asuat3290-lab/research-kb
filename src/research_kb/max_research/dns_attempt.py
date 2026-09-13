"""Server-owned, two-phase DNS attempt and receipt control plane.

The resolver is deliberately outside the SQLite transaction.  Transaction A
commits the one-shot attempt fence and both DNS authority consumptions before
the resolver boundary.  Transaction B can only append a bounded receipt for
that committed attempt.  If B cannot commit, recovery records an unknown
terminal event; it never calls the resolver again.

This module never serializes an address.  Resolver values exist only while a
single call is being normalized in memory.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from ..policy import Actor
from .contract import canonical_json, canonical_sha256, make_stable_id
from .persistence.db import MaxControlError, control_transaction
from .persistence.repository import MaxControlRepository, _parse_timestamp, _timestamp, _utc_now
from .provider.live import StdlibDNSResolver, validate_resolved_addresses


class DNSAttemptError(MaxControlError):
    """A DNS attempt failed closed without exposing resolver material."""


class DNSResolver(Protocol):
    lookup_count: int

    def resolve(self, host: str, port: int) -> Sequence[Any]:
        ...


_PHRASE_PREFIX = "APPROVE MR-4B1 DNS PREFLIGHT "
_HASH_FIELDS = {
    "snapshot_hash", "preview_hash", "handoff_hash", "request_hash",
    "authority_hash", "source_binding_hash", "release_identity_hash",
    "provider_profile_hash", "network_policy_hash", "budget_hash",
}
_FAILURE_CODES = {
    "DNS_ADDRESS_INVALID", "DNS_RESULT_EMPTY", "DNS_CANDIDATE_LIMIT_EXCEEDED",
    "SSRF_ADDRESS_BLOCKED",
}


def _json(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DNSAttemptError("server-owned DNS binding JSON is invalid", error_code="BINDING_INVALID") from exc
    if not isinstance(parsed, dict):
        raise DNSAttemptError("server-owned DNS binding is not an object", error_code="BINDING_INVALID")
    return parsed


def _hash_json(value: Any) -> str:
    return canonical_sha256(value)


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value.casefold()):
        raise DNSAttemptError(f"{name} binding is invalid", error_code="BINDING_INVALID")
    return value.casefold()


def _resolved_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (tuple, list)) and value and isinstance(value[0], str):
        return value[0]
    raise ValueError("address shape")


def _candidate_result(values: Any, *, max_candidates: int) -> dict[str, Any]:
    """Normalize every candidate and return bounded facts only."""

    try:
        raw_values = list(values or ())
    except Exception:
        raw_values = []
        collection_error = True
    else:
        collection_error = False

    seen: set[str] = set()
    ipv4 = 0
    ipv6 = 0
    all_global = True
    ssrf_safe = True
    invalid = False
    unsafe = False
    for raw in raw_values:
        try:
            parsed = ipaddress.ip_address(_resolved_text(raw))
        except Exception:
            invalid = True
            continue
        normalized = str(parsed)
        if normalized in seen:
            continue
        seen.add(normalized)
        if parsed.version == 4:
            ipv4 += 1
        else:
            ipv6 += 1
        if not parsed.is_global:
            all_global = False
        if (
            parsed.is_private or parsed.is_loopback or parsed.is_link_local
            or parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified
            or not parsed.is_global
        ):
            ssrf_safe = False
            unsafe = True

    candidate_count = len(seen)
    if collection_error or invalid:
        error_code = "DNS_ADDRESS_INVALID"
    elif candidate_count == 0:
        error_code = "DNS_RESULT_EMPTY"
    elif unsafe:
        error_code = "SSRF_ADDRESS_BLOCKED"
    elif candidate_count > max_candidates:
        error_code = "DNS_CANDIDATE_LIMIT_EXCEEDED"
    else:
        error_code = None
    cap_satisfied = candidate_count <= max_candidates
    passed = bool(candidate_count and all_global and ssrf_safe and cap_satisfied and error_code is None)
    result: dict[str, Any] = {
        "max_getaddrinfo_calls": 1,
        "getaddrinfo_attempts": 1,
        "max_dns_candidates": int(max_candidates),
        "candidate_count": candidate_count,
        "ipv4_count": ipv4,
        "ipv6_count": ipv6,
        "all_global": bool(all_global and candidate_count > 0 and not invalid),
        "ssrf_safe": bool(ssrf_safe and candidate_count > 0 and not invalid),
        "cap_satisfied": bool(cap_satisfied),
        "retry_count": 0,
        "credential_reads": 0,
        "tcp_connections": 0,
        "tls_https_calls": 0,
        "provider_calls": 0,
        "cost_units": 0,
        "status": "passed" if passed else "failed",
    }
    if error_code is not None:
        result["error_code"] = error_code
    result["bounded_result_hash"] = canonical_sha256(result)
    return result


class DNSAttemptStore:
    """Formal v14R3 DNS attempt boundary."""

    phrase_prefix = _PHRASE_PREFIX

    def __init__(self, repository: MaxControlRepository) -> None:
        self.repository = repository

    def _connect(self, *, read_only: bool) -> sqlite3.Connection:
        return self.repository._connect(read_only=read_only)

    @staticmethod
    def _request_binding(request_value: Mapping[str, Any]) -> dict[str, Any]:
        keys = (
            "schema", "hostname", "port", "scheme", "snapshot_id", "snapshot_hash",
            "preview_id", "preview_hash", "endpoint_origin_hash", "network_policy_hash",
            "max_getaddrinfo_calls", "max_dns_candidates", "credential_reads",
            "tcp_connections", "tls_https_calls", "provider_calls", "cost_units",
        )
        return {key: request_value.get(key) for key in keys}

    def _load_binding(
        self,
        connection: sqlite3.Connection,
        *,
        preview_id: str,
        request_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT p.*, s.snapshot_json, s.snapshot_hash, s.run_id, s.project_id, "
            "s.release_identity_hash AS dns_release_identity_hash, "
            "s.provider_profile_hash AS dns_provider_profile_hash, "
            "s.budget_hash AS dns_budget_hash, "
            "a.authority_id AS dns_authority_id, "
            "r.request_json, r.request_hash, r.status AS request_status, "
            "a.authority_json, a.authority_hash, a.status AS authority_status, a.expires_at, "
            "h.handoff_json, h.handoff_hash, h.handoff_id, h.run_id AS handoff_run_id, "
            "hc.state AS handoff_current_state, g.lifecycle_state "
            "FROM max_live_canary_preparation_previews p "
            "JOIN max_live_canary_preparation_snapshots s ON s.snapshot_id=p.snapshot_id "
            "JOIN max_live_canary_preparation_dns_requests r ON r.request_id=? AND r.preview_hash=p.preview_hash "
            "JOIN max_live_canary_preparation_dns_authorities a ON a.authority_id=r.authority_id AND a.preview_id=p.preview_id "
            "JOIN max_runner_preparation_handoffs h ON h.preview_id=p.preview_id AND h.dns_request_id=r.request_id "
            "JOIN max_runner_preparation_handoff_current hc ON hc.handoff_id=h.handoff_id "
            "JOIN max_runner_call_group_current g ON g.group_id=h.call_group_id "
            "WHERE p.preview_id=?",
            (request_id, preview_id),
        ).fetchone()
        if row is None:
            raise DNSAttemptError("DNS attempt binding is incomplete", error_code="BINDING_INVALID")
        snapshot_value = _json(row["snapshot_json"])
        preview_value = _json(row["preview_json"])
        request_value = _json(row["request_json"])
        authority_value = _json(row["authority_json"])
        handoff_value = _json(row["handoff_json"])
        if _hash_json(snapshot_value) != row["snapshot_hash"] or _hash_json(preview_value) != row["preview_hash"]:
            raise DNSAttemptError("DNS attempt binding hash drifted", error_code="BINDING_DRIFT")
        if _hash_json(authority_value) != row["authority_hash"] or _hash_json(handoff_value) != row["handoff_hash"]:
            raise DNSAttemptError("DNS attempt authority or handoff hash drifted", error_code="BINDING_DRIFT")
        if canonical_sha256(self._request_binding(request_value)) != row["request_hash"]:
            raise DNSAttemptError("DNS request binding hash drifted", error_code="BINDING_DRIFT")
        if (
            row["request_hash"] != authority_value.get("request_hash")
            or request_value.get("authority_id") != row["dns_authority_id"]
            or request_value.get("authority_hash") != row["authority_hash"]
            or request_value.get("preview_id") != preview_id
            or request_value.get("preview_hash") != row["preview_hash"]
            or request_value.get("snapshot_hash") != row["snapshot_hash"]
        ):
            raise DNSAttemptError("DNS request serialized binding drifted", error_code="BINDING_DRIFT")
        if row["request_status"] != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION" or row["authority_status"] != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION":
            raise DNSAttemptError("DNS authority or request is not awaiting its one attempt", error_code="ALREADY_CONSUMED")
        expiry = _parse_timestamp(row["expires_at"])
        if expiry is None or expiry <= now.astimezone(expiry.tzinfo):
            raise DNSAttemptError("DNS authority is expired", error_code="AUTHORITY_EXPIRED")
        if row["handoff_current_state"] != "PREPARED_AWAITING_AUTHORIZATION" or row["lifecycle_state"] != "PREPARED_AWAITING_AUTHORIZATION":
            raise DNSAttemptError("preparation handoff is not waiting for DNS authorization", error_code="HANDOFF_INVALID")
        if row["handoff_run_id"] != row["run_id"]:
            raise DNSAttemptError("handoff Run binding drifted", error_code="BINDING_DRIFT")
        if row["endpoint_origin_hash"] != request_value.get("endpoint_origin_hash") or row["network_policy_hash"] != request_value.get("network_policy_hash"):
            raise DNSAttemptError("DNS endpoint or network policy drifted", error_code="BINDING_DRIFT")
        if request_value.get("hostname") != "opencode.ai" or request_value.get("port") != 443 or request_value.get("scheme") != "https":
            raise DNSAttemptError("DNS endpoint is outside the governed boundary", error_code="ENDPOINT_INVALID")
        for key in ("max_getaddrinfo_calls", "credential_reads", "tcp_connections", "tls_https_calls", "provider_calls", "cost_units"):
            expected = 1 if key == "max_getaddrinfo_calls" else 0
            if request_value.get(key) != expected:
                raise DNSAttemptError("DNS zero-action boundary drifted", error_code="BINDING_DRIFT")
        if request_value.get("max_dns_candidates") != 16:
            raise DNSAttemptError("DNS candidate cap drifted", error_code="BINDING_DRIFT")

        # The preparation handoff is the only accepted server-owned fence.
        # No active invocation/lease may remain when the DNS boundary opens.
        lease = connection.execute("SELECT owner_id,session_id,fencing_token,expires_at,released_at FROM max_leases WHERE run_id=?", (row["run_id"],)).fetchone()
        lease_expiry = None if lease is None else _parse_timestamp(lease["expires_at"])
        active_leases = int(bool(lease is not None and lease["released_at"] is None and lease_expiry is not None and lease_expiry > now.astimezone(lease_expiry.tzinfo)))
        active_claims = 0
        if active_leases:
            for claim in connection.execute(
                "SELECT actor_id,actor_session,fencing_token,expires_at FROM max_runner_invocation_claims c "
                "WHERE c.run_id=? AND c.status='active' AND NOT EXISTS "
                "(SELECT 1 FROM max_runner_invocation_claims r WHERE r.run_id=c.run_id "
                "AND r.status='released' AND r.claim_id=c.claim_id || ':released')",
                (row["run_id"],),
            ):
                claim_expiry = _parse_timestamp(claim["expires_at"])
                if (
                    claim_expiry is not None and claim_expiry > now.astimezone(claim_expiry.tzinfo)
                    and claim["actor_id"] == lease["owner_id"]
                    and claim["actor_session"] == lease["session_id"]
                    and int(claim["fencing_token"]) == int(lease["fencing_token"])
                ):
                    active_claims = 1
                    break
        if active_claims or active_leases:
            raise DNSAttemptError("preparation claim or lease is still active", error_code="HANDOFF_INVALID")
        for table in ("max_provider_call_records", "max_provider_dispatch_attempts", "max_live_canary_native_approvals", "max_live_canary_native_jit_authorities"):
            if int(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?", (row["run_id"],)).fetchone()[0]):
                raise DNSAttemptError("Provider or Live authority activity already exists", error_code="EXTERNAL_ACTIVITY")
        if connection.execute("SELECT 1 FROM max_live_canary_native_dns_receipts WHERE request_id=?", (request_id,)).fetchone() is not None:
            raise DNSAttemptError("legacy DNS receipt cannot be mixed with v14R3 attempt closure", error_code="LEGACY_RECEIPT_PRESENT")
        source_binding_hash = canonical_sha256(snapshot_value.get("source_binding"))
        release_identity_hash = _require_hash(row["dns_release_identity_hash"], "release identity")
        binding = {
            "preview_id": preview_id,
            "request_id": request_id,
            "authority_id": row["dns_authority_id"],
            "snapshot_id": row["snapshot_id"],
            "handoff_id": row["handoff_id"],
            "run_id": row["run_id"],
            "project_id": row["project_id"],
            "snapshot_hash": row["snapshot_hash"],
            "preview_hash": row["preview_hash"],
            "handoff_hash": row["handoff_hash"],
            "request_hash": row["request_hash"],
            "authority_hash": row["authority_hash"],
            "source_binding_hash": source_binding_hash,
            "release_identity_hash": release_identity_hash,
            "provider_profile_hash": row["dns_provider_profile_hash"],
            "network_policy_hash": row["network_policy_hash"],
            "budget_hash": row["dns_budget_hash"],
            "endpoint_scheme": "https", "endpoint_hostname": "opencode.ai", "endpoint_port": 443,
            "max_getaddrinfo_calls": 1, "max_dns_candidates": 16,
            "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0,
            "provider_calls": 0, "cost_units": 0,
        }
        for key in _HASH_FIELDS:
            _require_hash(binding[key], key)
        return {"row": row, "snapshot_value": snapshot_value, "preview_value": preview_value, "request_value": request_value, "authority_value": authority_value, "handoff_value": handoff_value, "binding": binding}

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        attempt: Mapping[str, Any],
        state: str,
        failure_stage: str,
        payload: Mapping[str, Any],
        actor: Actor,
        now: str,
    ) -> dict[str, Any]:
        previous_row = connection.execute("SELECT event_hash, sequence_no FROM max_live_canary_dns_attempt_events WHERE attempt_id=? ORDER BY sequence_no DESC LIMIT 1", (attempt["attempt_id"],)).fetchone()
        previous = None if previous_row is None else previous_row["event_hash"]
        sequence = 1 if previous_row is None else int(previous_row["sequence_no"]) + 1
        bounded = dict(payload)
        if any(str(key).casefold() in {"ip", "ips", "address", "addresses", "raw_ip", "raw_ips", "prompt", "source_text", "credential", "api_key"} for key in bounded):
            raise DNSAttemptError("DNS event contains forbidden material", error_code="PRIVACY_FAILURE")
        payload_hash = canonical_sha256(bounded)
        basis = {"attempt_id": attempt["attempt_id"], "request_id": attempt["request_id"], "run_id": attempt["run_id"], "sequence_no": sequence, "state": state, "failure_stage": failure_stage, "payload_hash": payload_hash, "previous_event_hash": previous, "created_at": now}
        event_hash = canonical_sha256(basis)
        event_id = make_stable_id("dns_attempt_event", event_hash[:64])
        connection.execute(
            "INSERT INTO max_live_canary_dns_attempt_events(event_id,attempt_id,request_id,run_id,sequence_no,state,failure_stage,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, attempt["attempt_id"], attempt["request_id"], attempt["run_id"], sequence, state, failure_stage, canonical_json(bounded), payload_hash, previous, event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id),
        )
        current_value = {"attempt_id": attempt["attempt_id"], "request_id": attempt["request_id"], "state": state, "event_hash": event_hash, "sequence_no": sequence, "payload_hash": payload_hash}
        current_hash = canonical_sha256(current_value)
        current = connection.execute("SELECT attempt_id FROM max_live_canary_dns_attempt_current WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()
        if current is None:
            connection.execute(
                "INSERT INTO max_live_canary_dns_attempt_current(attempt_id,request_id,run_id,state,current_event_sequence,current_event_hash,current_json,current_hash,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (attempt["attempt_id"], attempt["request_id"], attempt["run_id"], state, sequence, event_hash, canonical_json(current_value), current_hash, now, actor.actor_id),
            )
        else:
            connection.execute(
                "UPDATE max_live_canary_dns_attempt_current SET state=?,current_event_sequence=?,current_event_hash=?,current_json=?,current_hash=?,updated_at=?,updated_by=? WHERE attempt_id=?",
                (state, sequence, event_hash, canonical_json(current_value), current_hash, now, actor.actor_id, attempt["attempt_id"]),
            )
        return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "state": state}

    def begin_attempt(
        self,
        *,
        preview_id: str,
        request_id: str,
        confirmation_phrase: str,
        actor: Actor,
        fault_stage: str | None = None,
    ) -> dict[str, Any]:
        if not actor.is_admin:
            raise DNSAttemptError("DNS attempt requires the human admin control plane", error_code="FORBIDDEN")
        if confirmation_phrase is None or not isinstance(confirmation_phrase, str):
            raise DNSAttemptError("DNS confirmation phrase is required", error_code="CONFIRMATION_INVALID")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                now_dt = _utc_now(self.repository.clock)
                chain = self._load_binding(connection, preview_id=preview_id, request_id=request_id, now=now_dt)
                request_hash = str(chain["binding"]["request_hash"])
                expected = self.phrase_prefix + request_hash
                if confirmation_phrase != expected:
                    raise DNSAttemptError("DNS confirmation phrase is not the exact server-owned phrase", error_code="CONFIRMATION_INVALID")
                existing = connection.execute("SELECT attempt_id,state,attempt_hash FROM max_live_canary_dns_attempts WHERE request_id=?", (request_id,)).fetchone()
                if existing is not None:
                    raise DNSAttemptError("DNS request already has a durable attempt", error_code="ALREADY_CONSUMED")
                phrase_hash = canonical_sha256(confirmation_phrase)
                binding = {**chain["binding"], "confirmation_phrase_hash": phrase_hash, "phase": "resolver_started"}
                attempt_hash = canonical_sha256(binding)
                attempt_id = make_stable_id("dns_attempt", attempt_hash[:64])
                attempt = {**binding, "attempt_id": attempt_id, "attempt_hash": attempt_hash}
                if fault_stage == "preflight_validation":
                    raise DNSAttemptError("injected preflight failure", error_code="KNOWN_PRE_RESOLVER_FAILURE")
                connection.execute(
                    "INSERT INTO max_live_canary_dns_attempts(attempt_id,request_id,authority_id,snapshot_id,preview_id,handoff_id,run_id,project_id,snapshot_hash,preview_hash,handoff_hash,request_hash,authority_hash,endpoint_scheme,endpoint_hostname,endpoint_port,source_binding_hash,release_identity_hash,provider_profile_hash,network_policy_hash,budget_hash,confirmation_phrase_hash,max_getaddrinfo_calls,max_dns_candidates,credential_reads,tcp_connections,tls_https_calls,provider_calls,cost_units,state,attempt_json,attempt_hash,started_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (attempt_id, request_id, chain["row"]["dns_authority_id"], chain["row"]["snapshot_id"], preview_id, chain["row"]["handoff_id"], chain["row"]["run_id"], chain["row"]["project_id"], chain["row"]["snapshot_hash"], chain["row"]["preview_hash"], chain["row"]["handoff_hash"], chain["row"]["request_hash"], chain["row"]["authority_hash"], "https", "opencode.ai", 443, chain["binding"]["source_binding_hash"], chain["row"]["dns_release_identity_hash"], chain["row"]["dns_provider_profile_hash"], chain["row"]["network_policy_hash"], chain["row"]["dns_budget_hash"], phrase_hash, 1, 16, 0, 0, 0, 0, 0, "resolver_started", canonical_json(binding), attempt_hash, _timestamp(self.repository.clock), actor.actor_id, actor.actor_kind, actor.session_id),
                )
                for consumption_type in ("authority", "request"):
                    value = {"schema": "research-kb/mr4b1b-v14r3-dns-consumption/v1", "attempt_id": attempt_id, "request_id": request_id, "authority_id": chain["row"]["dns_authority_id"], "consumption_type": consumption_type, "binding_hash": chain["row"]["authority_hash"] if consumption_type == "authority" else chain["row"]["request_hash"], "consumed_at": _timestamp(self.repository.clock)}
                    consumption_hash = canonical_sha256(value)
                    consumption_id = make_stable_id("dns_consumption", consumption_hash[:64])
                    connection.execute(
                        "INSERT INTO max_live_canary_dns_attempt_consumptions(consumption_id,attempt_id,request_id,authority_id,consumption_type,binding_hash,consumption_json,consumption_hash,consumed_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (consumption_id, attempt_id, request_id, chain["row"]["dns_authority_id"], consumption_type, value["binding_hash"], canonical_json(value), consumption_hash, value["consumed_at"], actor.actor_id, actor.actor_kind, actor.session_id),
                    )
                event = self._append_event(connection, attempt=attempt, state="resolver_started", failure_stage="resolver_started", payload={"attempt_id": attempt_id, "authority_consumed": True, "request_consumed": True, "attempts": 0, "retries": 0}, actor=actor, now=_timestamp(self.repository.clock))
                if fault_stage == "attempt_claim":
                    raise DNSAttemptError("injected attempt-claim failure", error_code="KNOWN_PRE_RESOLVER_FAILURE")
                return {"ok": True, "attempt_id": attempt_id, "attempt_hash": attempt_hash, "event_hash": event["event_hash"], "request_consumption": 1, "authority_consumption": 1, "resolver_started": True, "resolver_calls": 0, "retries": 0}
        except sqlite3.IntegrityError as exc:
            raise DNSAttemptError("DNS attempt conflicts with an immutable request", error_code="ALREADY_CONSUMED") from exc
        finally:
            connection.close()

    def _transition_unknown(self, *, attempt_id: str, actor: Actor, failure_stage: str, reason: str) -> dict[str, Any]:
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                attempt = connection.execute("SELECT * FROM max_live_canary_dns_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
                if attempt is None:
                    raise DNSAttemptError("DNS attempt was not found", error_code="ATTEMPT_NOT_FOUND")
                current = connection.execute("SELECT * FROM max_live_canary_dns_attempt_current WHERE attempt_id=?", (attempt_id,)).fetchone()
                if current is None:
                    raise DNSAttemptError("DNS attempt current projection is missing", error_code="CONTROL_PLANE_FAILURE")
                if current["state"] == "UNKNOWN_AFTER_RESOLVER_START":
                    return {"ok": False, "attempt_id": attempt_id, "state": current["state"], "idempotent": True, "resolver_calls": 1, "retries": 0}
                if current["state"] != "resolver_started":
                    raise DNSAttemptError("DNS attempt is already terminal", error_code="ALREADY_TERMINAL")
                event = self._append_event(connection, attempt=attempt, state="UNKNOWN_AFTER_RESOLVER_START", failure_stage=failure_stage, payload={"attempt_id": attempt_id, "reason_code": reason[:96], "resolver_calls": 1, "retries": 0, "receipt_present": False}, actor=actor, now=_timestamp(self.repository.clock))
                return {"ok": False, "attempt_id": attempt_id, "state": "UNKNOWN_AFTER_RESOLVER_START", "idempotent": False, "event_hash": event["event_hash"], "resolver_calls": 1, "retries": 0, "receipt_present": False}
        finally:
            connection.close()

    def recover_unknown(self, *, attempt_id: str, actor: Actor, reason: str = "recovery_after_resolver_start") -> dict[str, Any]:
        if not actor.is_admin:
            raise DNSAttemptError("DNS recovery requires the human admin control plane", error_code="FORBIDDEN")
        return self._transition_unknown(attempt_id=attempt_id, actor=actor, failure_stage="receipt_transaction", reason=reason)

    def _commit_result(
        self,
        *,
        attempt_id: str,
        result: Mapping[str, Any],
        actor: Actor,
        fault_stage: str | None = None,
    ) -> dict[str, Any]:
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                attempt = connection.execute("SELECT * FROM max_live_canary_dns_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
                if attempt is None:
                    raise DNSAttemptError("DNS attempt was not found", error_code="ATTEMPT_NOT_FOUND")
                current = connection.execute("SELECT * FROM max_live_canary_dns_attempt_current WHERE attempt_id=?", (attempt_id,)).fetchone()
                if current is None or current["state"] != "resolver_started":
                    raise DNSAttemptError("DNS attempt is no longer writable", error_code="ALREADY_TERMINAL")
                bounded = dict(result)
                if fault_stage == "result_normalization":
                    raise DNSAttemptError("injected normalization failure", error_code="CONTROL_PLANE_FAILURE")
                self._append_event(connection, attempt=attempt, state="resolver_returned", failure_stage="resolver_call", payload={"attempt_id": attempt_id, "candidate_count": bounded["candidate_count"], "ipv4_count": bounded["ipv4_count"], "ipv6_count": bounded["ipv6_count"], "all_global": bounded["all_global"], "ssrf_safe": bounded["ssrf_safe"], "cap_satisfied": bounded["cap_satisfied"], "bounded_result_hash": bounded["bounded_result_hash"]}, actor=actor, now=_timestamp(self.repository.clock))
                receipt_value = {
                    "schema": "research-kb/mr4b1b-v14r3-dns-receipt/v1",
                    "attempt_id": attempt_id, "request_id": attempt["request_id"], "authority_id": attempt["authority_id"], "snapshot_id": attempt["snapshot_id"], "preview_id": attempt["preview_id"], "handoff_id": attempt["handoff_id"], "run_id": attempt["run_id"], "project_id": attempt["project_id"],
                    "snapshot_hash": attempt["snapshot_hash"], "preview_hash": attempt["preview_hash"], "handoff_hash": attempt["handoff_hash"], "request_hash": attempt["request_hash"], "authority_hash": attempt["authority_hash"],
                    "endpoint_scheme": "https", "endpoint_hostname": "opencode.ai", "endpoint_port": 443,
                    "bounded_result": bounded, "bounded_result_hash": bounded["bounded_result_hash"], "raw_ip_persisted": False,
                    "executed_at": _timestamp(self.repository.clock), "failure_stage": "receipt_transaction",
                }
                receipt_hash = canonical_sha256(receipt_value)
                receipt_id = make_stable_id("dns_attempt_receipt", receipt_hash[:64])
                if fault_stage == "receipt_transaction":
                    raise DNSAttemptError("injected receipt transaction failure", error_code="CONTROL_PLANE_FAILURE")
                receipt_values = (
                    receipt_id, attempt_id, attempt["request_id"], attempt["authority_id"], attempt["snapshot_id"], attempt["preview_id"], attempt["handoff_id"], attempt["run_id"], attempt["project_id"], attempt["snapshot_hash"], attempt["preview_hash"], attempt["handoff_hash"], attempt["request_hash"], attempt["authority_hash"], "https", "opencode.ai", 443, 1, 1, bounded["max_dns_candidates"], bounded["candidate_count"], bounded["ipv4_count"], bounded["ipv6_count"], int(bounded["all_global"]), int(bounded["ssrf_safe"]), int(bounded["cap_satisfied"]), 0, 0, 0, 0, 0, 0, bounded["status"], bounded.get("error_code"), "receipt_transaction", bounded["bounded_result_hash"], canonical_json(receipt_value), receipt_hash, receipt_value["executed_at"], actor.actor_id, actor.actor_kind, actor.session_id,
                )
                connection.execute(
                    "INSERT INTO max_live_canary_dns_attempt_receipts(receipt_id,attempt_id,request_id,authority_id,snapshot_id,preview_id,handoff_id,run_id,project_id,snapshot_hash,preview_hash,handoff_hash,request_hash,authority_hash,endpoint_scheme,endpoint_hostname,endpoint_port,max_getaddrinfo_calls,getaddrinfo_attempts,max_dns_candidates,candidate_count,ipv4_count,ipv6_count,all_global,ssrf_safe,cap_satisfied,retry_count,credential_reads,tcp_connections,tls_https_calls,provider_calls,cost_units,status,error_code,failure_stage,bounded_result_hash,receipt_json,receipt_hash,executed_at,actor_id,actor_kind,actor_session) VALUES (" + ",".join("?" for _ in receipt_values) + ")",
                    receipt_values,
                )
                self._append_event(connection, attempt=attempt, state="receipt_committed", failure_stage="receipt_committed", payload={"attempt_id": attempt_id, "receipt_id": receipt_id, "receipt_hash": receipt_hash, "bounded_result_hash": bounded["bounded_result_hash"]}, actor=actor, now=_timestamp(self.repository.clock))
                terminal = "DNS_PREFLIGHT_PASSED" if bounded["status"] == "passed" else "FAILED_WITH_BOUNDED_RESULT"
                terminal_event = self._append_event(connection, attempt=attempt, state=terminal, failure_stage="receipt_committed", payload={"attempt_id": attempt_id, "receipt_id": receipt_id, "receipt_hash": receipt_hash, "status": bounded["status"], "error_code": bounded.get("error_code")}, actor=actor, now=_timestamp(self.repository.clock))
                if fault_stage == "receipt_committed":
                    raise DNSAttemptError("injected post-commit observation failure", error_code="CONTROL_PLANE_FAILURE")
                return {"ok": bounded["status"] == "passed", "attempt_id": attempt_id, "state": terminal, "receipt_id": receipt_id, "receipt_hash": receipt_hash, "bounded_result_hash": bounded["bounded_result_hash"], "candidate_count": bounded["candidate_count"], "ipv4_count": bounded["ipv4_count"], "ipv6_count": bounded["ipv6_count"], "all_global": bounded["all_global"], "ssrf_safe": bounded["ssrf_safe"], "cap_satisfied": bounded["cap_satisfied"], "error_code": bounded.get("error_code"), "event_hash": terminal_event["event_hash"], "resolver_calls": 1, "retries": 0, "raw_ip_persisted": False}
        except sqlite3.IntegrityError as exc:
            raise DNSAttemptError("DNS receipt conflicts with an immutable attempt", error_code="CONTROL_PLANE_FAILURE") from exc
        finally:
            connection.close()

    def execute(
        self,
        *,
        preview_id: str,
        request_id: str,
        confirmation_phrase: str,
        actor: Actor,
        allow_execute: bool = False,
        resolver: DNSResolver | None = None,
        fault_stage: str | None = None,
    ) -> dict[str, Any]:
        if not allow_execute:
            raise DNSAttemptError("DNS execute requires the explicit --execute boundary", error_code="EXECUTE_FLAG_REQUIRED")
        begin = self.begin_attempt(preview_id=preview_id, request_id=request_id, confirmation_phrase=confirmation_phrase, actor=actor, fault_stage=fault_stage)
        attempt_id = begin["attempt_id"]
        if fault_stage == "after_resolver_started":
            return begin
        selected = resolver or StdlibDNSResolver()
        try:
            # Materialize the resolver return once.  This prevents a lazy
            # iterable from being traversed a second time by validation.
            values = list(selected.resolve("opencode.ai", 443))
        except Exception as exc:
            return self._transition_unknown(attempt_id=attempt_id, actor=actor, failure_stage="resolver_call", reason="resolver_exception_" + type(exc).__name__)
        try:
            result = _candidate_result(values, max_candidates=16)
            # The existing validator is retained as a defense-in-depth check;
            # it receives the in-memory candidates and its result is discarded.
            if result["status"] == "passed":
                validate_resolved_addresses(values, max_candidates=16)
            if fault_stage == "result_normalization":
                raise DNSAttemptError("injected normalization failure", error_code="CONTROL_PLANE_FAILURE")
        except DNSAttemptError:
            self._transition_unknown(attempt_id=attempt_id, actor=actor, failure_stage="result_normalization", reason="normalization_failure")
            raise
        except Exception as exc:
            # The result is not safely bounded.  Do not write a guessed receipt.
            return self._transition_unknown(attempt_id=attempt_id, actor=actor, failure_stage="result_normalization", reason="normalization_exception_" + type(exc).__name__)
        try:
            return self._commit_result(attempt_id=attempt_id, result=result, actor=actor, fault_stage=fault_stage)
        except DNSAttemptError:
            # Transaction B may have rolled back after resolver_started.  The
            # recovery transition is the only permitted next action; it never
            # invokes the resolver.
            try:
                return self._transition_unknown(attempt_id=attempt_id, actor=actor, failure_stage="receipt_transaction", reason="receipt_commit_failure")
            except DNSAttemptError:
                raise

    def status(self, *, attempt_id: str | None = None, request_id: str | None = None) -> dict[str, Any]:
        if not attempt_id and not request_id:
            raise DNSAttemptError("DNS status requires an attempt or request selector", error_code="INVALID_SELECTOR")
        connection = self._connect(read_only=True)
        try:
            if attempt_id:
                row = connection.execute("SELECT * FROM max_live_canary_dns_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            else:
                row = connection.execute("SELECT * FROM max_live_canary_dns_attempts WHERE request_id=?", (request_id,)).fetchone()
            if row is None:
                raise DNSAttemptError("DNS attempt was not found", error_code="ATTEMPT_NOT_FOUND")
            current = connection.execute("SELECT state,current_event_sequence,current_event_hash,current_hash FROM max_live_canary_dns_attempt_current WHERE attempt_id=?", (row["attempt_id"],)).fetchone()
            receipt = connection.execute("SELECT receipt_id,receipt_hash,status,error_code,bounded_result_hash,candidate_count,ipv4_count,ipv6_count,all_global,ssrf_safe,cap_satisfied FROM max_live_canary_dns_attempt_receipts WHERE attempt_id=?", (row["attempt_id"],)).fetchone()
            counts = {"attempts": 1, "retries": 0, "authority_consumptions": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_consumptions WHERE attempt_id=? AND consumption_type='authority'", (row["attempt_id"],)).fetchone()[0]), "request_consumptions": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_consumptions WHERE attempt_id=? AND consumption_type='request'", (row["attempt_id"],)).fetchone()[0])}
            return {"ok": current is not None, "attempt_id": row["attempt_id"], "attempt_hash": row["attempt_hash"], "request_id": row["request_id"], "state": None if current is None else current["state"], "current_event_sequence": None if current is None else current["current_event_sequence"], "current_event_hash": None if current is None else current["current_event_hash"], "current_hash": None if current is None else current["current_hash"], "receipt": None if receipt is None else dict(receipt), "counts": counts, "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0, "provider_calls": 0, "cost_units": 0}
        finally:
            connection.close()

    def verify(self, *, attempt_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            attempt = connection.execute("SELECT * FROM max_live_canary_dns_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if attempt is None:
                raise DNSAttemptError("DNS attempt was not found", error_code="ATTEMPT_NOT_FOUND")
            issues: list[str] = []
            if _hash_json(_json(attempt["attempt_json"])) != attempt["attempt_hash"]:
                issues.append("attempt_hash")
            events = list(connection.execute("SELECT * FROM max_live_canary_dns_attempt_events WHERE attempt_id=? ORDER BY sequence_no", (attempt_id,)))
            previous = None
            for index, event in enumerate(events, 1):
                if int(event["sequence_no"]) != index or event["previous_event_hash"] != previous:
                    issues.append("event_chain")
                if canonical_sha256(_json(event["payload_json"])) != event["payload_hash"]:
                    issues.append("event_payload_hash")
                basis = {"attempt_id": event["attempt_id"], "request_id": event["request_id"], "run_id": event["run_id"], "sequence_no": int(event["sequence_no"]), "state": event["state"], "failure_stage": event["failure_stage"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                if canonical_sha256(basis) != event["event_hash"]:
                    issues.append("event_hash")
                previous = event["event_hash"]
            current = connection.execute("SELECT * FROM max_live_canary_dns_attempt_current WHERE attempt_id=?", (attempt_id,)).fetchone()
            if current is None or not events or current["current_event_hash"] != events[-1]["event_hash"] or int(current["current_event_sequence"]) != int(events[-1]["sequence_no"]):
                issues.append("current_projection")
            if current is not None:
                current_value = _json(current["current_json"])
                if canonical_sha256(current_value) != current["current_hash"]:
                    issues.append("current_projection")
            receipt = connection.execute("SELECT * FROM max_live_canary_dns_attempt_receipts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if receipt is not None:
                value = _json(receipt["receipt_json"])
                if canonical_sha256(value) != receipt["receipt_hash"] or value.get("raw_ip_persisted") is not False:
                    issues.append("receipt_hash_or_privacy")
            return {"ok": not issues, "attempt_id": attempt_id, "state": None if current is None else current["state"], "event_count": len(events), "receipt_count": 0 if receipt is None else 1, "issues": sorted(set(issues)), "authority_consumptions": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_consumptions WHERE attempt_id=? AND consumption_type='authority'", (attempt_id,)).fetchone()[0]), "request_consumptions": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_consumptions WHERE attempt_id=? AND consumption_type='request'", (attempt_id,)).fetchone()[0]), "external_actions": {"resolver_calls": 1, "retries": 0, "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0, "provider_calls": 0, "cost_units": 0}}
        finally:
            connection.close()


__all__ = ["DNSAttemptError", "DNSAttemptStore", "DNSResolver"]
