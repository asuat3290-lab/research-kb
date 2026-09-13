"""Server-owned Live Canary Approval Preview boundary for MR-4B1B-v15R2.

The Preparation Preview and the Live Approval Preview are intentionally
different objects.  Creating the latter only reads the already committed
v14R3 DNS receipt and appends one immutable control-plane row; it does not
create an Approval, acquire a lease/claim, read a credential, or open any
network boundary.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from typing import Any, Mapping

from ..policy import Actor
from .contract import canonical_json, canonical_sha256, make_stable_id
from .persistence.db import MaxControlError, control_transaction
from .persistence.repository import (
    MaxControlRepository,
    _parse_timestamp,
    _timestamp,
    _utc_now,
)
from .release_identity import normalize_release_identity
from .provider.store import ProviderStore


class LiveApprovalPreviewError(MaxControlError):
    """A server-owned Live Approval Preview invariant failed closed."""


_PHRASE_PREFIX = "APPROVE MR-4B1 CANARY "
_HASH_FIELDS = {
    "snapshot_hash", "snapshot_state_hash", "preparation_preview_hash",
    "handoff_hash", "request_manifest_hash", "dns_attempt_hash",
    "dns_receipt_hash", "bounded_dns_result_hash", "endpoint_origin_hash",
    "provider_profile_hash", "pricing_hash", "network_policy_hash",
    "source_policy_hash", "credential_reference_hash", "release_identity_hash",
    "budget_hash",
}


def _json(value: Any, name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LiveApprovalPreviewError(f"{name} is invalid") from exc
    if not isinstance(parsed, dict):
        raise LiveApprovalPreviewError(f"{name} must be an object")
    return parsed


def _hash_json(value: Any, name: str) -> str:
    try:
        return canonical_sha256(value)
    except Exception as exc:  # pragma: no cover - defensive serialization seam
        raise LiveApprovalPreviewError(f"{name} cannot be hashed") from exc


def _bounded_ttl(value: Any, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 300 or value > maximum:
        raise LiveApprovalPreviewError(f"{name} is outside its bounded range")
    return int(value)


def _bounded_nonnegative(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LiveApprovalPreviewError(f"{name} is invalid")
    return int(value)


def _preview_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the hash input without the derived phrase hash."""

    result = dict(value)
    result.pop("confirmation_phrase_hash", None)
    return result


class LiveApprovalPreviewStore:
    """Append-only server-owned Live Approval Preview persistence."""

    phrase_prefix = _PHRASE_PREFIX

    def __init__(
        self,
        repository: MaxControlRepository,
        *,
        expected_release_identity: Mapping[str, Any] | None = None,
    ) -> None:
        self.repository = repository
        self.expected_release_identity = (
            normalize_release_identity(expected_release_identity)
            if expected_release_identity is not None
            else None
        )

    def _connect(self, *, read_only: bool) -> sqlite3.Connection:
        return self.repository._connect(read_only=read_only)

    @staticmethod
    def _release(snapshot_value: Mapping[str, Any], expected: Mapping[str, Any] | None) -> dict[str, Any]:
        try:
            release = normalize_release_identity(snapshot_value["release_identity"])
        except (KeyError, TypeError, ValueError) as exc:
            raise LiveApprovalPreviewError("Snapshot release identity is invalid") from exc
        if expected is not None and release != dict(expected):
            raise LiveApprovalPreviewError("Snapshot release identity does not match the current server release")
        return release

    def _load_chain(
        self,
        connection: sqlite3.Connection,
        *,
        preparation_preview_id: str,
        now,
    ) -> dict[str, Any]:
        preparation = connection.execute(
            "SELECT * FROM max_live_canary_preparation_previews WHERE preview_id=?",
            (preparation_preview_id,),
        ).fetchone()
        if preparation is None:
            raise LiveApprovalPreviewError("Preparation Preview was not found")
        snapshot = connection.execute(
            "SELECT * FROM max_live_canary_preparation_snapshots WHERE snapshot_id=?",
            (preparation["snapshot_id"],),
        ).fetchone()
        handoff = connection.execute(
            "SELECT * FROM max_runner_preparation_handoffs WHERE preview_id=? ORDER BY created_at DESC LIMIT 1",
            (preparation_preview_id,),
        ).fetchone()
        if snapshot is None or handoff is None:
            raise LiveApprovalPreviewError("Preparation Preview has no complete handoff")
        current_snapshot = connection.execute(
            "SELECT * FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?",
            (snapshot["snapshot_id"],),
        ).fetchone()
        handoff_current = connection.execute(
            "SELECT * FROM max_runner_preparation_handoff_current WHERE handoff_id=?",
            (handoff["handoff_id"],),
        ).fetchone()
        group_current = connection.execute(
            "SELECT * FROM max_runner_call_group_current WHERE group_id=?",
            (handoff["call_group_id"],),
        ).fetchone()
        request = connection.execute(
            "SELECT * FROM max_live_canary_preparation_dns_requests WHERE request_id=?",
            (handoff["dns_request_id"],),
        ).fetchone()
        authority = connection.execute(
            "SELECT * FROM max_live_canary_preparation_dns_authorities WHERE authority_id=?",
            (handoff["dns_authority_id"],),
        ).fetchone()
        if current_snapshot is None or handoff_current is None or group_current is None or request is None or authority is None:
            raise LiveApprovalPreviewError("Preparation chain projection is incomplete")
        attempt = connection.execute(
            "SELECT * FROM max_live_canary_dns_attempts WHERE request_id=?",
            (request["request_id"],),
        ).fetchone()
        receipt = connection.execute(
            "SELECT * FROM max_live_canary_dns_attempt_receipts WHERE request_id=?",
            (request["request_id"],),
        ).fetchone()
        attempt_current = None if attempt is None else connection.execute(
            "SELECT * FROM max_live_canary_dns_attempt_current WHERE attempt_id=?",
            (attempt["attempt_id"],),
        ).fetchone()
        if attempt is None or receipt is None or attempt_current is None:
            raise LiveApprovalPreviewError("A durable DNS Receipt is required before Live Approval Preview")

        values = {
            "preparation": preparation,
            "snapshot": snapshot,
            "current_snapshot": current_snapshot,
            "handoff": handoff,
            "handoff_current": handoff_current,
            "group_current": group_current,
            "request": request,
            "authority": authority,
            "attempt": attempt,
            "attempt_current": attempt_current,
            "receipt": receipt,
        }
        for label, row, field in (
            ("Snapshot", snapshot, "snapshot_json"),
            ("Preparation Preview", preparation, "preview_json"),
            ("Handoff", handoff, "handoff_json"),
            ("DNS authority", authority, "authority_json"),
            ("DNS request", request, "request_json"),
            ("DNS attempt", attempt, "attempt_json"),
            ("DNS receipt", receipt, "receipt_json"),
        ):
            parsed = _json(row[field], label)
            # Use explicit hash columns; the client never supplies these.
            hash_column = {
                "Snapshot": "snapshot_hash",
                "Preparation Preview": "preview_hash",
                "Handoff": "handoff_hash",
                "DNS authority": "authority_hash",
                "DNS request": "request_hash",
                "DNS attempt": "attempt_hash",
                "DNS receipt": "receipt_hash",
            }[label]
            computed_hash = _hash_json(parsed, label)
            if label == "DNS request":
                request_binding = {
                    key: parsed.get(key)
                    for key in (
                        "schema", "hostname", "port", "scheme", "snapshot_id", "snapshot_hash",
                        "preview_id", "preview_hash", "endpoint_origin_hash", "network_policy_hash",
                        "max_getaddrinfo_calls", "max_dns_candidates", "credential_reads",
                        "tcp_connections", "tls_https_calls", "provider_calls", "cost_units",
                    )
                }
                computed_hash = canonical_sha256(request_binding)
            if computed_hash != row[hash_column]:
                raise LiveApprovalPreviewError(f"{label} hash validation failed")
            value_key = {
                "Snapshot": "snapshot_value",
                "Preparation Preview": "preparation_value",
                "Handoff": "handoff_value",
                "DNS authority": "authority_value",
                "DNS request": "request_value",
                "DNS attempt": "attempt_value",
                "DNS receipt": "receipt_value",
            }[label]
            values[value_key] = parsed
        snapshot_value = values["snapshot_value"]
        preparation_value = values["preparation_value"]
        handoff_value = values["handoff_value"]
        request_value = values["request_value"]
        authority_value = values["authority_value"]
        attempt_value = values["attempt_value"]
        receipt_value = values["receipt_value"]
        try:
            policy_binding = ProviderStore.validate_network_policy_binding(
                connection,
                run_id=str(snapshot["run_id"]),
                expected_release_identity_hash=str(snapshot["release_identity_hash"]),
            )
        except MaxControlError as exc:
            raise LiveApprovalPreviewError("Live Approval Preview requires a valid server-owned network policy binding") from exc
        if (
            policy_binding["network_policy_hash"] != snapshot["network_policy_hash"]
            or policy_binding["endpoint_origin_hash"] != preparation["endpoint_origin_hash"]
            or policy_binding["credential_reference_hash"] != snapshot["credential_reference_hash"]
        ):
            raise LiveApprovalPreviewError("Live Network Policy binding does not match the preparation chain")
        if current_snapshot["status"] != "active":
            raise LiveApprovalPreviewError("Snapshot is not active")
        if handoff_current["state"] != "PREPARED_AWAITING_AUTHORIZATION" or group_current["lifecycle_state"] != "PREPARED_AWAITING_AUTHORIZATION":
            raise LiveApprovalPreviewError("preparation handoff is not awaiting human authorization")
        if handoff["handoff_state"] != "PREPARED_AWAITING_AUTHORIZATION":
            raise LiveApprovalPreviewError("handoff immutable state is invalid")
        if authority["status"] != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION" or request["status"] != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION":
            raise LiveApprovalPreviewError("DNS authority or request is not in its server-owned terminal boundary")
        if receipt["status"] != "passed" or attempt_current["state"] != "DNS_PREFLIGHT_PASSED":
            raise LiveApprovalPreviewError("Live Approval Preview requires a passed durable DNS Receipt")
        if receipt["attempt_id"] != attempt["attempt_id"] or receipt["handoff_id"] != handoff["handoff_id"]:
            raise LiveApprovalPreviewError("DNS Receipt attempt/handoff binding drifted")
        if receipt["snapshot_hash"] != snapshot["snapshot_hash"] or receipt["preview_hash"] != preparation["preview_hash"] or receipt["handoff_hash"] != handoff["handoff_hash"]:
            raise LiveApprovalPreviewError("DNS Receipt preparation binding drifted")
        if attempt["snapshot_hash"] != snapshot["snapshot_hash"] or attempt["preview_hash"] != preparation["preview_hash"] or attempt["handoff_hash"] != handoff["handoff_hash"]:
            raise LiveApprovalPreviewError("DNS attempt preparation binding drifted")
        if request_value.get("preview_id") != preparation_preview_id or request_value.get("preview_hash") != preparation["preview_hash"] or request_value.get("snapshot_hash") != snapshot["snapshot_hash"]:
            raise LiveApprovalPreviewError("DNS request serialized binding drifted")
        if authority_value.get("request_hash") != request["request_hash"] or request_value.get("authority_id") != authority["authority_id"]:
            raise LiveApprovalPreviewError("DNS authority/request serialized binding drifted")
        if receipt["candidate_count"] < 1 or not bool(receipt["all_global"]) or not bool(receipt["ssrf_safe"]) or not bool(receipt["cap_satisfied"]):
            raise LiveApprovalPreviewError("DNS Receipt is not safe for Live Approval Preview")
        if any(int(receipt[key]) != 0 for key in ("retry_count", "credential_reads", "tcp_connections", "tls_https_calls", "provider_calls", "cost_units")):
            raise LiveApprovalPreviewError("DNS Receipt external-action counters are not zero")
        consumption_counts = {
            kind: int(connection.execute(
                "SELECT COUNT(*) FROM max_live_canary_dns_attempt_consumptions WHERE attempt_id=? AND consumption_type=?",
                (attempt["attempt_id"], kind),
            ).fetchone()[0])
            for kind in ("authority", "request")
        }
        if consumption_counts != {"authority": 1, "request": 1}:
            raise LiveApprovalPreviewError("DNS authority/request consumption is not exactly once")
        if connection.execute(
            "SELECT 1 FROM max_live_canary_native_dns_receipts WHERE request_id=?",
            (request["request_id"],),
        ).fetchone() is not None:
            raise LiveApprovalPreviewError("legacy DNS Receipt cannot be mixed with v14R3 durable Receipt")
        if any(
            int(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?", (snapshot["run_id"],)).fetchone()[0])
            for table in ("max_provider_call_records", "max_provider_dispatch_attempts", "max_live_canary_native_approvals", "max_live_canary_native_jit_authorities")
        ):
            raise LiveApprovalPreviewError("Provider or prior native authority activity already exists")
        lease = connection.execute(
            "SELECT expires_at,released_at FROM max_leases WHERE run_id=?",
            (snapshot["run_id"],),
        ).fetchone()
        if lease is not None and lease["released_at"] is None:
            expiry = _parse_timestamp(lease["expires_at"])
            if expiry is not None and expiry > now.astimezone(expiry.tzinfo):
                raise LiveApprovalPreviewError("preparation lease is still active")
        release = self._release(snapshot_value, self.expected_release_identity)
        if _hash_json(release, "release identity") != snapshot["release_identity_hash"]:
            raise LiveApprovalPreviewError("release identity hash drifted")
        return {**values, "release": release, "consumption_counts": consumption_counts}

    @staticmethod
    def _caps(snapshot: sqlite3.Row, snapshot_value: Mapping[str, Any]) -> dict[str, int]:
        try:
            raw = json.loads(str(snapshot["caps_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LiveApprovalPreviewError("Snapshot caps are invalid") from exc
        if not isinstance(raw, dict):
            raise LiveApprovalPreviewError("Snapshot caps are invalid")
        if canonical_sha256(raw) != snapshot["caps_hash"]:
            raise LiveApprovalPreviewError("Snapshot caps hash drifted")
        max_cost = _bounded_nonnegative(raw.get("max_cost_units", 0), "max_cost_units")
        human = _bounded_nonnegative(raw.get("human_cost_ceiling", max_cost), "human_cost_ceiling")
        profile = _bounded_nonnegative(raw.get("profile_worst_case", max_cost), "profile_worst_case")
        effective = _bounded_nonnegative(raw.get("effective_cost_cap", min(human, profile)), "effective_cost_cap")
        if effective > human or effective > profile:
            raise LiveApprovalPreviewError("effective cost cap exceeds a governing ceiling")
        return {
            "human_cost_ceiling": human,
            "profile_cost_ceiling": profile,
            "effective_cost_cap": effective,
            "max_input_tokens": _bounded_nonnegative(raw.get("max_input_tokens", 0), "max_input_tokens"),
            "max_output_tokens": _bounded_nonnegative(raw.get("max_output_tokens", 0), "max_output_tokens"),
            "max_provider_calls": _bounded_nonnegative(raw.get("max_provider_calls", 1), "max_provider_calls"),
        }

    @staticmethod
    def _redacted(row: sqlite3.Row, *, include_phrase: bool = False) -> dict[str, Any]:
        result = {
            "ok": True,
            "approval_preview_id": row["approval_preview_id"],
            "approval_preview_hash": row["approval_preview_hash"],
            "project_id": row["project_id"],
            "run_id": row["run_id"],
            "snapshot_id": row["snapshot_id"],
            "preparation_preview_id": row["preparation_preview_id"],
            "handoff_id": row["handoff_id"],
            "dns_attempt_id": row["dns_attempt_id"],
            "dns_receipt_id": row["dns_receipt_id"],
            "bounded_dns_result_hash": row["bounded_dns_result_hash"],
            "model_identity": row["model_identity"],
            "effective_cost_cap": int(row["effective_cost_cap"]),
            "max_input_tokens": int(row["max_input_tokens"]),
            "max_output_tokens": int(row["max_output_tokens"]),
            "max_provider_calls": int(row["max_provider_calls"]),
            "state": row["state"],
            "preview_expires_at": row["preview_expires_at"],
            "approval_expires_at": row["approval_expires_at"],
            "confirmation_phrase_hash": row["confirmation_phrase_hash"],
            "live_canary_approval_created": 0,
            "jit_authority_created": 0,
            "credential_reads": 0,
            "provider_calls": 0,
            "cost_units": 0,
        }
        if include_phrase:
            result["confirmation_phrase"] = _PHRASE_PREFIX + str(row["approval_preview_hash"])
        return result

    def create_approval_preview(
        self,
        *,
        preparation_preview_id: str,
        actor: Actor,
        preview_ttl_seconds: int = 3600,
        approval_ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        if not actor.is_admin:
            raise LiveApprovalPreviewError("Live Approval Preview creation requires admin authority")
        if not isinstance(preparation_preview_id, str) or not preparation_preview_id.strip():
            raise LiveApprovalPreviewError("Preparation Preview selector is required")
        preview_ttl_seconds = _bounded_ttl(preview_ttl_seconds, "preview_ttl_seconds", maximum=7 * 24 * 3600)
        approval_ttl_seconds = _bounded_ttl(approval_ttl_seconds, "approval_ttl_seconds", maximum=24 * 3600)
        if approval_ttl_seconds > preview_ttl_seconds:
            raise LiveApprovalPreviewError("approval TTL cannot exceed Preview TTL")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                now_dt = _utc_now(self.repository.clock)
                chain = self._load_chain(connection, preparation_preview_id=preparation_preview_id, now=now_dt)
                snapshot = chain["snapshot"]
                preparation = chain["preparation"]
                handoff = chain["handoff"]
                attempt = chain["attempt"]
                receipt = chain["receipt"]
                caps = self._caps(snapshot, chain["snapshot"] and chain["snapshot_value"])
                existing = connection.execute(
                    "SELECT * FROM max_live_canary_approval_previews WHERE dns_receipt_id=? AND release_identity_hash=?",
                    (receipt["receipt_id"], snapshot["release_identity_hash"]),
                ).fetchone()
                if existing is not None:
                    return self._redacted(existing, include_phrase=True) | {"idempotent": True}
                now = _timestamp(self.repository.clock)
                preview_expires = (now_dt + timedelta(seconds=preview_ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
                approval_expires = (now_dt + timedelta(seconds=approval_ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
                snapshot_value = chain["snapshot_value"]
                binding = {
                    "schema": "research-kb/mr4b1b-v15r2-live-approval-preview/v1",
                    "project_id": snapshot["project_id"], "run_id": snapshot["run_id"],
                    "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"],
                    "snapshot_state_hash": chain["current_snapshot"]["current_hash"],
                    "preparation_preview_id": preparation["preview_id"], "preparation_preview_hash": preparation["preview_hash"],
                    "handoff_id": handoff["handoff_id"], "handoff_hash": handoff["handoff_hash"],
                    "handoff_state": "PREPARED_AWAITING_AUTHORIZATION",
                    "request_manifest_hash": handoff["request_manifest_hash"],
                    "dns_attempt_id": attempt["attempt_id"], "dns_attempt_hash": attempt["attempt_hash"],
                    "dns_receipt_id": receipt["receipt_id"], "dns_receipt_hash": receipt["receipt_hash"],
                    "bounded_dns_result_hash": receipt["bounded_result_hash"],
                    "endpoint_origin_hash": preparation["endpoint_origin_hash"],
                    "provider_profile_hash": snapshot["provider_profile_hash"], "model_identity": snapshot["model_identity"],
                    "pricing_hash": snapshot["pricing_hash"], "network_policy_hash": snapshot["network_policy_hash"],
                    "source_policy_hash": snapshot["source_policy_hash"], "credential_reference_hash": snapshot["credential_reference_hash"],
                    "release_identity_hash": snapshot["release_identity_hash"], "budget_hash": snapshot["budget_hash"],
                    **caps, "approval_expires_at": approval_expires, "preview_expires_at": preview_expires,
                    "state": "AWAITING_HUMAN_APPROVAL",
                }
                for key in _HASH_FIELDS:
                    value = binding.get(key)
                    if not isinstance(value, str) or len(value) != 64:
                        raise LiveApprovalPreviewError(f"{key} binding is invalid")
                preview_hash = canonical_sha256(binding)
                phrase = _PHRASE_PREFIX + preview_hash
                phrase_hash = canonical_sha256(phrase)
                preview_value = {**binding, "confirmation_phrase_hash": phrase_hash}
                approval_preview_id = make_stable_id("live_approval_preview", preview_hash[:64])
                insert_values = (
                    approval_preview_id, snapshot["project_id"], snapshot["run_id"], snapshot["snapshot_id"], snapshot["snapshot_hash"], chain["current_snapshot"]["current_hash"], preparation["preview_id"], preparation["preview_hash"], handoff["handoff_id"], handoff["handoff_hash"], "PREPARED_AWAITING_AUTHORIZATION", handoff["request_manifest_hash"], attempt["attempt_id"], attempt["attempt_hash"], receipt["receipt_id"], receipt["receipt_hash"], receipt["bounded_result_hash"], preparation["endpoint_origin_hash"], snapshot["provider_profile_hash"], snapshot["model_identity"], snapshot["pricing_hash"], snapshot["network_policy_hash"], snapshot["source_policy_hash"], snapshot["credential_reference_hash"], snapshot["release_identity_hash"], snapshot["budget_hash"], caps["human_cost_ceiling"], caps["profile_cost_ceiling"], caps["effective_cost_cap"], caps["max_input_tokens"], caps["max_output_tokens"], caps["max_provider_calls"], approval_expires, preview_expires, phrase_hash, "AWAITING_HUMAN_APPROVAL", canonical_json(preview_value), preview_hash, now, actor.actor_id, actor.actor_kind, actor.session_id,
                )
                connection.execute(
                    "INSERT INTO max_live_canary_approval_previews(approval_preview_id,project_id,run_id,snapshot_id,snapshot_hash,snapshot_state_hash,preparation_preview_id,preparation_preview_hash,handoff_id,handoff_hash,handoff_state,request_manifest_hash,dns_attempt_id,dns_attempt_hash,dns_receipt_id,dns_receipt_hash,bounded_dns_result_hash,endpoint_origin_hash,provider_profile_hash,model_identity,pricing_hash,network_policy_hash,source_policy_hash,credential_reference_hash,release_identity_hash,budget_hash,human_cost_ceiling,profile_cost_ceiling,effective_cost_cap,max_input_tokens,max_output_tokens,max_provider_calls,approval_expires_at,preview_expires_at,confirmation_phrase_hash,state,preview_json,approval_preview_hash,created_at,actor_id,actor_kind,actor_session) VALUES (" + ",".join("?" for _ in insert_values) + ")",
                    insert_values,
                )
                created = connection.execute(
                    "SELECT * FROM max_live_canary_approval_previews WHERE approval_preview_id=?",
                    (approval_preview_id,),
                ).fetchone()
                return self._redacted(created, include_phrase=True) | {"idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise LiveApprovalPreviewError("Live Approval Preview conflicts with an immutable DNS Receipt") from exc
        finally:
            connection.close()

    def _preview_row(self, connection: sqlite3.Connection, approval_preview_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM max_live_canary_approval_previews WHERE approval_preview_id=?",
            (approval_preview_id,),
        ).fetchone()
        if row is None:
            raise LiveApprovalPreviewError("Live Approval Preview was not found")
        value = _json(row["preview_json"], "Live Approval Preview")
        phrase = _PHRASE_PREFIX + str(row["approval_preview_hash"])
        stored_phrase_hash = row["confirmation_phrase_hash"]
        if stored_phrase_hash != canonical_sha256(phrase) or value.get("confirmation_phrase_hash") != stored_phrase_hash:
            raise LiveApprovalPreviewError("Live Approval Preview confirmation binding is invalid")
        if canonical_sha256(_preview_basis(value)) != row["approval_preview_hash"]:
            raise LiveApprovalPreviewError("Live Approval Preview hash validation failed")
        if row["state"] != "AWAITING_HUMAN_APPROVAL":
            raise LiveApprovalPreviewError("Live Approval Preview is not awaiting human approval")
        return row

    def status(self, *, approval_preview_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            row = self._preview_row(connection, approval_preview_id)
            return self._redacted(row)
        finally:
            connection.close()

    def authorize(
        self,
        *,
        approval_preview_id: str,
        confirmation_phrase: str,
        actor: Actor,
    ) -> dict[str, Any]:
        """Create one v2 Native Approval from the exact Live Preview phrase.

        This is the next human gate.  v15R2 never calls this method.  The
        method intentionally accepts no client caps, model, receipt, or
        expiry fields; all such fields are read from the immutable Preview.
        """

        if not actor.is_admin:
            raise LiveApprovalPreviewError("Live Canary Approval requires admin authority")
        if not isinstance(approval_preview_id, str) or not isinstance(confirmation_phrase, str):
            raise LiveApprovalPreviewError("Live Approval Preview selector and exact phrase are required")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._preview_row(connection, approval_preview_id)
                expected = _PHRASE_PREFIX + str(row["approval_preview_hash"])
                if confirmation_phrase != expected or canonical_sha256(confirmation_phrase) != row["confirmation_phrase_hash"]:
                    raise LiveApprovalPreviewError("confirmation phrase is not the exact server-owned Live Approval Preview phrase")
                now_dt = _utc_now(self.repository.clock)
                for field in ("preview_expires_at", "approval_expires_at"):
                    expiry = _parse_timestamp(row[field])
                    if expiry is None or expiry <= now_dt.astimezone(expiry.tzinfo):
                        raise LiveApprovalPreviewError("Live Approval Preview is expired")
                chain = self._load_chain(connection, preparation_preview_id=row["preparation_preview_id"], now=now_dt)
                if chain["snapshot"]["snapshot_hash"] != row["snapshot_hash"] or chain["receipt"]["receipt_hash"] != row["dns_receipt_hash"] or chain["handoff"]["handoff_hash"] != row["handoff_hash"]:
                    raise LiveApprovalPreviewError("Live Approval Preview binding drifted")
                existing = connection.execute(
                    "SELECT * FROM max_live_canary_native_approvals_v2 WHERE approval_preview_id=?",
                    (approval_preview_id,),
                ).fetchone()
                if existing is not None:
                    return {"ok": True, "idempotent": True, "approval_id": existing["approval_id"], "approval_hash": existing["approval_hash"], "approval_preview_id": approval_preview_id, "provider_calls": 0, "cost_units": 0}
                old_activity = int(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals WHERE run_id=?", (row["run_id"],)).fetchone()[0])
                if old_activity:
                    raise LiveApprovalPreviewError("legacy native Approval activity conflicts with the v2 Preview")
                now = _timestamp(self.repository.clock)
                approval_value = {
                    "schema": "research-kb/mr4b1b-v15r2-native-approval/v1",
                    "approval_preview_id": row["approval_preview_id"], "approval_preview_hash": row["approval_preview_hash"],
                    "project_id": row["project_id"], "run_id": row["run_id"], "snapshot_id": row["snapshot_id"], "snapshot_hash": row["snapshot_hash"],
                    "preparation_preview_id": row["preparation_preview_id"], "preparation_preview_hash": row["preparation_preview_hash"],
                    "handoff_id": row["handoff_id"], "handoff_hash": row["handoff_hash"], "dns_attempt_id": row["dns_attempt_id"], "dns_attempt_hash": row["dns_attempt_hash"],
                    "dns_receipt_id": row["dns_receipt_id"], "dns_receipt_hash": row["dns_receipt_hash"],
                    "provider_profile_hash": row["provider_profile_hash"], "model_identity": row["model_identity"], "pricing_hash": row["pricing_hash"],
                    "network_policy_hash": row["network_policy_hash"], "source_policy_hash": row["source_policy_hash"], "credential_reference_hash": row["credential_reference_hash"],
                    "release_identity_hash": row["release_identity_hash"], "budget_hash": row["budget_hash"], "effective_cost_cap": int(row["effective_cost_cap"]),
                    "max_provider_calls": int(row["max_provider_calls"]), "confirmation_phrase_hash": row["confirmation_phrase_hash"], "created_at": now, "expires_at": row["approval_expires_at"],
                }
                approval_hash = canonical_sha256(approval_value)
                approval_id = make_stable_id("native_approval_v2", approval_hash[:64])
                connection.execute(
                    "INSERT INTO max_live_canary_native_approvals_v2(approval_id,approval_preview_id,project_id,run_id,snapshot_id,snapshot_hash,preparation_preview_id,preparation_preview_hash,handoff_id,handoff_hash,dns_attempt_id,dns_attempt_hash,dns_receipt_id,dns_receipt_hash,provider_profile_hash,model_identity,pricing_hash,network_policy_hash,source_policy_hash,credential_reference_hash,release_identity_hash,budget_hash,effective_cost_cap,max_provider_calls,confirmation_phrase_hash,approval_json,approval_hash,created_at,expires_at,approved_by,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (approval_id, row["approval_preview_id"], row["project_id"], row["run_id"], row["snapshot_id"], row["snapshot_hash"], row["preparation_preview_id"], row["preparation_preview_hash"], row["handoff_id"], row["handoff_hash"], row["dns_attempt_id"], row["dns_attempt_hash"], row["dns_receipt_id"], row["dns_receipt_hash"], row["provider_profile_hash"], row["model_identity"], row["pricing_hash"], row["network_policy_hash"], row["source_policy_hash"], row["credential_reference_hash"], row["release_identity_hash"], row["budget_hash"], int(row["effective_cost_cap"]), int(row["max_provider_calls"]), row["confirmation_phrase_hash"], canonical_json(approval_value), approval_hash, now, row["approval_expires_at"], actor.actor_id, actor.actor_kind, actor.session_id),
                )
                return {"ok": True, "idempotent": False, "approval_id": approval_id, "approval_hash": approval_hash, "approval_preview_id": approval_preview_id, "expires_at": row["approval_expires_at"], "provider_calls": 0, "cost_units": 0}
        except sqlite3.IntegrityError as exc:
            raise LiveApprovalPreviewError("Native Approval conflicts with an immutable Live Approval Preview") from exc
        finally:
            connection.close()

    def verify(self, *, approval_preview_id: str | None = None) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        issues: list[str] = []
        try:
            if approval_preview_id is not None:
                row = self._preview_row(connection, approval_preview_id)
                rows = [row]
            else:
                rows = list(connection.execute("SELECT * FROM max_live_canary_approval_previews ORDER BY created_at,approval_preview_id"))
            for row in rows:
                try:
                    self._preview_row(connection, row["approval_preview_id"])
                except LiveApprovalPreviewError as exc:
                    issues.append(str(exc))
            return {
                "ok": not issues,
                "approval_preview_count": len(rows),
                "issues": sorted(set(issues)),
                "live_canary_approval_created": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approvals_v2").fetchone()[0]),
                "live_canary_approval_consumed": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_approval_v2_consumptions").fetchone()[0]),
                "jit_authority_created": 0,
                "provider_calls": 0,
                "credential_reads": 0,
                "cost_units": 0,
            }
        finally:
            connection.close()


__all__ = ["LiveApprovalPreviewError", "LiveApprovalPreviewStore"]
