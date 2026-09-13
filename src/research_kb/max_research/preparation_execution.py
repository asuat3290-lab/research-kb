"""Native MR-4B1B-v12R1 Preparation -> JIT -> Provider bridge.

The v11 lifetime-separated objects remain a preparation compatibility surface.
This module is the native server-owned execution boundary for schema 21.  It
does not instantiate the legacy live-canary authority store and it never
accepts client-supplied hashes for an execution decision.  DNS receipts,
human approvals, JIT authorities, and JIT state transitions are immutable
facts; successor events carry the later provider/permit bindings.

The executor accepts only an injected hermetic transport in this release.  A
future production transport can be wired behind the same server-owned seam,
but the ordinary CLI cannot turn this module into an implicit network path.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any, Mapping

from .. import __version__
from ..policy import Actor
from .contract import RunStatus, canonical_json, canonical_sha256, make_stable_id
from .lifetime_separation import PreparationSnapshotError, PreparationSnapshotStore
from .preparation_handoff import PreparationHandoffError, PreparationHandoffStore
from .persistence.db import MaxControlError, control_transaction
from .persistence.repository import (
    MaxControlRepository,
    _hash,
    _loads,
    _parse_timestamp,
    _timestamp,
    _utc_now,
)
from .persistence.runner import RunnerPersistence
from .persistence.version import CONTROL_SCHEMA_VERSION
from .provider.codec import OpenAICompatibleCodec, ProviderCodecError
from .provider.store import ProviderStore
from .provider.transport import HermeticTransport, ProviderTransport, ProviderTransportError, is_injected_hermetic_transport
from .provider.usage import (
    PROVIDER_USAGE_AUTHORITY_ID,
    ProviderCallRecord,
    ProviderUsageAttestation,
    ProviderUsageAuthority,
)
from .release_identity import normalize_release_identity
from .request_builder import BuiltServerRequest, ServerOwnedRequestBuilder, ServerRequestBuildError
from .runner.contracts import ModelCallResult, ModelCallStatus, ModelResponseEnvelope


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_NATIVE_STATES = {
    "ready",
    "send_started",
    "known_pre_send_failure",
    "unknown_after_send",
    "succeeded",
    "failed_with_authoritative_response",
    "closed",
}
_TERMINAL_STATES = {
    "known_pre_send_failure",
    "unknown_after_send",
    "succeeded",
    "failed_with_authoritative_response",
}
_FORBIDDEN_RESULT_KEYS = {
    "ip", "ips", "address", "addresses", "raw_ip", "raw_ips", "resolved_addresses",
    "prompt", "messages", "source_text", "full_text", "request_body", "body",
    "credential", "credential_value", "api_key", "authorization",
}


class NativePreparationBridgeError(MaxControlError):
    """A native schema-21 bridge invariant failed closed."""


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value.casefold()):
        raise NativePreparationBridgeError(f"{name} must be a SHA-256 digest")
    return value.casefold()


def _json_load(value: Any, name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NativePreparationBridgeError(f"{name} is invalid") from exc
    if not isinstance(parsed, dict):
        raise NativePreparationBridgeError(f"{name} must be an object")
    return parsed


def _walk_forbidden(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _FORBIDDEN_RESULT_KEYS:
                return True
            if _walk_forbidden(child):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_walk_forbidden(item) for item in value)
    return False


def _bounded_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise NativePreparationBridgeError(f"{name} must be boolean")
    return value


def _bounded_int(value: Any, name: str, *, minimum: int = 0, maximum: int = 2_000_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        raise NativePreparationBridgeError(f"{name} is outside its bounded range")
    return int(value)


def _safe_status_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep event payloads hash/count/identifier-only."""

    result = dict(value)
    if _walk_forbidden(result):
        raise NativePreparationBridgeError("native event contains source, request-body, IP, or credential material")
    for key, item in result.items():
        if isinstance(item, str) and len(item) > 512:
            raise NativePreparationBridgeError(f"native event field is too large: {key}")
    return result


class NativePreparationStore:
    """Schema-21 persistence for DNS receipts and human approvals."""

    approval_phrase_prefix = "APPROVE MR-4B1 SNAPSHOT "

    def __init__(
        self,
        repository: MaxControlRepository,
        *,
        source_database: str | Path | None = None,
        expected_release_identity: Mapping[str, Any] | None = None,
    ) -> None:
        self.repository = repository
        self.snapshots = PreparationSnapshotStore(repository, source_database=source_database)
        self.expected_release_identity = (
            normalize_release_identity(expected_release_identity)
            if expected_release_identity is not None
            else None
        )

    def _connect(self, *, read_only: bool) -> sqlite3.Connection:
        return self.repository._connect(read_only=read_only)

    @staticmethod
    def current_runtime_identity() -> dict[str, Any]:
        """Return the release fields that can be checked inside the package."""

        return {
            "package": "research-kb",
            "package_version": __version__,
            "core_schema_version": 5,
            "max_control_schema_version": CONTROL_SCHEMA_VERSION,
        }

    def _check_release(self, value: Mapping[str, Any]) -> dict[str, Any]:
        try:
            normalized = normalize_release_identity(value)
        except Exception as exc:
            raise NativePreparationBridgeError("release identity is invalid") from exc
        runtime = self.current_runtime_identity()
        if (
            normalized["package"] != runtime["package"]
            or normalized["package_version"] != runtime["package_version"]
            or normalized["core_schema_version"] != runtime["core_schema_version"]
            or normalized["max_control_schema_version"] != runtime["max_control_schema_version"]
        ):
            raise NativePreparationBridgeError("release identity is not the current native runtime")
        if self.expected_release_identity is not None and normalized != self.expected_release_identity:
            raise NativePreparationBridgeError("release identity does not match the server-owned candidate")
        return normalized

    def _rows_for_preview(self, connection: sqlite3.Connection, preview_id: str) -> dict[str, sqlite3.Row]:
        preview = connection.execute(
            "SELECT * FROM max_live_canary_preparation_previews WHERE preview_id=?",
            (preview_id,),
        ).fetchone()
        if preview is None:
            raise NativePreparationBridgeError("preparation Preview was not found")
        snapshot = connection.execute(
            "SELECT * FROM max_live_canary_preparation_snapshots WHERE snapshot_id=?",
            (preview["snapshot_id"],),
        ).fetchone()
        request = connection.execute(
            "SELECT r.*, a.authority_hash, a.endpoint_origin_hash, a.network_policy_hash AS dns_network_policy_hash "
            "FROM max_live_canary_preparation_dns_requests r "
            "JOIN max_live_canary_preparation_dns_authorities a ON a.authority_id=r.authority_id "
            "WHERE r.request_id=?",
            (self._request_id_for_preview(connection, preview_id),),
        ).fetchone()
        if snapshot is None or request is None:
            raise NativePreparationBridgeError("Preview has no complete DNS-bound preparation chain")
        return {"preview": preview, "snapshot": snapshot, "request": request}

    @staticmethod
    def _request_id_for_preview(connection: sqlite3.Connection, preview_id: str) -> str:
        row = connection.execute(
            "SELECT r.request_id FROM max_live_canary_preparation_dns_requests r "
            "JOIN max_live_canary_preparation_dns_authorities a ON a.authority_id=r.authority_id "
            "WHERE a.preview_id=? ORDER BY r.created_at DESC LIMIT 1",
            (preview_id,),
        ).fetchone()
        if row is None:
            raise NativePreparationBridgeError("Preview has no DNS request")
        return str(row["request_id"])

    def _verify_preview_chain(self, connection: sqlite3.Connection, preview_id: str) -> dict[str, Any]:
        rows = self._rows_for_preview(connection, preview_id)
        preview, snapshot, request = rows["preview"], rows["snapshot"], rows["request"]
        snapshot_value = _json_load(snapshot["snapshot_json"], "snapshot")
        preview_value = _json_load(preview["preview_json"], "Preview")
        request_value = _json_load(request["request_json"], "DNS request")
        if _hash(snapshot_value) != snapshot["snapshot_hash"] or _hash(preview_value) != preview["preview_hash"]:
            raise NativePreparationBridgeError("preparation chain hash validation failed")
        if preview["snapshot_hash"] != snapshot["snapshot_hash"] or request["preview_hash"] != preview["preview_hash"] or request["snapshot_hash"] != snapshot["snapshot_hash"]:
            raise NativePreparationBridgeError("preparation chain binding drifted")
        request_binding = {
            "schema": "research-kb/mr4b1b-v11r1-dns-only-request/v1",
            "hostname": request_value.get("hostname"), "port": request_value.get("port"), "scheme": request_value.get("scheme"),
            "snapshot_id": request_value.get("snapshot_id"), "snapshot_hash": request_value.get("snapshot_hash"),
            "preview_id": request_value.get("preview_id"), "preview_hash": request_value.get("preview_hash"),
            "endpoint_origin_hash": request_value.get("endpoint_origin_hash"), "network_policy_hash": request_value.get("network_policy_hash"),
            "max_getaddrinfo_calls": request_value.get("max_getaddrinfo_calls"), "max_dns_candidates": request_value.get("max_dns_candidates"),
            "credential_reads": request_value.get("credential_reads"), "tcp_connections": request_value.get("tcp_connections"),
            "tls_https_calls": request_value.get("tls_https_calls"), "provider_calls": request_value.get("provider_calls"), "cost_units": request_value.get("cost_units"),
        }
        if canonical_sha256(request_binding) != request["request_hash"]:
            raise NativePreparationBridgeError("DNS request binding hash is invalid")
        if request_value.get("preview_hash") != preview["preview_hash"] or request_value.get("snapshot_hash") != snapshot["snapshot_hash"] or request_value.get("authority_id") != request["authority_id"]:
            raise NativePreparationBridgeError("DNS request serialized binding drifted")
        release = self._check_release(snapshot_value.get("release_identity"))
        current = connection.execute(
            "SELECT * FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?",
            (snapshot["snapshot_id"],),
        ).fetchone()
        if current is None:
            raise NativePreparationBridgeError("preparation Snapshot current projection is missing")
        return {**rows, "snapshot_value": snapshot_value, "preview_value": preview_value, "request_value": request_value, "release": release, "current": current}

    def record_dns_receipt(
        self,
        *,
        preview_id: str,
        request_id: str | None = None,
        bounded_result: Mapping[str, Any],
        actor: Actor,
    ) -> dict[str, Any]:
        """Persist one DNS result receipt; this method never performs DNS."""

        if actor.actor_kind == "model" or actor.role == "model":
            raise NativePreparationBridgeError("model actors cannot record DNS receipts")
        if not isinstance(bounded_result, Mapping) or _walk_forbidden(bounded_result):
            raise NativePreparationBridgeError("DNS receipt must contain bounded metadata only")
        raw = dict(bounded_result)
        allowed = {
            "max_getaddrinfo_calls", "getaddrinfo_attempts", "dns_attempts", "max_dns_candidates",
            "candidate_count", "ipv4_count", "ipv6_count", "all_global", "ssrf_safe",
            "retry_count", "credential_reads", "tcp_connections", "tls_https_calls",
            "provider_calls", "cost_units", "status", "error_code", "bounded_result_hash",
        }
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise NativePreparationBridgeError("DNS receipt contains unknown fields: " + ", ".join(unknown))
        attempts = raw.get("getaddrinfo_attempts", raw.get("dns_attempts", 0))
        safe = {
            "max_getaddrinfo_calls": _bounded_int(raw.get("max_getaddrinfo_calls"), "max_getaddrinfo_calls", minimum=1, maximum=1),
            "getaddrinfo_attempts": _bounded_int(attempts, "getaddrinfo_attempts", minimum=0, maximum=1),
            "max_dns_candidates": _bounded_int(raw.get("max_dns_candidates"), "max_dns_candidates", minimum=1, maximum=16),
            "candidate_count": _bounded_int(raw.get("candidate_count"), "candidate_count", maximum=16),
            "ipv4_count": _bounded_int(raw.get("ipv4_count"), "ipv4_count", maximum=16),
            "ipv6_count": _bounded_int(raw.get("ipv6_count"), "ipv6_count", maximum=16),
            "all_global": _bounded_bool(raw.get("all_global"), "all_global"),
            "ssrf_safe": _bounded_bool(raw.get("ssrf_safe"), "ssrf_safe"),
            "retry_count": _bounded_int(raw.get("retry_count", 0), "retry_count", maximum=0),
            "credential_reads": _bounded_int(raw.get("credential_reads", 0), "credential_reads", maximum=0),
            "tcp_connections": _bounded_int(raw.get("tcp_connections", 0), "tcp_connections", maximum=0),
            "tls_https_calls": _bounded_int(raw.get("tls_https_calls", 0), "tls_https_calls", maximum=0),
            "provider_calls": _bounded_int(raw.get("provider_calls", 0), "provider_calls", maximum=0),
            "cost_units": _bounded_int(raw.get("cost_units", 0), "cost_units", maximum=0),
        }
        if safe["getaddrinfo_attempts"] != 1 or safe["max_getaddrinfo_calls"] != 1:
            raise NativePreparationBridgeError("DNS receipt must prove exactly one bounded resolver attempt")
        if safe["max_dns_candidates"] > 16 or safe["candidate_count"] > safe["max_dns_candidates"]:
            raise NativePreparationBridgeError("DNS candidate cap is exceeded")
        if safe["candidate_count"] != safe["ipv4_count"] + safe["ipv6_count"]:
            raise NativePreparationBridgeError("DNS address-family counts do not add up")
        computed_status = "passed" if safe["candidate_count"] >= 1 and safe["all_global"] and safe["ssrf_safe"] and safe["candidate_count"] <= safe["max_dns_candidates"] else "failed"
        supplied_status = raw.get("status")
        if supplied_status is not None and supplied_status != computed_status:
            raise NativePreparationBridgeError("DNS receipt status is not server-derived")
        safe["status"] = computed_status
        if computed_status == "failed" and isinstance(raw.get("error_code"), str) and raw["error_code"]:
            safe["error_code"] = raw["error_code"][:128]
        bounded_hash = canonical_sha256(safe)
        if raw.get("bounded_result_hash") is not None and raw["bounded_result_hash"] != bounded_hash:
            raise NativePreparationBridgeError("bounded DNS result hash is not canonical")

        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                chain = self._verify_preview_chain(connection, preview_id)
                preview, snapshot, request = chain["preview"], chain["snapshot"], chain["request"]
                if request_id is not None and request["request_id"] != request_id:
                    raise NativePreparationBridgeError("DNS request selector is not server-owned")
                authority = connection.execute(
                    "SELECT * FROM max_live_canary_preparation_dns_authorities WHERE authority_id=?",
                    (request["authority_id"],),
                ).fetchone()
                if authority is None or authority["status"] != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION":
                    raise NativePreparationBridgeError("DNS authority is not awaiting its one result")
                if authority["preview_hash"] != preview["preview_hash"] or authority["snapshot_hash"] != snapshot["snapshot_hash"] or authority["request_hash"] != request["request_hash"]:
                    raise NativePreparationBridgeError("DNS authority/request binding drifted")
                existing = connection.execute(
                    "SELECT * FROM max_live_canary_native_dns_receipts WHERE request_id=?",
                    (request["request_id"],),
                ).fetchone()
                if existing is not None:
                    if existing["bounded_result_hash"] != bounded_hash:
                        raise NativePreparationBridgeError("DNS request already has a conflicting receipt")
                    return {
                        "ok": existing["status"] == "passed", "idempotent": True,
                        "receipt_id": existing["receipt_id"], "receipt_hash": existing["receipt_hash"],
                        "status": existing["status"], "candidate_count": int(existing["candidate_count"]),
                    }
                release = chain["release"]
                receipt_value = {
                    "schema": "research-kb/mr4b1b-v12r1-dns-receipt/v1",
                    "request_id": request["request_id"], "authority_id": authority["authority_id"],
                    "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"],
                    "preview_id": preview["preview_id"], "preview_hash": preview["preview_hash"],
                    "run_id": snapshot["run_id"], "project_id": snapshot["project_id"],
                    "request_hash": request["request_hash"], "dns_authority_hash": authority["authority_hash"],
                    "endpoint_scheme": "https", "endpoint_hostname": "opencode.ai", "endpoint_port": 443,
                    "network_policy_hash": snapshot["network_policy_hash"],
                    "provider_profile_hash": snapshot["provider_profile_hash"],
                    "source_tree_sha256": snapshot["source_tree_sha256"],
                    "release_identity": release, "release_identity_hash": snapshot["release_identity_hash"],
                    "bounded_result": safe, "bounded_result_hash": bounded_hash,
                    "executed_at": now, "raw_ip_persisted": False,
                }
                receipt_hash = canonical_sha256(receipt_value)
                receipt_id = make_stable_id("native_dns_receipt", receipt_hash[:64])
                connection.execute(
                    "INSERT INTO max_live_canary_native_dns_receipts(receipt_id,request_id,authority_id,snapshot_id,preview_id,run_id,project_id,snapshot_hash,preview_hash,request_hash,dns_authority_hash,endpoint_scheme,endpoint_hostname,endpoint_port,network_policy_hash,provider_profile_hash,source_tree_sha256,release_identity_hash,max_getaddrinfo_calls,getaddrinfo_attempts,max_dns_candidates,candidate_count,ipv4_count,ipv6_count,all_global,ssrf_safe,cap_satisfied,retry_count,credential_reads,tcp_connections,tls_https_calls,provider_calls,cost_units,status,bounded_result_hash,receipt_json,receipt_hash,executed_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        receipt_id, request["request_id"], authority["authority_id"], snapshot["snapshot_id"], preview["preview_id"], snapshot["run_id"], snapshot["project_id"],
                        snapshot["snapshot_hash"], preview["preview_hash"], request["request_hash"], authority["authority_hash"], "https", "opencode.ai", 443,
                        snapshot["network_policy_hash"], snapshot["provider_profile_hash"], snapshot["source_tree_sha256"], snapshot["release_identity_hash"],
                        safe["max_getaddrinfo_calls"], safe["getaddrinfo_attempts"], safe["max_dns_candidates"], safe["candidate_count"], safe["ipv4_count"], safe["ipv6_count"],
                        int(safe["all_global"]), int(safe["ssrf_safe"]), int(safe["candidate_count"] <= safe["max_dns_candidates"]), safe["retry_count"], safe["credential_reads"], safe["tcp_connections"], safe["tls_https_calls"], safe["provider_calls"], safe["cost_units"], safe["status"], bounded_hash, canonical_json(receipt_value), receipt_hash, now, actor.actor_id, actor.actor_kind, actor.session_id,
                    ),
                )
                return {
                    "ok": computed_status == "passed", "idempotent": False,
                    "receipt_id": receipt_id, "receipt_hash": receipt_hash, "status": computed_status,
                    "request_id": request["request_id"], "candidate_count": safe["candidate_count"],
                    "ipv4_count": safe["ipv4_count"], "ipv6_count": safe["ipv6_count"],
                    "all_global": safe["all_global"], "ssrf_safe": safe["ssrf_safe"],
                    "raw_ip_persisted": False, "cost_units": 0,
                }
        except sqlite3.IntegrityError as exc:
            raise NativePreparationBridgeError("DNS receipt conflicted with an immutable request") from exc
        finally:
            connection.close()

    create_dns_receipt = record_dns_receipt

    def create_approval(
        self,
        *,
        preview_id: str,
        confirmation_phrase: str,
        expires_at: str,
        actor: Actor,
    ) -> dict[str, Any]:
        if not actor.is_admin:
            raise NativePreparationBridgeError("native human approval requires admin authority")
        if not isinstance(confirmation_phrase, str):
            raise NativePreparationBridgeError("confirmation phrase is required")
        now = _timestamp(self.repository.clock)
        expiry = _parse_timestamp(expires_at)
        if expiry is None or expiry <= _utc_now(self.repository.clock):
            raise NativePreparationBridgeError("native approval expiry is invalid")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                chain = self._verify_preview_chain(connection, preview_id)
                preview, snapshot = chain["preview"], chain["snapshot"]
                expected_phrase = self.approval_phrase_prefix + str(preview["preview_hash"])
                if confirmation_phrase != expected_phrase:
                    raise NativePreparationBridgeError("confirmation phrase is not the exact server-owned phrase")
                current = chain["current"]
                if current["status"] != "active":
                    raise NativePreparationBridgeError("native approval requires an active preparation Snapshot")
                issues = self.snapshots._verify_event_chain(connection, snapshot["snapshot_id"])
                issues += self.snapshots._drift(connection, snapshot, release_identity=chain["release"])
                if issues:
                    raise NativePreparationBridgeError("native approval binding drifted: " + ", ".join(sorted(set(issues))))
                receipt = connection.execute(
                    "SELECT * FROM max_live_canary_native_dns_receipts WHERE preview_id=? ORDER BY executed_at DESC LIMIT 1",
                    (preview_id,),
                ).fetchone()
                if receipt is None or receipt["status"] != "passed":
                    raise NativePreparationBridgeError("native approval requires a passed DNS bounded receipt")
                if receipt["release_identity_hash"] != snapshot["release_identity_hash"] or receipt["preview_hash"] != preview["preview_hash"]:
                    raise NativePreparationBridgeError("DNS receipt release or Preview binding drifted")
                revoked = connection.execute(
                    "SELECT revocation_id FROM max_live_canary_native_approval_revocations WHERE approval_id IN (SELECT approval_id FROM max_live_canary_native_approvals WHERE preview_id=?)",
                    (preview_id,),
                ).fetchone()
                existing = connection.execute(
                    "SELECT * FROM max_live_canary_native_approvals WHERE preview_id=? ORDER BY created_at DESC LIMIT 1",
                    (preview_id,),
                ).fetchone()
                if existing is not None:
                    if revoked is not None:
                        raise NativePreparationBridgeError("native approval Preview was revoked; create a fresh Preview")
                    if existing["confirmation_phrase_hash"] != canonical_sha256(confirmation_phrase):
                        raise NativePreparationBridgeError("a different native approval already exists for this Preview")
                    return {"ok": True, "idempotent": True, "approval_id": existing["approval_id"], "approval_hash": existing["approval_hash"], "expires_at": existing["expires_at"], "confirmation_phrase": expected_phrase}
                stable = chain["snapshot_value"]
                binding = {
                    "schema": "research-kb/mr4b1b-v12r1-native-human-approval/v1",
                    "run_id": snapshot["run_id"], "project_id": snapshot["project_id"],
                    "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"],
                    "snapshot_state_hash": current["current_hash"], "preview_id": preview["preview_id"], "preview_hash": preview["preview_hash"],
                    "request_manifest_hash": stable["request_manifest_hash"],
                    "dns_receipt_id": receipt["receipt_id"], "dns_receipt_hash": receipt["receipt_hash"],
                    "provider_profile_hash": snapshot["provider_profile_hash"], "model_identity": snapshot["model_identity"],
                    "pricing_hash": snapshot["pricing_hash"], "network_policy_hash": snapshot["network_policy_hash"],
                    "source_policy_hash": stable["source_policy_hash"], "credential_reference_hash": snapshot["credential_reference_hash"],
                    "release_identity": chain["release"], "release_identity_hash": snapshot["release_identity_hash"],
                    "budget_hash": snapshot["budget_hash"], "caps": stable["caps"], "caps_hash": snapshot["caps_hash"],
                    "confirmation_phrase_hash": canonical_sha256(confirmation_phrase),
                    "created_at": now, "expires_at": expires_at, "approved_by": actor.actor_id, "actor_session": actor.session_id,
                }
                approval_hash = canonical_sha256(binding)
                approval_id = make_stable_id("native_preparation_approval", approval_hash[:64])
                connection.execute(
                    "INSERT INTO max_live_canary_native_approvals(approval_id,run_id,project_id,snapshot_id,snapshot_hash,preview_id,preview_hash,snapshot_state_hash,request_manifest_hash,dns_receipt_id,dns_receipt_hash,provider_profile_hash,model_identity,pricing_hash,network_policy_hash,source_policy_hash,credential_reference_hash,release_identity_hash,budget_hash,caps_hash,confirmation_phrase_hash,approval_json,approval_hash,created_at,expires_at,approved_by,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        approval_id, snapshot["run_id"], snapshot["project_id"], snapshot["snapshot_id"], snapshot["snapshot_hash"], preview["preview_id"], preview["preview_hash"], current["current_hash"], stable["request_manifest_hash"], receipt["receipt_id"], receipt["receipt_hash"], snapshot["provider_profile_hash"], snapshot["model_identity"], snapshot["pricing_hash"], snapshot["network_policy_hash"], stable["source_policy_hash"], snapshot["credential_reference_hash"], snapshot["release_identity_hash"], snapshot["budget_hash"], snapshot["caps_hash"], binding["confirmation_phrase_hash"], canonical_json(binding), approval_hash, now, expires_at, actor.actor_id, actor.actor_kind, actor.session_id,
                    ),
                )
                return {"ok": True, "idempotent": False, "approval_id": approval_id, "approval_hash": approval_hash, "expires_at": expires_at, "confirmation_phrase": expected_phrase, "live_canary_approval_created": 0, "provider_calls": 0, "cost_units": 0}
        except sqlite3.IntegrityError as exc:
            raise NativePreparationBridgeError("native approval conflicted with an immutable Preview") from exc
        finally:
            connection.close()

    def revoke_approval(self, *, approval_id: str, actor: Actor, reason: str) -> dict[str, Any]:
        if not actor.is_admin:
            raise NativePreparationBridgeError("native approval revocation requires admin authority")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 256 or "\n" in reason or "\r" in reason:
            raise NativePreparationBridgeError("native approval revocation reason is invalid")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                approval = connection.execute("SELECT * FROM max_live_canary_native_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                if approval is None:
                    raise NativePreparationBridgeError("native approval was not found")
                consumed = connection.execute("SELECT 1 FROM max_live_canary_native_approval_consumptions WHERE approval_id=?", (approval_id,)).fetchone()
                if consumed is not None:
                    raise NativePreparationBridgeError("consumed native approval cannot be revoked")
                existing = connection.execute("SELECT * FROM max_live_canary_native_approval_revocations WHERE approval_id=?", (approval_id,)).fetchone()
                if existing is not None:
                    return {"ok": True, "idempotent": True, "approval_id": approval_id, "revocation_id": existing["revocation_id"], "status": "revoked"}
                value = {"schema": "research-kb/mr4b1b-v12r1-native-approval-revocation/v1", "approval_id": approval_id, "run_id": approval["run_id"], "reason_hash": canonical_sha256(reason.strip()), "created_at": now}
                revocation_hash = canonical_sha256(value)
                revocation_id = make_stable_id("native_approval_revocation", revocation_hash[:64])
                connection.execute("INSERT INTO max_live_canary_native_approval_revocations(revocation_id,approval_id,run_id,reason_hash,revocation_json,revocation_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?)", (revocation_id, approval_id, approval["run_id"], value["reason_hash"], canonical_json(value), revocation_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                return {"ok": True, "idempotent": False, "approval_id": approval_id, "revocation_id": revocation_id, "status": "revoked"}
        finally:
            connection.close()

    def status(self, *, preview_id: str | None = None, run_id: str | None = None, authority_id: str | None = None) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            if authority_id:
                authority = connection.execute("SELECT * FROM max_live_canary_native_jit_authorities WHERE authority_id=?", (authority_id,)).fetchone()
                if authority is None:
                    raise NativePreparationBridgeError("native JIT authority was not found")
                run_id = authority["run_id"]
                latest = connection.execute("SELECT * FROM max_live_canary_native_jit_events WHERE authority_id=? ORDER BY sequence_no DESC LIMIT 1", (authority_id,)).fetchone()
                return {"ok": latest is not None, "authority_id": authority_id, "run_id": run_id, "state": None if latest is None else latest["state"], "event_count": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_jit_events WHERE authority_id=?", (authority_id,)).fetchone()[0]), "terminal": bool(latest is not None and latest["state"] == "closed"), "provider_calls": int(connection.execute("SELECT COUNT(*) FROM max_provider_call_records WHERE run_id=?", (run_id,)).fetchone()[0]), "cost_units": int(connection.execute("SELECT COALESCE(SUM(cost_units),0) FROM max_provider_usage_attestations WHERE run_id=?", (run_id,)).fetchone()[0])}
            if preview_id:
                approvals = connection.execute("SELECT approval_id,approval_hash,expires_at FROM max_live_canary_native_approvals WHERE preview_id=? ORDER BY created_at", (preview_id,)).fetchall()
                receipts = connection.execute("SELECT receipt_id,receipt_hash,status,candidate_count FROM max_live_canary_native_dns_receipts WHERE preview_id=? ORDER BY executed_at", (preview_id,)).fetchall()
                return {"ok": True, "preview_id": preview_id, "approval_count": len(approvals), "approvals": [{"approval_id": row["approval_id"], "approval_hash": row["approval_hash"], "expires_at": row["expires_at"], "consumed": connection.execute("SELECT 1 FROM max_live_canary_native_approval_consumptions WHERE approval_id=?", (row["approval_id"],)).fetchone() is not None, "revoked": connection.execute("SELECT 1 FROM max_live_canary_native_approval_revocations WHERE approval_id=?", (row["approval_id"],)).fetchone() is not None} for row in approvals], "dns_receipts": [dict(row) for row in receipts], "live_canary_approval_created": 0, "provider_calls": int(connection.execute("SELECT COUNT(*) FROM max_provider_call_records WHERE run_id=(SELECT run_id FROM max_live_canary_preparation_previews WHERE preview_id=?)", (preview_id,)).fetchone()[0])}
            if run_id:
                authorities = connection.execute("SELECT authority_id FROM max_live_canary_native_jit_authorities WHERE run_id=? ORDER BY created_at", (run_id,)).fetchall()
                return {"ok": True, "run_id": run_id, "authority_ids": [row["authority_id"] for row in authorities], "native_authority_count": len(authorities)}
            raise NativePreparationBridgeError("native status requires preview_id, run_id, or authority_id")
        finally:
            connection.close()


class PreparationCanaryExecutor:
    """Server-owned native JIT and hermetic Provider execution."""

    def __init__(
        self,
        repository: MaxControlRepository,
        *,
        store: NativePreparationStore | None = None,
        admin_actor: Actor | None = None,
        worker_actor: Actor | None = None,
        transport: ProviderTransport | None = None,
        request_builder: ServerOwnedRequestBuilder | None = None,
        source_database: str | Path | None = None,
        expected_release_identity: Mapping[str, Any] | None = None,
        usage_authority: ProviderUsageAuthority | None = None,
    ) -> None:
        self.repository = repository
        self.store = store or NativePreparationStore(repository, source_database=source_database, expected_release_identity=expected_release_identity)
        self.handoffs = PreparationHandoffStore(repository, source_database=source_database)
        self.admin_actor = admin_actor or Actor("mr4b1b-v12r1-native-admin", "mr4b1b-v12r1-native-admin-session", "admin", "admin", "research-kb-native")
        self.worker_actor = worker_actor or Actor("mr4b1b-v12r1-native-worker", "mr4b1b-v12r1-native-worker-session", "worker", "runner", "research-kb-native")
        self.transport = transport
        self.request_builder = request_builder or ServerOwnedRequestBuilder()
        self.provider_store = ProviderStore(repository)
        # The native bridge owns the same local usage authority used by the
        # governed RunnerPersistence result/ledger closure.  Keeping this
        # explicit prevents a native provider result from bypassing the
        # runner's receipt verifier merely because the caller constructed a
        # bare repository for the service facade.
        self.usage_authority = usage_authority or repository.usage_authority or ProviderUsageAuthority()
        self.repository.usage_authority = self.usage_authority

    def authorize(self, **kwargs: Any) -> dict[str, Any]:
        return self.store.create_approval(actor=self.admin_actor, **kwargs)

    def revoke(self, *, approval_id: str, reason: str) -> dict[str, Any]:
        return self.store.revoke_approval(approval_id=approval_id, actor=self.admin_actor, reason=reason)

    def _append_event(self, *, authority_id: str, state: str, actor: Actor, payload: Mapping[str, Any]) -> dict[str, Any]:
        if state not in _NATIVE_STATES:
            raise NativePreparationBridgeError("native JIT state is invalid")
        value = _safe_status_payload(payload)
        now = _timestamp(self.repository.clock)
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                authority = connection.execute("SELECT * FROM max_live_canary_native_jit_authorities WHERE authority_id=?", (authority_id,)).fetchone()
                if authority is None:
                    raise NativePreparationBridgeError("native JIT authority was not found")
                prior = connection.execute("SELECT * FROM max_live_canary_native_jit_events WHERE authority_id=? ORDER BY sequence_no DESC LIMIT 1", (authority_id,)).fetchone()
                prior_state = None if prior is None else prior["state"]
                if prior_state == "closed":
                    raise NativePreparationBridgeError("native JIT authority is terminally closed")
                allowed = {
                    None: {"ready"}, "ready": {"ready", "send_started", "known_pre_send_failure"},
                    "send_started": {"send_started", "known_pre_send_failure", "unknown_after_send", "succeeded", "failed_with_authoritative_response"},
                    "known_pre_send_failure": {"closed"}, "unknown_after_send": {"closed"}, "succeeded": {"closed"}, "failed_with_authoritative_response": {"closed"},
                }
                if state not in allowed.get(prior_state, set()):
                    raise NativePreparationBridgeError(f"invalid native JIT state transition {prior_state}->{state}")
                sequence = 1 if prior is None else int(prior["sequence_no"]) + 1
                previous_hash = None if prior is None else prior["event_hash"]
                payload_hash = canonical_sha256(value)
                identity = {"authority_id": authority_id, "run_id": authority["run_id"], "sequence_no": sequence, "state": state, "payload_hash": payload_hash, "previous_event_hash": previous_hash, "created_at": now}
                event_hash = canonical_sha256({**identity, "payload_json": canonical_json(value), "actor_id": actor.actor_id, "actor_kind": actor.actor_kind, "actor_session": actor.session_id})
                event_id = make_stable_id("native_jit_event", event_hash[:64])
                connection.execute("INSERT INTO max_live_canary_native_jit_events(event_id,authority_id,run_id,project_id,sequence_no,state,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (event_id, authority_id, authority["run_id"], authority["project_id"], sequence, state, canonical_json(value), payload_hash, previous_hash, event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "state": state}
        finally:
            connection.close()

    def _context(self, *, preview_id: str, connection: sqlite3.Connection | None = None) -> dict[str, Any]:
        own = connection is None
        conn = connection or self.repository._connect(read_only=True)
        try:
            chain = self.store._verify_preview_chain(conn, preview_id)
            snapshot = chain["snapshot"]
            issues = self.store.snapshots._verify_event_chain(conn, snapshot["snapshot_id"])
            issues += self.store.snapshots._drift(conn, snapshot, release_identity=chain["release"])
            if issues:
                raise NativePreparationBridgeError("native execution binding drifted: " + ", ".join(sorted(set(issues))))
            start_approvals = int(conn.execute("SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?", (snapshot["run_id"],)).fetchone()[0])
            if start_approvals != 1:
                raise NativePreparationBridgeError("native execution requires exactly one consumed StartApproval")
            policy = conn.execute("SELECT * FROM max_source_egress_policies WHERE run_id=? ORDER BY created_at DESC LIMIT 1", (snapshot["run_id"],)).fetchone()
            intent = conn.execute("SELECT * FROM max_model_call_intents WHERE intent_id=? AND run_id=?", (snapshot["intent_id"], snapshot["run_id"])).fetchone()
            plan = conn.execute("SELECT * FROM max_runner_plans WHERE plan_id=? AND run_id=?", (snapshot["plan_id"], snapshot["run_id"])).fetchone()
            if policy is None or intent is None or plan is None:
                raise NativePreparationBridgeError("native execution manifest chain is incomplete")
            try:
                policy_value = _json_load(policy["policy_json"], "source policy")
            except NativePreparationBridgeError:
                policy_value = {}
            source = chain["snapshot_value"]["source_binding"]
            authority = {
                **chain["snapshot_value"],
                "source_allowlist": [{"passage_id": source["passage_id"], "document_id": source["document_id"], "document_version_id": source["source_version"], "source_role": source["source_role"], "evidential_function": source["evidential_function"], "purpose": source["purpose"]}],
                "source_policy": {**policy_value, "max_source_characters": int(policy["max_source_characters"]), "max_source_tokens": int(policy["max_source_tokens"])},
                "runner_profile_hash": plan["profile_hash"],
                "source_egress_policy_hash": snapshot["source_egress_policy_hash"],
            }
            return {**chain, "policy": policy, "intent": intent, "plan": plan, "authority": authority}
        finally:
            if own:
                conn.close()

    def _create_jit(self, *, preview_id: str) -> dict[str, Any]:
        now = _timestamp(self.repository.clock)
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                ctx = self._context(preview_id=preview_id, connection=connection)
                snapshot, preview, receipt = ctx["snapshot"], ctx["preview"], None
                approval = connection.execute("SELECT * FROM max_live_canary_native_approvals WHERE preview_id=? ORDER BY created_at DESC LIMIT 1", (preview_id,)).fetchone()
                if approval is None:
                    raise NativePreparationBridgeError("native human approval was not found")
                if _parse_timestamp(approval["expires_at"]) is None or _parse_timestamp(approval["expires_at"]) <= _utc_now(self.repository.clock):
                    raise NativePreparationBridgeError("native human approval has expired")
                if connection.execute("SELECT 1 FROM max_live_canary_native_approval_revocations WHERE approval_id=?", (approval["approval_id"],)).fetchone() is not None:
                    raise NativePreparationBridgeError("native human approval has been revoked")
                if connection.execute("SELECT 1 FROM max_live_canary_native_approval_consumptions WHERE approval_id=?", (approval["approval_id"],)).fetchone() is not None:
                    raise NativePreparationBridgeError("native human approval has already been consumed")
                receipt = connection.execute("SELECT * FROM max_live_canary_native_dns_receipts WHERE receipt_id=?", (approval["dns_receipt_id"],)).fetchone()
                if receipt is None or receipt["status"] != "passed" or receipt["release_identity_hash"] != snapshot["release_identity_hash"]:
                    raise NativePreparationBridgeError("native JIT requires the current passed DNS receipt")
                active_native = connection.execute("SELECT authority_id FROM max_live_canary_native_jit_authorities WHERE run_id=?", (snapshot["run_id"],)).fetchone()
                if active_native is not None:
                    raise NativePreparationBridgeError("a native JIT authority already exists for this Run")
                # Invocation claims are append-only: releasing a claim adds a
                # released successor row and preserves the original active
                # row.  The latest row is therefore the authoritative claim
                # state for this Run.
                latest_claim = connection.execute("SELECT claim_id,status,expires_at FROM max_runner_invocation_claims WHERE run_id=? ORDER BY rowid DESC LIMIT 1", (snapshot["run_id"],)).fetchone()
                if latest_claim is not None and latest_claim["status"] == "active" and latest_claim["expires_at"] > now:
                    raise NativePreparationBridgeError("an invocation claim is already active for this Run")
                if connection.execute("SELECT status FROM max_runs WHERE run_id=?", (snapshot["run_id"],)).fetchone()[0] != RunStatus.RUNNING.value:
                    raise NativePreparationBridgeError("native JIT requires a RUNNING Run")
                lease = self.repository._acquire_lease_connection(connection, run_id=snapshot["run_id"], actor=self.worker_actor, ttl_seconds=600, now=now, allowed_statuses={RunStatus.RUNNING})
                claim_basis = {"approval_id": approval["approval_id"], "run_id": snapshot["run_id"], "worker": self.worker_actor.actor_id, "session": self.worker_actor.session_id, "fencing_token": int(lease["fencing_token"])}
                claim_id = make_stable_id("native_jit_invocation", canonical_sha256(claim_basis)[:64])
                claim_payload = {"claim_id": claim_id, "run_id": snapshot["run_id"], "actor_id": self.worker_actor.actor_id, "actor_session": self.worker_actor.session_id, "fencing_token": int(lease["fencing_token"]), "attempt_id": claim_id, "expires_at": lease["expires_at"], "status": "active", "native_bridge": True}
                connection.execute("INSERT INTO max_runner_invocation_claims(claim_id,run_id,actor_id,actor_session,fencing_token,attempt_id,expires_at,status,claim_json,claim_hash,created_at,released_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)", (claim_id, snapshot["run_id"], self.worker_actor.actor_id, self.worker_actor.session_id, int(lease["fencing_token"]), claim_id, lease["expires_at"], "active", canonical_json(claim_payload), canonical_sha256(claim_payload), now))
                self.repository._append_event(connection, run_id=snapshot["run_id"], event_type="lease_acquired", payload={"owner_id": self.worker_actor.actor_id, "session_id": self.worker_actor.session_id, "fencing_token": int(lease["fencing_token"]), "expires_at": lease["expires_at"], "reason": "mr4b1b-v12r1-native-jit"}, actor=self.worker_actor, now=now)
                self.repository._append_event(connection, run_id=snapshot["run_id"], event_type="runner_invocation_claimed", payload={"claim_id": claim_id, "attempt_id": claim_id, "fencing_token": int(lease["fencing_token"],), "expires_at": lease["expires_at"], "reason": "mr4b1b-v12r1-native-jit"}, actor=self.worker_actor, now=now)
                self.handoffs.transition_to_jit_connection(connection, preview_id=preview_id, worker=self.worker_actor, claim_id=claim_id, fencing_token=int(lease["fencing_token"]), now=now)
                consumption_value = {"schema": "research-kb/mr4b1b-v12r1-native-approval-consumption/v1", "approval_id": approval["approval_id"], "approval_hash": approval["approval_hash"], "run_id": snapshot["run_id"], "snapshot_id": snapshot["snapshot_id"], "preview_id": preview["preview_id"], "consumed_at": now, "authority_kind": "preparation-to-jit-native"}
                consumption_hash = canonical_sha256(consumption_value)
                consumption_id = make_stable_id("native_approval_consumption", consumption_hash[:64])
                connection.execute("INSERT INTO max_live_canary_native_approval_consumptions(consumption_id,approval_id,run_id,project_id,snapshot_id,preview_id,approval_hash,consumption_json,consumption_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (consumption_id, approval["approval_id"], snapshot["run_id"], snapshot["project_id"], snapshot["snapshot_id"], preview["preview_id"], approval["approval_hash"], canonical_json(consumption_value), consumption_hash, now, self.worker_actor.actor_id, self.worker_actor.actor_kind, self.worker_actor.session_id))
                authority_value = {"schema": "research-kb/mr4b1b-v12r1-native-jit-authority/v1", "approval_id": approval["approval_id"], "consumption_id": consumption_id, "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"], "preview_id": preview["preview_id"], "preview_hash": preview["preview_hash"], "dns_receipt_id": receipt["receipt_id"], "dns_receipt_hash": receipt["receipt_hash"], "run_id": snapshot["run_id"], "project_id": snapshot["project_id"], "lease_id": "run-lease:" + snapshot["run_id"], "claim_id": claim_id, "owner_id": self.worker_actor.actor_id, "owner_session": self.worker_actor.session_id, "fencing_token": int(lease["fencing_token"]), "request_hash": snapshot["request_hash"], "intent_hash": snapshot["intent_hash"], "idempotency_key_hash": canonical_sha256(ctx["intent"]["idempotency_key"]), "provider_profile_hash": snapshot["provider_profile_hash"], "pricing_hash": snapshot["pricing_hash"], "network_policy_hash": snapshot["network_policy_hash"], "source_policy_hash": snapshot["source_egress_policy_hash"], "release_identity_hash": snapshot["release_identity_hash"], "budget_hash": snapshot["budget_hash"], "authority_expires_at": lease["expires_at"], "state": "ready", "execution": {"dns": 0, "credential": 0, "tcp": 0, "tls": 0, "https": 0, "provider": 0, "cost_units": 0}}
                authority_hash = canonical_sha256(authority_value)
                authority_id = make_stable_id("native_jit_authority", authority_hash[:64])
                connection.execute("INSERT INTO max_live_canary_native_jit_authorities(authority_id,approval_id,consumption_id,snapshot_id,preview_id,dns_receipt_id,run_id,project_id,lease_id,claim_id,owner_id,owner_session,fencing_token,request_hash,intent_hash,idempotency_key_hash,provider_profile_hash,pricing_hash,network_policy_hash,source_policy_hash,release_identity_hash,budget_hash,grant_id,network_authorization_id,dispatch_permit_id,source_permit_id,authority_expires_at,state,authority_json,authority_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (authority_id, approval["approval_id"], consumption_id, snapshot["snapshot_id"], preview["preview_id"], receipt["receipt_id"], snapshot["run_id"], snapshot["project_id"], authority_value["lease_id"], claim_id, self.worker_actor.actor_id, self.worker_actor.session_id, int(lease["fencing_token"]), snapshot["request_hash"], snapshot["intent_hash"], authority_value["idempotency_key_hash"], snapshot["provider_profile_hash"], snapshot["pricing_hash"], snapshot["network_policy_hash"], snapshot["source_egress_policy_hash"], snapshot["release_identity_hash"], snapshot["budget_hash"], None, None, None, None, lease["expires_at"], "ready", canonical_json(authority_value), authority_hash, now, self.worker_actor.actor_id, self.worker_actor.actor_kind, self.worker_actor.session_id))
                event_payload = {"authority_hash": authority_hash, "approval_id": approval["approval_id"], "consumption_id": consumption_id, "claim_id": claim_id, "fencing_token": int(lease["fencing_token"]), "execution_counts": authority_value["execution"]}
                payload_hash = canonical_sha256(event_payload)
                event_identity = {"authority_id": authority_id, "run_id": snapshot["run_id"], "sequence_no": 1, "state": "ready", "payload_hash": payload_hash, "previous_event_hash": None, "created_at": now}
                event_hash = canonical_sha256({**event_identity, "payload_json": canonical_json(event_payload), "actor_id": self.worker_actor.actor_id, "actor_kind": self.worker_actor.actor_kind, "actor_session": self.worker_actor.session_id})
                connection.execute("INSERT INTO max_live_canary_native_jit_events(event_id,authority_id,run_id,project_id,sequence_no,state,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (make_stable_id("native_jit_event", event_hash[:64]), authority_id, snapshot["run_id"], snapshot["project_id"], 1, "ready", canonical_json(event_payload), payload_hash, None, event_hash, now, self.worker_actor.actor_id, self.worker_actor.actor_kind, self.worker_actor.session_id))
                return {"ok": True, "authority_id": authority_id, "authority_hash": authority_hash, "approval_id": approval["approval_id"], "consumption_id": consumption_id, "claim_id": claim_id, "lease": lease, "fencing_token": int(lease["fencing_token"]), "preview_id": preview_id, "run_id": snapshot["run_id"], "state": "ready", "next": "provider_prepare"}
        except sqlite3.IntegrityError as exc:
            raise NativePreparationBridgeError("native JIT approval or claim was concurrently consumed") from exc
        finally:
            connection.close()

    def _load_jit(self, authority_id: str) -> tuple[sqlite3.Row, sqlite3.Row]:
        connection = self.repository._connect(read_only=True)
        try:
            authority = connection.execute("SELECT * FROM max_live_canary_native_jit_authorities WHERE authority_id=?", (authority_id,)).fetchone()
            if authority is None:
                raise NativePreparationBridgeError("native JIT authority was not found")
            event = connection.execute("SELECT * FROM max_live_canary_native_jit_events WHERE authority_id=? ORDER BY sequence_no DESC LIMIT 1", (authority_id,)).fetchone()
            if event is None:
                raise NativePreparationBridgeError("native JIT event chain is empty")
            return authority, event
        finally:
            connection.close()

    def _release_runner(self, *, run_id: str, claim_id: str, fencing_token: int) -> list[str]:
        errors: list[str] = []
        try:
            RunnerPersistence(self.repository).release_invocation(run_id=run_id, claim_id=claim_id, actor=self.worker_actor, fencing_token=fencing_token)
        except Exception as exc:
            errors.append("claim_release:" + type(exc).__name__)
        try:
            self.repository.release_lease(run_id=run_id, actor=self.worker_actor, fencing_token=fencing_token)
        except Exception as exc:
            errors.append("lease_release:" + type(exc).__name__)
        return errors

    def _server_request(self, ctx: Mapping[str, Any], profile: Any) -> BuiltServerRequest:
        try:
            with closing(self.repository._connect(read_only=True)) as connection:
                return self.request_builder.build_from_row(authority=ctx["authority"], connection=connection, provider_profile=profile)
        except (ServerRequestBuildError, ProviderCodecError, sqlite3.Error) as exc:
            raise NativePreparationBridgeError("server-owned request rebuild failed") from exc

    def _persist_runner_success(
        self,
        *,
        ctx: Mapping[str, Any],
        built: BuiltServerRequest,
        decoded: Any,
        call_record: ProviderCallRecord,
        attestation: ProviderUsageAttestation,
        cost_units: int,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Close the existing Runner group through its formal persistence API.

        The native JIT is a new authority boundary, but it still completes the
        already-created preparation Run through the same immutable
        ``ModelCallResult -> usage ledger -> iteration outcome -> call-group``
        chain as the foreground runner.  This method deliberately contains no
        SQL: the native bridge may not manufacture a parallel runner history.
        """

        run_id = str(ctx["snapshot"]["run_id"])
        iteration_id = str(ctx["intent"]["iteration_id"])
        logical_call_id = str(built.intent.logical_call_id)
        intent_hash = str(built.intent.intent_hash)
        request_hash = str(built.intent.request_hash)
        runner = RunnerPersistence(self.repository)
        receipt = self.usage_authority.to_usage_receipt(
            call_record,
            attestation,
            logical_call_id=logical_call_id,
            intent_hash=intent_hash,
            request_hash=request_hash,
            iteration_id=iteration_id,
            inference_profile_hash=str(ctx["intent"]["inference_profile_hash"]),
        )
        response = ModelResponseEnvelope(
            logical_call_id=logical_call_id,
            intent_hash=intent_hash,
            model_identity=call_record.model_identity,
            inference_profile_hash=str(ctx["intent"]["inference_profile_hash"]),
            status=ModelCallStatus.SUCCEEDED.value,
            proposal=dict(decoded.proposal),
            usage_receipt=receipt.as_mapping(),
            provider_call_id=call_record.provider_call_id,
            dispatch_known=True,
            error_code=None,
        )
        result = ModelCallResult(
            logical_call_id=logical_call_id,
            intent_hash=intent_hash,
            status=ModelCallStatus.SUCCEEDED.value,
            response=response,
        )
        stored_result = runner.record_result(
            run_id=run_id,
            result=result,
            actor=self.worker_actor,
            fencing_token=fencing_token,
        )
        reservation = runner.budget_reservation(
            run_id=run_id,
            idempotency_key=f"mr2a:reserve:{logical_call_id}",
        )
        if reservation is None:
            raise NativePreparationBridgeError("native runner result has no durable budget reservation")
        reservation_id = str(reservation.get("reservation_id") or reservation.get("entry_id"))
        if not reservation_id:
            raise NativePreparationBridgeError("native runner budget reservation ID is missing")
        amount = dict(receipt.amount)
        if int(amount.get("cost_units", 0)) != int(cost_units):
            raise NativePreparationBridgeError("native usage cost differs from the provider attestation")
        # The preparation Run already contains a worst-case reservation.  The
        # repository budget invariant does not permit appending actual usage
        # while that full reservation is still held (used + reserved would
        # transiently exceed the Charter ceiling).  Release that immutable
        # reservation first, then append the authoritative receipt as the
        # actual spend.  The release is append-only and idempotent; a crash
        # after it remains a known post-send settlement boundary, never a
        # reason to retry the Provider call.
        self.repository.release_budget(
            run_id=run_id,
            reservation_id=reservation_id,
            amount=None,
            idempotency_key=f"mr4b1b-v12r1:release-before-usage:{logical_call_id}",
            actor=self.worker_actor,
            fencing_token=fencing_token,
            iteration_id=iteration_id,
        )
        usage = self.repository.record_authoritative_usage(
            run_id=run_id,
            amount=amount,
            receipt=receipt,
            provenance={"runner": "mr4b1b-v12r1-native", "logical_call_id": logical_call_id},
            idempotency_key=f"mr2a.2:usage:{logical_call_id}",
            actor=self.worker_actor,
            fencing_token=fencing_token,
            iteration_id=iteration_id,
            logical_call_id=logical_call_id,
            intent_hash=intent_hash,
            request_hash=request_hash,
            provider_call_id=call_record.provider_call_id,
            inference_profile_hash=str(ctx["intent"]["inference_profile_hash"]),
        )
        usage_entry_id = str(usage["entry_id"])
        stored = runner.stored_result(run_id=run_id, logical_call_id=logical_call_id)
        if stored is None:
            raise NativePreparationBridgeError("native runner result disappeared before usage binding")
        usage_binding = runner.record_usage_binding(
            run_id=run_id,
            result_id=str(stored["result_id"]),
            receipt=receipt,
            usage_entry_id=usage_entry_id,
            actor=self.worker_actor,
            fencing_token=fencing_token,
        )
        self.repository.record_server_usage(
            run_id=run_id,
            amount={"iteration_count": 1},
            idempotency_key=f"mr2a.2:iteration:{iteration_id}",
            actor=self.worker_actor,
            fencing_token=fencing_token,
            iteration_id=iteration_id,
            charge_kind="iteration",
        )
        budget_delta = runner.iteration_budget_delta(run_id=run_id, iteration_id=iteration_id)
        current_state_hash = str(self.repository.get_run(run_id)["current_state_hash"])
        finished = self.repository.finish_iteration(
            run_id=run_id,
            iteration_id=iteration_id,
            actor=self.worker_actor,
            fencing_token=fencing_token,
            status="completed",
            output_state_hash=current_state_hash,
            budget_delta=budget_delta,
            outcome_metadata={
                "native_bridge": "mr4b1b-v12r1",
                "provider_result_count": 1,
                "provider_usage": dict(decoded.usage),
                "provider_cost_units": int(cost_units),
            },
        )
        group = runner.current_group(run_id=run_id)
        if group is None:
            raise NativePreparationBridgeError("native runner call group disappeared before finalization")
        outcome = {
            "group_id": str(group["group_id"]),
            "result_hash": result.result_hash,
            "usage_entry_id": usage_entry_id,
            "iteration_outcome_id": str(finished["outcome_id"]),
            "output_state_hash": current_state_hash,
            "plan_hash": str(ctx["plan"]["plan_hash"]),
        }
        links = (
            {
                "link_type": "iteration_outcome",
                "target_id": str(finished["outcome_id"]),
                "target_hash": str(finished["outcome_hash"]),
            },
            {
                "link_type": "budget_entry",
                "target_id": usage_entry_id,
                "target_hash": canonical_sha256({"entry_id": usage_entry_id, "logical_call_id": logical_call_id}),
            },
        )
        runner_outcome = runner.record_outcome(
            run_id=run_id,
            logical_call_id=logical_call_id,
            status="completed",
            iteration_id=iteration_id,
            outcome=outcome,
            actor=self.worker_actor,
            fencing_token=fencing_token,
            links=links,
        )
        group_finished = runner.finalize_call_group(
            run_id=run_id,
            group_id=str(group["group_id"]),
            status="completed",
            actor=self.worker_actor,
            fencing_token=fencing_token,
        )
        verification = runner.verify_run(run_id=run_id)
        if not verification.get("ok"):
            raise NativePreparationBridgeError("native runner closure verification failed")
        return {
            "result_id": str(stored_result["result_id"]),
            "result_hash": result.result_hash,
            "usage_entry_id": usage_entry_id,
            "usage_binding_id": str(usage_binding["binding_id"]),
            "iteration_outcome_id": str(finished["outcome_id"]),
            "iteration_outcome_hash": str(finished["outcome_hash"]),
            "runner_outcome_id": str(runner_outcome["outcome_id"]),
            "call_group_id": str(group_finished["group_id"]),
            "verification": verification,
        }

    def _persist_runner_provider_failure(
        self,
        *,
        ctx: Mapping[str, Any],
        built: BuiltServerRequest,
        call_record: ProviderCallRecord,
        error_code: str,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Close a dispatch-known provider failure through the runner API.

        A provider rejection is not a pre-send abort: the provider call row
        and dispatch acknowledgement are durable facts, but no usage receipt
        is billable.  Keep that distinction in the runner result and close
        the reservation through the same append-only iteration/group APIs
        used by the success path.
        """

        run_id = str(ctx["snapshot"]["run_id"])
        iteration_id = str(ctx["intent"]["iteration_id"])
        logical_call_id = str(built.intent.logical_call_id)
        intent_hash = str(built.intent.intent_hash)
        runner = RunnerPersistence(self.repository)
        response = ModelResponseEnvelope(
            logical_call_id=logical_call_id,
            intent_hash=intent_hash,
            model_identity=call_record.model_identity,
            inference_profile_hash=str(ctx["intent"]["inference_profile_hash"]),
            status=ModelCallStatus.FAILED.value,
            proposal={},
            usage_receipt={},
            provider_call_id=call_record.provider_call_id,
            dispatch_known=True,
            error_code=error_code,
        )
        result = ModelCallResult(
            logical_call_id=logical_call_id,
            intent_hash=intent_hash,
            status=ModelCallStatus.FAILED.value,
            response=response,
        )
        stored_result = runner.record_result(
            run_id=run_id,
            result=result,
            actor=self.worker_actor,
            fencing_token=fencing_token,
        )
        reservation = runner.budget_reservation(
            run_id=run_id,
            idempotency_key=f"mr2a:reserve:{logical_call_id}",
        )
        if reservation is None:
            raise NativePreparationBridgeError("native provider failure has no durable budget reservation")
        reservation_id = str(reservation.get("reservation_id") or reservation.get("entry_id"))
        if not reservation_id:
            raise NativePreparationBridgeError("native provider failure budget reservation ID is missing")
        self.repository.release_budget(
            run_id=run_id,
            reservation_id=reservation_id,
            amount=None,
            idempotency_key=f"mr4b1b-v12r1:release-before-provider-failure:{logical_call_id}",
            actor=self.worker_actor,
            fencing_token=fencing_token,
            iteration_id=iteration_id,
        )
        self.repository.record_server_usage(
            run_id=run_id,
            amount={"iteration_count": 1},
            idempotency_key=f"mr2a.2:iteration:{iteration_id}",
            actor=self.worker_actor,
            fencing_token=fencing_token,
            iteration_id=iteration_id,
            charge_kind="iteration",
        )
        budget_delta = runner.iteration_budget_delta(run_id=run_id, iteration_id=iteration_id)
        finished = self.repository.finish_iteration(
            run_id=run_id,
            iteration_id=iteration_id,
            actor=self.worker_actor,
            fencing_token=fencing_token,
            status="aborted",
            output_state_hash=None,
            budget_delta=budget_delta,
            outcome_metadata={
                "native_bridge": "mr-convergence-dev19",
                "provider_result_count": 1,
                "provider_usage": {},
                "provider_cost_units": 0,
                "failure_stage": "provider_response",
                "error_code": error_code,
            },
        )
        group = runner.current_group(run_id=run_id)
        if group is None:
            raise NativePreparationBridgeError("native provider failure call group disappeared before finalization")
        outcome = {
            "group_id": str(group["group_id"]),
            "result_hash": result.result_hash,
            "iteration_outcome_id": str(finished["outcome_id"]),
            "provider_call_id_hash": canonical_sha256(call_record.provider_call_id),
            "provider_usage": {},
            "provider_cost_units": 0,
            "dispatch_known": True,
            "failure_stage": "provider_response",
            "error_code": error_code,
            "plan_hash": str(ctx["plan"]["plan_hash"]),
        }
        links = ({
            "link_type": "iteration_outcome",
            "target_id": str(finished["outcome_id"]),
            "target_hash": str(finished["outcome_hash"]),
        },)
        runner_outcome = runner.record_outcome(
            run_id=run_id,
            logical_call_id=logical_call_id,
            status="aborted",
            iteration_id=iteration_id,
            outcome=outcome,
            actor=self.worker_actor,
            fencing_token=fencing_token,
            links=links,
        )
        group_finished = runner.finalize_call_group(
            run_id=run_id,
            group_id=str(group["group_id"]),
            status="aborted",
            actor=self.worker_actor,
            fencing_token=fencing_token,
        )
        verification = runner.verify_run(run_id=run_id)
        if not verification.get("ok"):
            raise NativePreparationBridgeError("native provider failure runner closure verification failed")
        return {
            "result_id": str(stored_result["result_id"]),
            "result_hash": result.result_hash,
            "iteration_outcome_id": str(finished["outcome_id"]),
            "iteration_outcome_hash": str(finished["outcome_hash"]),
            "runner_outcome_id": str(runner_outcome["outcome_id"]),
            "call_group_id": str(group_finished["group_id"]),
            "verification": verification,
        }

    def _close_pre_send_permissions(
        self,
        *,
        grant: Mapping[str, Any] | None,
        provider_permit: Any,
        network_authorization_id: str | None,
        error_code: str,
        fencing_token: int,
    ) -> list[str]:
        """Close only server-owned reservations when no physical send occurred."""

        errors: list[str] = []
        if provider_permit is not None:
            try:
                self.provider_store.abort_live_dispatch_before_send(
                    permit=provider_permit,
                    actor=self.worker_actor,
                    fencing_token=fencing_token,
                    details={"error_code": error_code, "bridge": "mr4b1b-v12r1"},
                )
            except Exception as exc:
                errors.append("dispatch_abort:" + type(exc).__name__)
        if grant is not None:
            try:
                self.provider_store.close_execution_grant_before_send(
                    grant_id=str(grant["grant_id"]),
                    actor=self.worker_actor,
                    failure_stage="native_pre_send",
                    error_code=error_code,
                )
            except Exception as exc:
                errors.append("grant_close:" + type(exc).__name__)
        # A consumed network authority is immutable and cannot be changed
        # back to active.  Its bounded ID/state is included in the terminal
        # native event by the caller; only the dispatch permit and grant are
        # executable capabilities that need a pre-send abort operation.
        return errors

    def _record_native_terminal(self, *, authority_id: str, state: str, payload: Mapping[str, Any], run_id: str, claim_id: str, fencing_token: int) -> dict[str, Any]:
        event = self._append_event(authority_id=authority_id, state=state, actor=self.worker_actor, payload=payload)
        close = self._append_event(authority_id=authority_id, state="closed", actor=self.worker_actor, payload={"terminal_state": state, "terminal_event_hash": event["event_hash"], "cleanup": "claim_and_lease_release_attempted"})
        cleanup = self._release_runner(run_id=run_id, claim_id=claim_id, fencing_token=fencing_token)
        handoff_state = {"succeeded": "SUCCEEDED", "unknown_after_send": "UNKNOWN", "known_pre_send_failure": "FAILED", "failed_with_authoritative_response": "FAILED"}.get(state)
        if handoff_state is not None:
            try:
                with closing(self.repository._connect(read_only=True)) as connection:
                    row = connection.execute("SELECT preview_id FROM max_live_canary_native_jit_authorities WHERE authority_id=?", (authority_id,)).fetchone()
                if row is not None:
                    self.handoffs.transition_terminal(preview_id=row["preview_id"], state=handoff_state, actor=self.worker_actor, claim_id=claim_id, fencing_token=fencing_token)
            except PreparationHandoffError as exc:
                cleanup.append("handoff_terminal:" + type(exc).__name__)
        return {"terminal_state": state, "terminal_event": event, "closed_event": close, "cleanup_errors": cleanup}

    def execute(self, *, authority_id: str, allow_execute: bool = False) -> dict[str, Any]:
        if not allow_execute:
            raise NativePreparationBridgeError("native execute requires an explicit execution flag")
        if not is_injected_hermetic_transport(self.transport):
            raise NativePreparationBridgeError("native Provider execution requires an injected hermetic transport")
        authority, latest = self._load_jit(authority_id)
        run_id = str(authority["run_id"])
        fencing_token = int(authority["fencing_token"])
        claim_id = str(authority["claim_id"])
        grant: dict[str, Any] | None = None
        provider_permit: Any = None
        network_authorization_id: str | None = None
        source_permit_id: str | None = None
        send_boundary_reached = False
        ctx: Mapping[str, Any] | None = None
        built: BuiltServerRequest | None = None
        live_caps: dict[str, int] = {}
        idempotency_key = "native-unbound"
        try:
            if latest["state"] != "ready":
                raise NativePreparationBridgeError("native JIT authority is not in its initial ready state")
            ctx = self._context(preview_id=authority["preview_id"])
            authority_value = _json_load(authority["authority_json"], "native JIT authority")
            if ctx["snapshot"]["snapshot_hash"] != authority_value.get("snapshot_hash") or ctx["preview"]["preview_hash"] != authority_value.get("preview_hash") or ctx["snapshot"]["release_identity_hash"] != authority["release_identity_hash"]:
                raise NativePreparationBridgeError("native JIT release or preparation binding drifted")
            profile = self.provider_store.get_profile(profile_hash=authority["provider_profile_hash"])
            built = self._server_request(ctx, profile)
            if built.intent.request_hash != authority["request_hash"] or built.intent.intent_hash != authority["intent_hash"]:
                raise NativePreparationBridgeError("server-owned request hash drifted from native JIT")
            if built.manifest.get("manifest_hash") != ctx["snapshot_value"]["request_manifest_hash"]:
                raise NativePreparationBridgeError("server-owned request manifest drifted from native JIT")
            idempotency_key = str(ctx["intent"]["idempotency_key"])
            caps = dict(ctx["snapshot_value"]["caps"])
            try:
                live_caps = {
                    "max_ticks": int(caps["max_ticks"]),
                    "max_iterations": int(caps["max_iterations"]),
                    "max_wall_clock_seconds": int(caps["max_wall_clock_seconds"]),
                    "max_consecutive_failures": int(caps.get("max_consecutive_failures", 1)),
                    "max_no_progress": int(caps.get("max_no_progress", 1)),
                    "max_provider_calls": int(caps["max_provider_calls"]),
                    "max_input_tokens": int(caps["max_input_tokens"]),
                    "max_output_tokens": int(caps["max_output_tokens"]),
                    "max_cache_read_tokens": int(caps.get("max_cache_read_tokens", 0)),
                    "max_reasoning_tokens": int(caps.get("max_reasoning_tokens", 0)),
                    "max_cost_units": int(caps["max_cost_units"]),
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise NativePreparationBridgeError("native execution caps are incomplete") from exc
            try:
                profile_network = self.provider_store.network_policy_status(network_policy_hash_value=profile.network_policy_hash)
            except MaxControlError as exc:
                raise NativePreparationBridgeError("registered provider network policy is unavailable") from exc
            if not isinstance(profile_network.get("policy"), Mapping):
                raise NativePreparationBridgeError("registered provider network policy is unavailable")
            source_permit_id = make_stable_id("native_source_permit", canonical_sha256({"authority_id": authority_id, "manifest_hash": built.manifest["manifest_hash"], "fencing_token": fencing_token})[:64])
            self._append_event(authority_id=authority_id, state="ready", actor=self.worker_actor, payload={"source_permit_id": source_permit_id, "source_manifest_hash": built.manifest["manifest_hash"], "source_policy_hash": authority["source_policy_hash"], "source_permit_state": "consumed"})
            grant = self.provider_store.issue_live_execution_grant(run_id=run_id, actor=self.admin_actor, profile_hash=profile.profile_hash, caps=live_caps, reason="mr4b1b-v12r1-native-jit", ttl_seconds=600, network_policy_hash=profile.network_policy_hash, pricing_hash=profile.pricing.pricing_hash, budget_hash=authority["budget_hash"])
            consumed_grant = self.provider_store.consume_execution_grant(grant_id=grant["grant_id"], run_id=run_id, project_id=authority["project_id"], profile_hash=profile.profile_hash, model_identity=profile.model_identity, network_policy_hash=profile.network_policy_hash, pricing_hash=profile.pricing.pricing_hash, budget_hash=authority["budget_hash"], consumer=self.worker_actor)
            network_caps = {key: live_caps[key] for key in ("max_provider_calls", "max_input_tokens", "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens", "max_cost_units")}
            network = self.provider_store.issue_live_network_authorization(run_id=run_id, grant_id=grant["grant_id"], caps=network_caps, network_policy=profile_network["policy"], reason="mr4b1b-v12r1-native-jit", actor=self.admin_actor, ttl_seconds=600, profile_hash=profile.profile_hash)
            network_authorization_id = str(network["authorization_id"])
            dispatch = self.provider_store.prepare_live_dispatch(authorization_id=network_authorization_id, run_id=run_id, project_id=authority["project_id"], grant_id=grant["grant_id"], profile=profile, request_hash=built.intent.request_hash, wire_request_hash=str(built.manifest["wire_request_hash"]), intent_hash=built.intent.intent_hash, logical_call_id=built.intent.logical_call_id, idempotency_key=idempotency_key, actor=self.worker_actor, fencing_token=fencing_token, permit_ttl_seconds=120)
            provider_permit = dispatch["permit"]
            self._append_event(authority_id=authority_id, state="ready", actor=self.worker_actor, payload={"grant_id": grant["grant_id"], "grant_consumption_id": consumed_grant["consumption_id"], "network_authorization_id": network_authorization_id, "dispatch_permit_id": provider_permit.permit_id, "source_permit_id": source_permit_id, "request_manifest_hash": built.manifest["manifest_hash"]})
            provider_permit = self.provider_store.start_live_dispatch(permit=provider_permit, actor=self.worker_actor, fencing_token=fencing_token)
            self._append_event(authority_id=authority_id, state="send_started", actor=self.worker_actor, payload={"dispatch_permit_id": provider_permit.permit_id, "attempt_id": provider_permit.attempt_id, "claim_id": provider_permit.claim_id, "fencing_token": fencing_token, "send_boundary_reached": False})
            encoded = OpenAICompatibleCodec.encode(built.request, profile)
            send_boundary_reached = True
            response = self.transport.send(encoded.body, headers={"content-type": "application/json", "accept": "application/json", "idempotency-key": idempotency_key}, timeout_ms=int(profile.timeout_policy.get("total_ms", 120_000)), idempotency_key=idempotency_key)
            response_hash = hashlib.sha256(response.body_bytes()).hexdigest()
            if not response.dispatch_known or not response.provider_call_id:
                self.provider_store.mark_provider_call_unknown(claim_id=provider_permit.claim_id, actor=self.worker_actor, fencing_token=fencing_token)
                self.provider_store.mark_live_dispatch_outcome(permit=provider_permit, state="unknown", actor=self.worker_actor, details={"response_hash": response_hash, "status_code": response.status_code})
                self.provider_store.record_live_network_attempt(authorization_id=network_authorization_id, run_id=run_id, project_id=authority["project_id"], outcome="unknown", actor=self.worker_actor, provider_attempt_id=provider_permit.attempt_id, claim_id=provider_permit.claim_id, fencing_token=fencing_token, details={"response_hash": response_hash, "status_code": response.status_code})
                terminal = self._record_native_terminal(authority_id=authority_id, state="unknown_after_send", payload={"response_hash": response_hash, "status_code": response.status_code, "provider_call_id_present": bool(response.provider_call_id), "retry_allowed": False, "reservation_policy": "retain_until_reconciliation"}, run_id=run_id, claim_id=claim_id, fencing_token=fencing_token)
                return {"ok": False, "outcome": "UNKNOWN_AFTER_SEND", "authority_id": authority_id, "provider_call_id": response.provider_call_id or None, "response_hash": response_hash, "usage": {}, "reserved_cost_units": live_caps["max_cost_units"], "settled_cost_units": 0, "released_cost_units": 0, "network": {"dns": 0, "credential_reads": int(getattr(self.transport, "credential_read_count", 0)), "tcp": 0, "tls": 0, "https": 0, "provider_calls": int(getattr(self.transport, "network_call_count", 0))}, "terminal": terminal, "retry_allowed": False}
            try:
                decoded = OpenAICompatibleCodec.decode(response, built.request, profile, encoded=encoded)
                usage = dict(decoded.usage)
                cost_units = int(profile.pricing.cost_units_for_usage(usage))
                response_manifest = {**dict(decoded.response_manifest), "response_hash": response_hash}
                terminal_status = "succeeded" if 200 <= response.status_code < 300 else "failed"
                proposal = decoded.proposal if terminal_status == "succeeded" else None
            except Exception as exc:
                usage = {}
                cost_units = 0
                response_manifest = {**response.response_manifest, "response_hash": response_hash, "decode_error": type(exc).__name__}
                terminal_status = "failed"
                proposal = None
            context = self.provider_store.live_dispatch_context(permit=provider_permit)
            call_basis = {"provider_call_id": response.provider_call_id, "run_id": context["run_id"], "logical_call_id": context["logical_call_id"], "intent_hash": context["intent_hash"], "request_hash": context["request_hash"], "idempotency_key": idempotency_key, "response_hash": response_hash}
            call_record = ProviderCallRecord(call_record_id=make_stable_id("native_provider_call_record", canonical_sha256(call_basis)[:64]), provider_call_id=response.provider_call_id, run_id=context["run_id"], project_id=context["project_id"], profile_hash=context["profile_hash"], model_identity=context["model_identity"], intent_hash=context["intent_hash"], request_hash=context["request_hash"], idempotency_key=idempotency_key, transport_status=f"http_{response.status_code}", terminal_status=terminal_status, usage=usage, response_manifest=response_manifest, pricing_hash=context["pricing_hash"], logical_call_id=context["logical_call_id"], intent_id=context["intent_id"], iteration_id=context["iteration_id"])
            self.provider_store.record_provider_call(record=call_record, actor=self.worker_actor, proposal=proposal, attempt_id=provider_permit.attempt_id)
            attestation = None
            if terminal_status == "succeeded":
                attestation = ProviderUsageAttestation(attestation_id=make_stable_id("native_provider_attestation", canonical_sha256(call_record.call_record_id)[:64]), call_record_id=call_record.call_record_id, provider_call_id=call_record.provider_call_id, run_id=call_record.run_id, profile_hash=call_record.profile_hash, pricing_hash=call_record.pricing_hash, usage=call_record.usage, cost_units=cost_units, authority_id=PROVIDER_USAGE_AUTHORITY_ID)
                self.provider_store.record_provider_attestation(attestation=attestation, actor=self.worker_actor)
                RunnerPersistence(self.repository).record_dispatch_ack(run_id=run_id, logical_call_id=built.intent.logical_call_id, status="dispatched", dispatch_known=True, provider_call_id=response.provider_call_id, actor=self.worker_actor, fencing_token=fencing_token, preserve_existing=True)
                runner_closure = self._persist_runner_success(ctx=ctx, built=built, decoded=decoded, call_record=call_record, attestation=attestation, cost_units=cost_units, fencing_token=fencing_token)
            else:
                runner_closure = None
            self.provider_store.mark_live_dispatch_outcome(permit=provider_permit, state="settled" if terminal_status == "succeeded" else "failed", actor=self.worker_actor, details={"response_hash": response_hash, "usage_hash": canonical_sha256(usage), "cost_units": cost_units, "terminal_status": terminal_status})
            self.provider_store.record_live_network_attempt(authorization_id=network_authorization_id, run_id=run_id, project_id=authority["project_id"], outcome="settled", actor=self.worker_actor, provider_attempt_id=provider_permit.attempt_id, claim_id=provider_permit.claim_id, fencing_token=fencing_token, details={"response_hash": response_hash, "status_code": response.status_code, "cost_units": cost_units, "terminal_status": terminal_status})
            final_state = "succeeded" if terminal_status == "succeeded" else "failed_with_authoritative_response"
            terminal = self._record_native_terminal(authority_id=authority_id, state=final_state, payload={"provider_call_id": response.provider_call_id, "call_record_id": call_record.call_record_id, "response_hash": response_hash, "status_code": response.status_code, "usage": usage, "usage_hash": canonical_sha256(usage), "cost_units": cost_units, "runner_closure": runner_closure, "source_permit_id": source_permit_id, "network_authorization_id": network_authorization_id, "retry_allowed": False}, run_id=run_id, claim_id=claim_id, fencing_token=fencing_token)
            return {"ok": final_state == "succeeded", "outcome": "CANARY_SUCCEEDED" if final_state == "succeeded" else "AUTHORITATIVE_PROVIDER_RESULT", "authority_id": authority_id, "provider_call_id": response.provider_call_id, "http_status": response.status_code, "response_hash": response_hash, "usage": usage, "reserved_cost_units": live_caps["max_cost_units"], "settled_cost_units": cost_units if final_state == "succeeded" else 0, "released_cost_units": max(0, live_caps["max_cost_units"] - cost_units) if final_state == "succeeded" else live_caps["max_cost_units"], "network": {"dns": 0, "credential_reads": int(getattr(self.transport, "credential_read_count", 0)), "tcp": 0, "tls": 0, "https": 0, "provider_calls": int(getattr(self.transport, "network_call_count", 0))}, "runner": runner_closure, "terminal": terminal, "retry_allowed": False}
        except ProviderTransportError as exc:
            send_known = send_boundary_reached or bool(getattr(exc, "dispatch_known", False))
            cleanup_errors: list[str] = []
            runner_closure: dict[str, Any] | None = None
            if send_known and provider_permit is not None:
                try:
                    self.provider_store.mark_provider_call_unknown(claim_id=provider_permit.claim_id, actor=self.worker_actor, fencing_token=fencing_token)
                    self.provider_store.mark_live_dispatch_outcome(permit=provider_permit, state="unknown", actor=self.worker_actor, details={"error_code": exc.code, "exception_type": type(exc).__name__})
                    if network_authorization_id is not None:
                        self.provider_store.record_live_network_attempt(authorization_id=network_authorization_id, run_id=run_id, project_id=str(authority["project_id"]), outcome="unknown", actor=self.worker_actor, provider_attempt_id=provider_permit.attempt_id, claim_id=provider_permit.claim_id, fencing_token=fencing_token, details={"error_code": exc.code, "exception_type": type(exc).__name__})
                except Exception as cleanup_exc:
                    cleanup_errors.append("post_send:" + type(cleanup_exc).__name__)
            elif not send_known:
                pre_send_code = re.sub(r"[^A-Za-z0-9_]", "_", str(exc.code))[:128] or "NATIVE_PRE_SEND_FAILURE"
                try:
                    runner_closure = RunnerPersistence(self.repository).abort_pre_send(
                        run_id=run_id,
                        actor=self.worker_actor,
                        fencing_token=fencing_token,
                        failure_stage="mr4b1b_v12r1_native_pre_send",
                        error_code=pre_send_code,
                        logical_call_id=None if built is None else built.intent.logical_call_id,
                    )
                except Exception as closure_exc:
                    cleanup_errors.append("runner_abort:" + type(closure_exc).__name__)
                cleanup_errors.extend(self._close_pre_send_permissions(grant=grant, provider_permit=provider_permit, network_authorization_id=network_authorization_id, error_code=pre_send_code, fencing_token=fencing_token))
            terminal_state = "unknown_after_send" if send_known else "known_pre_send_failure"
            terminal = self._record_native_terminal(authority_id=authority_id, state=terminal_state, payload={"error_code": exc.code, "exception_type": type(exc).__name__, "send_boundary_reached": send_known, "source_permit_id": source_permit_id, "network_authorization_id": network_authorization_id, "runner_closure": runner_closure, "cleanup_errors": cleanup_errors, "retry_allowed": False}, run_id=run_id, claim_id=claim_id, fencing_token=fencing_token)
            return {"ok": False, "outcome": "UNKNOWN_AFTER_SEND" if send_known else "KNOWN_PRE_SEND_FAILURE", "authority_id": authority_id, "error_code": exc.code, "runner": runner_closure, "terminal": terminal, "retry_allowed": False, "network": {"dns": 0, "credential_reads": int(getattr(self.transport, "credential_read_count", 0)), "tcp": 0, "tls": 0, "https": 0, "provider_calls": int(getattr(self.transport, "network_call_count", 0))}}
        except Exception as exc:
            send_known = send_boundary_reached
            cleanup_errors: list[str] = []
            runner_closure: dict[str, Any] | None = None
            if send_known and provider_permit is not None:
                try:
                    self.provider_store.mark_provider_call_unknown(claim_id=provider_permit.claim_id, actor=self.worker_actor, fencing_token=fencing_token)
                    self.provider_store.mark_live_dispatch_outcome(permit=provider_permit, state="unknown", actor=self.worker_actor, details={"exception_type": type(exc).__name__})
                    if network_authorization_id is not None:
                        self.provider_store.record_live_network_attempt(authorization_id=network_authorization_id, run_id=run_id, project_id=str(authority["project_id"]), outcome="unknown", actor=self.worker_actor, provider_attempt_id=provider_permit.attempt_id, claim_id=provider_permit.claim_id, fencing_token=fencing_token, details={"exception_type": type(exc).__name__})
                except Exception as cleanup_exc:
                    cleanup_errors.append("post_send:" + type(cleanup_exc).__name__)
            elif not send_known:
                pre_send_code = re.sub(r"[^A-Za-z0-9_]", "_", type(exc).__name__)[:128] or "NATIVE_PRE_SEND_FAILURE"
                try:
                    runner_closure = RunnerPersistence(self.repository).abort_pre_send(
                        run_id=run_id,
                        actor=self.worker_actor,
                        fencing_token=fencing_token,
                        failure_stage="mr4b1b_v12r1_native_pre_send",
                        error_code=pre_send_code,
                        logical_call_id=None if built is None else built.intent.logical_call_id,
                    )
                except Exception as closure_exc:
                    cleanup_errors.append("runner_abort:" + type(closure_exc).__name__)
                cleanup_errors.extend(self._close_pre_send_permissions(grant=grant, provider_permit=provider_permit, network_authorization_id=network_authorization_id, error_code=pre_send_code, fencing_token=fencing_token))
            terminal_state = "unknown_after_send" if send_known else "known_pre_send_failure"
            terminal = self._record_native_terminal(authority_id=authority_id, state=terminal_state, payload={"exception_type": type(exc).__name__, "send_boundary_reached": send_known, "source_permit_id": source_permit_id, "network_authorization_id": network_authorization_id, "runner_closure": runner_closure, "cleanup_errors": cleanup_errors, "retry_allowed": False}, run_id=run_id, claim_id=claim_id, fencing_token=fencing_token)
            return {"ok": False, "outcome": "UNKNOWN_AFTER_SEND" if send_known else "KNOWN_PRE_SEND_FAILURE", "authority_id": authority_id, "error_code": type(exc).__name__, "runner": runner_closure, "terminal": terminal, "retry_allowed": False, "network": {"dns": 0, "credential_reads": int(getattr(self.transport, "credential_read_count", 0)), "tcp": 0, "tls": 0, "https": 0, "provider_calls": int(getattr(self.transport, "network_call_count", 0))}}

    def execute_from_preview(self, *, preview_id: str, allow_execute: bool = False) -> dict[str, Any]:
        if not allow_execute:
            raise NativePreparationBridgeError("native execute requires an explicit execution flag")
        if not is_injected_hermetic_transport(self.transport):
            raise NativePreparationBridgeError("native Provider execution requires an injected hermetic transport")
        prepared = self._create_jit(preview_id=preview_id)
        return self.execute(authority_id=str(prepared["authority_id"]), allow_execute=allow_execute)


__all__ = ["NativePreparationBridgeError", "NativePreparationStore", "PreparationCanaryExecutor"]
