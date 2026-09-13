"""Server-owned Native JIT to production live-provider bridge.

This module is intentionally separate from :mod:`preparation_execution`.
The latter remains hermetic-only.  The live bridge accepts identifiers only,
rebuilds the request from the durable Preparation chain, and obtains every
network capability just-in-time after consuming a server-owned execution
authorization.  Tests may use :class:`FixtureLiveProviderTransportFactory`,
but the production entry point never accepts a client transport or fixture
payload.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from ..policy import Actor
from .contract import canonical_json, canonical_sha256, make_stable_id
from .persistence.db import MaxControlError, control_transaction
from .persistence.repository import MaxControlRepository, _parse_timestamp, _timestamp, _utc_now
from .persistence.runner import RunnerPersistence
from .preparation_execution import NativePreparationBridgeError, PreparationCanaryExecutor
from .preparation_handoff import PreparationHandoffError, PreparationHandoffStore
from .provider.contract import ProviderProfile
from .provider.live import (
    InjectedDNSResolver,
    InjectedHTTPSConnector,
    LiveProviderTransportFactory,
    OpenAICompatibleHTTPSLiveTransport,
    ProviderTransportError,
    StdlibDNSResolver,
    StdlibHTTPSConnector,
    credential_reference_hash,
    endpoint_hashes,
    is_trusted_live_transport_factory,
    network_policy_hash,
)
from .provider.live_adapter import LiveOpenAICompatibleAdapter
from .provider.store import ProviderStore
from .provider.usage import ProviderCallRecord, ProviderUsageAttestation, ProviderUsageAuthority
from .request_builder import BuiltServerRequest, ServerOwnedRequestBuilder, ServerRequestBuildError


class NativeLiveCanaryError(MaxControlError):
    """A fail-closed error in the Native live bridge."""


def _loads(value: Any, name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NativeLiveCanaryError(f"{name} is invalid") from exc
    if not isinstance(parsed, dict):
        raise NativeLiveCanaryError(f"{name} is invalid")
    return parsed


def _hash64(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise NativeLiveCanaryError(f"{name} is not a SHA-256 hash")
    return value.lower()


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or "\r" in value or "\n" in value:
        raise NativeLiveCanaryError(f"{name} is invalid")
    lowered = value.casefold()
    if any(fragment in lowered for fragment in ("api_key", "apikey", "cookie", "password", "secret", "access_token", "refresh_token", "private_key")):
        raise NativeLiveCanaryError(f"{name} contains forbidden secret material")
    return value


def _bounded_payload(value: Mapping[str, Any], name: str = "payload") -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise NativeLiveCanaryError(f"{name} must be an object")
    forbidden = {"prompt", "source_text", "full_text", "raw_response", "response_body", "api_key", "authorization", "secret", "password", "credential"}

    def walk(item: Any, depth: int = 0) -> None:
        if depth > 12:
            raise NativeLiveCanaryError(f"{name} is too deeply nested")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if str(key).casefold() in forbidden or any(fragment in str(key).casefold() for fragment in ("prompt", "source_text", "raw_response", "api_key", "secret", "password")):
                    raise NativeLiveCanaryError(f"{name} contains forbidden material")
                walk(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str) and len(item) > 4096:
            raise NativeLiveCanaryError(f"{name} contains an oversized value")

    walk(value)
    encoded = canonical_json(value)
    if len(encoded.encode("utf-8")) > 50_000:
        raise NativeLiveCanaryError(f"{name} exceeds its bounded size")
    return dict(value)


def _execution_preview_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    """Hash only immutable preview identity; exclude derived self-references."""

    result = dict(value)
    result.pop("execution_preview_id", None)
    result.pop("execution_preview_hash", None)
    result.pop("execution_phrase_hash", None)
    return result


def _execution_preview_hash(value: Mapping[str, Any]) -> str:
    return canonical_sha256(_execution_preview_basis(value))


def _expiry(value: str, *, now: Any) -> None:
    parsed = _parse_timestamp(value)
    if parsed is None or parsed <= now:
        raise NativeLiveCanaryError("server-owned live execution authority is expired")


class NativeLiveExecutionStore:
    """Persistence for the second, send-specific human authorization."""

    execution_phrase_prefix = "EXECUTE MR-4B1 CANARY "

    def __init__(self, repository: MaxControlRepository, *, expected_release_identity: Mapping[str, Any] | None = None) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("NativeLiveExecutionStore requires MaxControlRepository")
        self.repository = repository
        self.expected_release_identity = None if expected_release_identity is None else dict(expected_release_identity)

    @staticmethod
    def _actor(actor: Actor) -> None:
        if not isinstance(actor, Actor) or not actor.is_admin:
            raise NativeLiveCanaryError("Native live authorization requires an admin actor")

    @staticmethod
    def _worker(actor: Actor) -> None:
        if not isinstance(actor, Actor) or actor.is_admin or actor.actor_kind == "model" or actor.role == "model":
            raise NativeLiveCanaryError("Native live execution requires a non-admin server worker actor")

    def _approval(self, connection: sqlite3.Connection, approval_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM max_live_canary_native_approvals_v2 WHERE approval_id=?",
            (approval_id,),
        ).fetchone()
        if row is None:
            raise NativeLiveCanaryError("server-owned Human Live Approval was not found")
        if _parse_timestamp(row["expires_at"]) is None or _parse_timestamp(row["expires_at"]) <= _utc_now(self.repository.clock):
            raise NativeLiveCanaryError("Human Live Approval is expired")
        consumed = connection.execute(
            "SELECT 1 FROM max_live_canary_native_approval_v2_consumptions WHERE approval_id=?",
            (approval_id,),
        ).fetchone()
        if consumed is not None:
            raise NativeLiveCanaryError("Human Live Approval has already been consumed")
        try:
            approval_value = _loads(row["approval_json"], "Human Live Approval")
        except NativeLiveCanaryError:
            raise
        if canonical_sha256(approval_value) != row["approval_hash"]:
            raise NativeLiveCanaryError("Human Live Approval hash is invalid")
        return row

    def _approval_preview(self, connection: sqlite3.Connection, approval: sqlite3.Row) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM max_live_canary_approval_previews WHERE approval_preview_id=?",
            (approval["approval_preview_id"],),
        ).fetchone()
        if row is None:
            raise NativeLiveCanaryError("Live Approval Preview was not found")
        if row["state"] != "AWAITING_HUMAN_APPROVAL":
            raise NativeLiveCanaryError("Live Approval Preview is not awaiting execution authorization")
        preview_value = _loads(row["preview_json"], "Live Approval Preview")
        preview_basis = {key: value for key, value in preview_value.items() if key != "confirmation_phrase_hash"}
        if canonical_sha256(preview_basis) != row["approval_preview_hash"]:
            raise NativeLiveCanaryError("Live Approval Preview hash is invalid")
        if row["approval_preview_id"] != approval["approval_preview_id"]:
            raise NativeLiveCanaryError("Live Approval Preview binding drifted")
        return row

    def _preview_binding(self, connection: sqlite3.Connection, approval: sqlite3.Row, approval_preview: sqlite3.Row) -> dict[str, Any]:
        preview_value = _loads(approval_preview["preview_json"], "Live Approval Preview")
        preview_basis = {key: value for key, value in preview_value.items() if key != "confirmation_phrase_hash"}
        if canonical_sha256(preview_basis) != approval_preview["approval_preview_hash"]:
            raise NativeLiveCanaryError("Live Approval Preview hash is invalid")
        snapshot = connection.execute(
            "SELECT * FROM max_live_canary_preparation_snapshots WHERE snapshot_id=?",
            (approval["snapshot_id"],),
        ).fetchone()
        if snapshot is None:
            raise NativeLiveCanaryError("Preparation Snapshot is missing")
        snapshot_state = connection.execute(
            "SELECT current_hash AS state_hash,current_event_sequence AS state_version FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?",
            (approval["snapshot_id"],),
        ).fetchone()
        if snapshot_state is None:
            raise NativeLiveCanaryError("Preparation Snapshot current projection is missing")
        source_tree_hash = _hash64(snapshot["source_tree_sha256"], "source tree hash")
        wheel_hash = _hash64(snapshot["candidate_wheel_sha256"], "wheel hash")
        caps = {
            "human_cost_ceiling": int(preview_value.get("human_cost_ceiling", approval["effective_cost_cap"])),
            "profile_worst_case_cost": int(preview_value.get("profile_cost_ceiling", approval["effective_cost_cap"])),
            "effective_cost_cap": int(preview_value.get("effective_cost_cap", approval["effective_cost_cap"])),
            "max_provider_calls": int(preview_value.get("max_provider_calls", approval["max_provider_calls"])),
            "max_input_tokens": int(preview_value.get("max_input_tokens", 0)),
            "max_output_tokens": int(preview_value.get("max_output_tokens", 0)),
            "max_cache_read_tokens": int(preview_value.get("max_cache_read_tokens", 0)),
            "max_reasoning_tokens": int(preview_value.get("max_reasoning_tokens", 0)),
        }
        if caps["max_provider_calls"] != 1 or any(value < 0 for value in caps.values()):
            raise NativeLiveCanaryError("Live Approval Preview caps are invalid")
        binding = {
            "schema": "research-kb/mr4b1b-v16r3-native-live-execution-preview/v1",
            "approval_id": approval["approval_id"],
            "approval_hash": approval["approval_hash"],
            "approval_preview_id": approval_preview["approval_preview_id"],
            "approval_preview_hash": approval_preview["approval_preview_hash"],
            "project_id": approval["project_id"],
            "run_id": approval["run_id"],
            "snapshot_id": approval["snapshot_id"],
            "snapshot_hash": approval["snapshot_hash"],
            "preparation_preview_id": approval["preparation_preview_id"],
            "preparation_preview_hash": approval["preparation_preview_hash"],
            "handoff_id": approval["handoff_id"],
            "handoff_hash": approval["handoff_hash"],
            "request_manifest_hash": approval_preview["request_manifest_hash"],
            "dns_attempt_id": approval_preview["dns_attempt_id"],
            "dns_receipt_id": approval["dns_receipt_id"],
            "dns_receipt_hash": approval["dns_receipt_hash"],
            "bounded_dns_result_hash": approval_preview["bounded_dns_result_hash"],
            "provider_profile_hash": approval["provider_profile_hash"],
            "model_identity": approval["model_identity"],
            "pricing_hash": approval["pricing_hash"],
            "network_policy_hash": approval["network_policy_hash"],
            "source_policy_hash": approval["source_policy_hash"],
            "endpoint_origin_hash": approval_preview["endpoint_origin_hash"],
            "credential_reference_hash": approval["credential_reference_hash"],
            "release_identity_hash": approval["release_identity_hash"],
            "source_tree_hash": source_tree_hash,
            "wheel_hash": wheel_hash,
            "budget_hash": approval["budget_hash"],
            "current_state_hash": approval_preview["snapshot_state_hash"],
            "current_state_version": int(snapshot_state["state_version"]),
            **caps,
        }
        if self.expected_release_identity is not None:
            expected_hash = canonical_sha256(self.expected_release_identity)
            if expected_hash != binding["release_identity_hash"]:
                raise NativeLiveCanaryError("release identity is not the current server release")
        return binding

    def _check_dns(self, connection: sqlite3.Connection, binding: Mapping[str, Any]) -> None:
        receipt = connection.execute(
            "SELECT r.status,r.receipt_hash,r.bounded_result_hash,r.snapshot_hash,r.preview_hash,r.handoff_hash,a.release_identity_hash,r.provider_calls,r.credential_reads,r.tcp_connections,r.tls_https_calls,r.cost_units FROM max_live_canary_dns_attempt_receipts r JOIN max_live_canary_dns_attempts a ON a.attempt_id=r.attempt_id WHERE r.receipt_id=?",
            (binding["dns_receipt_id"],),
        ).fetchone()
        if receipt is None or receipt["status"] != "passed":
            raise NativeLiveCanaryError("a passed durable DNS receipt is required")
        if any(receipt[key] != 0 for key in ("provider_calls", "credential_reads", "tcp_connections", "tls_https_calls", "cost_units")):
            raise NativeLiveCanaryError("DNS receipt contains non-zero external-action counters")
        if (
            receipt["receipt_hash"] != binding["dns_receipt_hash"]
            or receipt["bounded_result_hash"] != binding["bounded_dns_result_hash"]
            or receipt["snapshot_hash"] != binding["snapshot_hash"]
            or receipt["preview_hash"] != binding["preparation_preview_hash"]
            or receipt["handoff_hash"] != binding["handoff_hash"]
            or receipt["release_identity_hash"] != binding["release_identity_hash"]
        ):
            raise NativeLiveCanaryError("DNS receipt binding drifted")

    def _read_preview(self, execution_preview_id: str) -> tuple[sqlite3.Row, dict[str, Any]]:
        connection = self.repository._connect(read_only=True)
        try:
            row = connection.execute(
                "SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?",
                (execution_preview_id,),
            ).fetchone()
            if row is None:
                raise NativeLiveCanaryError("Live Execution Preview was not found")
            value = _loads(row["execution_preview_json"], "Live Execution Preview")
            if _execution_preview_hash(value) != row["execution_preview_hash"]:
                raise NativeLiveCanaryError("Live Execution Preview hash is invalid")
            return row, value
        finally:
            connection.close()

    @staticmethod
    def _preview_lineage(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "generation": int(row["generation"] or 0),
            "supersedes_execution_preview_id": row["supersedes_execution_preview_id"],
            "supersedes_execution_preview_hash": row["supersedes_execution_preview_hash"],
            "renewal_reason": row["renewal_reason"],
        }

    @staticmethod
    def _preview_binding_fields() -> tuple[str, ...]:
        return (
            "approval_hash", "approval_preview_id", "approval_preview_hash", "project_id", "run_id",
            "snapshot_id", "snapshot_hash", "preparation_preview_id", "preparation_preview_hash",
            "handoff_id", "handoff_hash", "request_manifest_hash", "dns_attempt_id", "dns_receipt_id",
            "dns_receipt_hash", "bounded_dns_result_hash", "provider_profile_hash", "model_identity",
            "pricing_hash", "network_policy_hash", "source_policy_hash", "endpoint_origin_hash",
            "credential_reference_hash", "release_identity_hash", "source_tree_hash", "wheel_hash",
            "budget_hash", "current_state_hash", "current_state_version", "human_cost_ceiling",
            "profile_worst_case_cost", "effective_cost_cap", "max_provider_calls", "max_input_tokens",
            "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens",
        )

    def _assert_preview_binding_stable(self, row: sqlite3.Row, binding: Mapping[str, Any]) -> None:
        for field in self._preview_binding_fields():
            if row[field] != binding[field]:
                raise NativeLiveCanaryError(f"execution window binding drifted: {field}")

    @staticmethod
    def _current_preview(connection: sqlite3.Connection, approval_id: str) -> sqlite3.Row:
        current = connection.execute(
            "SELECT c.*,p.* FROM max_live_canary_native_execution_preview_current c JOIN max_live_canary_native_execution_previews p ON p.execution_preview_id=c.execution_preview_id WHERE c.approval_id=?",
            (approval_id,),
        ).fetchone()
        if current is None:
            raise NativeLiveCanaryError("execution window current projection is missing")
        return current

    @staticmethod
    def _preview_is_current(connection: sqlite3.Connection, row: sqlite3.Row) -> bool:
        current = connection.execute(
            "SELECT execution_preview_id,execution_preview_hash FROM max_live_canary_native_execution_preview_current WHERE approval_id=?",
            (row["approval_id"],),
        ).fetchone()
        return current is not None and current["execution_preview_id"] == row["execution_preview_id"] and current["execution_preview_hash"] == row["execution_preview_hash"]

    def _renewal_block_reason(self, connection: sqlite3.Connection, *, approval_id: str, run_id: str) -> str | None:
        if connection.execute(
            "SELECT 1 FROM max_live_canary_native_approval_v2_consumptions WHERE approval_id=? LIMIT 1",
            (approval_id,),
        ).fetchone() is not None:
            return "human_approval_consumed"
        if connection.execute(
            "SELECT 1 FROM max_live_canary_native_execution_authorization_consumptions WHERE approval_id=? LIMIT 1",
            (approval_id,),
        ).fetchone() is not None:
            return "execution_authorization_consumed"
        checks = (
            ("jit_authority_exists", "SELECT 1 FROM max_live_canary_native_live_jit_authorities WHERE approval_id=? LIMIT 1", (approval_id,)),
            ("active_lease_exists", "SELECT 1 FROM max_leases WHERE run_id=? AND released_at IS NULL LIMIT 1", (run_id,)),
            ("active_invocation_claim_exists", "SELECT 1 FROM max_runner_invocation_claims c WHERE c.run_id=? AND c.status='active' AND NOT EXISTS (SELECT 1 FROM max_runner_invocation_claims r WHERE r.run_id=c.run_id AND r.status='released' AND r.claim_id=c.claim_id || ':released') LIMIT 1", (run_id,)),
            ("source_permit_exists", "SELECT 1 FROM max_live_canary_native_source_permits WHERE run_id=? LIMIT 1", (run_id,)),
            ("live_grant_exists", "SELECT 1 FROM max_live_execution_grants WHERE run_id=? LIMIT 1", (run_id,)),
            ("network_authorization_exists", "SELECT 1 FROM max_live_network_authorizations WHERE run_id=? LIMIT 1", (run_id,)),
            ("dispatch_attempt_exists", "SELECT 1 FROM max_provider_dispatch_attempts WHERE run_id=? LIMIT 1", (run_id,)),
            ("provider_call_exists", "SELECT 1 FROM max_provider_call_records WHERE run_id=? LIMIT 1", (run_id,)),
            ("provider_usage_exists", "SELECT 1 FROM max_provider_usage_attestations WHERE run_id=? LIMIT 1", (run_id,)),
        )
        for reason, sql, args in checks:
            if connection.execute(sql, args).fetchone() is not None:
                return reason
        return None

    @staticmethod
    def _append_preview_event(
        connection: sqlite3.Connection,
        *,
        value: Mapping[str, Any],
        event_type: str,
        actor: Actor,
        now: str,
    ) -> dict[str, Any]:
        prior = connection.execute(
            "SELECT sequence_no,event_hash FROM max_live_canary_native_execution_preview_events WHERE approval_id=? ORDER BY sequence_no DESC LIMIT 1",
            (value["approval_id"],),
        ).fetchone()
        sequence = 1 if prior is None else int(prior["sequence_no"]) + 1
        payload = {
            "execution_preview_id": value["execution_preview_id"],
            "approval_id": value["approval_id"],
            "run_id": value["run_id"],
            "execution_preview_hash": value["execution_preview_hash"],
            "generation": int(value.get("generation", 0)),
            "supersedes_execution_preview_id": value.get("supersedes_execution_preview_id"),
            "supersedes_execution_preview_hash": value.get("supersedes_execution_preview_hash"),
            "renewal_reason": value.get("renewal_reason"),
        }
        payload_hash = canonical_sha256(payload)
        identity = {
            "execution_preview_id": value["execution_preview_id"],
            "approval_id": value["approval_id"],
            "run_id": value["run_id"],
            "sequence_no": sequence,
            "event_type": event_type,
            "payload_hash": payload_hash,
            "previous_event_hash": None if prior is None else prior["event_hash"],
            "created_at": now,
        }
        event_hash = canonical_sha256(identity)
        event_id = make_stable_id("native_execution_preview_event", event_hash[:64])
        connection.execute(
            "INSERT INTO max_live_canary_native_execution_preview_events(event_id,execution_preview_id,approval_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, value["execution_preview_id"], value["approval_id"], value["run_id"], sequence, event_type, canonical_json(payload), payload_hash, identity["previous_event_hash"], event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id),
        )
        return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "event_type": event_type}

    def _preview_result(
        self,
        row: sqlite3.Row,
        *,
        idempotent: bool,
        now_dt: Any,
        renewal_block_reason: str | None = None,
    ) -> dict[str, Any]:
        lineage = self._preview_lineage(row)
        expires = _parse_timestamp(row["expires_at"])
        current = expires is not None and expires > now_dt
        return {
            "ok": True,
            "idempotent": idempotent,
            "execution_preview_id": row["execution_preview_id"],
            "execution_preview_hash": row["execution_preview_hash"],
            "expires_at": row["expires_at"],
            "state": row["state"],
            **lineage,
            "current": True,
            "renewable": not current and renewal_block_reason is None,
            "renewal_block_reason": renewal_block_reason,
            **({"confirmation_phrase": self.execution_phrase_prefix + row["execution_preview_hash"]} if not idempotent else {}),
        }

    def create_execution_preview(self, *, approval_id: str, actor: Actor, ttl_seconds: int = 900) -> dict[str, Any]:
        self._actor(actor)
        _identifier(approval_id, "approval_id")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 3600:
            raise NativeLiveCanaryError("execution Preview TTL is outside the supported range")
        now_dt = _utc_now(self.repository.clock)
        now = _timestamp(self.repository.clock)
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                approval = self._approval(connection, approval_id)
                approval_preview = self._approval_preview(connection, approval)
                binding = self._preview_binding(connection, approval, approval_preview)
                self._check_dns(connection, binding)
                try:
                    policy_binding = ProviderStore.validate_network_policy_binding(
                        connection,
                        run_id=str(binding["run_id"]),
                        expected_release_identity_hash=str(binding["release_identity_hash"]),
                    )
                except MaxControlError as exc:
                    raise NativeLiveCanaryError(
                        "Execution Preview requires a valid server-owned network policy binding"
                    ) from exc
                if (
                    policy_binding["network_policy_hash"] != binding["network_policy_hash"]
                    or policy_binding["endpoint_origin_hash"] != binding["endpoint_origin_hash"]
                    or policy_binding["credential_reference_hash"] != binding["credential_reference_hash"]
                ):
                    raise NativeLiveCanaryError("Execution Preview network policy binding drifted")
                current = connection.execute(
                    "SELECT execution_preview_id FROM max_live_canary_native_execution_preview_current WHERE approval_id=?",
                    (approval_id,),
                ).fetchone()
                if current is None:
                    prior = None
                else:
                    prior = connection.execute(
                        "SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?",
                        (current["execution_preview_id"],),
                    ).fetchone()
                    if prior is None or not self._preview_is_current(connection, prior):
                        raise NativeLiveCanaryError("execution window current projection is invalid")
                if prior is not None:
                    self._assert_preview_binding_stable(prior, binding)
                    prior_expiry = _parse_timestamp(prior["expires_at"])
                    if prior_expiry is not None and prior_expiry > now_dt:
                        return self._preview_result(prior, idempotent=True, now_dt=now_dt)
                    block_reason = self._renewal_block_reason(
                        connection, approval_id=approval_id, run_id=str(prior["run_id"])
                    )
                    if block_reason is not None:
                        raise NativeLiveCanaryError("execution window renewal blocked: " + block_reason)
                approval_expiry = _parse_timestamp(approval["expires_at"])
                expiry = min(approval_expiry, now_dt + timedelta(seconds=ttl_seconds)) if approval_expiry is not None else now_dt
                if expiry <= now_dt:
                    raise NativeLiveCanaryError("Human Live Approval is expired")
                generation = 0 if prior is None else int(prior["generation"]) + 1
                identity = {
                    **binding,
                    "created_at": now,
                    "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z",
                    "state": "AWAITING_EXPLICIT_EXECUTION_AUTHORIZATION",
                    "generation": generation,
                    "supersedes_execution_preview_id": None if prior is None else prior["execution_preview_id"],
                    "supersedes_execution_preview_hash": None if prior is None else prior["execution_preview_hash"],
                    "renewal_reason": None if prior is None else "expired_before_execution",
                }
                execution_preview_hash = _execution_preview_hash(identity)
                execution_preview_id = make_stable_id("native_live_execution_preview", execution_preview_hash[:64])
                value = {
                    **identity,
                    "execution_preview_id": execution_preview_id,
                    "execution_preview_hash": execution_preview_hash,
                    "execution_phrase_hash": canonical_sha256(self.execution_phrase_prefix + execution_preview_hash),
                }
                insert_values = (
                    execution_preview_id, approval_id, binding["approval_hash"], binding["approval_preview_id"], binding["approval_preview_hash"], binding["project_id"], binding["run_id"], binding["snapshot_id"], binding["snapshot_hash"], binding["preparation_preview_id"], binding["preparation_preview_hash"], binding["handoff_id"], binding["handoff_hash"], binding["request_manifest_hash"], binding["dns_attempt_id"], binding["dns_receipt_id"], binding["dns_receipt_hash"], binding["bounded_dns_result_hash"], binding["provider_profile_hash"], binding["model_identity"], binding["pricing_hash"], binding["network_policy_hash"], binding["source_policy_hash"], binding["endpoint_origin_hash"], binding["credential_reference_hash"], binding["release_identity_hash"], binding["source_tree_hash"], binding["wheel_hash"], binding["budget_hash"], binding["current_state_hash"], binding["current_state_version"], binding["human_cost_ceiling"], binding["profile_worst_case_cost"], binding["effective_cost_cap"], binding["max_provider_calls"], binding["max_input_tokens"], binding["max_output_tokens"], binding["max_cache_read_tokens"], binding["max_reasoning_tokens"], value["state"], value["execution_phrase_hash"], canonical_json(value), execution_preview_hash, now, value["expires_at"], actor.actor_id, actor.actor_kind, actor.session_id, generation, identity["supersedes_execution_preview_id"], identity["supersedes_execution_preview_hash"], identity["renewal_reason"],
                )
                connection.execute(
                    "INSERT INTO max_live_canary_native_execution_previews(execution_preview_id,approval_id,approval_hash,approval_preview_id,approval_preview_hash,project_id,run_id,snapshot_id,snapshot_hash,preparation_preview_id,preparation_preview_hash,handoff_id,handoff_hash,request_manifest_hash,dns_attempt_id,dns_receipt_id,dns_receipt_hash,bounded_dns_result_hash,provider_profile_hash,model_identity,pricing_hash,network_policy_hash,source_policy_hash,endpoint_origin_hash,credential_reference_hash,release_identity_hash,source_tree_hash,wheel_hash,budget_hash,current_state_hash,current_state_version,human_cost_ceiling,profile_worst_case_cost,effective_cost_cap,max_provider_calls,max_input_tokens,max_output_tokens,max_cache_read_tokens,max_reasoning_tokens,state,execution_phrase_hash,execution_preview_json,execution_preview_hash,created_at,expires_at,actor_id,actor_kind,actor_session,generation,supersedes_execution_preview_id,supersedes_execution_preview_hash,renewal_reason) VALUES (" + ",".join("?" for _ in insert_values) + ")",
                    insert_values,
                )
                current_value = {
                    "approval_id": approval_id,
                    "execution_preview_id": execution_preview_id,
                    "execution_preview_hash": execution_preview_hash,
                    "generation": generation,
                    "state": value["state"],
                    "expires_at": value["expires_at"],
                    "updated_at": now,
                }
                if prior is None:
                    connection.execute(
                        "INSERT INTO max_live_canary_native_execution_preview_current(approval_id,execution_preview_id,execution_preview_hash,generation,state,expires_at,current_json,current_hash,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                        (approval_id, execution_preview_id, execution_preview_hash, generation, value["state"], value["expires_at"], canonical_json(current_value), canonical_sha256(current_value), now),
                    )
                    event_type = "created"
                else:
                    updated = connection.execute(
                        "UPDATE max_live_canary_native_execution_preview_current SET execution_preview_id=?,execution_preview_hash=?,generation=?,state=?,expires_at=?,current_json=?,current_hash=?,updated_at=? WHERE approval_id=? AND execution_preview_id=? AND generation=?",
                        (execution_preview_id, execution_preview_hash, generation, value["state"], value["expires_at"], canonical_json(current_value), canonical_sha256(current_value), now, approval_id, prior["execution_preview_id"], int(prior["generation"])),
                    )
                    if updated.rowcount != 1:
                        raise NativeLiveCanaryError("execution window current projection changed concurrently")
                    event_type = "renewed"
                self._append_preview_event(connection, value=value, event_type=event_type, actor=actor, now=now)
                created_row = connection.execute(
                    "SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?",
                    (execution_preview_id,),
                ).fetchone()
                return self._preview_result(created_row, idempotent=False, now_dt=now_dt)
        except sqlite3.IntegrityError as exc:
            raise NativeLiveCanaryError("Live Execution Preview conflicted with an immutable Approval") from exc
        finally:
            connection.close()

    def authorize_execution(self, *, execution_preview_id: str, confirmation_phrase: str, actor: Actor) -> dict[str, Any]:
        self._actor(actor)
        _identifier(execution_preview_id, "execution_preview_id")
        if not isinstance(confirmation_phrase, str) or "\r" in confirmation_phrase or "\n" in confirmation_phrase:
            raise NativeLiveCanaryError("execution confirmation phrase is invalid")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                preview_row, value = self._read_preview_in_connection(connection, execution_preview_id)
                self._ensure_preview_current(connection, preview_row)
                expected = self.execution_phrase_prefix + preview_row["execution_preview_hash"]
                if confirmation_phrase != expected:
                    raise NativeLiveCanaryError("execution confirmation phrase is not the exact server-owned phrase")
                _expiry(preview_row["expires_at"], now=_utc_now(self.repository.clock))
                approval = self._approval(connection, preview_row["approval_id"])
                if approval["approval_hash"] != preview_row["approval_hash"]:
                    raise NativeLiveCanaryError("Human Approval binding drifted")
                existing = connection.execute(
                    "SELECT * FROM max_live_canary_native_execution_authorizations WHERE execution_preview_id=?",
                    (execution_preview_id,),
                ).fetchone()
                if existing is not None:
                    return {"ok": True, "idempotent": True, "execution_authorization_id": existing["execution_authorization_id"], "execution_authorization_hash": existing["authorization_hash"], "expires_at": existing["expires_at"], "state": "READY_UNCONSUMED"}
                auth_value = {"schema": "research-kb/mr4b1b-v16r3-native-live-execution-authorization/v1", "execution_preview_id": execution_preview_id, "execution_preview_hash": preview_row["execution_preview_hash"], "approval_id": preview_row["approval_id"], "approval_hash": preview_row["approval_hash"], "project_id": preview_row["project_id"], "run_id": preview_row["run_id"], "current_state_hash": preview_row["current_state_hash"], "current_state_version": int(preview_row["current_state_version"]), "max_provider_calls": int(preview_row["max_provider_calls"]), "effective_cost_cap": int(preview_row["effective_cost_cap"]), "created_at": _timestamp(self.repository.clock), "expires_at": preview_row["expires_at"]}
                auth_hash = canonical_sha256(auth_value)
                auth_id = make_stable_id("native_live_execution_authorization", auth_hash[:64])
                connection.execute(
                    "INSERT INTO max_live_canary_native_execution_authorizations(execution_authorization_id,execution_preview_id,execution_preview_hash,approval_id,approval_hash,project_id,run_id,current_state_hash,current_state_version,max_provider_calls,effective_cost_cap,authorization_json,authorization_hash,created_at,expires_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (auth_id, execution_preview_id, preview_row["execution_preview_hash"], preview_row["approval_id"], preview_row["approval_hash"], preview_row["project_id"], preview_row["run_id"], preview_row["current_state_hash"], int(preview_row["current_state_version"]), int(preview_row["max_provider_calls"]), int(preview_row["effective_cost_cap"]), canonical_json(auth_value), auth_hash, auth_value["created_at"], auth_value["expires_at"], actor.actor_id, actor.actor_kind, actor.session_id),
                )
                return {"ok": True, "idempotent": False, "execution_authorization_id": auth_id, "execution_authorization_hash": auth_hash, "expires_at": auth_value["expires_at"], "state": "READY_UNCONSUMED"}
        except sqlite3.IntegrityError as exc:
            recovery = self.repository._connect(read_only=True)
            try:
                existing = recovery.execute(
                    "SELECT execution_authorization_id,authorization_hash,expires_at FROM max_live_canary_native_execution_authorizations WHERE execution_preview_id=?",
                    (execution_preview_id,),
                ).fetchone()
                if existing is not None:
                    return {"ok": True, "idempotent": True, "execution_authorization_id": existing["execution_authorization_id"], "execution_authorization_hash": existing["authorization_hash"], "expires_at": existing["expires_at"], "state": "READY_UNCONSUMED"}
            finally:
                recovery.close()
            raise NativeLiveCanaryError("Execution Authorization conflicted with an immutable Preview") from exc
        finally:
            connection.close()

    def _read_preview_in_connection(self, connection: sqlite3.Connection, execution_preview_id: str) -> tuple[sqlite3.Row, dict[str, Any]]:
        row = connection.execute("SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?", (execution_preview_id,)).fetchone()
        if row is None:
            raise NativeLiveCanaryError("Live Execution Preview was not found")
        value = _loads(row["execution_preview_json"], "Live Execution Preview")
        if _execution_preview_hash(value) != row["execution_preview_hash"]:
            raise NativeLiveCanaryError("Live Execution Preview hash is invalid")
        return row, value

    def _ensure_preview_current(self, connection: sqlite3.Connection, row: sqlite3.Row) -> None:
        if not self._preview_is_current(connection, row):
            raise NativeLiveCanaryError("Live Execution Preview has been superseded")

    def preflight_execution(self, *, execution_authorization_id: str, execution_authorization_hash: str) -> dict[str, Any]:
        _identifier(execution_authorization_id, "execution_authorization_id")
        _hash64(execution_authorization_hash, "execution_authorization_hash")
        connection = self.repository._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_live_canary_native_execution_authorizations WHERE execution_authorization_id=?", (execution_authorization_id,)).fetchone()
            if row is None or row["authorization_hash"] != execution_authorization_hash:
                raise NativeLiveCanaryError("Execution Authorization hash is invalid")
            _expiry(row["expires_at"], now=_utc_now(self.repository.clock))
            if connection.execute("SELECT 1 FROM max_live_canary_native_execution_authorization_consumptions WHERE execution_authorization_id=?", (execution_authorization_id,)).fetchone() is not None:
                raise NativeLiveCanaryError("Execution Authorization has already been consumed")
            approval = self._approval(connection, row["approval_id"])
            if approval["approval_hash"] != row["approval_hash"]:
                raise NativeLiveCanaryError("Human Approval binding drifted")
            preview = connection.execute("SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?", (row["execution_preview_id"],)).fetchone()
            if preview is None or preview["execution_preview_hash"] != row["execution_preview_hash"]:
                raise NativeLiveCanaryError("Live Execution Preview binding drifted")
            self._ensure_preview_current(connection, preview)
            preview_value = _loads(preview["execution_preview_json"], "Live Execution Preview")
            self._check_dns(connection, preview_value)
            return {"ok": True, "execution_authorization_id": execution_authorization_id, "execution_authorization_hash": execution_authorization_hash, "approval_id": row["approval_id"], "run_id": row["run_id"], "expires_at": row["expires_at"]}
        finally:
            connection.close()

    def consume_execution(self, *, execution_authorization_id: str, execution_authorization_hash: str, actor: Actor) -> dict[str, Any]:
        self._worker(actor)
        _identifier(execution_authorization_id, "execution_authorization_id")
        execution_authorization_hash = _hash64(execution_authorization_hash, "execution_authorization_hash")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_live_canary_native_execution_authorizations WHERE execution_authorization_id=?", (execution_authorization_id,)).fetchone()
                if row is None or row["authorization_hash"] != execution_authorization_hash:
                    raise NativeLiveCanaryError("Execution Authorization hash is invalid")
                _expiry(row["expires_at"], now=_utc_now(self.repository.clock))
                approval = self._approval(connection, row["approval_id"])
                existing = connection.execute("SELECT 1 FROM max_live_canary_native_execution_authorization_consumptions WHERE execution_authorization_id=?", (execution_authorization_id,)).fetchone()
                if existing is not None:
                    raise NativeLiveCanaryError("Execution Authorization has already been consumed")
                preview = connection.execute("SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?", (row["execution_preview_id"],)).fetchone()
                if preview is None or preview["execution_preview_hash"] != row["execution_preview_hash"]:
                    raise NativeLiveCanaryError("Live Execution Preview binding drifted")
                self._ensure_preview_current(connection, preview)
                preview_value = _loads(preview["execution_preview_json"], "Live Execution Preview")
                self._check_dns(connection, preview_value)
                value = {"schema": "research-kb/mr4b1b-v16r3-native-live-execution-consumption/v1", "execution_authorization_id": execution_authorization_id, "execution_authorization_hash": execution_authorization_hash, "execution_preview_id": row["execution_preview_id"], "approval_id": row["approval_id"], "run_id": row["run_id"], "consumed_at": _timestamp(self.repository.clock), "consumer_id": actor.actor_id, "consumer_session": actor.session_id}
                consumption_hash = canonical_sha256(value)
                consumption_id = make_stable_id("native_live_execution_consumption", consumption_hash[:64])
                connection.execute("INSERT INTO max_live_canary_native_execution_authorization_consumptions(consumption_id,execution_authorization_id,execution_preview_id,approval_id,run_id,authorization_hash,consumption_json,consumption_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (consumption_id, execution_authorization_id, row["execution_preview_id"], row["approval_id"], row["run_id"], execution_authorization_hash, canonical_json(value), consumption_hash, value["consumed_at"], actor.actor_id, actor.actor_kind, actor.session_id))
                approval_consumption = {
                    "schema": "research-kb/mr4b1b-v16r3-live-approval-consumption/v1",
                    "approval_id": row["approval_id"],
                    "approval_hash": row["approval_hash"],
                    "run_id": row["run_id"],
                    "execution_authorization_id": execution_authorization_id,
                    "execution_consumption_id": consumption_id,
                    "consumed_at": value["consumed_at"],
                    "authority_kind": "native-jit-production-live",
                }
                approval_consumption_hash = canonical_sha256(approval_consumption)
                approval_consumption_id = make_stable_id("native_approval_v2_consumption", approval_consumption_hash[:64])
                connection.execute("INSERT INTO max_live_canary_native_approval_v2_consumptions(consumption_id,approval_id,approval_preview_id,run_id,approval_hash,consumption_json,consumption_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?)", (approval_consumption_id, row["approval_id"], approval["approval_preview_id"], row["run_id"], row["approval_hash"], canonical_json(approval_consumption), approval_consumption_hash, value["consumed_at"], actor.actor_id, actor.actor_kind, actor.session_id))
                return {"ok": True, "consumption_id": consumption_id, "consumption_hash": consumption_hash, "approval_consumption_id": approval_consumption_id, "approval_consumption_hash": approval_consumption_hash, **value}
        except sqlite3.IntegrityError as exc:
            raise NativeLiveCanaryError("Execution Authorization was concurrently consumed") from exc
        finally:
            connection.close()

    def execution_context(self, *, execution_authorization_id: str, execution_authorization_hash: str) -> dict[str, Any]:
        self.preflight_execution(execution_authorization_id=execution_authorization_id, execution_authorization_hash=execution_authorization_hash)
        connection = self.repository._connect(read_only=True)
        try:
            auth = connection.execute("SELECT * FROM max_live_canary_native_execution_authorizations WHERE execution_authorization_id=?", (execution_authorization_id,)).fetchone()
            preview = connection.execute("SELECT * FROM max_live_canary_native_execution_previews WHERE execution_preview_id=?", (auth["execution_preview_id"],)).fetchone()
            value = _loads(preview["execution_preview_json"], "Live Execution Preview")
            return {"authorization": dict(auth), "preview": dict(preview), "preview_value": value}
        finally:
            connection.close()

    def issue_source_permit(self, *, execution_authorization_id: str, execution_preview_id: str, run_id: str, worker: Actor, fencing_token: int, manifest: Mapping[str, Any], expires_at: str, release_identity_hash: str, source_tree_hash: str, source_policy_hash: str) -> dict[str, Any]:
        self._worker(worker)
        required = ("manifest_hash", "passage_id", "document_id", "source_version")
        if any(not isinstance(manifest.get(key), str) or not manifest[key] for key in required):
            raise NativeLiveCanaryError("source permit manifest is incomplete")
        _expiry(expires_at, now=_utc_now(self.repository.clock))
        value = {"schema": "research-kb/mr4b1b-v16r3-native-source-permit/v1", "execution_authorization_id": execution_authorization_id, "execution_preview_id": execution_preview_id, "project_id": str(manifest.get("project_id", "")), "run_id": run_id, "passage_id": manifest["passage_id"], "document_id": manifest["document_id"], "source_version": manifest["source_version"], "request_manifest_hash": manifest["manifest_hash"], "source_policy_hash": source_policy_hash, "source_tree_hash": source_tree_hash, "release_identity_hash": release_identity_hash, "worker_id": worker.actor_id, "worker_session": worker.session_id, "fencing_token": int(fencing_token), "expires_at": expires_at}
        permit_hash = canonical_sha256(value)
        permit_id = make_stable_id("native_source_permit", permit_hash[:64])
        now = _timestamp(self.repository.clock)
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                existing = connection.execute("SELECT p.source_permit_id,c.state,p.permit_hash FROM max_live_canary_native_source_permits p JOIN max_live_canary_native_source_permit_current c ON c.source_permit_id=p.source_permit_id WHERE p.execution_authorization_id=?", (execution_authorization_id,)).fetchone()
                if existing is not None:
                    return {"ok": True, "idempotent": True, "source_permit_id": existing["source_permit_id"], "permit_hash": existing["permit_hash"], "state": existing["state"]}
                connection.execute("INSERT INTO max_live_canary_native_source_permits(source_permit_id,execution_authorization_id,execution_preview_id,project_id,run_id,passage_id,document_id,source_version,request_manifest_hash,source_policy_hash,source_tree_hash,release_identity_hash,worker_id,worker_session,fencing_token,expires_at,permit_json,permit_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (permit_id, execution_authorization_id, execution_preview_id, value["project_id"], run_id, value["passage_id"], value["document_id"], value["source_version"], value["request_manifest_hash"], source_policy_hash, source_tree_hash, release_identity_hash, worker.actor_id, worker.session_id, int(fencing_token), expires_at, canonical_json(value), permit_hash, now, worker.actor_id, worker.actor_kind, worker.session_id))
                current = {"source_permit_id": permit_id, "run_id": run_id, "state": "issued", "updated_at": now}
                connection.execute("INSERT INTO max_live_canary_native_source_permit_current(source_permit_id,run_id,state,current_json,current_hash,updated_at) VALUES (?,?,?,?,?,?)", (permit_id, run_id, "issued", canonical_json(current), canonical_sha256(current), now))
                self._source_event(connection, permit_id, run_id, "issued", {"permit_hash": permit_hash, "request_manifest_hash": value["request_manifest_hash"]}, worker, now)
                return {"ok": True, "idempotent": False, "source_permit_id": permit_id, "permit_hash": permit_hash, "state": "issued"}
        finally:
            connection.close()

    def _source_event(self, connection: sqlite3.Connection, permit_id: str, run_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str) -> None:
        prior = connection.execute("SELECT sequence_no,event_hash FROM max_live_canary_native_source_permit_events WHERE source_permit_id=? ORDER BY sequence_no DESC LIMIT 1", (permit_id,)).fetchone()
        sequence = 1 if prior is None else int(prior["sequence_no"]) + 1
        payload_hash = canonical_sha256(_bounded_payload(payload, "source permit event"))
        value = {"source_permit_id": permit_id, "run_id": run_id, "sequence_no": sequence, "event_type": event_type, "payload_hash": payload_hash, "previous_event_hash": None if prior is None else prior["event_hash"], "created_at": now}
        event_hash = canonical_sha256(value)
        event_id = make_stable_id("native_source_permit_event", event_hash[:64])
        connection.execute("INSERT INTO max_live_canary_native_source_permit_events(source_permit_event_id,source_permit_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (event_id, permit_id, run_id, sequence, event_type, canonical_json(payload), payload_hash, value["previous_event_hash"], event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))

    def transition_source_permit(self, *, source_permit_id: str, state: str, actor: Actor) -> dict[str, Any]:
        self._worker(actor)
        if state not in {"consumed", "revoked", "expired"}:
            raise NativeLiveCanaryError("source permit terminal state is invalid")
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_live_canary_native_source_permits WHERE source_permit_id=?", (source_permit_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_canary_native_source_permit_current WHERE source_permit_id=?", (source_permit_id,)).fetchone()
                if row is None or current is None or current["state"] not in {"issued", state}:
                    raise NativeLiveCanaryError("source permit is missing, expired, revoked, or already consumed")
                now = _timestamp(self.repository.clock)
                value = {"source_permit_id": source_permit_id, "run_id": row["run_id"], "state": state, "updated_at": now}
                connection.execute("UPDATE max_live_canary_native_source_permit_current SET state=?,current_json=?,current_hash=?,updated_at=? WHERE source_permit_id=? AND state='issued'", (state, canonical_json(value), canonical_sha256(value), now, source_permit_id))
                self._source_event(connection, source_permit_id, row["run_id"], state, {"permit_hash": row["permit_hash"]}, actor, now)
                return {"ok": True, "source_permit_id": source_permit_id, "state": state}
        finally:
            connection.close()

    def create_jit_authority(self, *, binding: Mapping[str, Any], consumption: Mapping[str, Any], lease: Mapping[str, Any], claim: Mapping[str, Any], grant: Mapping[str, Any], grant_consumption: Mapping[str, Any], network_authorization_id: str, dispatch_permit_id: str, source_permit_id: str, actor: Actor) -> dict[str, Any]:
        self._worker(actor)
        value = {"schema": "research-kb/mr4b1b-v16r3-native-live-jit-authority/v1", "execution_authorization_id": consumption["execution_authorization_id"], "execution_consumption_id": consumption["consumption_id"], "approval_id": binding["approval_id"], "project_id": binding["project_id"], "run_id": binding["run_id"], "execution_preview_hash": binding["execution_preview_hash"], "request_manifest_hash": binding["request_manifest_hash"], "provider_profile_hash": binding["provider_profile_hash"], "model_identity": binding["model_identity"], "pricing_hash": binding["pricing_hash"], "network_policy_hash": binding["network_policy_hash"], "source_policy_hash": binding["source_policy_hash"], "endpoint_origin_hash": binding["endpoint_origin_hash"], "credential_reference_hash": binding["credential_reference_hash"], "release_identity_hash": binding["release_identity_hash"], "source_tree_hash": binding["source_tree_hash"], "wheel_hash": binding["wheel_hash"], "budget_hash": binding["budget_hash"], "lease_id": "run-lease:" + binding["run_id"], "claim_id": claim["claim_id"], "fencing_token": int(lease["fencing_token"]), "grant_id": grant["grant_id"], "grant_consumption_id": grant_consumption["consumption_id"], "network_authorization_id": network_authorization_id, "dispatch_permit_id": dispatch_permit_id, "source_permit_id": source_permit_id, "authority_expires_at": lease["expires_at"], "state": "ready"}
        authority_hash = canonical_sha256(value)
        authority_id = make_stable_id("native_live_jit_authority", authority_hash[:64])
        now = _timestamp(self.repository.clock)
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                connection.execute("INSERT INTO max_live_canary_native_live_jit_authorities(authority_id,execution_authorization_id,execution_consumption_id,approval_id,project_id,run_id,execution_preview_hash,request_manifest_hash,provider_profile_hash,model_identity,pricing_hash,network_policy_hash,source_policy_hash,endpoint_origin_hash,credential_reference_hash,release_identity_hash,source_tree_hash,wheel_hash,budget_hash,lease_id,claim_id,fencing_token,grant_id,grant_consumption_id,network_authorization_id,dispatch_permit_id,source_permit_id,authority_expires_at,state,authority_json,authority_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (authority_id, value["execution_authorization_id"], value["execution_consumption_id"], value["approval_id"], value["project_id"], value["run_id"], value["execution_preview_hash"], value["request_manifest_hash"], value["provider_profile_hash"], value["model_identity"], value["pricing_hash"], value["network_policy_hash"], value["source_policy_hash"], value["endpoint_origin_hash"], value["credential_reference_hash"], value["release_identity_hash"], value["source_tree_hash"], value["wheel_hash"], value["budget_hash"], value["lease_id"], value["claim_id"], value["fencing_token"], value["grant_id"], value["grant_consumption_id"], value["network_authorization_id"], value["dispatch_permit_id"], value["source_permit_id"], value["authority_expires_at"], "ready", canonical_json(value), authority_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                self.append_jit_event(connection, authority_id=authority_id, run_id=value["run_id"], state="ready", payload={"authority_hash": authority_hash}, actor=actor, now=now)
        finally:
            connection.close()
        return {"authority_id": authority_id, "authority_hash": authority_hash, **value}

    def append_jit_event(self, connection: sqlite3.Connection, *, authority_id: str, run_id: str, state: str, payload: Mapping[str, Any], actor: Actor, now: str | None = None) -> dict[str, Any]:
        allowed = {"ready", "preflight_validated", "credential_read_started", "credential_resolved", "transport_created", "send_started", "response_headers_received", "response_body_received", "authoritative_result_committed", "authoritative_provider_rejection", "known_pre_send_failure", "unknown_after_send", "closed"}
        if state not in allowed:
            raise NativeLiveCanaryError("Native live JIT event state is invalid")
        now_value = now or _timestamp(self.repository.clock)
        prior = connection.execute("SELECT sequence_no,event_hash,state FROM max_live_canary_native_live_jit_events WHERE authority_id=? ORDER BY sequence_no DESC LIMIT 1", (authority_id,)).fetchone()
        prior_state = None if prior is None else prior["state"]
        if prior_state == "closed":
            raise NativeLiveCanaryError("Native live JIT authority is already closed")
        if state == "ready" and prior is not None:
            raise NativeLiveCanaryError("Native live JIT ready event already exists")
        transitions = {
            None: {"ready"},
            "ready": {"preflight_validated", "known_pre_send_failure"},
            "preflight_validated": {"preflight_validated", "credential_read_started", "credential_resolved", "transport_created", "send_started", "known_pre_send_failure"},
            "credential_read_started": {"credential_resolved", "known_pre_send_failure"},
            "credential_resolved": {"transport_created", "send_started", "known_pre_send_failure"},
            "transport_created": {"preflight_validated", "credential_read_started", "credential_resolved", "transport_created", "send_started", "known_pre_send_failure"},
            "send_started": {"response_headers_received", "response_body_received", "authoritative_result_committed", "authoritative_provider_rejection", "unknown_after_send"},
            "response_headers_received": {"response_body_received", "authoritative_result_committed", "authoritative_provider_rejection", "unknown_after_send"},
            "response_body_received": {"authoritative_result_committed", "authoritative_provider_rejection", "unknown_after_send"},
            "authoritative_result_committed": {"closed"},
            "authoritative_provider_rejection": {"closed"},
            "known_pre_send_failure": {"closed"},
            "unknown_after_send": {"closed"},
        }
        if state not in transitions.get(prior_state, set()):
            raise NativeLiveCanaryError(f"Native live JIT event transition {prior_state}->{state} is invalid")
        sequence = 1 if prior is None else int(prior["sequence_no"]) + 1
        safe = _bounded_payload(payload, "Native live JIT event")
        payload_hash = canonical_sha256(safe)
        value = {"authority_id": authority_id, "run_id": run_id, "sequence_no": sequence, "state": state, "payload_hash": payload_hash, "previous_event_hash": None if prior is None else prior["event_hash"], "created_at": now_value}
        event_hash = canonical_sha256(value)
        event_id = make_stable_id("native_live_jit_event", event_hash[:64])
        connection.execute("INSERT INTO max_live_canary_native_live_jit_events(event_id,authority_id,run_id,sequence_no,state,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?, ?,?)", (event_id, authority_id, run_id, sequence, state, canonical_json(safe), payload_hash, value["previous_event_hash"], event_hash, now_value, actor.actor_id, actor.actor_kind, actor.session_id))
        return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "state": state}

    def status(self, *, execution_preview_id: str | None = None, execution_authorization_id: str | None = None, run_id: str | None = None) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            if execution_preview_id:
                preview_where, preview_args = "execution_preview_id=?", (execution_preview_id,)
                auth_where, auth_args = "execution_preview_id=?", (execution_preview_id,)
                jit_where, jit_args = "execution_authorization_id IN (SELECT execution_authorization_id FROM max_live_canary_native_execution_authorizations WHERE execution_preview_id=?)", (execution_preview_id,)
            elif execution_authorization_id:
                auth_row = connection.execute("SELECT execution_preview_id FROM max_live_canary_native_execution_authorizations WHERE execution_authorization_id=?", (execution_authorization_id,)).fetchone()
                if auth_row is None:
                    raise NativeLiveCanaryError("native live authorization was not found")
                preview_where, preview_args = "execution_preview_id=?", (auth_row["execution_preview_id"],)
                auth_where, auth_args = "execution_authorization_id=?", (execution_authorization_id,)
                jit_where, jit_args = "execution_authorization_id=?", (execution_authorization_id,)
            elif run_id:
                preview_where, preview_args = "run_id=?", (run_id,)
                auth_where, auth_args = "run_id=?", (run_id,)
                jit_where, jit_args = "run_id=?", (run_id,)
            else:
                raise NativeLiveCanaryError("native live status requires a server-owned selector")
            preview_rows = connection.execute(f"SELECT * FROM max_live_canary_native_execution_previews WHERE {preview_where}", preview_args).fetchall()
            now_dt = _utc_now(self.repository.clock)
            previews = []
            for preview in preview_rows:
                current = connection.execute(
                    "SELECT execution_preview_id,execution_preview_hash FROM max_live_canary_native_execution_preview_current WHERE approval_id=?",
                    (preview["approval_id"],),
                ).fetchone()
                is_current = current is not None and current["execution_preview_id"] == preview["execution_preview_id"] and current["execution_preview_hash"] == preview["execution_preview_hash"]
                expires = _parse_timestamp(preview["expires_at"])
                block = None
                renewable = False
                if not is_current:
                    block = "superseded"
                elif expires is not None and expires <= now_dt:
                    approval = connection.execute(
                        "SELECT expires_at FROM max_live_canary_native_approvals_v2 WHERE approval_id=?",
                        (preview["approval_id"],),
                    ).fetchone()
                    if approval is None or _parse_timestamp(approval["expires_at"]) is None or _parse_timestamp(approval["expires_at"]) <= now_dt:
                        block = "human_approval_expired"
                    elif connection.execute(
                        "SELECT 1 FROM max_live_canary_native_approval_v2_consumptions WHERE approval_id=? LIMIT 1",
                        (preview["approval_id"],),
                    ).fetchone() is not None:
                        block = "human_approval_consumed"
                    else:
                        block = self._renewal_block_reason(connection, approval_id=preview["approval_id"], run_id=preview["run_id"])
                    renewable = block is None
                lineage = self._preview_lineage(preview)
                previews.append({"execution_preview_id": preview["execution_preview_id"], "execution_preview_hash": preview["execution_preview_hash"], "state": preview["state"], "expires_at": preview["expires_at"], **lineage, "current": is_current, "renewable": renewable, "renewal_block_reason": block})
            auths = connection.execute(f"SELECT execution_authorization_id,authorization_hash,expires_at FROM max_live_canary_native_execution_authorizations WHERE {auth_where}", auth_args).fetchall()
            jit_count = int(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_live_jit_authorities WHERE " + jit_where, jit_args).fetchone()[0])
            return {"ok": True, "execution_previews": [dict(row) for row in previews], "authorizations": [{**dict(row), "consumed": connection.execute("SELECT 1 FROM max_live_canary_native_execution_authorization_consumptions WHERE execution_authorization_id=?", (row["execution_authorization_id"],)).fetchone() is not None} for row in auths], "jit_authority_count": jit_count}
        finally:
            connection.close()

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        issues: list[str] = []
        try:
            query = " WHERE run_id=?" if run_id else ""
            args = (run_id,) if run_id else ()
            rows = list(connection.execute("SELECT * FROM max_live_canary_native_execution_previews" + query, args))
            rows_by_approval: dict[str, list[sqlite3.Row]] = {}
            for row in rows:
                rows_by_approval.setdefault(str(row["approval_id"]), []).append(row)
                try:
                    value = _loads(row["execution_preview_json"], "Live Execution Preview")
                    if _execution_preview_hash(value) != row["execution_preview_hash"]:
                        issues.append("execution_preview_hash_mismatch")
                    generation = int(row["generation"])
                    if "generation" in value and int(value["generation"]) != generation:
                        issues.append("execution_preview_generation_mismatch")
                    for field in ("supersedes_execution_preview_id", "supersedes_execution_preview_hash", "renewal_reason"):
                        if field in value and value[field] != row[field]:
                            issues.append("execution_preview_lineage_mismatch")
                except NativeLiveCanaryError:
                    issues.append("execution_preview_json_invalid")

            # The history is append-only.  A single current projection is the
            # only mutable object and must point to the highest contiguous
            # generation for each Human Approval.
            current_rows = list(connection.execute(
                "SELECT c.* FROM max_live_canary_native_execution_preview_current c "
                "JOIN max_live_canary_native_execution_previews p "
                "ON p.execution_preview_id=c.execution_preview_id" +
                (" WHERE p.run_id=?" if run_id else ""), args
            ))
            current_by_approval = {str(row["approval_id"]): row for row in current_rows}
            if len(current_by_approval) != len(rows_by_approval):
                issues.append("execution_preview_current_projection_count_mismatch")
            for approval_id, group in rows_by_approval.items():
                ordered = sorted(group, key=lambda item: (int(item["generation"]), item["created_at"], item["execution_preview_id"]))
                generations = [int(item["generation"]) for item in ordered]
                if generations != list(range(len(ordered))):
                    issues.append("execution_preview_generation_gap_or_duplicate")
                by_generation = {int(item["generation"]): item for item in ordered}
                for generation, item in by_generation.items():
                    if generation == 0:
                        if item["supersedes_execution_preview_id"] is not None or item["supersedes_execution_preview_hash"] is not None or item["renewal_reason"] is not None:
                            issues.append("execution_preview_initial_lineage_invalid")
                    else:
                        prior = by_generation.get(generation - 1)
                        if (
                            prior is None
                            or item["supersedes_execution_preview_id"] != prior["execution_preview_id"]
                            or item["supersedes_execution_preview_hash"] != prior["execution_preview_hash"]
                            or item["renewal_reason"] != "expired_before_execution"
                        ):
                            issues.append("execution_preview_successor_lineage_invalid")
                        # Renewal is legal only before any execution boundary.
                        # Historical activity after a valid renewal is allowed;
                        # activity at or before the successor creation is not.
                        created_at = item["created_at"]
                        earlier_checks = (
                            ("max_live_canary_native_approval_v2_consumptions", "created_at", "approval_id=? AND created_at<=?", (approval_id, created_at)),
                            ("max_live_canary_native_execution_authorization_consumptions", "created_at", "approval_id=? AND created_at<=?", (approval_id, created_at)),
                            ("max_live_canary_native_live_jit_authorities", "created_at", "approval_id=? AND created_at<=?", (approval_id, created_at)),
                            ("max_live_canary_native_live_jit_events", "created_at", "run_id=? AND created_at<=? AND state IN ('credential_read_started','credential_resolved','transport_created','send_started','response_headers_received','response_body_received','authoritative_result_committed','authoritative_provider_rejection','unknown_after_send')", (item["run_id"], created_at)),
                            ("max_provider_dispatch_attempts", "created_at", "run_id=? AND created_at<=?", (item["run_id"], created_at)),
                            ("max_provider_call_records", "created_at", "run_id=? AND created_at<=?", (item["run_id"], created_at)),
                            ("max_provider_usage_attestations", "created_at", "run_id=? AND created_at<=?", (item["run_id"], created_at)),
                        )
                        for table, _column, predicate, predicate_args in earlier_checks:
                            if connection.execute(f"SELECT 1 FROM {table} WHERE {predicate} LIMIT 1", predicate_args).fetchone() is not None:
                                issues.append("execution_preview_renewal_after_execution_activity")
                                break
                current = current_by_approval.get(approval_id)
                latest = ordered[-1] if ordered else None
                if current is None or latest is None or current["execution_preview_id"] != latest["execution_preview_id"] or current["execution_preview_hash"] != latest["execution_preview_hash"] or int(current["generation"]) != int(latest["generation"]):
                    issues.append("execution_preview_current_projection_drift")

            # Validate the server-owned projection digest and the hash-chained
            # lineage events independently of the history rows.
            preview_event_query = " WHERE run_id=?" if run_id else ""
            preview_event_rows = list(connection.execute(
                "SELECT * FROM max_live_canary_native_execution_preview_events" + preview_event_query + " ORDER BY approval_id,sequence_no", args
            ))
            events_by_approval: dict[str, list[sqlite3.Row]] = {}
            for event in preview_event_rows:
                events_by_approval.setdefault(str(event["approval_id"]), []).append(event)
                prior_events = events_by_approval[str(event["approval_id"])][:-1]
                prior_event = prior_events[-1] if prior_events else None
                expected_sequence = 1 if prior_event is None else int(prior_event["sequence_no"]) + 1
                if int(event["sequence_no"]) != expected_sequence:
                    issues.append("execution_preview_event_sequence_invalid")
                expected_previous = None if prior_event is None else prior_event["event_hash"]
                if event["previous_event_hash"] != expected_previous:
                    issues.append("execution_preview_event_previous_hash_invalid")
                identity = {"execution_preview_id": event["execution_preview_id"], "approval_id": event["approval_id"], "run_id": event["run_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                if canonical_sha256(identity) != event["event_hash"]:
                    issues.append("execution_preview_event_hash_invalid")
                try:
                    payload = _bounded_payload(_loads(event["payload_json"], "Native execution Preview event"), "Native execution Preview event")
                    if canonical_sha256(payload) != event["payload_hash"]:
                        issues.append("execution_preview_event_payload_hash_invalid")
                except NativeLiveCanaryError:
                    issues.append("execution_preview_event_payload_invalid")
            for approval_id, group in rows_by_approval.items():
                events = events_by_approval.get(approval_id, [])
                ordered = sorted(group, key=lambda item: int(item["generation"]))
                if len(events) != len(ordered):
                    issues.append("execution_preview_event_count_mismatch")
                    continue
                for index, (item, event) in enumerate(zip(ordered, events)):
                    expected_type = "created" if index == 0 else "renewed"
                    if event["execution_preview_id"] != item["execution_preview_id"] or event["event_type"] != expected_type or int(event["sequence_no"]) != index + 1:
                        issues.append("execution_preview_event_lineage_mismatch")
                    try:
                        payload = _loads(event["payload_json"], "Native execution Preview event")
                        expected_payload = {
                            "execution_preview_id": item["execution_preview_id"], "approval_id": item["approval_id"], "run_id": item["run_id"],
                            "execution_preview_hash": item["execution_preview_hash"], "generation": int(item["generation"]),
                            "supersedes_execution_preview_id": item["supersedes_execution_preview_id"],
                            "supersedes_execution_preview_hash": item["supersedes_execution_preview_hash"], "renewal_reason": item["renewal_reason"],
                        }
                        if payload != expected_payload:
                            issues.append("execution_preview_event_payload_lineage_mismatch")
                    except NativeLiveCanaryError:
                        pass
            for current in current_rows:
                try:
                    current_value = _loads(current["current_json"], "Native execution Preview current projection")
                    if canonical_sha256(current_value) != current["current_hash"] or current_value.get("approval_id") != current["approval_id"] or current_value.get("execution_preview_id") != current["execution_preview_id"] or current_value.get("execution_preview_hash") != current["execution_preview_hash"] or int(current_value.get("generation", -1)) != int(current["generation"]):
                        issues.append("execution_preview_current_projection_hash_or_binding_invalid")
                except NativeLiveCanaryError:
                    issues.append("execution_preview_current_projection_invalid")

            jit_count = int(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_live_jit_authorities" + query, args).fetchone()[0])
            event_rows = list(connection.execute("SELECT * FROM max_live_canary_native_live_jit_events" + query + " ORDER BY authority_id,sequence_no", args))
            prior_by_authority: dict[str, sqlite3.Row | None] = {}
            for row in event_rows:
                authority_id = str(row["authority_id"])
                prior = prior_by_authority.get(authority_id)
                expected_sequence = 1 if prior is None else int(prior["sequence_no"]) + 1
                if int(row["sequence_no"]) != expected_sequence:
                    issues.append("jit_event_sequence_invalid")
                expected_previous = None if prior is None else prior["event_hash"]
                if row["previous_event_hash"] != expected_previous:
                    issues.append("jit_event_previous_hash_invalid")
                identity = {"authority_id": authority_id, "run_id": row["run_id"], "sequence_no": int(row["sequence_no"]), "state": row["state"], "payload_hash": row["payload_hash"], "previous_event_hash": row["previous_event_hash"], "created_at": row["created_at"]}
                if canonical_sha256(identity) != row["event_hash"]:
                    issues.append("jit_event_hash_invalid")
                try:
                    payload = _loads(row["payload_json"], "Native live JIT event")
                    if canonical_sha256(_bounded_payload(payload, "Native live JIT event")) != row["payload_hash"]:
                        issues.append("jit_event_payload_hash_invalid")
                except NativeLiveCanaryError:
                    issues.append("jit_event_payload_invalid")
                prior_state = None if prior is None else prior["state"]
                transitions = {
                    None: {"ready"}, "ready": {"preflight_validated", "known_pre_send_failure"},
                    "preflight_validated": {"preflight_validated", "credential_read_started", "credential_resolved", "transport_created", "send_started", "known_pre_send_failure"},
                    "credential_read_started": {"credential_resolved", "known_pre_send_failure"}, "credential_resolved": {"transport_created", "send_started", "known_pre_send_failure"},
                    "transport_created": {"preflight_validated", "credential_read_started", "credential_resolved", "transport_created", "send_started", "known_pre_send_failure"},
                    "send_started": {"response_headers_received", "response_body_received", "authoritative_result_committed", "authoritative_provider_rejection", "unknown_after_send"},
                    "response_headers_received": {"response_body_received", "authoritative_result_committed", "authoritative_provider_rejection", "unknown_after_send"},
                    "response_body_received": {"authoritative_result_committed", "authoritative_provider_rejection", "unknown_after_send"},
                    "authoritative_result_committed": {"closed"}, "authoritative_provider_rejection": {"closed"}, "known_pre_send_failure": {"closed"}, "unknown_after_send": {"closed"},
                }
                if row["state"] not in transitions.get(prior_state, set()):
                    issues.append("jit_event_transition_invalid")
                prior_by_authority[authority_id] = row
            jit_rows = list(connection.execute("SELECT authority_id FROM max_live_canary_native_live_jit_authorities" + query, args))
            for row in jit_rows:
                last = prior_by_authority.get(str(row["authority_id"]))
                if last is None or last["state"] != "closed":
                    issues.append("jit_authority_not_closed")
            return {"ok": not issues, "schema_version": 26, "execution_preview_count": len(rows), "execution_preview_current_count": len(current_rows), "execution_preview_event_count": len(preview_event_rows), "jit_authority_count": jit_count, "jit_event_count": len(event_rows), "issues": sorted(set(issues))}
        finally:
            connection.close()


class FixtureCredentialResolver:
    """Explicit non-secret credential seam for fixture databases only."""

    def __init__(self, value: str = "fixture-secret") -> None:
        if not value or "\r" in value or "\n" in value:
            raise ValueError("fixture credential is invalid")
        self.value = value
        self.read_count = 0

    def resolve(self, _reference: Any) -> str:
        self.read_count += 1
        return self.value


class FixtureLiveProviderTransportFactory(LiveProviderTransportFactory):
    """Fixture-only factory using the production HTTPS transport class."""

    fixture_only = True

    def __init__(self, *, resolver: Any, connector: Any, credential_resolver: Any) -> None:
        self.resolver = resolver
        self.connector = connector
        self.credential_resolver = credential_resolver

    def create_for_permit(self, *, profile: ProviderProfile, permit: Any, provider_store: ProviderStore, network_event_callback: Callable[[str, Mapping[str, Any]], None] | None = None, send_boundary_callback: Callable[[Any], None] | None = None) -> OpenAICompatibleHTTPSLiveTransport:
        if not provider_store.repository.is_fixture_database():
            raise ProviderTransportError("FIXTURE_FACTORY_FORBIDDEN", "fixture transport factory requires a fixture control database", dispatch_known=True)
        policy_record = provider_store.network_policy_status(network_policy_hash_value=profile.network_policy_hash)
        policy = policy_record.get("policy") if isinstance(policy_record, Mapping) else None
        if not isinstance(policy, Mapping) or network_policy_hash(policy) != profile.network_policy_hash:
            raise ProviderTransportError("LIVE_NETWORK_POLICY_BINDING_MISMATCH", "fixture network policy binding is invalid", dispatch_known=True)
        return OpenAICompatibleHTTPSLiveTransport(
            endpoint_origin=profile.endpoint_origin,
            endpoint_path_policy=profile.endpoint_path_policy,
            credential_ref=profile.credential_ref,
            network_policy=policy,
            credential_resolver=self.credential_resolver,
            permit=permit,
            permit_validator=provider_store.validate_live_dispatch_permit,
            dns_resolver=self.resolver,
            connector=self.connector,
            network_event_callback=network_event_callback,
            send_boundary_callback=send_boundary_callback,
        )


class NativeLiveCanaryExecutor:
    """Production-only executor for one server-authorized live iteration."""

    one_shot_only = True
    hermetic = False

    def __init__(self, repository: MaxControlRepository, *, admin_actor: Actor | None = None, worker_actor: Actor | None = None, source_database: str | None = None, expected_release_identity: Mapping[str, Any] | None = None, transport_factory: LiveProviderTransportFactory | None = None, request_builder: ServerOwnedRequestBuilder | None = None, usage_authority: ProviderUsageAuthority | None = None, live_network_enabled: bool = True) -> None:
        self.repository = repository
        self.admin_actor = admin_actor or Actor("mr4b1b-v16r3-admin", "mr4b1b-v16r3-admin-session", "admin", "admin", "research-kb-v16r3")
        self.worker_actor = worker_actor or Actor("mr4b1b-v16r3-worker", "mr4b1b-v16r3-worker-session", "worker", "runner", "research-kb-v16r3")
        self.execution = NativeLiveExecutionStore(repository, expected_release_identity=expected_release_identity)
        self.provider_store = ProviderStore(repository)
        self.source_database = source_database
        self.expected_release_identity = None if expected_release_identity is None else dict(expected_release_identity)
        if transport_factory is None:
            self.transport_factory = LiveProviderTransportFactory()
        else:
            fixture_allowed = repository.is_fixture_database() and type(transport_factory) is FixtureLiveProviderTransportFactory and getattr(transport_factory, "fixture_only", False) is True
            package_owned = is_trusted_live_transport_factory(transport_factory)
            if not fixture_allowed and not package_owned:
                raise NativeLiveCanaryError("production live executor does not accept a client transport factory")
            self.transport_factory = transport_factory
        self.request_builder = request_builder or ServerOwnedRequestBuilder()
        self.usage_authority = usage_authority or ProviderUsageAuthority()
        self.live_network_enabled = bool(live_network_enabled)

    def create_execution_preview(self, **kwargs: Any) -> dict[str, Any]:
        return self.execution.create_execution_preview(**kwargs)

    def authorize_execution(self, **kwargs: Any) -> dict[str, Any]:
        return self.execution.authorize_execution(**kwargs)

    def status(self, **kwargs: Any) -> dict[str, Any]:
        return self.execution.status(**kwargs)

    def verify(self, **kwargs: Any) -> dict[str, Any]:
        return self.execution.verify(**kwargs)

    def _preparation_context(self, preview_id: str) -> dict[str, Any]:
        try:
            hermetic = PreparationCanaryExecutor(self.repository, source_database=self.source_database, expected_release_identity=self.expected_release_identity, request_builder=self.request_builder)
            return hermetic._context(preview_id=preview_id)
        except (NativePreparationBridgeError, Exception) as exc:
            if isinstance(exc, NativeLiveCanaryError):
                raise
            raise NativeLiveCanaryError("Preparation chain could not be revalidated") from exc

    def _caps(self, binding: Mapping[str, Any], *, profile: ProviderProfile | None = None) -> dict[str, int]:
        profile_usage = {} if profile is None else profile.authority_maximum_usage()
        return {
            "max_ticks": 1, "max_iterations": 1, "max_wall_clock_seconds": 120,
            "max_consecutive_failures": 1, "max_no_progress": 1,
            "max_provider_calls": 1, "max_input_tokens": int(binding["max_input_tokens"]),
            "max_output_tokens": int(binding["max_output_tokens"]), "max_cache_read_tokens": int(profile_usage.get("cache_read_tokens", binding.get("max_cache_read_tokens", 0))),
            "max_reasoning_tokens": int(profile_usage.get("reasoning_tokens", binding.get("max_reasoning_tokens", 0))), "max_cost_units": int(binding["effective_cost_cap"]),
        }

    def _cleanup_runner(self, *, run_id: str, claim: Mapping[str, Any] | None, lease: Mapping[str, Any] | None) -> list[str]:
        errors: list[str] = []
        if claim is not None:
            try:
                token = int(claim.get("fencing_token") if lease is None else lease["fencing_token"])
                RunnerPersistence(self.repository).release_invocation(run_id=run_id, claim_id=str(claim["claim_id"]), actor=self.worker_actor, fencing_token=token)
            except Exception as exc:
                errors.append("claim_release:" + type(exc).__name__)
        if lease is not None:
            try:
                self.repository.release_lease(run_id=run_id, actor=self.worker_actor, fencing_token=int(lease["fencing_token"]))
            except Exception as exc:
                errors.append("lease_release:" + type(exc).__name__)
        return errors

    def _record_event(self, authority_id: str, run_id: str, state: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                return self.execution.append_jit_event(connection, authority_id=authority_id, run_id=run_id, state=state, payload=payload, actor=self.worker_actor)
        finally:
            connection.close()

    def _close_pre_send_permissions(
        self,
        *,
        grant: Mapping[str, Any] | None,
        prepared: Mapping[str, Any] | None,
        error_code: str,
        fencing_token: int,
    ) -> list[str]:
        """Close server-owned send capabilities after a proven pre-send error."""

        errors: list[str] = []
        if prepared is not None:
            try:
                self.provider_store.abort_live_dispatch_before_send(
                    permit=prepared["permit"],
                    actor=self.worker_actor,
                    fencing_token=fencing_token,
                    details={"error_code": error_code, "bridge": "mr-convergence-dev19"},
                )
            except Exception as exc:
                errors.append("dispatch_abort:" + type(exc).__name__)
        if grant is not None:
            try:
                self.provider_store.close_execution_grant_before_send(
                    grant_id=str(grant["grant_id"]),
                    actor=self.worker_actor,
                    failure_stage="convergence_pre_send",
                    error_code=error_code,
                )
            except Exception as exc:
                errors.append("grant_close:" + type(exc).__name__)
        return errors

    def _persist_runner_success(
        self,
        *,
        preparation_context: Mapping[str, Any],
        built: BuiltServerRequest,
        decoded: Any,
        call_record: Any,
        attestation: Any,
        cost_units: int,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Use the formal runner result/usage/iteration closure for success."""

        bridge = PreparationCanaryExecutor(
            self.repository,
            admin_actor=self.admin_actor,
            worker_actor=self.worker_actor,
            source_database=self.source_database,
            expected_release_identity=self.expected_release_identity,
            request_builder=self.request_builder,
            usage_authority=self.usage_authority,
        )
        return bridge._persist_runner_success(
            ctx=preparation_context,
            built=built,
            decoded=decoded,
            call_record=call_record,
            attestation=attestation,
            cost_units=cost_units,
            fencing_token=fencing_token,
        )

    def _persist_runner_provider_failure(
        self,
        *,
        preparation_context: Mapping[str, Any],
        built: BuiltServerRequest,
        call_record: ProviderCallRecord,
        error_code: str,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Use the formal runner closure for a dispatch-known rejection."""

        bridge = PreparationCanaryExecutor(
            self.repository,
            admin_actor=self.admin_actor,
            worker_actor=self.worker_actor,
            source_database=self.source_database,
            expected_release_identity=self.expected_release_identity,
            request_builder=self.request_builder,
            usage_authority=self.usage_authority,
        )
        return bridge._persist_runner_provider_failure(
            ctx=preparation_context,
            built=built,
            call_record=call_record,
            error_code=error_code,
            fencing_token=fencing_token,
        )

    def _persisted_provider_facts(
        self,
        *,
        run_id: str,
        idempotency_key: str,
    ) -> tuple[ProviderCallRecord, ProviderUsageAttestation | None, Any]:
        """Rehydrate only server-persisted provider facts for runner closure."""

        value = self.provider_store.provider_call(run_id=run_id, idempotency_key=idempotency_key)
        if value is None:
            raise NativeLiveCanaryError("durable provider call record is missing")
        fields = {
            "call_record_id", "provider_call_id", "run_id", "project_id", "profile_hash",
            "model_identity", "intent_hash", "request_hash", "idempotency_key",
            "transport_status", "terminal_status", "usage", "response_manifest",
            "pricing_hash", "logical_call_id", "intent_id", "iteration_id",
            "created_at", "record_hash",
        }
        try:
            record = ProviderCallRecord(**{key: value[key] for key in fields})
        except Exception as exc:
            raise NativeLiveCanaryError("durable provider call record is invalid") from exc
        attestation = None
        if isinstance(value.get("attestation"), Mapping):
            try:
                attestation = ProviderUsageAttestation(**dict(value["attestation"]))
            except Exception as exc:
                raise NativeLiveCanaryError("durable provider usage attestation is invalid") from exc
        decoded = SimpleNamespace(
            proposal=dict(value.get("proposal") or {}),
            usage=dict(record.usage),
            response_manifest=dict(record.response_manifest),
        )
        return record, attestation, decoded

    def _record_native_terminal(
        self,
        *,
        authority_id: str,
        preview_id: str,
        state: str,
        payload: Mapping[str, Any],
        run_id: str,
        claim: Mapping[str, Any] | None,
        lease: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Append the JIT terminal chain and close the preparation handoff."""

        terminal_event = self._record_event(authority_id, run_id, state, payload)
        closed_event = self._record_event(
            authority_id,
            run_id,
            "closed",
            {
                "terminal_state": state,
                "terminal_event_hash": terminal_event["event_hash"],
                "cleanup": "runner_claim_lease_and_handoff",
            },
        )
        cleanup_errors = self._cleanup_runner(run_id=run_id, claim=claim, lease=lease)
        handoff_state = {
            "authoritative_result_committed": "SUCCEEDED",
            "unknown_after_send": "UNKNOWN",
            "known_pre_send_failure": "FAILED",
            "authoritative_provider_rejection": "FAILED",
        }.get(state)
        if handoff_state is not None:
            try:
                handoff = PreparationHandoffStore(
                    self.repository,
                    source_database=self.source_database,
                )
                token = int((lease or claim or {}).get("fencing_token", 0))
                handoff.transition_terminal(
                    preview_id=preview_id,
                    state=handoff_state,
                    actor=self.worker_actor,
                    claim_id="" if claim is None else str(claim["claim_id"]),
                    fencing_token=token,
                )
            except PreparationHandoffError as exc:
                cleanup_errors.append("handoff_terminal:" + type(exc).__name__)
            except Exception as exc:
                cleanup_errors.append("handoff_terminal:" + type(exc).__name__)
        return {
            "terminal_state": state,
            "terminal_event": terminal_event,
            "closed_event": closed_event,
            "cleanup_errors": cleanup_errors,
        }

    def execute(self, *, execution_authorization_id: str, execution_authorization_hash: str, allow_execute: bool = False) -> dict[str, Any]:
        if not allow_execute:
            raise NativeLiveCanaryError("live execution requires an explicit execution flag")
        if not self.live_network_enabled:
            raise NativeLiveCanaryError("production live transport is disabled")
        self.execution.preflight_execution(execution_authorization_id=execution_authorization_id, execution_authorization_hash=execution_authorization_hash)
        context = self.execution.execution_context(execution_authorization_id=execution_authorization_id, execution_authorization_hash=execution_authorization_hash)
        preview_value = context["preview_value"]
        prep_context = self._preparation_context(str(preview_value["preparation_preview_id"]))
        profile = self.provider_store.get_profile(profile_hash=str(preview_value["provider_profile_hash"]))
        if profile.model_identity != preview_value["model_identity"] or profile.pricing.pricing_hash != preview_value["pricing_hash"] or credential_reference_hash(profile.credential_ref) != preview_value["credential_reference_hash"]:
            raise NativeLiveCanaryError("Provider profile binding drifted")
        policy_record = self.provider_store.network_policy_status(network_policy_hash_value=profile.network_policy_hash)
        policy = policy_record.get("policy") if isinstance(policy_record, Mapping) else None
        if not isinstance(policy, Mapping) or network_policy_hash(policy) != preview_value["network_policy_hash"]:
            raise NativeLiveCanaryError("Network policy binding drifted")
        binding = {**preview_value, "runner_profile_hash": prep_context["authority"].get("runner_profile_hash"), "source_allowlist": prep_context["authority"].get("source_allowlist"), "source_policy": prep_context["authority"].get("source_policy"), "source_egress_policy_hash": prep_context["authority"].get("source_egress_policy_hash"), "caps": self._caps(preview_value, profile=profile), "_provider_profile": profile}
        try:
            with closing(self.repository._connect(read_only=True)) as connection:
                built = self.request_builder.build_from_row(authority=binding, connection=connection, provider_profile=profile)
        except (ServerRequestBuildError, Exception) as exc:
            if isinstance(exc, NativeLiveCanaryError):
                raise
            raise NativeLiveCanaryError("server-owned request rebuild failed before execution authorization consumption") from exc
        consumption = self.execution.consume_execution(execution_authorization_id=execution_authorization_id, execution_authorization_hash=execution_authorization_hash, actor=self.worker_actor)
        run_id = str(preview_value["run_id"])
        lease: Mapping[str, Any] | None = None
        runner_claim: Mapping[str, Any] | None = None
        source_permit: Mapping[str, Any] | None = None
        prepared: Mapping[str, Any] | None = None
        grant: Mapping[str, Any] | None = None
        authority: Mapping[str, Any] | None = None
        send_started = False
        stage = "pre_send_setup"
        runner_closure: Mapping[str, Any] | None = None
        try:
            stage = "lease_acquire"
            lease = self.repository.acquire_lease(run_id=run_id, actor=self.worker_actor, ttl_seconds=600)
            stage = "runner_claim"
            runner_claim = RunnerPersistence(self.repository).claim_invocation(run_id=run_id, actor=self.worker_actor, fencing_token=int(lease["fencing_token"]), ttl_seconds=120)
            stage = "source_permit_issue"
            source_permit = self.execution.issue_source_permit(execution_authorization_id=execution_authorization_id, execution_preview_id=str(preview_value["execution_preview_id"]), run_id=run_id, worker=self.worker_actor, fencing_token=int(lease["fencing_token"]), manifest=built.manifest, expires_at=str(lease["expires_at"]), release_identity_hash=str(preview_value["release_identity_hash"]), source_tree_hash=str(preview_value["source_tree_hash"]), source_policy_hash=str(preview_value["source_policy_hash"]))
            stage = "source_permit_consume"
            self.execution.transition_source_permit(source_permit_id=str(source_permit["source_permit_id"]), state="consumed", actor=self.worker_actor)
            caps = dict(binding["caps"])
            stage = "grant_issue"
            grant = self.provider_store.issue_live_execution_grant(run_id=run_id, actor=self.admin_actor, profile_hash=profile.profile_hash, caps=caps, reason="MR-4B1B-v16R3 governed live bridge", ttl_seconds=600, network_policy_hash=profile.network_policy_hash, pricing_hash=profile.pricing.pricing_hash, budget_hash=str(preview_value["budget_hash"]))
            stage = "grant_consume"
            grant_consumption = self.provider_store.consume_execution_grant(grant_id=grant["grant_id"], run_id=run_id, project_id=str(preview_value["project_id"]), profile_hash=profile.profile_hash, model_identity=profile.model_identity, network_policy_hash=profile.network_policy_hash, pricing_hash=profile.pricing.pricing_hash, budget_hash=str(preview_value["budget_hash"]), consumer=self.worker_actor)
            stage = "network_authorization_issue"
            network = self.provider_store.issue_live_network_authorization(run_id=run_id, grant_id=grant["grant_id"], caps={"max_provider_calls": 1, "max_input_tokens": caps["max_input_tokens"], "max_output_tokens": caps["max_output_tokens"], "max_cache_read_tokens": caps["max_cache_read_tokens"], "max_reasoning_tokens": caps["max_reasoning_tokens"], "max_cost_units": caps["max_cost_units"]}, network_policy=policy, reason="MR-4B1B-v16R3 governed live bridge", actor=self.admin_actor, ttl_seconds=300, profile_hash=profile.profile_hash)
            stage = "provider_preflight"
            provider_preflight = self.provider_store.provider_live_preflight(run_id=run_id, authorization_id=str(network["authorization_id"]))
            if not provider_preflight.get("ok"):
                raise NativeLiveCanaryError("provider live preflight failed")
            stage = "dispatch_prepare"
            prepared = self.provider_store.prepare_live_dispatch(authorization_id=network["authorization_id"], run_id=run_id, project_id=str(preview_value["project_id"]), grant_id=grant["grant_id"], profile=profile, request_hash=built.intent.request_hash, wire_request_hash=hashlib.sha256(built.body).hexdigest(), intent_hash=built.intent.intent_hash or built.intent.request_hash, logical_call_id=built.intent.logical_call_id, idempotency_key=built.intent.idempotency_key, actor=self.worker_actor, fencing_token=int(lease["fencing_token"]), permit_ttl_seconds=120)
            permit = prepared["permit"]
            stage = "jit_authority_create"
            authority = self.execution.create_jit_authority(binding=preview_value, consumption=consumption, lease=lease, claim=runner_claim, grant=grant, grant_consumption=grant_consumption, network_authorization_id=str(network["authorization_id"]), dispatch_permit_id=str(permit.permit_id), source_permit_id=str(source_permit["source_permit_id"]), actor=self.worker_actor)
            self._record_event(authority["authority_id"], run_id, "preflight_validated", {"request_manifest_hash": built.manifest["manifest_hash"], "dns_receipt_hash": preview_value["dns_receipt_hash"]})

            def execution_event(event_type: str, payload: Mapping[str, Any]) -> None:
                mapping = {"credential_resolution_started": "credential_read_started", "credential_resolution_completed": "credential_resolved", "transport_preflight_started": "transport_created", "transport_created": "transport_created", "http_dispatch_boundary_crossed": "send_started", "dns_resolution_started": "preflight_validated"}
                state = mapping.get(event_type)
                if state is not None and authority is not None:
                    nonlocal send_started
                    if state == "send_started":
                        send_started = True
                    self._record_event(authority["authority_id"], run_id, state, {"event_type": event_type, **{key: value for key, value in dict(payload).items() if key not in {"address", "secret", "authorization"}}})

            stage = "adapter_dispatch"
            adapter = LiveOpenAICompatibleAdapter(profile, transport_factory=self.transport_factory, provider_store=self.provider_store, actor=self.worker_actor, grant_id=grant["grant_id"], authorization_id=str(network["authorization_id"]), fencing_token=int(lease["fencing_token"]), usage_authority=self.usage_authority, execution_event_callback=execution_event, prepared_dispatch=prepared)
            response = adapter.dispatch(built.request, idempotency_key=built.intent.idempotency_key)
            self._record_event(authority["authority_id"], run_id, "response_headers_received", {"provider_call_id_hash": canonical_sha256(response.provider_call_id)})
            self._record_event(authority["authority_id"], run_id, "response_body_received", {"response_hash": canonical_sha256(response.usage_receipt)})
            call_record, attestation, decoded = self._persisted_provider_facts(run_id=run_id, idempotency_key=built.intent.idempotency_key)
            if call_record.terminal_status != "succeeded" or attestation is None:
                raise NativeLiveCanaryError("successful provider response lacks an authoritative usage attestation")
            RunnerPersistence(self.repository).record_dispatch_ack(
                run_id=run_id,
                logical_call_id=built.intent.logical_call_id,
                status="dispatched",
                dispatch_known=True,
                provider_call_id=call_record.provider_call_id,
                actor=self.worker_actor,
                fencing_token=int(lease["fencing_token"]),
                preserve_existing=True,
            )
            runner_closure = self._persist_runner_success(
                preparation_context=prep_context,
                built=built,
                decoded=decoded,
                call_record=call_record,
                attestation=attestation,
                cost_units=int(attestation.cost_units),
                fencing_token=int(lease["fencing_token"]),
            )
            terminal = self._record_native_terminal(
                authority_id=authority["authority_id"],
                preview_id=str(prep_context["preview"]["preview_id"]),
                state="authoritative_result_committed",
                payload={
                    "outcome": "AUTHORITATIVE_PROVIDER_RESULT",
                    "provider_call_id_hash": canonical_sha256(call_record.provider_call_id),
                    "usage_hash": canonical_sha256(call_record.usage),
                    "runner_result_hash": runner_closure["result_hash"],
                    "retry_allowed": False,
                },
                run_id=run_id,
                claim=runner_claim,
                lease=lease,
            )
            return {"ok": True, "outcome": "AUTHORITATIVE_PROVIDER_RESULT", "authority_id": authority["authority_id"], "execution_authorization_id": execution_authorization_id, "provider_call_id": call_record.provider_call_id, "usage_hash": canonical_sha256(response.usage_receipt), "runner_closure": runner_closure, "terminal": terminal, "network": {"dns": 0, "credential_reads": 1, "tcp": 1, "tls": 1, "https": 1, "provider_calls": 1}, "retry_allowed": False}
        except Exception as exc:
            error_code = getattr(exc, "code", type(exc).__name__)
            error_text = str(error_code)
            fencing_token = int((lease or runner_claim or {}).get("fencing_token", 0))
            cleanup_errors: list[str] = []
            authoritative_provider_failure = False
            provider_failure_record: ProviderCallRecord | None = None
            if send_started and built is not None:
                # A bounded failed provider record is an authoritative
                # rejection.  It is distinct from UNKNOWN_AFTER_SEND, which
                # is reserved for a missing or non-authoritative observation.
                try:
                    provider_value = self.provider_store.provider_call(
                        run_id=run_id,
                        idempotency_key=built.intent.idempotency_key,
                    )
                    if provider_value is not None and provider_value.get("terminal_status") == "failed":
                        provider_failure_record, _unused_attestation, _unused_decoded = self._persisted_provider_facts(
                            run_id=run_id,
                            idempotency_key=built.intent.idempotency_key,
                        )
                        authoritative_provider_failure = True
                        RunnerPersistence(self.repository).record_dispatch_ack(
                            run_id=run_id,
                            logical_call_id=built.intent.logical_call_id,
                            status="dispatched",
                            dispatch_known=True,
                            provider_call_id=provider_failure_record.provider_call_id,
                            actor=self.worker_actor,
                            fencing_token=fencing_token,
                            preserve_existing=True,
                        )
                        runner_closure = self._persist_runner_provider_failure(
                            preparation_context=prep_context,
                            built=built,
                            call_record=provider_failure_record,
                            error_code=error_text,
                            fencing_token=fencing_token,
                        )
                except Exception as provider_close_exc:
                    cleanup_errors.append("provider_failure_closure:" + type(provider_close_exc).__name__)
                    authoritative_provider_failure = False
            if not send_started:
                cleanup_errors.extend(self._close_pre_send_permissions(
                    grant=grant,
                    prepared=prepared,
                    error_code=error_text,
                    fencing_token=fencing_token,
                ))
                if lease is not None:
                    try:
                        RunnerPersistence(self.repository).abort_pre_send(
                            run_id=run_id,
                            actor=self.worker_actor,
                            fencing_token=fencing_token,
                            failure_stage=stage,
                            error_code=error_text,
                            logical_call_id=None if built is None else built.intent.logical_call_id,
                        )
                    except Exception as runner_exc:
                        cleanup_errors.append("runner_abort:" + type(runner_exc).__name__)
            terminal_state = (
                "authoritative_provider_rejection" if authoritative_provider_failure else
                "unknown_after_send" if send_started else
                "known_pre_send_failure"
            )
            terminal = None
            if authority is not None:
                try:
                    terminal = self._record_native_terminal(
                        authority_id=authority["authority_id"],
                        preview_id=str(prep_context["preview"]["preview_id"]),
                        state=terminal_state,
                        payload={
                            "error_code": error_text,
                            "send_boundary_reached": send_started,
                            "provider_call_id_hash": None if provider_failure_record is None else canonical_sha256(provider_failure_record.provider_call_id),
                            "runner_result_hash": None if runner_closure is None else runner_closure.get("result_hash"),
                            "cleanup_errors": cleanup_errors,
                            "retry_allowed": False,
                        },
                        run_id=run_id,
                        claim=runner_claim,
                        lease=lease,
                    )
                except Exception as terminal_exc:
                    cleanup_errors.append("native_terminal:" + type(terminal_exc).__name__)
            else:
                cleanup_errors.extend(self._cleanup_runner(run_id=run_id, claim=runner_claim, lease=lease))
            outcome = "KNOWN_PROVIDER_FAILURE" if authoritative_provider_failure else "UNKNOWN_AFTER_SEND" if send_started else "KNOWN_PRE_SEND_FAILURE"
            return {"ok": False, "outcome": outcome, "authority_id": None if authority is None else authority["authority_id"], "error_code": error_text, "error_stage": stage, "runner_closure": runner_closure, "terminal": terminal, "cleanup_errors": cleanup_errors, "retry_allowed": False, "network": {"dns": 0, "credential_reads": 0 if not send_started else 1, "tcp": 0 if not send_started else 1, "tls": 0 if not send_started else 1, "https": 0 if not send_started else 1, "provider_calls": 0 if not send_started else 1}}


__all__ = [
    "FixtureCredentialResolver", "FixtureLiveProviderTransportFactory", "NativeLiveCanaryError",
    "NativeLiveCanaryExecutor", "NativeLiveExecutionStore",
]
