"""MR-4B0 plan-only live-canary authority.

This module deliberately stops at a durable, hash-bound permit.  It has no
provider transport, DNS resolver, credential resolver, retry loop, or model
call.  The later live stage must consume the same one-shot permit before any
I/O is even considered.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from ..policy import Actor
from .contract import canonical_json, canonical_sha256
from .persistence.db import CONTROL_SCHEMA_VERSION, MaxControlError, control_transaction
from .persistence.repository import MaxControlRepository, _parse_timestamp, _timestamp, _utc_now


class LiveCanaryAuthorityError(MaxControlError):
    """A canary authority invariant rejected the requested transition."""


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ABSOLUTE_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)")
_SECRET_RE = re.compile(r"(?:bearer\s+|sk-[A-Za-z0-9_-]{8,}|api[_ -]?key\s*[:=]|secret\s*[:=]|password\s*[:=])", re.I)
_FORBIDDEN_KEY_FRAGMENTS = ("prompt", "source_text", "full_text", "passage_text", "document_text", "excerpt", "content", "body", "api_key", "secret", "password", "access_token", "refresh_token", "private_key")
_APPROVAL_STATES = {"active", "revoked", "expired", "consumed"}
_PERMIT_STATES = {"ready", "send_started", "succeeded", "failed", "unknown", "aborted", "revoked"}


def _now(clock: Callable[[], datetime] | None) -> datetime:
    value = clock() if clock is not None else datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _time(clock: Callable[[], datetime] | None) -> str:
    return _now(clock).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"


def _hash(value: Any) -> str:
    return canonical_sha256(value)


def _preview_confirmation_phrase(preview_hash: str, preview_status: str | None) -> str:
    """Return a live phrase only for a Preview that reached that boundary."""

    if preview_status == "AWAITING_DNS_PREFLIGHT_AUTHORIZATION":
        return ""
    return f"APPROVE MR-4B1 CANARY {preview_hash}"


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value.lower()):
        raise LiveCanaryAuthorityError(f"{name} must be a SHA-256 hash")
    return value.lower()


def _safe_identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512 or "\r" in value or "\n" in value:
        raise LiveCanaryAuthorityError(f"{name} is invalid")
    if _ABSOLUTE_PATH_RE.match(value) or value.casefold().startswith(("http://", "https://", "file:")):
        raise LiveCanaryAuthorityError(f"{name} must not contain a path or endpoint")
    return value.strip()


def _safe_json(value: Any, name: str, *, max_bytes: int = 300_000) -> Any:
    """Reject raw source/prompt/secret/path material before persistence."""

    def walk(item: Any, depth: int = 0) -> None:
        if depth > 20:
            raise LiveCanaryAuthorityError(f"{name} is too deeply nested")
        if isinstance(item, Mapping):
            for key, child in item.items():
                lowered = str(key).casefold()
                # The durable SourceEgressPolicy legitimately carries the
                # numeric ``max_excerpt_characters`` bound.  Allow that one
                # metadata key while continuing to reject every source
                # excerpt/text/content field and every credential/prompt key.
                excerpt_bound = name == "source policy" and lowered == "max_excerpt_characters"
                source_hash_bound = name == "source binding" and lowered in {
                    "document_content_hash",
                    "passage_content_hash",
                    "citation_locator_hash",
                    "metadata_hash",
                    "source_policy_hash",
                }
                if any(fragment in lowered for fragment in _FORBIDDEN_KEY_FRAGMENTS) and not (excerpt_bound or source_hash_bound):
                    raise LiveCanaryAuthorityError(f"{name} contains prohibited material")
                walk(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > 20_000 or _ABSOLUTE_PATH_RE.match(item) or _SECRET_RE.search(item):
                raise LiveCanaryAuthorityError(f"{name} contains prohibited material")

    walk(value)
    encoded = canonical_json(value)
    if len(encoded.encode("utf-8")) > max_bytes:
        raise LiveCanaryAuthorityError(f"{name} is oversized")
    return json.loads(encoded)


def _actor_fields(actor: Actor) -> tuple[str, str, str]:
    return actor.actor_id, actor.actor_kind, actor.session_id


def _admin(actor: Actor) -> None:
    if not actor.is_admin:
        raise LiveCanaryAuthorityError("live canary approval/revocation requires human admin authority")


def _event_hash(value: Mapping[str, Any]) -> str:
    return _hash(value)


def _fixed_cap_vector(value: Mapping[str, Any]) -> dict[str, int]:
    required = {
        "max_provider_calls": 1,
        "max_ticks": 1,
        "max_iterations": 1,
        "max_acquisition_requests": 0,
        "max_ocr_requests": 0,
        "max_ingest_operations": 0,
    }
    numeric_caps = {
        "max_input_tokens", "max_output_tokens", "max_cache_read_tokens",
        "max_reasoning_tokens", "max_cost_units", "max_wall_clock_seconds",
        "max_source_passages", "max_source_characters",
    }
    if not isinstance(value, Mapping):
        raise LiveCanaryAuthorityError("canary cap vector is required")
    normalized: dict[str, int] = {}
    for key, raw in value.items():
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise LiveCanaryAuthorityError("canary caps must be bounded non-negative integers")
        normalized[str(key)] = int(raw)
    for key, maximum in required.items():
        if normalized.get(key) != maximum:
            raise LiveCanaryAuthorityError(f"canary cap {key} must be exactly {maximum}")
    missing_numeric = numeric_caps - set(normalized)
    if missing_numeric:
        raise LiveCanaryAuthorityError("canary cap vector is incomplete: " + ", ".join(sorted(missing_numeric)))
    for key in numeric_caps:
        if normalized[key] < 0:
            raise LiveCanaryAuthorityError(f"canary cap {key} must be non-negative")
    if normalized["max_input_tokens"] < 1 or normalized["max_output_tokens"] < 1 or normalized["max_wall_clock_seconds"] < 1:
        raise LiveCanaryAuthorityError("input/output/wall-clock caps must be positive")
    if normalized["max_source_passages"] > 1 or normalized["max_source_characters"] > 2000:
        raise LiveCanaryAuthorityError("canary source caps exceed the one-passage/2000-character bound")
    for key in ("max_provider_calls", "max_ticks", "max_iterations"):
        if normalized[key] > 1:
            raise LiveCanaryAuthorityError("MR-4B1 canary caps cannot exceed one")
    return dict(sorted(normalized.items()))


def _source_allowlist(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)) or len(value) > 1:
        raise LiveCanaryAuthorityError("MR-4B1 canary allowlist must contain at most one passage")
    allowed = {"project_id", "document_id", "document_version_id", "passage_id", "source_role", "evidential_function", "verification_status", "reliability_status"}
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping) or set(str(key) for key in item) - allowed:
            raise LiveCanaryAuthorityError("source allowlist contains unsupported or untrusted fields")
        if "passage_id" not in item:
            raise LiveCanaryAuthorityError("source allowlist requires an exact passage_id")
        result.append(_safe_json(dict(item), "source allowlist entry"))
    return result


_PREVIEW_REQUIRED = (
    "project_id", "run_id", "charter_hash", "current_state_hash", "current_checkpoint_id", "current_state_version",
    "engine_package", "engine_version", "core_schema_version", "control_schema_version",
    "candidate_wheel_sha256", "source_manifest_sha256", "source_tree_sha256", "provider_profile_hash",
    "provider_name", "model_identity", "model_version", "pricing_hash", "budget_hash",
    "endpoint_origin_hash", "endpoint_path_policy_hash", "network_policy_hash", "credential_ref_hash",
    "source_egress_policy_hash", "source_allowlist", "source_policy", "runner_profile_hash",
    "worker_id", "worker_session", "fencing_token", "claim_id", "caps", "transport_policy", "kill_rollback_incident_policy",
)
_PREVIEW_OPTIONAL = (
    "request_manifest_hash", "wire_request_hash", "request_hash", "intent_hash",
    "logical_call_id", "request_bytes", "request_prompt_chars",
    "human_cost_ceiling", "profile_worst_case_cost", "effective_provider_cost_cap",
    "preview_status", "dns_preflight_requirement", "source_binding",
)


def _normalize_preview_value(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize the hash-only Preview contract before any durable write."""

    if not isinstance(value, Mapping):
        raise LiveCanaryAuthorityError("canary preview must be an object")
    missing = [key for key in _PREVIEW_REQUIRED if key not in value]
    if missing:
        raise LiveCanaryAuthorityError("canary preview is missing: " + ", ".join(missing))
    unsupported = set(str(key) for key in value) - (set(_PREVIEW_REQUIRED) | set(_PREVIEW_OPTIONAL))
    if unsupported:
        raise LiveCanaryAuthorityError("canary preview contains unsupported fields")
    normalized: dict[str, Any] = {
        "project_id": _safe_identifier(value["project_id"], "project_id"),
        "run_id": _safe_identifier(value["run_id"], "run_id"),
        "charter_hash": _require_hash(value["charter_hash"], "charter_hash"),
        "current_state_hash": _require_hash(value["current_state_hash"], "current_state_hash"),
        "current_checkpoint_id": None if value.get("current_checkpoint_id") is None else _safe_identifier(value["current_checkpoint_id"], "current_checkpoint_id"),
        "current_state_version": value["current_state_version"],
        "engine_package": _safe_identifier(value["engine_package"], "engine_package"),
        "engine_version": _safe_identifier(value["engine_version"], "engine_version"),
        "core_schema_version": value["core_schema_version"],
        "control_schema_version": value["control_schema_version"],
        "candidate_wheel_sha256": _require_hash(value["candidate_wheel_sha256"], "candidate_wheel_sha256"),
        "source_manifest_sha256": _require_hash(value["source_manifest_sha256"], "source_manifest_sha256"),
        "source_tree_sha256": _require_hash(value["source_tree_sha256"], "source_tree_sha256"),
        "provider_profile_hash": _require_hash(value["provider_profile_hash"], "provider_profile_hash"),
        "provider_name": _safe_identifier(value["provider_name"], "provider_name"),
        "model_identity": _safe_identifier(value["model_identity"], "model_identity"),
        "model_version": _safe_identifier(value["model_version"], "model_version"),
        "pricing_hash": _require_hash(value["pricing_hash"], "pricing_hash"),
        "budget_hash": _require_hash(value["budget_hash"], "budget_hash"),
        "endpoint_origin_hash": _require_hash(value["endpoint_origin_hash"], "endpoint_origin_hash"),
        "endpoint_path_policy_hash": _require_hash(value["endpoint_path_policy_hash"], "endpoint_path_policy_hash"),
        "network_policy_hash": _require_hash(value["network_policy_hash"], "network_policy_hash"),
        "credential_ref_hash": _require_hash(value["credential_ref_hash"], "credential_ref_hash"),
        "source_egress_policy_hash": _require_hash(value["source_egress_policy_hash"], "source_egress_policy_hash"),
        "source_allowlist": _source_allowlist(value["source_allowlist"]),
        "source_policy": _safe_json(value["source_policy"], "source policy"),
        "runner_profile_hash": _require_hash(value["runner_profile_hash"], "runner_profile_hash"),
        "worker_id": _safe_identifier(value["worker_id"], "worker_id"),
        "worker_session": _safe_identifier(value["worker_session"], "worker_session"),
        "fencing_token": value["fencing_token"],
        "claim_id": _safe_identifier(value["claim_id"], "claim_id"),
        "caps": _fixed_cap_vector(value["caps"]),
        "transport_policy": _safe_json(value["transport_policy"], "transport policy"),
        "kill_rollback_incident_policy": _safe_json(value["kill_rollback_incident_policy"], "kill/rollback/incident policy"),
    }
    # Cost fields are integer micro-USD values.  The server rebuild below is
    # authoritative for profile/effective values; accepting the human ceiling
    # here keeps the client-supplied Preview a bounded input rather than a
    # provider authority.
    for key in ("human_cost_ceiling", "profile_worst_case_cost", "effective_provider_cost_cap"):
        if key in value:
            raw = value[key]
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0 or raw > 10_000_000:
                raise LiveCanaryAuthorityError(f"{key} must be an integer micro-USD value")
            normalized[key] = int(raw)
    if "preview_status" in value:
        status = _safe_identifier(value["preview_status"], "preview_status")
        if status != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION":
            raise LiveCanaryAuthorityError("unsupported canary Preview status")
        normalized["preview_status"] = status
    if "dns_preflight_requirement" in value:
        requirement = value["dns_preflight_requirement"]
        if not isinstance(requirement, Mapping):
            raise LiveCanaryAuthorityError("DNS preflight requirement must be an object")
        allowed = {
            "hostname", "port", "scheme", "provider_profile_hash", "network_policy_hash",
            "candidate_wheel_sha256", "run_id", "max_dns_attempts", "max_dns_candidates",
            "credential_reads", "https_connector_calls", "provider_calls", "actual_cost",
        }
        if set(str(key) for key in requirement) - allowed:
            raise LiveCanaryAuthorityError("DNS preflight requirement contains unsupported fields")
        required = {
            "hostname": "opencode.ai", "port": 443, "scheme": "https",
            "max_dns_attempts": 1,
            "credential_reads": 0, "https_connector_calls": 0,
            "provider_calls": 0, "actual_cost": 0,
        }
        for name, expected in required.items():
            if requirement.get(name) != expected:
                raise LiveCanaryAuthorityError(f"DNS preflight requirement mismatch: {name}")
        max_dns_candidates = requirement.get("max_dns_candidates")
        if isinstance(max_dns_candidates, bool) or not isinstance(max_dns_candidates, int) or not 1 <= max_dns_candidates <= 16:
            raise LiveCanaryAuthorityError("DNS preflight requirement max_dns_candidates is outside the reviewed bound")
        for name in ("provider_profile_hash", "network_policy_hash", "candidate_wheel_sha256"):
            if not isinstance(requirement.get(name), str) or len(requirement[name]) != 64:
                raise LiveCanaryAuthorityError(f"DNS preflight requirement hash is invalid: {name}")
        if requirement.get("run_id") != normalized["run_id"]:
            raise LiveCanaryAuthorityError("DNS preflight requirement run binding drifted")
        normalized["dns_preflight_requirement"] = _safe_json(dict(requirement), "DNS preflight requirement")
    if "source_binding" in value:
        binding = value["source_binding"]
        if not isinstance(binding, Mapping):
            raise LiveCanaryAuthorityError("source binding must be an object")
        allowed = {
            "project_id", "document_id", "passage_id", "source_version", "source_role",
            "source_status", "document_content_hash", "passage_content_hash",
            "citation_locator_hash", "metadata_hash", "source_policy_hash",
        }
        if set(str(key) for key in binding) - allowed:
            raise LiveCanaryAuthorityError("source binding contains unsupported fields")
        for name in ("project_id", "document_id", "passage_id", "source_version", "source_role", "source_status"):
            if not isinstance(binding.get(name), str) or not binding[name].strip():
                raise LiveCanaryAuthorityError(f"source binding field is invalid: {name}")
        for name in ("document_content_hash", "passage_content_hash", "citation_locator_hash", "metadata_hash", "source_policy_hash"):
            if not isinstance(binding.get(name), str) or len(binding[name]) != 64:
                raise LiveCanaryAuthorityError(f"source binding hash is invalid: {name}")
        if binding["project_id"] != normalized["project_id"]:
            raise LiveCanaryAuthorityError("source binding crosses the project boundary")
        normalized["source_binding"] = _safe_json(dict(binding), "source binding")
    if "human_cost_ceiling" not in normalized:
        normalized["human_cost_ceiling"] = int(normalized["caps"]["max_cost_units"])
    if "request_manifest_hash" in value:
        normalized["request_manifest_hash"] = _require_hash(value["request_manifest_hash"], "request_manifest_hash")
    if "wire_request_hash" in value:
        normalized["wire_request_hash"] = _require_hash(value["wire_request_hash"], "wire_request_hash")
    if "request_hash" in value:
        normalized["request_hash"] = _require_hash(value["request_hash"], "request_hash")
    if "intent_hash" in value:
        normalized["intent_hash"] = _require_hash(value["intent_hash"], "intent_hash")
    if "logical_call_id" in value:
        normalized["logical_call_id"] = _safe_identifier(value["logical_call_id"], "logical_call_id")
    for key, maximum in (("request_bytes", 65_536), ("request_prompt_chars", 12_000)):
        if key in value:
            raw = value[key]
            if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0 or raw > maximum:
                raise LiveCanaryAuthorityError(f"{key} is outside the bounded request authority")
            normalized[key] = int(raw)
    if any(isinstance(normalized[key], bool) or not isinstance(normalized[key], int) or normalized[key] <= 0 for key in ("current_state_version", "core_schema_version", "control_schema_version", "fencing_token")):
        raise LiveCanaryAuthorityError("version and fencing bindings must be positive integers")
    if normalized["control_schema_version"] not in (19, CONTROL_SCHEMA_VERSION):
        raise LiveCanaryAuthorityError("canary control schema binding is unsupported")
    if normalized["core_schema_version"] != 5:
        raise LiveCanaryAuthorityError("canary core schema binding is not current")
    return normalized


def _redact_preview(value: Mapping[str, Any]) -> dict[str, Any]:
    result = json.loads(canonical_json(value))
    # The preview is already hash-only for endpoint and credential fields;
    # this defensive pass keeps future callers from accidentally returning a
    # copied endpoint, reference name, or absolute path.
    for key in ("endpoint_origin", "endpoint", "credential", "credential_ref", "credential_value", "secret", "api_key", "token"):
        if key in result:
            result[key] = "[redacted]"
    return result


class LiveCanaryAuthorityStore:
    """Repository for independent preview -> approval -> permit transitions."""

    def __init__(self, repository: MaxControlRepository, *, clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("LiveCanaryAuthorityStore requires a MaxControlRepository")
        self.repository = repository
        self.clock = clock if clock is not None else repository.clock

    def _connect(self, *, read_only: bool) -> sqlite3.Connection:
        return self.repository._connect(read_only=read_only)

    def _run_binding(self, connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT run_id, project_id, charter_hash, model_identity, budget_hash, budget_policy_json, current_state_hash, current_checkpoint_id, state_version, status FROM max_runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise LiveCanaryAuthorityError("run is unknown")
        if str(row["status"]).casefold() != "running":
            raise LiveCanaryAuthorityError("canary requires an active RUNNING Max Run")
        return row

    def _assert_worker_fence(self, connection: sqlite3.Connection, *, run_id: str, worker_id: str, worker_session: str, fencing_token: int, now: datetime) -> None:
        lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
        expiry = None if lease is None else _parse_timestamp(lease["expires_at"])
        if lease is None or lease["owner_id"] != worker_id or lease["session_id"] != worker_session or int(lease["fencing_token"]) != int(fencing_token) or expiry is None or expiry <= now:
            raise LiveCanaryAuthorityError("worker lease or fencing token is stale or foreign")

    def _assert_invocation_claim(self, connection: sqlite3.Connection, *, run_id: str, claim_id: str, worker_id: str, worker_session: str, fencing_token: int, now: datetime) -> None:
        claim = connection.execute(
            "SELECT actor_id, actor_session, fencing_token, expires_at, status FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=?",
            (claim_id, run_id),
        ).fetchone()
        expiry = None if claim is None else _parse_timestamp(claim["expires_at"])
        if claim is None or claim["status"] != "active" or claim["actor_id"] != worker_id or claim["actor_session"] != worker_session or int(claim["fencing_token"]) != int(fencing_token) or expiry is None or expiry <= now:
            raise LiveCanaryAuthorityError("runner invocation claim is missing, stale, foreign, or expired")

    def _append_event(self, connection: sqlite3.Connection, *, preview_id: str, run_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str, approval_id: str | None = None, permit_id: str | None = None) -> str:
        previous = connection.execute(
            "SELECT event_hash, sequence_no FROM max_live_canary_events WHERE preview_id=? ORDER BY sequence_no DESC LIMIT 1",
            (preview_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence_no"]) + 1
        payload_value = _safe_json(payload, "event payload")
        payload_hash = _hash(payload_value)
        event_value = {
            "preview_id": preview_id, "run_id": run_id, "approval_id": approval_id,
            "permit_id": permit_id, "sequence_no": sequence, "event_type": event_type,
            "payload_hash": payload_hash, "previous_event_hash": None if previous is None else previous["event_hash"], "created_at": now,
        }
        event_hash = _event_hash(event_value)
        event_id = "live_canary_event_" + event_hash[:48]
        actor_id, actor_kind, actor_session = _actor_fields(actor)
        connection.execute(
            "INSERT INTO max_live_canary_events(event_id, preview_id, run_id, approval_id, permit_id, sequence_no, event_type, payload_json, payload_hash, previous_event_hash, event_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, preview_id, run_id, approval_id, permit_id, sequence, event_type, canonical_json(payload_value), payload_hash, event_value["previous_event_hash"], event_hash, now, actor_id, actor_kind, actor_session),
        )
        return event_id

    def preview(self, *, value: Mapping[str, Any], actor: Actor) -> dict[str, Any]:
        """Create or return a deterministic, non-authorizing preview.

        The caller supplies all bindings explicitly.  This method does not
        discover or choose a project, provider, endpoint, model, passage, or
        credential.
        """
        if not isinstance(value, Mapping):
            raise LiveCanaryAuthorityError("canary preview must be an object")
        allowed_keys = set(_PREVIEW_REQUIRED) | set(_PREVIEW_OPTIONAL) | {"preview_id", "preview_hash", "confirmation_phrase"}
        if set(str(key) for key in value) - allowed_keys:
            raise LiveCanaryAuthorityError("canary preview contains unsupported fields")
        normalized = _normalize_preview_value({key: value[key] for key in _PREVIEW_REQUIRED} | {key: value[key] for key in _PREVIEW_OPTIONAL if key in value})
        if normalized["control_schema_version"] != CONTROL_SCHEMA_VERSION:
            raise LiveCanaryAuthorityError("schema19 Preview is read-only and cannot create a new Preview")
        value_hash = _hash(normalized)
        preview_id = "live_canary_preview_" + value_hash[:48]
        # A fresh Preview may be deliberately held behind the DNS-only
        # boundary.  In that state the control plane must not mint a live
        # Canary confirmation phrase; the later DNS preflight request owns
        # its separate, narrowly scoped confirmation phrase.
        phrase = _preview_confirmation_phrase(value_hash, normalized.get("preview_status"))
        now = _time(self.clock)
        actor_id, actor_kind, actor_session = _actor_fields(actor)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = self._run_binding(connection, normalized["run_id"])
                for key in ("project_id", "charter_hash", "current_state_hash", "current_checkpoint_id", "current_state_version", "model_identity", "budget_hash"):
                    run_key = "project_id" if key == "project_id" else key
                    if key == "current_checkpoint_id":
                        expected = run["current_checkpoint_id"]
                    elif key == "current_state_version":
                        expected = int(run["state_version"])
                    else:
                        expected = run[run_key]
                    if normalized[key] != expected:
                        raise LiveCanaryAuthorityError(f"run binding drift: {key}")
                existing = connection.execute("SELECT preview_json, preview_hash, confirmation_phrase FROM max_live_canary_previews WHERE preview_id=?", (preview_id,)).fetchone()
                if existing is None:
                    connection.execute(
                        "INSERT INTO max_live_canary_previews(preview_id, project_id, run_id, charter_hash, current_state_hash, current_checkpoint_id, current_state_version, engine_package, engine_version, core_schema_version, control_schema_version, candidate_wheel_sha256, source_manifest_sha256, source_tree_sha256, provider_profile_hash, provider_name, model_identity, model_version, pricing_hash, budget_hash, endpoint_origin_hash, endpoint_path_policy_hash, network_policy_hash, credential_ref_hash, source_egress_policy_hash, source_allowlist_json, source_policy_json, runner_profile_hash, worker_id, worker_session, fencing_token, cap_vector_json, cap_vector_hash, transport_policy_json, kill_rollback_incident_policy_json, preview_json, preview_hash, confirmation_phrase, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (preview_id, normalized["project_id"], normalized["run_id"], normalized["charter_hash"], normalized["current_state_hash"], normalized["current_checkpoint_id"], normalized["current_state_version"], normalized["engine_package"], normalized["engine_version"], normalized["core_schema_version"], normalized["control_schema_version"], normalized["candidate_wheel_sha256"], normalized["source_manifest_sha256"], normalized["source_tree_sha256"], normalized["provider_profile_hash"], normalized["provider_name"], normalized["model_identity"], normalized["model_version"], normalized["pricing_hash"], normalized["budget_hash"], normalized["endpoint_origin_hash"], normalized["endpoint_path_policy_hash"], normalized["network_policy_hash"], normalized["credential_ref_hash"], normalized["source_egress_policy_hash"], canonical_json(normalized["source_allowlist"]), canonical_json(normalized["source_policy"]), normalized["runner_profile_hash"], normalized["worker_id"], normalized["worker_session"], normalized["fencing_token"], canonical_json(normalized["caps"]), _hash(normalized["caps"]), canonical_json(normalized["transport_policy"]), canonical_json(normalized["kill_rollback_incident_policy"]), canonical_json(normalized), value_hash, phrase, now, actor_id, actor_kind, actor_session),
                    )
                    self._append_event(connection, preview_id=preview_id, run_id=normalized["run_id"], event_type="preview_created", payload={"preview_hash": value_hash, "project_id": normalized["project_id"], "cap_hash": _hash(normalized["caps"])}, actor=actor, now=now)
                elif existing["preview_hash"] != value_hash or existing["confirmation_phrase"] != phrase or existing["preview_json"] != canonical_json(normalized):
                    raise LiveCanaryAuthorityError("preview hash collision or drift")
        except sqlite3.IntegrityError as exc:
            raise LiveCanaryAuthorityError("canary preview conflicts with durable authority") from exc
        finally:
            connection.close()
        return {"preview_id": preview_id, "preview_hash": value_hash, "confirmation_phrase": phrase, "authority_created": False, "preview": _redact_preview(normalized)}

    def _rebuild_authority_payload(self, connection: sqlite3.Connection, candidate: Mapping[str, Any], *, now: datetime, expires_at: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Rebuild Preview bindings from current server-owned records.

        The candidate carries only release/artifact identities and the exact
        source selection.  Provider, network, runner, lease, claim, run and
        source-policy values are read again from the control database and are
        never trusted from a client-side hash bundle.
        """

        run = self._run_binding(connection, str(candidate["run_id"]))
        if str(run["project_id"]) != candidate["project_id"] or str(run["charter_hash"]) != candidate["charter_hash"]:
            raise LiveCanaryAuthorityError("durable run/project authority does not match the requested binding")
        try:
            from .provider.contract import ProviderProfile
            from .provider.live import credential_reference_hash, endpoint_hashes, network_policy_hash
            from .runner.contracts import RunnerProfile
        except Exception as exc:  # pragma: no cover - package import failure is a hard gate
            raise LiveCanaryAuthorityError("authority contract dependencies are unavailable") from exc

        profile_row = connection.execute("SELECT * FROM max_provider_profiles WHERE profile_hash=?", (candidate["provider_profile_hash"],)).fetchone()
        if profile_row is None:
            raise LiveCanaryAuthorityError("durable provider profile is missing")
        try:
            profile = ProviderProfile.from_mapping(json.loads(profile_row["profile_json"]))
        except Exception as exc:
            raise LiveCanaryAuthorityError("durable provider profile is invalid") from exc
        if profile.profile_hash != profile_row["profile_hash"] or profile.profile_hash != candidate["provider_profile_hash"]:
            raise LiveCanaryAuthorityError("durable provider profile hash drifted")
        origin_hash, path_hash = endpoint_hashes(profile.endpoint_origin, profile.endpoint_path_policy)
        credential_hash = credential_reference_hash(profile.credential_ref)
        durable_model_version = profile.model_revision or "provider-managed-alias"
        if run["model_identity"] != profile.model_identity or candidate["provider_name"] != profile.provider_name or candidate["model_identity"] != profile.model_identity or candidate["model_version"] != durable_model_version or candidate["pricing_hash"] != profile.pricing.pricing_hash or candidate["endpoint_origin_hash"] != origin_hash or candidate["endpoint_path_policy_hash"] != path_hash or candidate["credential_ref_hash"] != credential_hash or candidate["network_policy_hash"] != profile.network_policy_hash:
            raise LiveCanaryAuthorityError("provider, pricing, endpoint or credential-reference authority drifted")

        network_row = connection.execute("SELECT * FROM max_live_network_policies WHERE network_policy_hash=?", (profile.network_policy_hash,)).fetchone()
        if network_row is None:
            raise LiveCanaryAuthorityError("durable live network policy is missing")
        try:
            network_policy = json.loads(network_row["policy_json"])
        except Exception as exc:
            raise LiveCanaryAuthorityError("durable live network policy is invalid") from exc
        if network_policy_hash(network_policy) != profile.network_policy_hash or network_row["policy_hash"] != profile.network_policy_hash:
            raise LiveCanaryAuthorityError("durable live network policy hash drifted")

        source_row = connection.execute("SELECT * FROM max_source_egress_policies WHERE run_id=? AND policy_hash=?", (candidate["run_id"], candidate["source_egress_policy_hash"])).fetchone()
        if source_row is None:
            raise LiveCanaryAuthorityError("durable source-egress policy is missing")
        try:
            source_policy = json.loads(source_row["policy_json"])
        except Exception as exc:
            raise LiveCanaryAuthorityError("durable source-egress policy is invalid") from exc
        if source_row["project_id"] != candidate["project_id"] or source_row["provider_profile_hash"] != profile.profile_hash or canonical_sha256(source_policy) != source_row["policy_hash"]:
            raise LiveCanaryAuthorityError("durable source-egress policy binding drifted")
        if canonical_json(source_policy) != canonical_json(candidate["source_policy"]):
            raise LiveCanaryAuthorityError("source-egress policy differs from the durable authority")
        try:
            allowed_passages = set(json.loads(source_row["allow_passage_ids_json"]))
            allowed_documents = set(json.loads(source_row["allow_document_ids_json"]))
            allowed_versions = set(json.loads(source_row["allowed_source_versions_json"]))
            allowed_purposes = set(json.loads(source_row["allowed_purposes_json"]))
            role_policy = json.loads(source_row["source_role_policy_json"])
            allowed_roles = set(role_policy.get("allowed_roles", ()))
            allowed_functions = set(role_policy.get("allowed_functions", ()))
            reliability_policy = json.loads(source_row["reliability_policy_json"])
            verification_policy = json.loads(source_row["verification_policy_json"])
            allowed_reliability = set(reliability_policy.get("allowed_statuses", ()))
            allowed_verification = set(verification_policy.get("allowed_statuses", ()))
        except Exception as exc:
            raise LiveCanaryAuthorityError("durable source allowlist is invalid") from exc
        for item in candidate["source_allowlist"]:
            if item.get("passage_id") not in allowed_passages or item.get("document_id") not in allowed_documents:
                raise LiveCanaryAuthorityError("exact source allowlist is outside the durable source policy")
            if item.get("document_version_id") not in allowed_versions:
                raise LiveCanaryAuthorityError("source version is outside the durable source policy")
            if item.get("project_id", candidate["project_id"]) != candidate["project_id"]:
                raise LiveCanaryAuthorityError("exact source allowlist crosses the project boundary")
            if item.get("source_role") not in allowed_roles or item.get("evidential_function") not in allowed_functions:
                raise LiveCanaryAuthorityError("source role/function is outside the durable source policy")
            if item.get("verification_status") not in allowed_verification or item.get("reliability_status") not in allowed_reliability:
                raise LiveCanaryAuthorityError("source verification/reliability status is outside the durable source policy")
        if "supports" not in allowed_purposes:
            raise LiveCanaryAuthorityError("server request source purpose is outside the durable source policy")

        runner_row = connection.execute("SELECT * FROM max_runner_profiles WHERE profile_hash=?", (candidate["runner_profile_hash"],)).fetchone()
        if runner_row is None:
            raise LiveCanaryAuthorityError("durable runner profile is missing")
        try:
            runner = RunnerProfile.from_mapping(json.loads(runner_row["profile_json"]))
        except Exception as exc:
            raise LiveCanaryAuthorityError("durable runner profile is invalid") from exc
        if runner.profile_hash != candidate["runner_profile_hash"] or runner.model_identity != profile.model_identity:
            raise LiveCanaryAuthorityError("durable runner profile is not bound to the provider model")

        lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at, runner_profile_hash FROM max_leases WHERE run_id=?", (candidate["run_id"],)).fetchone()
        lease_expiry = None if lease is None else _parse_timestamp(lease["expires_at"])
        if lease is None or lease["released_at"] is not None or lease["runner_profile_hash"] != runner.profile_hash or lease_expiry is None or lease_expiry <= now or lease["owner_id"] != candidate["worker_id"] or lease["session_id"] != candidate["worker_session"] or int(lease["fencing_token"]) != int(candidate["fencing_token"]):
            raise LiveCanaryAuthorityError("durable lease or fencing authority is stale, foreign, or drifted")
        authority_expiry = _parse_timestamp(expires_at)
        if authority_expiry is None or authority_expiry <= now or authority_expiry > lease_expiry:
            raise LiveCanaryAuthorityError("canary authority expiry is outside the active lease")

        claim = connection.execute("SELECT actor_id, actor_session, fencing_token, expires_at, status FROM max_runner_invocation_claims WHERE claim_id=? AND run_id=?", (candidate["claim_id"], candidate["run_id"])).fetchone()
        claim_expiry = None if claim is None else _parse_timestamp(claim["expires_at"])
        if claim is None or claim["status"] != "active" or claim["actor_id"] != candidate["worker_id"] or claim["actor_session"] != candidate["worker_session"] or int(claim["fencing_token"]) != int(candidate["fencing_token"]) or claim_expiry is None or claim_expiry <= now:
            raise LiveCanaryAuthorityError("durable invocation claim is missing, stale, foreign, or expired")

        # The profile is the server-owned source of the maximum usage/cost
        # authority.  Cost is integer micro-USD throughout: PricingSnapshot
        # applies the reviewed ROUND_CEILING rule before this boundary.  The
        # human ceiling remains a separate approval fact; execution uses the
        # effective minimum of that ceiling and the profile worst case.
        try:
            maximum_usage = profile.authority_maximum_usage()
            maximum_cost = profile.pricing.cost_units_for_usage(maximum_usage)
        except Exception as exc:
            raise LiveCanaryAuthorityError("provider profile has no bounded usage authority") from exc
        human_cost_ceiling = candidate.get("human_cost_ceiling", candidate["caps"].get("max_cost_units"))
        if isinstance(human_cost_ceiling, bool) or not isinstance(human_cost_ceiling, int) or human_cost_ceiling < 0 or human_cost_ceiling > 10_000_000:
            raise LiveCanaryAuthorityError("human cost ceiling is not a bounded integer micro-USD value")
        effective_cost = min(int(human_cost_ceiling), int(maximum_cost))
        candidate_cost = int(candidate["caps"]["max_cost_units"])
        if candidate_cost not in {int(human_cost_ceiling), effective_cost}:
            raise LiveCanaryAuthorityError("canary cost cap is neither the human ceiling nor the effective provider cap")
        if "profile_worst_case_cost" in candidate and int(candidate["profile_worst_case_cost"]) != int(maximum_cost):
            raise LiveCanaryAuthorityError("provider profile worst-case cost changed since the Preview candidate")
        if "effective_provider_cost_cap" in candidate and int(candidate["effective_provider_cost_cap"]) != effective_cost:
            raise LiveCanaryAuthorityError("effective provider cost cap changed since the Preview candidate")
        cap_limits = {
            "max_input_tokens": int(maximum_usage["input_tokens"]),
            "max_output_tokens": int(maximum_usage["output_tokens"]),
            "max_cache_read_tokens": int(maximum_usage["cache_read_tokens"]),
            "max_reasoning_tokens": int(maximum_usage["reasoning_tokens"]),
            "max_cost_units": int(maximum_cost),
        }
        if any(int(candidate["caps"][key]) > limit for key, limit in cap_limits.items() if key != "max_cost_units"):
            raise LiveCanaryAuthorityError("canary token cap vector exceeds the durable provider authority")
        try:
            budget_value = json.loads(run["budget_policy_json"])
            budget_cost = int(budget_value.get("max_cost_units", budget_value.get("cost_units")))
        except Exception as exc:
            raise LiveCanaryAuthorityError("durable run budget authority is invalid") from exc
        if int(human_cost_ceiling) > budget_cost:
            raise LiveCanaryAuthorityError("human cost ceiling exceeds the durable Charter budget")

        fresh = dict(candidate)
        fresh["caps"] = {**candidate["caps"], "max_cost_units": effective_cost}
        fresh.update({
            "project_id": run["project_id"], "charter_hash": run["charter_hash"],
            "current_state_hash": run["current_state_hash"], "current_checkpoint_id": run["current_checkpoint_id"],
            "current_state_version": int(run["state_version"]), "provider_profile_hash": profile.profile_hash,
            "provider_name": profile.provider_name, "model_identity": profile.model_identity, "model_version": durable_model_version,
            "pricing_hash": profile.pricing.pricing_hash, "budget_hash": run["budget_hash"],
            "endpoint_origin_hash": origin_hash, "endpoint_path_policy_hash": path_hash,
            "network_policy_hash": profile.network_policy_hash, "credential_ref_hash": credential_hash,
            "source_egress_policy_hash": source_row["policy_hash"], "source_policy": source_policy,
            "runner_profile_hash": runner.profile_hash, "worker_id": lease["owner_id"],
            "worker_session": lease["session_id"], "fencing_token": int(lease["fencing_token"]),
            "human_cost_ceiling": int(human_cost_ceiling),
            "profile_worst_case_cost": int(maximum_cost),
            "effective_provider_cost_cap": int(effective_cost),
        })
        details: dict[str, Any] = {}
        # MR-4B1A-R closes the last caller-controlled boundary by rebuilding a
        # hash-only request manifest from the unfinished durable intent, the
        # frozen runner plan and the fixed local core evidence gateway.  A
        # fixture authority without runner history keeps the historical
        # fixture seam, but production-shaped authorities fail closed.
        try:
            from .request_builder import ServerOwnedRequestBuilder, ServerRequestBuildError
            built = ServerOwnedRequestBuilder().build_from_row(
                authority={**fresh, "_provider_profile": profile},
                connection=connection,
                provider_profile=profile,
            )
            manifest = dict(built.manifest)
            fresh.update({
                "request_manifest_hash": manifest["manifest_hash"],
                "wire_request_hash": manifest["wire_request_hash"],
                "request_hash": manifest["request_hash"],
                "intent_hash": manifest["intent_hash"],
                "logical_call_id": manifest["logical_call_id"],
                "request_bytes": manifest["request_bytes"],
                "request_prompt_chars": manifest["prompt_chars"],
            })
            details["request_manifest"] = manifest
        except Exception as exc:
            try:
                is_fixture = self.repository.is_fixture_database()
            except Exception:
                is_fixture = False
            if not is_fixture:
                if isinstance(exc, LiveCanaryAuthorityError):
                    raise
                raise LiveCanaryAuthorityError("server-owned request manifest could not be rebuilt") from exc
            # Existing fixture tests intentionally do not create runner plans
            # or the Pilot core database.  Keep their explicit fixture-only
            # preview contract deterministic without making it a production
            # execution path.
            fallback = {
                "manifest_version": "mr4b1a-r/fixture-v1",
                "project_id": fresh["project_id"], "run_id": fresh["run_id"],
                "request_hash": canonical_sha256({"run_id": fresh["run_id"], "fixture": True}),
                "intent_hash": canonical_sha256({"run_id": fresh["run_id"], "fixture_intent": True}),
                "wire_request_hash": canonical_sha256({"run_id": fresh["run_id"], "fixture_wire": True}),
                "logical_call_id": "fixture-server-owned-logical-call",
                "request_bytes": 1, "prompt_chars": 1,
            }
            fallback["manifest_hash"] = canonical_sha256(fallback)
            fresh.update({
                "request_manifest_hash": fallback["manifest_hash"],
                "wire_request_hash": fallback["wire_request_hash"],
                "request_hash": fallback["request_hash"],
                "intent_hash": fallback["intent_hash"],
                "logical_call_id": fallback["logical_call_id"],
                "request_bytes": fallback["request_bytes"],
                "request_prompt_chars": fallback["prompt_chars"],
            })
            details["request_manifest"] = fallback
        return fresh, {**details, "profile": profile, "runner": runner, "network_policy": network_policy, "credential_ref": profile.credential_ref.to_mapping(), "source_policy": source_policy, "lease_expires_at": lease["expires_at"], "claim_expires_at": claim["expires_at"]}

    def register_authority(self, *, value: Mapping[str, Any], expires_at: str, actor: Actor) -> dict[str, Any]:
        """Persist a server-revalidated authority snapshot for a new Preview."""

        _admin(actor)
        normalized = _normalize_preview_value(value)
        if normalized["control_schema_version"] != CONTROL_SCHEMA_VERSION:
            raise LiveCanaryAuthorityError("schema19 Preview is read-only and cannot create a new Authority")
        now_dt = _now(self.clock)
        now = _time(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                fresh, details = self._rebuild_authority_payload(connection, normalized, now=now_dt, expires_at=expires_at)
                preview_hash = _hash(fresh)
                authority_hash = _hash({"authority": fresh})
                authority_id = "live_canary_authority_" + authority_hash[:48]
                preview_id = "live_canary_preview_" + preview_hash[:48]
                existing = connection.execute("SELECT authority_json, authority_hash, preview_hash, preview_id FROM max_live_canary_authority_bindings WHERE authority_id=?", (authority_id,)).fetchone()
                if existing is not None:
                    if existing["authority_hash"] != authority_hash or existing["authority_json"] != canonical_json(fresh):
                        raise LiveCanaryAuthorityError("server authority ID collision or drift")
                    return {"authority_id": authority_id, "preview_id": existing["preview_id"], "preview_hash": existing["preview_hash"], "authority_hash": authority_hash, "idempotent": True, "authority": _redact_preview(fresh), "durable_counts": {"provider_profiles": 1, "runner_profiles": 1, "network_policies": 1, "source_egress_policies": 1}}
                actor_id, actor_kind, actor_session = _actor_fields(actor)
                credential_ref = details["credential_ref"]
                connection.execute(
                    "INSERT INTO max_live_canary_authority_bindings(authority_id,preview_id,preview_hash,project_id,run_id,charter_hash,current_state_hash,current_checkpoint_id,current_state_version,engine_package,engine_version,core_schema_version,control_schema_version,candidate_wheel_sha256,source_manifest_sha256,source_tree_sha256,provider_profile_hash,provider_name,model_identity,model_version,pricing_hash,budget_hash,endpoint_origin_hash,endpoint_path_policy_hash,network_policy_hash,credential_ref_hash,source_egress_policy_hash,source_allowlist_json,source_policy_json,network_policy_json,credential_ref_json,runner_profile_hash,worker_id,worker_session,fencing_token,claim_id,cap_vector_json,cap_vector_hash,transport_policy_json,kill_rollback_incident_policy_json,authority_json,authority_hash,expires_at,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (authority_id, preview_id, preview_hash, fresh["project_id"], fresh["run_id"], fresh["charter_hash"], fresh["current_state_hash"], fresh["current_checkpoint_id"], fresh["current_state_version"], fresh["engine_package"], fresh["engine_version"], fresh["core_schema_version"], fresh["control_schema_version"], fresh["candidate_wheel_sha256"], fresh["source_manifest_sha256"], fresh["source_tree_sha256"], fresh["provider_profile_hash"], fresh["provider_name"], fresh["model_identity"], fresh["model_version"], fresh["pricing_hash"], fresh["budget_hash"], fresh["endpoint_origin_hash"], fresh["endpoint_path_policy_hash"], fresh["network_policy_hash"], fresh["credential_ref_hash"], fresh["source_egress_policy_hash"], canonical_json(fresh["source_allowlist"]), canonical_json(fresh["source_policy"]), canonical_json(details["network_policy"]), canonical_json(credential_ref), fresh["runner_profile_hash"], fresh["worker_id"], fresh["worker_session"], fresh["fencing_token"], fresh["claim_id"], canonical_json(fresh["caps"]), _hash(fresh["caps"]), canonical_json(fresh["transport_policy"]), canonical_json(fresh["kill_rollback_incident_policy"]), canonical_json(fresh), authority_hash, expires_at, now, actor_id, actor_kind, actor_session),
                )
        except sqlite3.IntegrityError as exc:
            raise LiveCanaryAuthorityError("server authority binding conflicts with an immutable record") from exc
        finally:
            connection.close()
        return {"authority_id": authority_id, "preview_id": preview_id, "preview_hash": preview_hash, "authority_hash": authority_hash, "idempotent": False, "authority": _redact_preview(fresh), "durable_counts": {"provider_profiles": 1, "runner_profiles": 1, "network_policies": 1, "source_egress_policies": 1}}

    def preview_from_authority(self, *, authority_id: str, actor: Actor) -> dict[str, Any]:
        """Rebuild and persist a Preview exclusively from a durable snapshot."""

        stored_preview_id: str | None = None
        stored_preview_hash: str | None = None
        stored_authority_hash: str | None = None
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_live_canary_authority_bindings WHERE authority_id=?", (authority_id,)).fetchone()
            if row is None:
                raise LiveCanaryAuthorityError("server canary authority was not found")
            stored_preview_id = str(row["preview_id"])
            stored_preview_hash = str(row["preview_hash"])
            stored_authority_hash = str(row["authority_hash"])
            try:
                stored = json.loads(row["authority_json"])
            except Exception as exc:
                raise LiveCanaryAuthorityError("server canary authority JSON is invalid") from exc
            if stored.get("control_schema_version") != CONTROL_SCHEMA_VERSION:
                raise LiveCanaryAuthorityError("schema19 authority is read-only and cannot be upgraded")
            if _hash({"authority": stored}) != stored_authority_hash or _hash(stored) != stored_preview_hash or stored_preview_id != "live_canary_preview_" + stored_preview_hash[:48]:
                raise LiveCanaryAuthorityError("server canary authority hash projection is invalid")
            fresh, details = self._rebuild_authority_payload(connection, _normalize_preview_value(stored), now=_now(self.clock), expires_at=row["expires_at"])
            if canonical_json(fresh) != canonical_json(stored):
                raise LiveCanaryAuthorityError("server canary authority drifted since it was bound")
        finally:
            connection.close()
        result = self.preview(value=fresh, actor=actor)
        if result["preview_id"] != stored_preview_id or result["preview_hash"] != stored_preview_hash:
            raise LiveCanaryAuthorityError("durable authority rebuilt a different Preview")
        self._persist_request_manifest(authority_id=authority_id, preview=result, details=details, actor=actor)
        return {**result, "authority_id": authority_id, "authority_hash": stored_authority_hash, "durable_authority": True}

    def _persist_request_manifest(self, *, authority_id: str, preview: Mapping[str, Any], details: Mapping[str, Any], actor: Actor) -> None:
        manifest = details.get("request_manifest")
        if not isinstance(manifest, Mapping):
            return
        if str(manifest.get("manifest_version", "")).startswith("mr4b1a-r/fixture"):
            return
        required = ("manifest_hash", "wire_request_hash", "request_hash", "intent_hash", "logical_call_id", "request_bytes", "prompt_chars", "project_id", "run_id", "intent_id", "provider_profile_hash", "source_policy_hash", "passage_id", "document_id", "source_version", "source_role", "evidential_function", "purpose", "document_content_hash", "passage_content_hash", "input_state_hash", "wire_template_hash", "max_input_tokens", "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens", "max_cache_read_tokens")
        if any(key not in manifest for key in required):
            raise LiveCanaryAuthorityError("server request manifest is incomplete")
        now = _time(self.clock)
        actor_id, actor_kind, actor_session = _actor_fields(actor)
        manifest_id = "live_canary_request_manifest_" + str(manifest["manifest_hash"])[:48]
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                existing = connection.execute("SELECT manifest_json, manifest_hash FROM max_live_canary_request_manifests WHERE manifest_hash=?", (manifest["manifest_hash"],)).fetchone()
                if existing is not None:
                    if existing["manifest_json"] != canonical_json(manifest):
                        raise LiveCanaryAuthorityError("request manifest hash collision")
                    return
                connection.execute(
                    "INSERT INTO max_live_canary_request_manifests(manifest_id,authority_id,preview_id,preview_hash,project_id,run_id,logical_call_id,intent_id,intent_hash,request_hash,provider_profile_hash,source_policy_hash,passage_id,document_id,source_version,source_role,evidential_function,purpose,document_content_hash,passage_content_hash,input_state_hash,wire_template_hash,wire_request_hash,request_bytes,prompt_chars,max_input_tokens,max_output_tokens,max_cache_read_tokens,max_reasoning_tokens,manifest_json,manifest_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (manifest_id, authority_id, preview["preview_id"], preview["preview_hash"], manifest["project_id"], manifest["run_id"], manifest["logical_call_id"], manifest["intent_id"], manifest["intent_hash"], manifest["request_hash"], manifest["provider_profile_hash"], manifest["source_policy_hash"], manifest["passage_id"], manifest["document_id"], manifest["source_version"], manifest["source_role"], manifest["evidential_function"], manifest["purpose"], manifest["document_content_hash"], manifest["passage_content_hash"], manifest["input_state_hash"], manifest["wire_template_hash"], manifest["wire_request_hash"], int(manifest["request_bytes"]), int(manifest["prompt_chars"]), int(manifest["max_input_tokens"]), int(manifest["max_output_tokens"]), int(manifest["max_cache_read_tokens"]), int(manifest["max_reasoning_tokens"]), canonical_json(manifest), manifest["manifest_hash"], now, actor_id, actor_kind, actor_session),
                )
        except sqlite3.IntegrityError as exc:
            raise LiveCanaryAuthorityError("request manifest conflicts with an immutable record") from exc
        finally:
            connection.close()

    def load_request_manifest(self, *, authority_id: str, manifest_hash: str) -> dict[str, Any]:
        expected = _require_hash(manifest_hash, "request_manifest_hash")
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT manifest_json, manifest_hash, preview_hash FROM max_live_canary_request_manifests WHERE authority_id=? AND manifest_hash=?", (authority_id, expected)).fetchone()
            if row is None:
                raise LiveCanaryAuthorityError("server request manifest is missing or foreign")
            value = json.loads(row["manifest_json"])
            stored_hash = value.get("manifest_hash") if isinstance(value, Mapping) else None
            unhashed = dict(value) if isinstance(value, Mapping) else {}
            unhashed.pop("manifest_hash", None)
            if _hash(unhashed) != row["manifest_hash"] or stored_hash != row["manifest_hash"] or row["manifest_hash"] != expected:
                raise LiveCanaryAuthorityError("server request manifest hash drifted")
            return value
        except LiveCanaryAuthorityError:
            raise
        except Exception as exc:
            raise LiveCanaryAuthorityError("server request manifest is invalid") from exc
        finally:
            connection.close()

    def issue_source_permit(self, *, authority_id: str, approval_id: str, canary_permit_id: str, manifest: Mapping[str, Any], worker_id: str, worker_session: str, fencing_token: int, actor: Actor) -> dict[str, Any]:
        """Issue one append-only source-egress permit after approval consumption."""

        required = ("manifest_hash", "project_id", "run_id", "passage_id", "document_id", "source_version", "source_policy_hash", "logical_call_id")
        if any(key not in manifest for key in required):
            raise LiveCanaryAuthorityError("source permit manifest is incomplete")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise LiveCanaryAuthorityError("source permit fencing token is invalid")
        now_dt = _now(self.clock); now = _time(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                authority = connection.execute("SELECT * FROM max_live_canary_authority_bindings WHERE authority_id=?", (authority_id,)).fetchone()
                preview = connection.execute("SELECT * FROM max_live_canary_previews WHERE preview_id=?", (authority["preview_id"] if authority else "",)).fetchone()
                approval = connection.execute("SELECT * FROM max_live_canary_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                current_approval = connection.execute("SELECT * FROM max_live_canary_approval_current WHERE approval_id=?", (approval_id,)).fetchone()
                if authority is None or preview is None or approval is None or current_approval is None or current_approval["state"] != "consumed":
                    raise LiveCanaryAuthorityError("source permit is outside the consumed approval closure")
                if approval["preview_hash"] != authority["preview_hash"]:
                    raise LiveCanaryAuthorityError("source permit authority binding drifted")
                try:
                    preview_value = json.loads(preview["preview_json"])
                    allowlist = json.loads(authority["source_allowlist_json"])
                except Exception as exc:
                    raise LiveCanaryAuthorityError("source permit authority JSON is invalid") from exc
                if not isinstance(preview_value, Mapping) or preview_value.get("request_manifest_hash") != manifest["manifest_hash"]:
                    raise LiveCanaryAuthorityError("source permit is not bound to the Preview request manifest")
                if not isinstance(allowlist, list) or len(allowlist) != 1 or not isinstance(allowlist[0], Mapping):
                    raise LiveCanaryAuthorityError("source permit exact source allowlist is invalid")
                selected = allowlist[0]
                if any(
                    manifest.get(manifest_key) != selected.get(allowlist_key)
                    for manifest_key, allowlist_key in (
                        ("passage_id", "passage_id"),
                        ("document_id", "document_id"),
                        ("source_version", "document_version_id"),
                        ("source_role", "source_role"),
                        ("evidential_function", "evidential_function"),
                    )
                ):
                    raise LiveCanaryAuthorityError("source permit exact passage/document binding drifted")
                if approval["approval_id"] != approval_id or approval["run_id"] != manifest["run_id"] or approval["project_id"] != manifest["project_id"]:
                    raise LiveCanaryAuthorityError("source permit project/run binding drifted")
                if str(authority["preview_hash"]) != str(preview["preview_hash"]):
                    raise LiveCanaryAuthorityError("source permit Preview hash drifted")
                if authority["source_egress_policy_hash"] != manifest["source_policy_hash"]:
                    raise LiveCanaryAuthorityError("source permit policy hash drifted")
                if manifest.get("provider_profile_hash") != authority["provider_profile_hash"]:
                    raise LiveCanaryAuthorityError("source permit provider binding drifted")
                canary_permit = connection.execute(
                    "SELECT permit_id, approval_id, preview_id, run_id, project_id FROM max_live_canary_execution_permits WHERE permit_id=?",
                    (canary_permit_id,),
                ).fetchone()
                if canary_permit is None or canary_permit["approval_id"] != approval_id or canary_permit["preview_id"] != preview["preview_id"] or canary_permit["run_id"] != manifest["run_id"] or canary_permit["project_id"] != manifest["project_id"]:
                    raise LiveCanaryAuthorityError("source permit canary execution binding drifted")
                if worker_id != authority["worker_id"] or worker_session != authority["worker_session"] or int(fencing_token) != int(authority["fencing_token"]):
                    raise LiveCanaryAuthorityError("source permit worker/fence binding drifted")
                expiry = _parse_timestamp(authority["expires_at"])
                if expiry is None or expiry <= now_dt:
                    raise LiveCanaryAuthorityError("source permit authority is expired")
                existing = connection.execute("SELECT * FROM max_live_canary_source_permits WHERE approval_id=? AND request_manifest_hash=?", (approval_id, manifest["manifest_hash"])).fetchone()
                if existing is not None:
                    current = connection.execute("SELECT state FROM max_live_canary_source_permit_current WHERE source_permit_id=?", (existing["source_permit_id"],)).fetchone()
                    if current is None:
                        raise LiveCanaryAuthorityError("source permit projection is missing")
                    return {"source_permit_id": existing["source_permit_id"], "permit_hash": existing["permit_hash"], "state": current["state"], "idempotent": True}
                policy = json.loads(preview["source_policy_json"])
                max_chars = min(2000, int(policy.get("max_source_characters", 2000)))
                max_tokens = min(512, int(policy.get("max_source_tokens", 512)))
                value = {
                    "source_permit_id": "live_canary_source_permit_" + uuid.uuid4().hex,
                    "authority_id": authority_id, "preview_id": preview["preview_id"], "approval_id": approval_id,
                    "canary_permit_id": canary_permit_id, "project_id": manifest["project_id"], "run_id": manifest["run_id"],
                    "passage_id": manifest["passage_id"], "document_id": manifest["document_id"], "source_version": manifest["source_version"],
                    "purpose": manifest.get("purpose", "supports"), "source_role": manifest.get("source_role", "primary"),
                    "evidential_function": manifest.get("evidential_function", "supports"), "source_policy_hash": manifest["source_policy_hash"],
                    "request_manifest_hash": manifest["manifest_hash"], "worker_id": worker_id, "worker_session": worker_session,
                    "fencing_token": fencing_token, "expires_at": authority["expires_at"], "max_source_characters": max_chars, "max_source_tokens": max_tokens, "created_at": now,
                }
                permit_hash = _hash(value)
                value["permit_hash"] = permit_hash
                actor_id, actor_kind, actor_session = _actor_fields(actor)
                connection.execute("INSERT INTO max_live_canary_source_permits(source_permit_id,authority_id,preview_id,approval_id,canary_permit_id,project_id,run_id,passage_id,document_id,source_version,purpose,source_role,evidential_function,source_policy_hash,request_manifest_hash,worker_id,worker_session,fencing_token,expires_at,max_source_characters,max_source_tokens,permit_json,permit_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (value["source_permit_id"], authority_id, value["preview_id"], approval_id, canary_permit_id, value["project_id"], value["run_id"], value["passage_id"], value["document_id"], value["source_version"], value["purpose"], value["source_role"], value["evidential_function"], value["source_policy_hash"], value["request_manifest_hash"], worker_id, worker_session, fencing_token, value["expires_at"], max_chars, max_tokens, canonical_json(value), permit_hash, now, actor_id, actor_kind, actor_session))
                current_value = {"source_permit_id": value["source_permit_id"], "project_id": value["project_id"], "run_id": value["run_id"], "state": "issued", "consumed_at": None, "updated_at": now}
                connection.execute("INSERT INTO max_live_canary_source_permit_current(source_permit_id,project_id,run_id,state,consumed_at,current_json,current_hash,updated_at) VALUES (?,?,?,?,?,?,?,?)", (value["source_permit_id"], value["project_id"], value["run_id"], "issued", None, canonical_json(current_value), _hash(current_value), now))
                payload = {"source_permit_id": value["source_permit_id"], "permit_hash": permit_hash, "request_manifest_hash": value["request_manifest_hash"], "passage_id": value["passage_id"], "source_version": value["source_version"]}
                payload_hash = _hash(payload); event_value = {"source_permit_id": value["source_permit_id"], "project_id": value["project_id"], "run_id": value["run_id"], "sequence_no": 1, "event_type": "source_permit_issued", "payload_hash": payload_hash, "previous_event_hash": None, "created_at": now}
                event_hash = _hash(event_value)
                connection.execute("INSERT INTO max_live_canary_source_permit_events(source_permit_event_id,source_permit_id,project_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("live_canary_source_permit_event_" + event_hash[:48], value["source_permit_id"], value["project_id"], value["run_id"], 1, "source_permit_issued", canonical_json(payload), payload_hash, None, event_hash, now, actor_id, actor_kind, actor_session))
                return {"source_permit_id": value["source_permit_id"], "permit_hash": permit_hash, "state": "issued", "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise LiveCanaryAuthorityError("source permit conflicts with an immutable record") from exc
        finally:
            connection.close()

    def consume_source_permit(self, *, source_permit_id: str, manifest_hash: str, worker_id: str, worker_session: str, fencing_token: int, actor: Actor) -> dict[str, Any]:
        expected = _require_hash(manifest_hash, "request_manifest_hash")
        now_dt = _now(self.clock); now = _time(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_live_canary_source_permits WHERE source_permit_id=?", (source_permit_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_canary_source_permit_current WHERE source_permit_id=?", (source_permit_id,)).fetchone()
                if row is None or current is None or row["request_manifest_hash"] != expected or current["state"] != "issued":
                    raise LiveCanaryAuthorityError("source permit is missing, replayed, expired or drifted")
                approval_current = connection.execute("SELECT state FROM max_live_canary_approval_current WHERE approval_id=?", (row["approval_id"],)).fetchone()
                if approval_current is None or approval_current["state"] != "consumed":
                    raise LiveCanaryAuthorityError("source permit approval closure is not consumed")
                expiry = _parse_timestamp(row["expires_at"])
                if expiry is None or expiry <= now_dt:
                    raise LiveCanaryAuthorityError("source permit has expired")
                if row["worker_id"] != worker_id or row["worker_session"] != worker_session or int(row["fencing_token"]) != int(fencing_token):
                    raise LiveCanaryAuthorityError("source permit worker/fence binding drifted")
                value = {"source_permit_id": source_permit_id, "project_id": row["project_id"], "run_id": row["run_id"], "state": "consumed", "consumed_at": now, "updated_at": now}
                connection.execute("UPDATE max_live_canary_source_permit_current SET state='consumed', consumed_at=?, current_json=?, current_hash=?, updated_at=? WHERE source_permit_id=? AND state='issued'", (now, canonical_json(value), _hash(value), now, source_permit_id))
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise LiveCanaryAuthorityError("source permit consumption lost its atomic race")
                previous = connection.execute("SELECT event_hash,sequence_no FROM max_live_canary_source_permit_events WHERE source_permit_id=? ORDER BY sequence_no DESC LIMIT 1", (source_permit_id,)).fetchone()
                payload = {"source_permit_id": source_permit_id, "request_manifest_hash": expected, "consumed_at": now}; payload_hash = _hash(payload)
                event_value = {"source_permit_id": source_permit_id, "project_id": row["project_id"], "run_id": row["run_id"], "sequence_no": int(previous["sequence_no"]) + 1, "event_type": "source_permit_consumed", "payload_hash": payload_hash, "previous_event_hash": previous["event_hash"], "created_at": now}; event_hash = _hash(event_value)
                connection.execute("INSERT INTO max_live_canary_source_permit_events(source_permit_event_id,source_permit_id,project_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("live_canary_source_permit_event_" + event_hash[:48], source_permit_id, row["project_id"], row["run_id"], event_value["sequence_no"], "source_permit_consumed", canonical_json(payload), payload_hash, previous["event_hash"], event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                return {"source_permit_id": source_permit_id, "state": "consumed", "permit_hash": row["permit_hash"]}
        finally:
            connection.close()

    def revoke_source_permit(self, *, source_permit_id: str, actor: Actor, reason: str = "known_pre_send_failure") -> dict[str, Any]:
        """Make an issued source permit unusable after a known pre-send failure."""

        if not isinstance(reason, str) or not reason or len(reason) > 256 or "\r" in reason or "\n" in reason or _SECRET_RE.search(reason):
            raise LiveCanaryAuthorityError("source permit revoke reason is invalid")
        now = _time(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_live_canary_source_permits WHERE source_permit_id=?", (source_permit_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_canary_source_permit_current WHERE source_permit_id=?", (source_permit_id,)).fetchone()
                if row is None or current is None:
                    raise LiveCanaryAuthorityError("source permit is unknown")
                if current["state"] == "revoked":
                    return {"source_permit_id": source_permit_id, "state": "revoked", "idempotent": True}
                if current["state"] != "issued":
                    return {"source_permit_id": source_permit_id, "state": current["state"], "idempotent": True}
                value = {
                    "source_permit_id": source_permit_id,
                    "project_id": row["project_id"],
                    "run_id": row["run_id"],
                    "state": "revoked",
                    "consumed_at": None,
                    "reason_hash": _hash(reason.strip()),
                    "updated_at": now,
                }
                connection.execute(
                    "UPDATE max_live_canary_source_permit_current SET state='revoked', consumed_at=NULL, current_json=?, current_hash=?, updated_at=? WHERE source_permit_id=? AND state='issued'",
                    (canonical_json(value), _hash(value), now, source_permit_id),
                )
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise LiveCanaryAuthorityError("source permit revoke lost its atomic race")
                previous = connection.execute("SELECT event_hash,sequence_no FROM max_live_canary_source_permit_events WHERE source_permit_id=? ORDER BY sequence_no DESC LIMIT 1", (source_permit_id,)).fetchone()
                payload = {"source_permit_id": source_permit_id, "reason_hash": value["reason_hash"], "revoked_at": now}
                payload_hash = _hash(payload)
                event_value = {
                    "source_permit_id": source_permit_id,
                    "project_id": row["project_id"],
                    "run_id": row["run_id"],
                    "sequence_no": int(previous["sequence_no"]) + 1,
                    "event_type": "source_permit_revoked",
                    "payload_hash": payload_hash,
                    "previous_event_hash": previous["event_hash"] if previous is not None else None,
                    "created_at": now,
                }
                event_hash = _hash(event_value)
                connection.execute(
                    "INSERT INTO max_live_canary_source_permit_events(source_permit_event_id,source_permit_id,project_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("live_canary_source_permit_event_" + event_hash[:48], source_permit_id, row["project_id"], row["run_id"], event_value["sequence_no"], event_value["event_type"], canonical_json(payload), payload_hash, event_value["previous_event_hash"], event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id),
                )
            return {"source_permit_id": source_permit_id, "state": "revoked", "idempotent": False}
        finally:
            connection.close()

    def authority_preflight(self, *, authority_id: str) -> dict[str, Any]:
        """Read-only revalidation used by status/execute/reconcile paths."""

        plan = self.validate_live_execution_plan(authority_id=authority_id)
        return {"ok": bool(plan["execution_plan_ok"]), **plan}

    def validate_live_execution_plan(
        self,
        *,
        authority_id: str | None = None,
        preview_id: str | None = None,
        preview_hash: str | None = None,
    ) -> dict[str, Any]:
        """Read-only, server-owned preflight for the complete canary plan.

        This method only opens a read-only SQLite connection.  It does not
        create Approval, permits, grants, network authorization, claims, or
        reservations, and it never reads credentials or performs DNS/network
        work.
        """

        if (authority_id is None) == (preview_id is None):
            raise LiveCanaryAuthorityError("execution-plan preflight requires exactly one authority or Preview selector")
        connection = self._connect(read_only=True)
        try:
            if authority_id is not None:
                row = connection.execute("SELECT * FROM max_live_canary_authority_bindings WHERE authority_id=?", (authority_id,)).fetchone()
                if row is None:
                    raise LiveCanaryAuthorityError("server canary authority was not found")
                stored = json.loads(row["authority_json"])
                fresh, details = self._rebuild_authority_payload(connection, _normalize_preview_value(stored), now=_now(self.clock), expires_at=row["expires_at"])
                if canonical_json(fresh) != canonical_json(stored) or _hash(fresh) != row["preview_hash"]:
                    raise LiveCanaryAuthorityError("server canary authority has drifted")
                selected_authority_id = str(authority_id)
                selected_preview_id = str(row["preview_id"])
                selected_preview_hash = str(row["preview_hash"])
                selected_authority_hash = str(row["authority_hash"])
                expires_at = row["expires_at"]
                production_binding = True
            else:
                preview_row = connection.execute("SELECT * FROM max_live_canary_previews WHERE preview_id=?", (preview_id,)).fetchone()
                if preview_row is None:
                    raise LiveCanaryAuthorityError("canary Preview was not found")
                selected_preview_id = str(preview_row["preview_id"])
                selected_preview_hash = str(preview_row["preview_hash"])
                if preview_hash is not None and str(preview_hash) != selected_preview_hash:
                    raise LiveCanaryAuthorityError("canary Preview hash drifted")
                authority_row = connection.execute("SELECT * FROM max_live_canary_authority_bindings WHERE preview_id=?", (selected_preview_id,)).fetchone()
                if authority_row is not None:
                    stored = json.loads(authority_row["authority_json"])
                    fresh, details = self._rebuild_authority_payload(connection, _normalize_preview_value(stored), now=_now(self.clock), expires_at=authority_row["expires_at"])
                    if canonical_json(fresh) != canonical_json(stored) or _hash(fresh) != authority_row["preview_hash"]:
                        raise LiveCanaryAuthorityError("server canary authority has drifted")
                    selected_authority_id = str(authority_row["authority_id"])
                    selected_authority_hash = str(authority_row["authority_hash"])
                    selected_preview_hash = str(authority_row["preview_hash"])
                    expires_at = authority_row["expires_at"]
                    production_binding = True
                else:
                    if not self.repository.is_fixture_database():
                        raise LiveCanaryAuthorityError("production Approval requires a server-owned authority binding")
                    stored = json.loads(preview_row["preview_json"])
                    fresh = _normalize_preview_value(stored)
                    details = {"credential_ref": {"kind": "fixture", "name": "fixture"}, "profile": None, "request_manifest": {}}
                    selected_authority_id = None
                    selected_authority_hash = None
                    expires_at = None
                    production_binding = False

            caps = dict(fresh["caps"])
            human_cost_ceiling = int(fresh.get("human_cost_ceiling", caps["max_cost_units"]))
            profile_worst_case_cost = fresh.get("profile_worst_case_cost")
            if profile_worst_case_cost is None:
                profile = details.get("profile")
                if profile is None:
                    profile_worst_case_cost = int(caps["max_cost_units"])
                else:
                    profile_worst_case_cost = int(profile.pricing.cost_units_for_usage(profile.authority_maximum_usage()))
            profile_worst_case_cost = int(profile_worst_case_cost)
            effective_provider_cost_cap = min(human_cost_ceiling, profile_worst_case_cost)
            reasons: list[str] = []
            if int(caps["max_cost_units"]) != effective_provider_cost_cap:
                reasons.append("effective_provider_cost_cap_mismatch")
            if int(fresh.get("effective_provider_cost_cap", effective_provider_cost_cap)) != effective_provider_cost_cap:
                reasons.append("effective_provider_cost_cap_binding_mismatch")
            if fresh.get("profile_worst_case_cost") is not None and int(fresh["profile_worst_case_cost"]) != profile_worst_case_cost:
                reasons.append("profile_worst_case_cost_binding_mismatch")
            if int(human_cost_ceiling) < 0 or int(profile_worst_case_cost) < 0:
                reasons.append("negative_cost_bound")

            profile = details.get("profile")
            if profile is not None:
                maximum_usage = profile.authority_maximum_usage()
                for component, cap_key in (("input_tokens", "max_input_tokens"), ("output_tokens", "max_output_tokens"), ("cache_read_tokens", "max_cache_read_tokens"), ("reasoning_tokens", "max_reasoning_tokens")):
                    if int(caps[cap_key]) < int(maximum_usage[component]):
                        reasons.append(f"{cap_key}_below_profile_maximum")
                if effective_provider_cost_cap < profile_worst_case_cost:
                    reasons.append("human_cost_ceiling_below_profile_worst_case")

            try:
                budget_value = json.loads(details.get("run_budget_policy_json", "{}")) if isinstance(details.get("run_budget_policy_json"), str) else None
            except Exception:
                budget_value = None
            if budget_value is None:
                run_row = connection.execute("SELECT budget_policy_json FROM max_runs WHERE run_id=?", (fresh["run_id"],)).fetchone()
                try:
                    budget_value = {} if run_row is None else json.loads(run_row["budget_policy_json"])
                except Exception:
                    budget_value = None
            if not isinstance(budget_value, Mapping):
                reasons.append("budget_policy_invalid")
                budget_cost = None
            else:
                try:
                    budget_cost = int(budget_value.get("max_cost_units", budget_value.get("cost_units")))
                    if human_cost_ceiling > budget_cost:
                        reasons.append("human_cost_ceiling_exceeds_budget")
                except Exception:
                    budget_cost = None
                    reasons.append("budget_cost_missing")

            grant_caps = {
                "max_ticks": 1,
                "max_iterations": 1,
                "max_wall_clock_seconds": int(caps["max_wall_clock_seconds"]),
                "max_consecutive_failures": 1,
                "max_no_progress": 1,
                "max_provider_calls": 1,
                "max_input_tokens": int(caps["max_input_tokens"]),
                "max_output_tokens": int(caps["max_output_tokens"]),
                "max_cache_read_tokens": int(caps["max_cache_read_tokens"]),
                "max_reasoning_tokens": int(caps["max_reasoning_tokens"]),
                "max_cost_units": int(effective_provider_cost_cap),
            }
            network_caps = {
                "max_provider_calls": 1,
                "max_input_tokens": int(caps["max_input_tokens"]),
                "max_output_tokens": int(caps["max_output_tokens"]),
                "max_cache_read_tokens": int(caps["max_cache_read_tokens"]),
                "max_reasoning_tokens": int(caps["max_reasoning_tokens"]),
                "max_cost_units": int(effective_provider_cost_cap),
            }
            network_authorization_feasible = not any(reason in reasons for reason in ("effective_provider_cost_cap_mismatch", "effective_provider_cost_cap_binding_mismatch", "human_cost_ceiling_below_profile_worst_case", "budget_cost_missing", "human_cost_ceiling_exceeds_budget"))
            if profile is not None and any(int(network_caps[key]) > int(limit) for key, limit in (("max_input_tokens", maximum_usage["input_tokens"]), ("max_output_tokens", maximum_usage["output_tokens"]), ("max_cache_read_tokens", maximum_usage["cache_read_tokens"]), ("max_reasoning_tokens", maximum_usage["reasoning_tokens"]), ("max_cost_units", profile_worst_case_cost))):
                reasons.append("network_authorization_cap_exceeds_profile")
                network_authorization_feasible = False
            if production_binding and fresh.get("control_schema_version") != CONTROL_SCHEMA_VERSION:
                reasons.append("control_schema_binding_stale")
            if fresh.get("core_schema_version") != 5 or fresh.get("engine_package") != "research-kb":
                reasons.append("package_schema_binding_invalid")
            request_manifest = details.get("request_manifest")
            source_permit_can_issue = isinstance(request_manifest, Mapping) and bool(fresh.get("source_allowlist")) and len(fresh.get("source_allowlist", ())) == 1
            if production_binding and not source_permit_can_issue:
                reasons.append("source_permit_manifest_not_issuable")
            if production_binding and not isinstance(details.get("network_policy"), Mapping):
                reasons.append("network_policy_missing")
            if production_binding:
                try:
                    from .provider.live import network_policy_hash, normalize_network_policy
                    normalized_policy = normalize_network_policy(details["network_policy"])
                    if network_policy_hash(normalized_policy) != fresh["network_policy_hash"]:
                        reasons.append("network_policy_hash_mismatch")
                except Exception:
                    reasons.append("network_policy_normalization_failed")

            plan_value = {
                "authority_id": selected_authority_id,
                "authority_hash": selected_authority_hash,
                "preview_id": selected_preview_id,
                "preview_hash": selected_preview_hash,
                "run_id": fresh["run_id"],
                "profile_hash": fresh["provider_profile_hash"],
                "pricing_hash": fresh["pricing_hash"],
                "network_policy_hash": fresh["network_policy_hash"],
                "human_cost_ceiling": human_cost_ceiling,
                "profile_worst_case_cost": profile_worst_case_cost,
                "effective_provider_cost_cap": effective_provider_cost_cap,
                "grant_caps": grant_caps,
                "network_authorization_caps": network_caps,
                "dispatch_reservation": {"provider_calls": 1, "reserved_cost_units": profile_worst_case_cost, "reserved_usage": {} if profile is None else profile.authority_maximum_usage()},
                "network_authorization_feasible": bool(network_authorization_feasible),
                "source_permit_can_issue": source_permit_can_issue,
                "budget_cost_units": budget_cost,
                "expires_at": expires_at,
                "reasons": reasons,
            }
            execution_plan_ok = not reasons and network_authorization_feasible
            plan_value["execution_plan_ok"] = execution_plan_ok
            plan_value["plan_hash"] = _hash(plan_value)
            return {
                **plan_value,
                "ok": execution_plan_ok,
                "credential_ref": {"kind": details["credential_ref"].get("kind"), "name": details["credential_ref"].get("name")},
                "network": {"dns_lookups": 0, "credential_reads": 0, "provider_calls": 0},
                "read_only": True,
            }
        except LiveCanaryAuthorityError:
            raise
        except Exception as exc:
            raise LiveCanaryAuthorityError("server live execution-plan preflight failed closed") from exc
        finally:
            connection.close()

    def authorize(self, *, preview_id: str, preview_hash: str, confirmation_phrase: str, expires_at: str, actor: Actor, reason: str) -> dict[str, Any]:
        _admin(actor)
        expected_hash = _require_hash(preview_hash, "preview_hash")
        if confirmation_phrase != f"APPROVE MR-4B1 CANARY {expected_hash}":
            raise LiveCanaryAuthorityError("typed confirmation phrase does not bind the preview hash")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000 or _SECRET_RE.search(reason):
            raise LiveCanaryAuthorityError("approval reason is invalid")
        expiry = _parse_timestamp(expires_at)
        # Production approvals are deliberately much shorter than the
        # Preview/lease window.  Historical fixture tests retain their
        # fixture-only one-hour seam, but a production-shaped database may
        # never create an approval longer than ten minutes.
        approval_window = timedelta(hours=1) if self.repository.is_fixture_database() else timedelta(minutes=10)
        if expiry is None or expiry <= _now(self.clock) or expiry > _now(self.clock) + approval_window:
            raise LiveCanaryAuthorityError("approval expiry is outside the bounded window")
        execution_plan = self.validate_live_execution_plan(preview_id=preview_id, preview_hash=expected_hash)
        if not bool(execution_plan.get("execution_plan_ok")):
            raise LiveCanaryAuthorityError("live execution plan preflight failed closed before Approval creation")
        now = _time(self.clock)
        approval_id = "live_canary_approval_" + uuid.uuid4().hex
        actor_id, actor_kind, actor_session = _actor_fields(actor)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                preview = connection.execute("SELECT * FROM max_live_canary_previews WHERE preview_id=?", (preview_id,)).fetchone()
                if preview is None or preview["preview_hash"] != expected_hash:
                    raise LiveCanaryAuthorityError("preview is missing or hash drifted")
                run = self._run_binding(connection, preview["run_id"])
                if any(run[run_key] != preview[preview_key] for run_key, preview_key in (("project_id", "project_id"), ("charter_hash", "charter_hash"), ("current_state_hash", "current_state_hash"), ("current_checkpoint_id", "current_checkpoint_id"), ("state_version", "current_state_version"))):
                    raise LiveCanaryAuthorityError("current run binding drifted since preview")
                approval_value = {"approval_id": approval_id, "preview_id": preview_id, "run_id": preview["run_id"], "project_id": preview["project_id"], "preview_hash": expected_hash, "confirmation_phrase": confirmation_phrase, "reason_hash": _hash(reason.strip()), "approved_at": now, "expires_at": expires_at, "authority": "human_admin"}
                approval_hash = _hash(approval_value)
                connection.execute("INSERT INTO max_live_canary_approvals(approval_id, preview_id, run_id, project_id, preview_hash, confirmation_phrase, approved_at, expires_at, approval_json, approval_hash, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (approval_id, preview_id, preview["run_id"], preview["project_id"], expected_hash, confirmation_phrase, now, expires_at, canonical_json(approval_value), approval_hash, actor_id, actor_kind, actor_session))
                current = {"approval_id": approval_id, "preview_id": preview_id, "run_id": preview["run_id"], "state": "active", "consumption_id": None, "approval_hash": approval_hash, "updated_at": now}
                connection.execute("INSERT INTO max_live_canary_approval_current(approval_id, preview_id, run_id, state, consumption_id, current_json, current_hash, updated_at) VALUES (?, ?, ?, 'active', NULL, ?, ?, ?)", (approval_id, preview_id, preview["run_id"], canonical_json(current), _hash(current), now))
                self._append_event(connection, preview_id=preview_id, run_id=preview["run_id"], approval_id=approval_id, event_type="approval_created", payload={"approval_id": approval_id, "approval_hash": approval_hash, "preview_hash": expected_hash, "reason_hash": approval_value["reason_hash"]}, actor=actor, now=now)
        finally:
            connection.close()
        return {"approval_id": approval_id, "preview_id": preview_id, "approval_hash": approval_hash, "state": "active", "expires_at": expires_at}

    def consume_approval(self, *, approval_id: str, preview_hash: str, consumer: Actor, worker_id: str, worker_session: str, fencing_token: int, claim_id: str) -> dict[str, Any]:
        expected_hash = _require_hash(preview_hash, "preview_hash")
        now_dt = _now(self.clock); now = _time(self.clock)
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise LiveCanaryAuthorityError("fencing token is invalid")
        actor_id, actor_kind, actor_session = _actor_fields(consumer)
        consumption_id = "live_canary_consumption_" + uuid.uuid4().hex
        connection = self._connect(read_only=False)
        expired = False
        try:
            with control_transaction(connection):
                approval = connection.execute("SELECT * FROM max_live_canary_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_canary_approval_current WHERE approval_id=?", (approval_id,)).fetchone()
                if approval is None or current is None or approval["preview_hash"] != expected_hash:
                    raise LiveCanaryAuthorityError("approval is missing or preview hash drifted")
                if current["state"] != "active":
                    raise LiveCanaryAuthorityError("approval is not active (expired, revoked, consumed, or replayed)")
                expiry = _parse_timestamp(approval["expires_at"])
                if expiry is None or expiry <= now_dt:
                    expired_value = {"approval_id": approval_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "state": "expired", "consumption_id": None, "updated_at": now}
                    connection.execute("UPDATE max_live_canary_approval_current SET state='expired', current_json=?, current_hash=?, updated_at=? WHERE approval_id=? AND state='active'", (canonical_json(expired_value), _hash(expired_value), now, approval_id))
                    expired = True
                if expired:
                    connection.commit()
                    raise LiveCanaryAuthorityError("approval has expired")
                preview = connection.execute("SELECT * FROM max_live_canary_previews WHERE preview_id=?", (approval["preview_id"],)).fetchone()
                run = self._run_binding(connection, approval["run_id"])
                self._assert_worker_fence(connection, run_id=approval["run_id"], worker_id=worker_id, worker_session=worker_session, fencing_token=fencing_token, now=now_dt)
                if preview is None or preview["preview_hash"] != expected_hash or any(run[run_key] != preview[preview_key] for run_key, preview_key in (("project_id", "project_id"), ("charter_hash", "charter_hash"), ("current_state_hash", "current_state_hash"), ("current_checkpoint_id", "current_checkpoint_id"), ("state_version", "current_state_version"))):
                    raise LiveCanaryAuthorityError("approval binding drifted before consumption")
                self._assert_invocation_claim(connection, run_id=approval["run_id"], claim_id=claim_id, worker_id=worker_id, worker_session=worker_session, fencing_token=fencing_token, now=now_dt)
                value = {"consumption_id": consumption_id, "approval_id": approval_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "project_id": approval["project_id"], "preview_hash": expected_hash, "consumer_id": actor_id, "consumer_kind": actor_kind, "consumer_session": actor_session, "worker_id": _safe_identifier(worker_id, "worker_id"), "worker_session": _safe_identifier(worker_session, "worker_session"), "fencing_token": fencing_token, "claim_id": _safe_identifier(claim_id, "claim_id"), "consumed_at": now}
                consumption_hash = _hash(value)
                connection.execute("INSERT INTO max_live_canary_approval_consumptions(consumption_id, approval_id, preview_id, run_id, project_id, preview_hash, consumer_id, consumer_kind, consumer_session, consumed_at, consumption_json, consumption_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (consumption_id, approval_id, approval["preview_id"], approval["run_id"], approval["project_id"], expected_hash, actor_id, actor_kind, actor_session, now, canonical_json(value), consumption_hash))
                updated = {"approval_id": approval_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "state": "consumed", "consumption_id": consumption_id, "updated_at": now}
                connection.execute("UPDATE max_live_canary_approval_current SET state='consumed', consumption_id=?, current_json=?, current_hash=?, updated_at=? WHERE approval_id=? AND state='active'", (consumption_id, canonical_json(updated), _hash(updated), now, approval_id))
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise LiveCanaryAuthorityError("approval consumption lost its atomic race")
                self._append_event(connection, preview_id=approval["preview_id"], run_id=approval["run_id"], approval_id=approval_id, event_type="approval_consumed", payload={"consumption_id": consumption_id, "consumption_hash": consumption_hash}, actor=consumer, now=now)
        except sqlite3.IntegrityError as exc:
            raise LiveCanaryAuthorityError("approval consumption lost its atomic race") from exc
        finally:
            connection.close()
        return {"consumption_id": consumption_id, "approval_id": approval_id, "preview_id": approval["preview_id"], "preview_hash": expected_hash, "state": "consumed"}

    def prepare_permit(self, *, consumption_id: str, consumer: Actor, request_hash: str, idempotency_key_hash: str) -> dict[str, Any]:
        req_hash = _require_hash(request_hash, "request_hash")
        idem_hash = _require_hash(idempotency_key_hash, "idempotency_key_hash")
        now = _time(self.clock); permit_id = "live_canary_permit_" + uuid.uuid4().hex
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                consumption = connection.execute("SELECT * FROM max_live_canary_approval_consumptions WHERE consumption_id=?", (consumption_id,)).fetchone()
                if consumption is None:
                    raise LiveCanaryAuthorityError("approval consumption is missing")
                preview = connection.execute("SELECT * FROM max_live_canary_previews WHERE preview_id=?", (consumption["preview_id"],)).fetchone()
                run = self._run_binding(connection, consumption["run_id"])
                consumed_value = json.loads(consumption["consumption_json"])
                self._assert_worker_fence(connection, run_id=consumption["run_id"], worker_id=consumed_value["worker_id"], worker_session=consumed_value["worker_session"], fencing_token=int(consumed_value["fencing_token"]), now=_now(self.clock))
                self._assert_invocation_claim(connection, run_id=consumption["run_id"], claim_id=consumed_value["claim_id"], worker_id=consumed_value["worker_id"], worker_session=consumed_value["worker_session"], fencing_token=int(consumed_value["fencing_token"]), now=_now(self.clock))
                if preview is None or preview["preview_hash"] != consumption["preview_hash"]:
                    raise LiveCanaryAuthorityError("consumption preview binding drifted")
                if any(run[run_key] != preview[preview_key] for run_key, preview_key in (("project_id", "project_id"), ("charter_hash", "charter_hash"), ("current_state_hash", "current_state_hash"), ("current_checkpoint_id", "current_checkpoint_id"), ("state_version", "current_state_version"))):
                    raise LiveCanaryAuthorityError("run state drifted before permit preparation")
                existing = connection.execute("SELECT * FROM max_live_canary_execution_permits WHERE consumption_id=?", (consumption_id,)).fetchone()
                if existing is not None:
                    raise LiveCanaryAuthorityError("canary permit already prepared; no retry or renewal is permitted")
                reservation = {"provider_calls": 1, "ticks": 1, "iterations": 1, "acquisition_requests": 0, "ocr_requests": 0, "ingest_operations": 0, "request_hash": req_hash, "idempotency_key_hash": idem_hash}
                value = {"permit_id": permit_id, "consumption_id": consumption_id, "approval_id": consumption["approval_id"], "preview_id": consumption["preview_id"], "run_id": consumption["run_id"], "project_id": consumption["project_id"], "claim_id": consumed_value["claim_id"], "reservation": reservation, "current_state_hash": preview["current_state_hash"], "current_checkpoint_id": preview["current_checkpoint_id"], "current_state_version": preview["current_state_version"], "provider_profile_hash": preview["provider_profile_hash"], "model_identity": preview["model_identity"], "pricing_hash": preview["pricing_hash"], "endpoint_origin_hash": preview["endpoint_origin_hash"], "endpoint_path_policy_hash": preview["endpoint_path_policy_hash"], "network_policy_hash": preview["network_policy_hash"], "credential_ref_hash": preview["credential_ref_hash"], "source_egress_policy_hash": preview["source_egress_policy_hash"], "worker_id": consumed_value["worker_id"], "worker_session": consumed_value["worker_session"], "fencing_token": consumed_value["fencing_token"], "created_at": now, "actor_id": consumer.actor_id, "actor_kind": consumer.actor_kind, "actor_session": consumer.session_id}
                reservation_hash = _hash(reservation)
                value["reservation_hash"] = reservation_hash
                permit_hash = _hash(value)
                connection.execute("INSERT INTO max_live_canary_execution_permits(permit_id, consumption_id, approval_id, preview_id, run_id, project_id, claim_id, reservation_json, reservation_hash, permit_json, permit_hash, current_state_hash, current_checkpoint_id, current_state_version, provider_profile_hash, model_identity, pricing_hash, endpoint_origin_hash, endpoint_path_policy_hash, network_policy_hash, credential_ref_hash, source_egress_policy_hash, worker_id, worker_session, fencing_token, request_hash, idempotency_key_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (permit_id, consumption_id, consumption["approval_id"], consumption["preview_id"], consumption["run_id"], consumption["project_id"], value["claim_id"], canonical_json(reservation), reservation_hash, canonical_json(value), permit_hash, preview["current_state_hash"], preview["current_checkpoint_id"], preview["current_state_version"], preview["provider_profile_hash"], preview["model_identity"], preview["pricing_hash"], preview["endpoint_origin_hash"], preview["endpoint_path_policy_hash"], preview["network_policy_hash"], preview["credential_ref_hash"], preview["source_egress_policy_hash"], value["worker_id"], value["worker_session"], value["fencing_token"], req_hash, idem_hash, now, consumer.actor_id, consumer.actor_kind, consumer.session_id))
                current = {"permit_id": permit_id, "preview_id": consumption["preview_id"], "run_id": consumption["run_id"], "state": "ready", "outcome_id": None, "request_hash": req_hash, "updated_at": now}
                connection.execute("INSERT INTO max_live_canary_execution_permit_current(permit_id, preview_id, run_id, state, outcome_id, current_json, current_hash, updated_at) VALUES (?, ?, ?, 'ready', NULL, ?, ?, ?)", (permit_id, consumption["preview_id"], consumption["run_id"], canonical_json(current), _hash(current), now))
                self._append_event(connection, preview_id=consumption["preview_id"], run_id=consumption["run_id"], approval_id=consumption["approval_id"], permit_id=permit_id, event_type="permit_prepared", payload={"permit_id": permit_id, "reservation_hash": reservation_hash, "request_hash": req_hash}, actor=consumer, now=now)
        except sqlite3.IntegrityError as exc:
            raise LiveCanaryAuthorityError("canary permit lost its atomic race or is already consumed") from exc
        finally:
            connection.close()
        return {"permit_id": permit_id, "preview_id": value["preview_id"], "run_id": value["run_id"], "state": "ready", "reservation_hash": reservation_hash, "request_hash": req_hash, "network": {"dns_lookups": 0, "credential_reads": 0, "provider_calls": 0}}

    def consume_and_prepare(self, *, approval_id: str, preview_hash: str, consumer: Actor, worker_id: str, worker_session: str, fencing_token: int, claim_id: str, request_hash: str, idempotency_key_hash: str) -> dict[str, Any]:
        """Atomically consume approval and reserve the one physical permit.

        This is the only assembly entrypoint intended for a production-shaped
        one-shot bridge.  It intentionally duplicates no settlement logic;
        it is the persistence-side transaction that precedes the shared tick
        pipeline.
        """

        req_hash = _require_hash(request_hash, "request_hash")
        idem_hash = _require_hash(idempotency_key_hash, "idempotency_key_hash")
        now_dt = _now(self.clock); now = _time(self.clock)
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise LiveCanaryAuthorityError("fencing token is invalid")
        consumption_id = "live_canary_consumption_" + uuid.uuid4().hex
        permit_id = "live_canary_permit_" + uuid.uuid4().hex
        actor_id, actor_kind, actor_session = _actor_fields(consumer)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                approval = connection.execute("SELECT * FROM max_live_canary_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                current_approval = connection.execute("SELECT * FROM max_live_canary_approval_current WHERE approval_id=?", (approval_id,)).fetchone()
                expected_hash = _require_hash(preview_hash, "preview_hash")
                if approval is None or current_approval is None or approval["preview_hash"] != expected_hash or current_approval["state"] != "active":
                    raise LiveCanaryAuthorityError("approval is missing, drifted, revoked, expired, consumed, or replayed")
                expiry = _parse_timestamp(approval["expires_at"])
                if expiry is None or expiry <= now_dt:
                    raise LiveCanaryAuthorityError("approval has expired")
                run = self._run_binding(connection, approval["run_id"])
                self._assert_worker_fence(connection, run_id=approval["run_id"], worker_id=worker_id, worker_session=worker_session, fencing_token=fencing_token, now=now_dt)
                preview = connection.execute("SELECT * FROM max_live_canary_previews WHERE preview_id=?", (approval["preview_id"],)).fetchone()
                if preview is None or preview["preview_hash"] != expected_hash or any(run[run_key] != preview[preview_key] for run_key, preview_key in (("project_id", "project_id"), ("charter_hash", "charter_hash"), ("current_state_hash", "current_state_hash"), ("current_checkpoint_id", "current_checkpoint_id"), ("state_version", "current_state_version"))):
                    raise LiveCanaryAuthorityError("approval or current run binding drifted")
                self._assert_invocation_claim(connection, run_id=approval["run_id"], claim_id=claim_id, worker_id=worker_id, worker_session=worker_session, fencing_token=fencing_token, now=now_dt)
                consumption_value = {"consumption_id": consumption_id, "approval_id": approval_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "project_id": approval["project_id"], "preview_hash": expected_hash, "consumer_id": actor_id, "consumer_kind": actor_kind, "consumer_session": actor_session, "worker_id": _safe_identifier(worker_id, "worker_id"), "worker_session": _safe_identifier(worker_session, "worker_session"), "fencing_token": fencing_token, "claim_id": _safe_identifier(claim_id, "claim_id"), "consumed_at": now}
                consumption_hash = _hash(consumption_value)
                connection.execute("INSERT INTO max_live_canary_approval_consumptions(consumption_id, approval_id, preview_id, run_id, project_id, preview_hash, consumer_id, consumer_kind, consumer_session, consumed_at, consumption_json, consumption_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (consumption_id, approval_id, approval["preview_id"], approval["run_id"], approval["project_id"], expected_hash, actor_id, actor_kind, actor_session, now, canonical_json(consumption_value), consumption_hash))
                updated_approval = {"approval_id": approval_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "state": "consumed", "consumption_id": consumption_id, "updated_at": now}
                connection.execute("UPDATE max_live_canary_approval_current SET state='consumed', consumption_id=?, current_json=?, current_hash=?, updated_at=? WHERE approval_id=? AND state='active'", (consumption_id, canonical_json(updated_approval), _hash(updated_approval), now, approval_id))
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise LiveCanaryAuthorityError("approval consumption lost its atomic race")
                reservation = {"provider_calls": 1, "ticks": 1, "iterations": 1, "acquisition_requests": 0, "ocr_requests": 0, "ingest_operations": 0, "request_hash": req_hash, "idempotency_key_hash": idem_hash}
                reservation_hash = _hash(reservation)
                permit_value = {"permit_id": permit_id, "consumption_id": consumption_id, "approval_id": approval_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "project_id": approval["project_id"], "claim_id": claim_id, "reservation": reservation, "current_state_hash": preview["current_state_hash"], "current_checkpoint_id": preview["current_checkpoint_id"], "current_state_version": preview["current_state_version"], "provider_profile_hash": preview["provider_profile_hash"], "model_identity": preview["model_identity"], "pricing_hash": preview["pricing_hash"], "endpoint_origin_hash": preview["endpoint_origin_hash"], "endpoint_path_policy_hash": preview["endpoint_path_policy_hash"], "network_policy_hash": preview["network_policy_hash"], "credential_ref_hash": preview["credential_ref_hash"], "source_egress_policy_hash": preview["source_egress_policy_hash"], "worker_id": worker_id, "worker_session": worker_session, "fencing_token": fencing_token, "request_hash": req_hash, "idempotency_key_hash": idem_hash, "created_at": now, "actor_id": actor_id, "actor_kind": actor_kind, "actor_session": actor_session}
                permit_hash = _hash(permit_value)
                connection.execute("INSERT INTO max_live_canary_execution_permits(permit_id, consumption_id, approval_id, preview_id, run_id, project_id, claim_id, reservation_json, reservation_hash, permit_json, permit_hash, current_state_hash, current_checkpoint_id, current_state_version, provider_profile_hash, model_identity, pricing_hash, endpoint_origin_hash, endpoint_path_policy_hash, network_policy_hash, credential_ref_hash, source_egress_policy_hash, worker_id, worker_session, fencing_token, request_hash, idempotency_key_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (permit_id, consumption_id, approval_id, approval["preview_id"], approval["run_id"], approval["project_id"], claim_id, canonical_json(reservation), reservation_hash, canonical_json(permit_value), permit_hash, preview["current_state_hash"], preview["current_checkpoint_id"], preview["current_state_version"], preview["provider_profile_hash"], preview["model_identity"], preview["pricing_hash"], preview["endpoint_origin_hash"], preview["endpoint_path_policy_hash"], preview["network_policy_hash"], preview["credential_ref_hash"], preview["source_egress_policy_hash"], worker_id, worker_session, fencing_token, req_hash, idem_hash, now, actor_id, actor_kind, actor_session))
                current_permit = {"permit_id": permit_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "state": "ready", "outcome_id": None, "request_hash": req_hash, "updated_at": now}
                connection.execute("INSERT INTO max_live_canary_execution_permit_current(permit_id, preview_id, run_id, state, outcome_id, current_json, current_hash, updated_at) VALUES (?, ?, ?, 'ready', NULL, ?, ?, ?)", (permit_id, approval["preview_id"], approval["run_id"], canonical_json(current_permit), _hash(current_permit), now))
                self._append_event(connection, preview_id=approval["preview_id"], run_id=approval["run_id"], approval_id=approval_id, permit_id=permit_id, event_type="approval_consumed_and_permit_prepared", payload={"consumption_id": consumption_id, "consumption_hash": consumption_hash, "permit_id": permit_id, "permit_hash": permit_hash, "reservation_hash": reservation_hash, "request_hash": req_hash}, actor=consumer, now=now)
        except sqlite3.IntegrityError as exc:
            raise LiveCanaryAuthorityError("approval consumption or permit preparation lost its atomic race") from exc
        finally:
            connection.close()
        return {"consumption_id": consumption_id, "approval_id": approval_id, "permit_id": permit_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "state": "ready", "reservation_hash": reservation_hash, "request_hash": req_hash, "network": {"dns_lookups": 0, "credential_reads": 0, "provider_calls": 0}}

    def mark_send_started(self, *, permit_id: str, actor: Actor) -> dict[str, Any]:
        return self._transition_permit(permit_id=permit_id, target="send_started", actor=actor)

    def mark_http_dispatch_boundary_crossed(
        self,
        *,
        permit_id: str,
        run_id: str,
        project_id: str,
        claim_id: str,
        attempt_id: str,
        fencing_token: int,
        request_hash: str,
        idempotency_key_hash: str,
        actor: Actor,
        canary_claim_id: str | None = None,
    ) -> dict[str, Any]:
        """Persist the only canary transition that authorizes a real send.

        Transport preparation, DNS, SSRF checks and credential resolution all
        happen before this method is called.  The callback is server-owned and
        binds the canary permit to the provider attempt, worker lease, request
        hash and idempotency hash in one durable transaction.  A failure here
        is fail-closed: the connector must not be invoked.
        """

        for value, name in ((permit_id, "permit_id"), (run_id, "run_id"), (project_id, "project_id"), (claim_id, "claim_id"), (attempt_id, "attempt_id")):
            _safe_identifier(value, name)
        if canary_claim_id is not None:
            _safe_identifier(canary_claim_id, "canary_claim_id")
        _require_hash(request_hash, "request_hash")
        _require_hash(idempotency_key_hash, "idempotency_key_hash")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise LiveCanaryAuthorityError("boundary fencing token is invalid")
        now_dt = _now(self.clock)
        now = _time(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                permit = connection.execute("SELECT * FROM max_live_canary_execution_permits WHERE permit_id=?", (permit_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_canary_execution_permit_current WHERE permit_id=?", (permit_id,)).fetchone()
                if permit is None or current is None:
                    raise LiveCanaryAuthorityError("canary permit is unknown")
                expected_canary_claim_id = str(canary_claim_id or permit["claim_id"])
                if permit["run_id"] != run_id or permit["project_id"] != project_id or permit["claim_id"] != expected_canary_claim_id or permit["request_hash"] != request_hash or permit["idempotency_key_hash"] != idempotency_key_hash:
                    raise LiveCanaryAuthorityError("canary boundary binding is invalid")
                if permit["worker_id"] != actor.actor_id or permit["worker_session"] != actor.session_id or int(permit["fencing_token"]) != fencing_token:
                    raise LiveCanaryAuthorityError("canary boundary actor or fence is invalid")
                self._assert_worker_fence(connection, run_id=run_id, worker_id=str(permit["worker_id"]), worker_session=str(permit["worker_session"]), fencing_token=fencing_token, now=now_dt)
                claim = connection.execute("SELECT c.claim_id, a.attempt_id, u.state AS claim_state FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id JOIN max_provider_dispatch_attempts a ON a.claim_id=c.claim_id WHERE c.claim_id=? ORDER BY a.physical_attempt_no DESC LIMIT 1", (claim_id,)).fetchone()
                dispatch = connection.execute("SELECT p.attempt_id, p.claim_id, p.run_id, p.project_id, p.request_hash, p.idempotency_key_hash, c.state FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.attempt_id=?", (attempt_id,)).fetchone()
                if claim is None or claim["attempt_id"] != attempt_id:
                    raise LiveCanaryAuthorityError("canary boundary claim/attempt binding is invalid")
                if dispatch is None or dispatch["claim_id"] != claim_id or dispatch["run_id"] != run_id or dispatch["project_id"] != project_id or dispatch["request_hash"] != request_hash or dispatch["idempotency_key_hash"] != idempotency_key_hash or dispatch["state"] != "send_started":
                    raise LiveCanaryAuthorityError("canary boundary dispatch binding is invalid")
                if current["state"] == "send_started":
                    return {"permit_id": permit_id, "state": "send_started", "idempotent": True, "boundary_event": "http_dispatch_boundary_crossed"}
                if current["state"] != "ready":
                    raise LiveCanaryAuthorityError("canary permit is not ready for the HTTP boundary")
                value = {"permit_id": permit_id, "preview_id": permit["preview_id"], "run_id": run_id, "project_id": project_id, "claim_id": claim_id, "attempt_id": attempt_id, "request_hash": request_hash, "idempotency_key_hash": idempotency_key_hash, "fencing_token": fencing_token, "state": "send_started", "outcome_id": None, "updated_at": now}
                connection.execute("UPDATE max_live_canary_execution_permit_current SET state='send_started', current_json=?, current_hash=?, updated_at=? WHERE permit_id=? AND state='ready'", (canonical_json({"permit_id": permit_id, "preview_id": permit["preview_id"], "run_id": run_id, "state": "send_started", "outcome_id": None, "updated_at": now}), _hash({"permit_id": permit_id, "preview_id": permit["preview_id"], "run_id": run_id, "state": "send_started", "outcome_id": None, "updated_at": now}), now, permit_id))
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise LiveCanaryAuthorityError("HTTP boundary transition lost its atomic race")
                self._append_event(connection, preview_id=permit["preview_id"], run_id=run_id, permit_id=permit_id, event_type="http_dispatch_boundary_crossed", payload={"permit_id": permit_id, "claim_id": claim_id, "canary_claim_id": expected_canary_claim_id, "attempt_id": attempt_id, "request_hash": request_hash, "idempotency_key_hash": idempotency_key_hash, "fencing_token": fencing_token, "send_boundary_reached": True}, actor=actor, now=now)
            return {"permit_id": permit_id, "state": "send_started", "idempotent": False, "boundary_event": "http_dispatch_boundary_crossed"}
        finally:
            connection.close()

    def classify_provider_boundary(self, *, permit_id: str) -> dict[str, Any]:
        """Classify the physical send boundary from durable evidence only.

        The process-local ``canary_send_started`` flag is intentionally not
        consulted here.  A crash or exception can occur between any two
        writes, so the classification is based on the append-only canary
        event and the durable provider/network projections instead.
        """

        _safe_identifier(permit_id, "permit_id")
        connection = self._connect(read_only=True)
        try:
            permit = connection.execute(
                "SELECT permit_id, preview_id, run_id, project_id, request_hash, idempotency_key_hash, provider_profile_hash AS profile_hash FROM max_live_canary_execution_permits WHERE permit_id=?",
                (permit_id,),
            ).fetchone()
            if permit is None:
                raise LiveCanaryAuthorityError("canary permit is missing for boundary classification")

            event_types = [
                str(row["event_type"])
                for row in connection.execute(
                    "SELECT event_type FROM max_live_canary_events WHERE preview_id=? AND permit_id=? ORDER BY sequence_no",
                    (permit["preview_id"], permit_id),
                )
            ]
            # ``send_started`` is a legacy v7 marker and is intentionally kept
            # as historical evidence.  New runs use the explicit boundary
            # event below; this avoids reclassifying old v7 data while making
            # DNS/credential failures definitively pre-send.
            canary_send_started = "send_started" in event_types
            explicit_canary_boundary = "http_dispatch_boundary_crossed" in event_types
            network_boundary_events = int(connection.execute(
                "SELECT COUNT(*) FROM max_live_network_access_events e JOIN max_live_dispatch_permits p ON p.authorization_id=e.authorization_id WHERE p.run_id=? AND p.project_id=? AND p.request_hash=? AND p.idempotency_key_hash=? AND e.run_id=p.run_id AND e.project_id=p.project_id AND e.event_type='http_dispatch_boundary_crossed'",
                (permit["run_id"], permit["project_id"], permit["request_hash"], permit["idempotency_key_hash"]),
            ).fetchone()[0])

            source_row = connection.execute(
                "SELECT c.state FROM max_live_canary_source_permits p LEFT JOIN max_live_canary_source_permit_current c ON c.source_permit_id=p.source_permit_id WHERE p.canary_permit_id=? ORDER BY p.created_at DESC LIMIT 1",
                (permit_id,),
            ).fetchone()
            source_state = None if source_row is None else source_row["state"]
            source_event_count = 0
            if source_row is not None:
                source_event_count = int(connection.execute(
                    "SELECT COUNT(*) FROM max_live_canary_source_permit_events e JOIN max_live_canary_source_permits p ON p.source_permit_id=e.source_permit_id WHERE p.canary_permit_id=?",
                    (permit_id,),
                ).fetchone()[0])

            execution_grants = int(connection.execute(
                "SELECT COUNT(*) FROM max_live_execution_grants WHERE run_id=? AND profile_hash=?",
                (permit["run_id"], permit["profile_hash"]),
            ).fetchone()[0])
            grant_consumptions = int(connection.execute(
                "SELECT COUNT(*) FROM max_live_execution_grant_consumptions c JOIN max_live_execution_grants g ON g.grant_id=c.grant_id WHERE c.run_id=? AND g.profile_hash=?",
                (permit["run_id"], permit["profile_hash"]),
            ).fetchone()[0])
            network_authorizations = int(connection.execute(
                "SELECT COUNT(*) FROM max_live_network_authorizations WHERE run_id=? AND profile_hash=?",
                (permit["run_id"], permit["profile_hash"]),
            ).fetchone()[0])
            network_authorization_consumptions = int(connection.execute(
                "SELECT COUNT(*) FROM max_live_network_authorization_consumptions c JOIN max_live_network_authorizations a ON a.authorization_id=c.authorization_id WHERE c.run_id=? AND a.profile_hash=?",
                (permit["run_id"], permit["profile_hash"]),
            ).fetchone()[0])

            dispatch_rows = connection.execute(
                "SELECT p.permit_id, p.authorization_id, c.state FROM max_live_dispatch_permits p LEFT JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.run_id=? AND p.request_hash=?",
                (permit["run_id"], permit["request_hash"]),
            ).fetchall()
            dispatch_states = [None if row["state"] is None else str(row["state"]) for row in dispatch_rows]
            dispatch_terminal_states = {"settled", "failed", "unknown", "disputed"}
            dispatch_boundary_markers: list[bool | None] = []
            for row in dispatch_rows:
                event = connection.execute(
                    "SELECT payload_json FROM max_live_dispatch_permit_events WHERE permit_id=? ORDER BY sequence_no DESC LIMIT 1",
                    (row["permit_id"],),
                ).fetchone()
                marker: bool | None = None
                if event is not None:
                    try:
                        payload = json.loads(event["payload_json"])
                        if isinstance(payload, Mapping) and isinstance(payload.get("send_boundary_reached"), bool):
                            marker = bool(payload["send_boundary_reached"])
                    except Exception:
                        marker = None
                dispatch_boundary_markers.append(marker)
            dispatch_terminal_count = sum(
                state in dispatch_terminal_states and marker is not False
                for state, marker in zip(dispatch_states, dispatch_boundary_markers)
            )

            authorization_ids = [str(row["authorization_id"]) for row in dispatch_rows if row["authorization_id"]]
            network_attempt_records = 0
            if authorization_ids:
                placeholders = ",".join("?" for _ in authorization_ids)
                network_attempt_records = int(connection.execute(
                    f"SELECT COUNT(*) FROM max_live_network_attempt_records WHERE authorization_id IN ({placeholders}) AND outcome <> 'not_dispatched'",
                    tuple(authorization_ids),
                ).fetchone()[0])

            provider_attempt_states = [
                None if row["state"] is None else str(row["state"])
                for row in connection.execute(
                    "SELECT c.state FROM max_provider_dispatch_attempts a LEFT JOIN max_provider_dispatch_attempt_current c ON c.attempt_id=a.attempt_id WHERE a.run_id=? AND a.request_hash=?",
                    (permit["run_id"], permit["request_hash"]),
                )
            ]
            provider_attempt_terminal_count = sum(state in dispatch_terminal_states for state in provider_attempt_states)
            provider_call_records = int(connection.execute(
                "SELECT COUNT(*) FROM max_provider_call_records WHERE run_id=? AND request_hash=?",
                (permit["run_id"], permit["request_hash"]),
            ).fetchone()[0])

            send_boundary_reached = bool(
                canary_send_started
                or explicit_canary_boundary
                or network_boundary_events > 0
                or network_attempt_records > 0
                or provider_call_records > 0
                or provider_attempt_terminal_count > 0
                or dispatch_terminal_count > 0
            )
            evidence = {
                "canary_event_types": event_types,
                "canary_send_started_event": canary_send_started,
                "explicit_canary_boundary_event": explicit_canary_boundary,
                "network_boundary_events": network_boundary_events,
                "source_permit_state": source_state,
                "source_permit_event_count": source_event_count,
                "execution_grants": execution_grants,
                "execution_grant_consumptions": grant_consumptions,
                "network_authorizations": network_authorizations,
                "network_authorization_consumptions": network_authorization_consumptions,
                "provider_dispatch_states": dispatch_states,
                "provider_dispatch_boundary_markers": dispatch_boundary_markers,
                "provider_dispatch_terminal_count": dispatch_terminal_count,
                "provider_dispatch_attempt_states": provider_attempt_states,
                "provider_dispatch_attempt_terminal_count": provider_attempt_terminal_count,
                "network_attempt_records": network_attempt_records,
                "provider_call_records": provider_call_records,
            }
            failure_class = "UNKNOWN_AFTER_SEND" if send_boundary_reached else "KNOWN_PRE_SEND_FAILURE"
            return {
                "failure_class": failure_class,
                "send_boundary_reached": send_boundary_reached,
                "reconciliation_required": send_boundary_reached,
                "retry_allowed": False,
                "durable_evidence": evidence,
            }
        finally:
            connection.close()

    def record_outcome(self, *, permit_id: str, outcome: str, usage: Mapping[str, Any], cost_units: int, actor: Actor, provider_call_id: str | None = None, response_hash: str | None = None, diagnostics: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if outcome not in {"succeeded", "failed", "unknown", "aborted"}:
            raise LiveCanaryAuthorityError("outcome is invalid")
        if outcome == "unknown" and (usage or cost_units != 0):
            raise LiveCanaryAuthorityError("unknown outcome cannot claim usage or cost")
        if outcome == "unknown":
            boundary = self.classify_provider_boundary(permit_id=permit_id)
            if not bool(boundary["send_boundary_reached"]):
                raise LiveCanaryAuthorityError("crash-before-send must be aborted, not unknown")
        if isinstance(cost_units, bool) or not isinstance(cost_units, int) or cost_units < 0:
            raise LiveCanaryAuthorityError("cost_units is invalid")
        if response_hash is not None:
            response_hash = _require_hash(response_hash, "response_hash")
        usage_value = _safe_json(usage, "usage")
        diagnostics_value: dict[str, Any] = {}
        if diagnostics is not None:
            checked_diagnostics = _safe_json(diagnostics, "outcome diagnostics", max_bytes=32_000)
            if not isinstance(checked_diagnostics, Mapping):
                raise LiveCanaryAuthorityError("outcome diagnostics must be an object")
            diagnostics_value = dict(checked_diagnostics)
            required_diagnostic_keys = {"failure_stage", "failure_class", "send_boundary_reached", "reconciliation_required", "retry_allowed"}
            if not required_diagnostic_keys.issubset(diagnostics_value):
                raise LiveCanaryAuthorityError("outcome diagnostics are incomplete")
            diagnostics_value.setdefault("error_code", "LIVE_CANARY_BOUNDARY_FAILURE")
            for key in ("human_cost_ceiling", "profile_worst_case_cost", "effective_provider_cost_cap"):
                if key in diagnostics_value:
                    raw = diagnostics_value[key]
                    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                        raise LiveCanaryAuthorityError("outcome diagnostics cost fields must be non-negative integers")
            if diagnostics_value["retry_allowed"] is not False:
                raise LiveCanaryAuthorityError("outcome diagnostics cannot allow retry")
            if bool(diagnostics_value["send_boundary_reached"]) != (outcome == "unknown"):
                raise LiveCanaryAuthorityError("outcome diagnostics disagree with the durable outcome")
            if bool(diagnostics_value["reconciliation_required"]) != (outcome == "unknown"):
                raise LiveCanaryAuthorityError("outcome diagnostics disagree with reconciliation policy")
        now = _time(self.clock); outcome_id = "live_canary_outcome_" + uuid.uuid4().hex
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                permit = connection.execute("SELECT * FROM max_live_canary_execution_permits WHERE permit_id=?", (permit_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_canary_execution_permit_current WHERE permit_id=?", (permit_id,)).fetchone()
                if permit is None or current is None or current["state"] not in {"send_started", "ready"}:
                    raise LiveCanaryAuthorityError("permit is not in a settleable state")
                if current["state"] == "ready" and outcome not in {"aborted", "failed"}:
                    raise LiveCanaryAuthorityError("permit was not marked send-started")
                value = {"outcome_id": outcome_id, "permit_id": permit_id, "preview_id": permit["preview_id"], "run_id": permit["run_id"], "project_id": permit["project_id"], "outcome": outcome, "provider_call_id": None if provider_call_id is None else _safe_identifier(provider_call_id, "provider_call_id"), "request_hash": permit["request_hash"], "response_hash": response_hash, "usage": usage_value, "cost_units": cost_units, "diagnostics": diagnostics_value, "created_at": now}
                outcome_hash = _hash(value)
                connection.execute("INSERT INTO max_live_canary_outcomes(outcome_id, permit_id, preview_id, run_id, project_id, outcome, provider_call_id, request_hash, response_hash, usage_json, cost_units, outcome_json, outcome_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (outcome_id, permit_id, permit["preview_id"], permit["run_id"], permit["project_id"], outcome, value["provider_call_id"], permit["request_hash"], response_hash, canonical_json(usage_value), cost_units, canonical_json(value), outcome_hash, now, actor.actor_id, actor.actor_kind, actor.session_id))
                current_value = {"permit_id": permit_id, "preview_id": permit["preview_id"], "run_id": permit["run_id"], "state": outcome, "outcome_id": outcome_id, "updated_at": now}
                connection.execute("UPDATE max_live_canary_execution_permit_current SET state=?, outcome_id=?, current_json=?, current_hash=?, updated_at=? WHERE permit_id=? AND state IN ('ready','send_started')", (outcome, outcome_id, canonical_json(current_value), _hash(current_value), now, permit_id))
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise LiveCanaryAuthorityError("permit settlement lost its atomic race")
                self._append_event(connection, preview_id=permit["preview_id"], run_id=permit["run_id"], permit_id=permit_id, event_type="outcome_recorded", payload={"outcome_id": outcome_id, "outcome": outcome, "outcome_hash": outcome_hash, "usage_hash": _hash(usage_value), "cost_units": cost_units}, actor=actor, now=now)
        except sqlite3.IntegrityError as exc:
            raise LiveCanaryAuthorityError("permit already has an immutable outcome") from exc
        finally:
            connection.close()
        return {"outcome_id": outcome_id, "permit_id": permit_id, "outcome": outcome, "usage": usage_value, "cost_units": cost_units, "diagnostics": diagnostics_value, "network": {"dns_lookups": 0, "credential_reads": 0, "provider_calls": 0}}

    def _transition_permit(self, *, permit_id: str, target: str, actor: Actor) -> dict[str, Any]:
        if target not in _PERMIT_STATES:
            raise LiveCanaryAuthorityError("permit transition is invalid")
        now = _time(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_live_canary_execution_permit_current WHERE permit_id=?", (permit_id,)).fetchone()
                permit = connection.execute("SELECT * FROM max_live_canary_execution_permits WHERE permit_id=?", (permit_id,)).fetchone()
                if row is None or permit is None:
                    raise LiveCanaryAuthorityError("permit is unknown")
                if target == "send_started" and row["state"] != "ready":
                    raise LiveCanaryAuthorityError("send-started is not replayable")
                value = {"permit_id": permit_id, "preview_id": permit["preview_id"], "run_id": permit["run_id"], "state": target, "outcome_id": None, "updated_at": now}
                connection.execute("UPDATE max_live_canary_execution_permit_current SET state=?, current_json=?, current_hash=?, updated_at=? WHERE permit_id=? AND state='ready'", (target, canonical_json(value), _hash(value), now, permit_id))
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise LiveCanaryAuthorityError("permit transition lost its atomic race")
                self._append_event(connection, preview_id=permit["preview_id"], run_id=permit["run_id"], permit_id=permit_id, event_type="send_started", payload={"permit_id": permit_id, "request_hash": permit["request_hash"]}, actor=actor, now=now)
        finally:
            connection.close()
        return {"permit_id": permit_id, "state": target, "network": {"dns_lookups": 0, "credential_reads": 0, "provider_calls": 0}}

    def revoke(self, *, approval_id: str, actor: Actor, reason: str) -> dict[str, Any]:
        _admin(actor)
        if not isinstance(reason, str) or not reason.strip() or _SECRET_RE.search(reason):
            raise LiveCanaryAuthorityError("revoke reason is invalid")
        now = _time(self.clock); connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_live_canary_approval_current WHERE approval_id=?", (approval_id,)).fetchone()
                approval = connection.execute("SELECT * FROM max_live_canary_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                if row is None or approval is None:
                    raise LiveCanaryAuthorityError("approval is unknown")
                if row["state"] not in {"active"}:
                    raise LiveCanaryAuthorityError("only an active approval can be revoked")
                value = {"approval_id": approval_id, "preview_id": approval["preview_id"], "run_id": approval["run_id"], "state": "revoked", "consumption_id": None, "reason_hash": _hash(reason.strip()), "updated_at": now}
                connection.execute("UPDATE max_live_canary_approval_current SET state='revoked', current_json=?, current_hash=?, updated_at=? WHERE approval_id=? AND state='active'", (canonical_json(value), _hash(value), now, approval_id))
                self._append_event(connection, preview_id=approval["preview_id"], run_id=approval["run_id"], approval_id=approval_id, event_type="approval_revoked", payload={"approval_id": approval_id, "reason_hash": value["reason_hash"]}, actor=actor, now=now)
        finally:
            connection.close()
        return {"approval_id": approval_id, "state": "revoked"}

    def revoke_permit(self, *, permit_id: str, actor: Actor, reason: str) -> dict[str, Any]:
        """Kill a not-yet-sent permit; a sent permit must be settled once."""

        _admin(actor)
        if not isinstance(reason, str) or not reason.strip() or _SECRET_RE.search(reason):
            raise LiveCanaryAuthorityError("permit revoke reason is invalid")
        now = _time(self.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                current = connection.execute("SELECT * FROM max_live_canary_execution_permit_current WHERE permit_id=?", (permit_id,)).fetchone()
                permit = connection.execute("SELECT * FROM max_live_canary_execution_permits WHERE permit_id=?", (permit_id,)).fetchone()
                if current is None or permit is None or current["state"] != "ready":
                    raise LiveCanaryAuthorityError("only an unsent ready permit can be killed")
                value = {"permit_id": permit_id, "preview_id": permit["preview_id"], "run_id": permit["run_id"], "state": "revoked", "outcome_id": None, "reason_hash": _hash(reason.strip()), "updated_at": now}
                connection.execute("UPDATE max_live_canary_execution_permit_current SET state='revoked', current_json=?, current_hash=?, updated_at=? WHERE permit_id=? AND state='ready'", (canonical_json(value), _hash(value), now, permit_id))
                self._append_event(connection, preview_id=permit["preview_id"], run_id=permit["run_id"], permit_id=permit_id, event_type="permit_revoked", payload={"permit_id": permit_id, "reason_hash": value["reason_hash"]}, actor=actor, now=now)
        finally:
            connection.close()
        return {"permit_id": permit_id, "state": "revoked"}

    def status(self, *, preview_id: str | None = None, run_id: str | None = None) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            where, params = [], []
            if preview_id is not None:
                where.append("p.preview_id=?"); params.append(preview_id)
            if run_id is not None:
                where.append("p.run_id=?"); params.append(run_id)
            predicate = " WHERE " + " AND ".join(where) if where else ""
            previews = []
            for row in connection.execute(f"SELECT p.preview_id, p.run_id, p.project_id, p.preview_hash, p.confirmation_phrase, a.approval_id, ac.state AS approval_state, pc.permit_id, pc.state AS permit_state FROM max_live_canary_previews p LEFT JOIN max_live_canary_approvals a ON a.preview_id=p.preview_id LEFT JOIN max_live_canary_approval_current ac ON ac.approval_id=a.approval_id LEFT JOIN max_live_canary_execution_permits ep ON ep.preview_id=p.preview_id LEFT JOIN max_live_canary_execution_permit_current pc ON pc.permit_id=ep.permit_id{predicate} ORDER BY p.created_at, p.preview_id", params):
                previews.append({"preview_id": row["preview_id"], "run_id": row["run_id"], "project_id": row["project_id"], "preview_hash": row["preview_hash"], "confirmation_phrase": row["confirmation_phrase"], "approval_id": row["approval_id"], "approval_state": row["approval_state"], "permit_id": row["permit_id"], "permit_state": row["permit_state"]})
            authority_query = "SELECT authority_id, preview_id, preview_hash, run_id, expires_at, authority_hash FROM max_live_canary_authority_bindings"
            authority_params: tuple[Any, ...] = ()
            if run_id is not None:
                authority_query += " WHERE run_id=?"
                authority_params = (run_id,)
            authorities = [dict(row) for row in connection.execute(authority_query + " ORDER BY created_at, authority_id", authority_params)]
            return {"schema_version": CONTROL_SCHEMA_VERSION, "previews": previews, "authorities": authorities, "authority_count": len(authorities), "network": {"dns_lookups": 0, "credential_reads": 0, "provider_calls": 0}}
        finally:
            connection.close()

    def verify(self, *, preview_id: str | None = None) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        issues: list[str] = []
        try:
            rows = connection.execute("SELECT * FROM max_live_canary_previews" + (" WHERE preview_id=?" if preview_id else "") + " ORDER BY preview_id", (preview_id,) if preview_id else ()).fetchall()
            for row in rows:
                try:
                    preview = json.loads(row["preview_json"])
                    if _hash(preview) != row["preview_hash"] or _hash(json.loads(row["cap_vector_json"])) != row["cap_vector_hash"]:
                        issues.append(f"preview hash mismatch: {row['preview_id']}")
                    approval_rows = connection.execute("SELECT a.approval_id, a.approval_json, a.approval_hash, c.current_json, c.current_hash FROM max_live_canary_approvals a LEFT JOIN max_live_canary_approval_current c ON c.approval_id=a.approval_id WHERE a.preview_id=?", (row["preview_id"],)).fetchall()
                    for approval in approval_rows:
                        if _hash(json.loads(approval["approval_json"])) != approval["approval_hash"] or approval["current_json"] is None or _hash(json.loads(approval["current_json"])) != approval["current_hash"]:
                            issues.append(f"approval projection mismatch: {approval['approval_id']}")
                    consumption_rows = connection.execute("SELECT consumption_id, consumption_json, consumption_hash FROM max_live_canary_approval_consumptions WHERE preview_id=?", (row["preview_id"],)).fetchall()
                    for consumption in consumption_rows:
                        if _hash(json.loads(consumption["consumption_json"])) != consumption["consumption_hash"]:
                            issues.append(f"consumption hash mismatch: {consumption['consumption_id']}")
                    permit_rows = connection.execute("SELECT e.permit_id, e.reservation_json, e.reservation_hash, e.permit_json, e.permit_hash, c.current_json, c.current_hash FROM max_live_canary_execution_permits e LEFT JOIN max_live_canary_execution_permit_current c ON c.permit_id=e.permit_id WHERE e.preview_id=?", (row["preview_id"],)).fetchall()
                    for permit in permit_rows:
                        if _hash(json.loads(permit["reservation_json"])) != permit["reservation_hash"] or _hash(json.loads(permit["permit_json"])) != permit["permit_hash"] or permit["current_json"] is None or _hash(json.loads(permit["current_json"])) != permit["current_hash"]:
                            issues.append(f"permit projection mismatch: {permit['permit_id']}")
                    outcome_rows = connection.execute("SELECT outcome_id, outcome_json, outcome_hash FROM max_live_canary_outcomes WHERE preview_id=?", (row["preview_id"],)).fetchall()
                    for outcome in outcome_rows:
                        if _hash(json.loads(outcome["outcome_json"])) != outcome["outcome_hash"]:
                            issues.append(f"outcome hash mismatch: {outcome['outcome_id']}")
                    events = connection.execute("SELECT * FROM max_live_canary_events WHERE preview_id=? ORDER BY sequence_no", (row["preview_id"],)).fetchall()
                    previous = None
                    for event in events:
                        expected = {"preview_id": event["preview_id"], "run_id": event["run_id"], "approval_id": event["approval_id"], "permit_id": event["permit_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": previous, "created_at": event["created_at"]}
                        if _hash(expected) != event["event_hash"] or previous != event["previous_event_hash"] or _hash(json.loads(event["payload_json"])) != event["payload_hash"]:
                            issues.append(f"event chain mismatch: {row['preview_id']}")
                        previous = event["event_hash"]
                except Exception:
                    issues.append(f"preview verification failed: {row['preview_id']}")
            return {"ok": not issues, "schema_version": CONTROL_SCHEMA_VERSION, "issues": issues, "network": {"dns_lookups": 0, "credential_reads": 0, "provider_calls": 0}}
        finally:
            connection.close()


__all__ = ["LiveCanaryAuthorityError", "LiveCanaryAuthorityStore"]
