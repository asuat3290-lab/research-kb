"""Compact, server-owned Max Research execution capsule.

MR-CONVERGENCE-DEV18 deliberately collapses the user-facing approval chain to
one immutable capsule Preview and one explicit execute command.  The older
DNS, Live Approval, Execution Preview and Execution Authorization records are
still used as internal append-only audit facts by the execution service; they
are never selected by the caller and are created only after the capsule has
been accepted.

This module has no research or ingestion responsibility.  It stores only
bounded identifiers, hashes, counters and state.  Prompt text, source text,
credentials, response bodies and resolved addresses are never persisted.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from ..policy import Actor
from .approval_preview import LiveApprovalPreviewStore
from .contract import canonical_json, canonical_sha256, make_stable_id
from .dns_attempt import DNSAttemptStore
from .lifetime_separation import PreparationSnapshotStore
from .native_live import (
    FixtureCredentialResolver,
    FixtureLiveProviderTransportFactory,
    NativeLiveCanaryExecutor,
)
from .persistence.db import MaxControlError, control_transaction
from .persistence.repository import (
    MaxControlRepository,
    _parse_timestamp,
    _timestamp,
    _utc_now,
)
from .preparation_execution import NativePreparationStore
from .preparation_handoff import PREPARED, PreparationHandoffStore
from .provider.live import (
    LiveProviderTransportFactory,
    make_convergence_transport_factory,
    SecureEnvironmentCredentialResolver,
    StdlibDNSResolver,
    StdlibHTTPSConnector,
    credential_reference_hash,
    endpoint_hashes,
    network_policy_hash,
)
from .provider.store import ProviderStore, _profile_from_row
from .provider.usage import ProviderUsageAuthority
from .request_builder import ServerOwnedRequestBuilder
from .long_run import LocalCoreEvidenceGateway
from .release_identity import normalize_release_identity


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_CAPSULE_SCHEMA = "research-kb/mr-convergence-dev19-live-execution-capsule/v1"
_CAPSULE_PHRASE_PREFIX = "EXECUTE MAX CANARY "
_CAPSULE_STATES = {
    "AWAITING_EXECUTION",
    "EXECUTING",
    "SUCCEEDED",
    "KNOWN_PRE_SEND_FAILURE",
    "KNOWN_PROVIDER_FAILURE",
    "UNKNOWN_AFTER_SEND",
}
_FORBIDDEN_KEYS = {
    "prompt", "messages", "source_text", "full_text", "passage_text",
    "response", "response_body", "request_body", "body", "credential",
    "credential_value", "api_key", "authorization", "address", "addresses",
    "ip", "ips", "raw_ip", "raw_ips", "resolved_addresses", "secret",
}


class LiveExecutionCapsuleError(MaxControlError):
    """A compact capsule operation failed closed."""


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value.casefold()) is None:
        raise LiveExecutionCapsuleError(f"{name} must be a SHA-256 digest")
    return value.casefold()


def _safe_mapping(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LiveExecutionCapsuleError(f"{name} must be an object")
    for key, child in value.items():
        if str(key).casefold() in _FORBIDDEN_KEYS:
            raise LiveExecutionCapsuleError(f"{name} contains forbidden material")
        if isinstance(child, Mapping):
            _safe_mapping(child, name)
        elif isinstance(child, (list, tuple)):
            for item in child:
                if isinstance(item, Mapping):
                    _safe_mapping(item, name)
                elif isinstance(item, str) and len(item) > 512:
                    raise LiveExecutionCapsuleError(f"{name} contains an oversized value")
        elif isinstance(child, str) and len(child) > 512:
            raise LiveExecutionCapsuleError(f"{name} contains an oversized value")
    return dict(value)


def _json_object(value: Any, name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LiveExecutionCapsuleError(f"{name} JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise LiveExecutionCapsuleError(f"{name} JSON is not an object")
    return _safe_mapping(parsed, name)


def _row_value(row: sqlite3.Row, column: str, name: str) -> dict[str, Any]:
    return _json_object(row[column], name)


def _remaining(expires_at: str, now: Any) -> int:
    expiry = _parse_timestamp(expires_at)
    if expiry is None:
        return -1
    return max(0, int((expiry - now).total_seconds()))


def _bounded_ttl(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 300 <= value <= 86_400:
        raise LiveExecutionCapsuleError("capsule TTL is outside the supported range")
    return int(value)


def _source_binding_hash(source: Mapping[str, Any]) -> str:
    return canonical_sha256(
        {
            "document_id": source.get("document_id"),
            "passage_id": source.get("passage_id"),
            "source_version": source.get("source_version"),
            "document_content_hash": source.get("document_content_hash"),
            "passage_content_hash": source.get("passage_content_hash"),
        }
    )


def _profile_usage(profile: Any) -> dict[str, int]:
    try:
        return {key: int(value) for key, value in profile.authority_maximum_usage().items()}
    except Exception as exc:
        raise LiveExecutionCapsuleError("provider profile lacks explicit token caps") from exc


class _OneShotCachingResolver:
    """Package-owned resolver cache shared by the DNS and transport stages."""

    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.lookup_count = 0
        self._values: tuple[Any, ...] | None = None

    def resolve(self, host: str, port: int) -> Sequence[Any]:
        if self._values is not None:
            return self._values
        if self.lookup_count != 0:
            raise RuntimeError("one-shot resolver was invoked more than once")
        self.lookup_count = 1
        values = tuple(self.delegate.resolve(host, port))
        self._values = values
        return values


class LiveExecutionCapsuleStore:
    """Persistence and execution facade for the two-user-approval flow."""

    phrase_prefix = _CAPSULE_PHRASE_PREFIX

    def __init__(
        self,
        repository: MaxControlRepository,
        *,
        source_database: str | Path | None = None,
        expected_release_identity: Mapping[str, Any] | None = None,
        clock: Callable[[], Any] | None = None,
    ) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("LiveExecutionCapsuleStore requires MaxControlRepository")
        self.repository = repository
        self.source_database = source_database
        self.expected_release_identity = None if expected_release_identity is None else normalize_release_identity(expected_release_identity)
        self.clock = clock or repository.clock

    def _now(self) -> Any:
        return _utc_now(self.clock)

    def _timestamp(self) -> str:
        return _timestamp(self.clock)

    @staticmethod
    def _admin(actor: Actor) -> None:
        if not isinstance(actor, Actor) or not actor.is_admin:
            raise LiveExecutionCapsuleError("capsule operation requires a human admin actor")

    def _preparation_chain(self, connection: sqlite3.Connection, preparation_preview_id: str) -> dict[str, Any]:
        native = NativePreparationStore(
            self.repository,
            source_database=self.source_database,
            expected_release_identity=self.expected_release_identity,
        )
        chain = native._verify_preview_chain(connection, preparation_preview_id)
        snapshot = chain["snapshot"]
        snapshot_value = chain["snapshot_value"]
        drift = native.snapshots._verify_event_chain(connection, snapshot["snapshot_id"])
        drift += native.snapshots._drift(connection, snapshot, release_identity=chain["release"])
        if drift:
            raise LiveExecutionCapsuleError("preparation binding drifted: " + ", ".join(sorted(set(drift))))
        handoff_current = connection.execute(
            "SELECT * FROM max_runner_preparation_handoff_current WHERE run_id=? AND call_group_id=?",
            (snapshot["run_id"], snapshot_value["group_id"]),
        ).fetchone()
        if handoff_current is None:
            raise LiveExecutionCapsuleError("preparation handoff is missing")
        handoff = connection.execute(
            "SELECT * FROM max_runner_preparation_handoffs WHERE handoff_id=?",
            (handoff_current["handoff_id"],),
        ).fetchone()
        if handoff is None:
            raise LiveExecutionCapsuleError("preparation handoff record is missing")
        issues = PreparationHandoffStore.verify_group_handoff(
            connection,
            run_id=str(snapshot["run_id"]),
            group_id=str(snapshot_value["group_id"]),
            now=self._now(),
        )
        if issues:
            raise LiveExecutionCapsuleError("preparation handoff is invalid: " + ", ".join(sorted(set(issues))))
        if handoff_current["state"] != PREPARED:
            raise LiveExecutionCapsuleError("preparation handoff is not waiting for execution authorization")
        return {**chain, "handoff": handoff, "handoff_current": handoff_current}

    def _binding_context(self, connection: sqlite3.Connection, preparation_preview_id: str) -> dict[str, Any]:
        chain = self._preparation_chain(connection, preparation_preview_id)
        snapshot = chain["snapshot"]
        snapshot_value = chain["snapshot_value"]
        preview = chain["preview"]
        preview_value = chain["preview_value"]
        request = chain["request"]
        request_value = chain["request_value"]
        handoff = chain["handoff"]
        run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (snapshot["run_id"],)).fetchone()
        provider = connection.execute("SELECT * FROM max_run_provider_bindings WHERE run_id=?", (snapshot["run_id"],)).fetchone()
        profile_row = None if provider is None else connection.execute(
            "SELECT * FROM max_provider_profiles WHERE profile_hash=?", (provider["profile_hash"],)
        ).fetchone()
        intent = connection.execute(
            "SELECT * FROM max_model_call_intents WHERE intent_id=? AND run_id=?",
            (snapshot_value["intent_id"], snapshot["run_id"]),
        ).fetchone()
        plan = None if intent is None else connection.execute(
            "SELECT * FROM max_runner_plans WHERE plan_id=? AND run_id=?",
            (intent["plan_id"], snapshot["run_id"]),
        ).fetchone()
        manifest = connection.execute(
            "SELECT * FROM max_runner_intent_manifests WHERE intent_id=? AND run_id=?",
            (snapshot_value["intent_id"], snapshot["run_id"]),
        ).fetchone()
        policy_binding = None
        if provider is not None:
            policy_binding = ProviderStore.validate_network_policy_binding(
                connection,
                run_id=str(snapshot["run_id"]),
                expected_release_identity_hash=str(snapshot["release_identity_hash"]),
            )
        if run is None or provider is None or profile_row is None or intent is None or plan is None or manifest is None or policy_binding is None:
            raise LiveExecutionCapsuleError("server-owned preparation binding is incomplete")
        profile = _profile_from_row(profile_row)
        usage = _profile_usage(profile)
        if provider["project_id"] != run["project_id"] or provider["model_identity"] != profile.model_identity:
            raise LiveExecutionCapsuleError("provider binding crosses its server-owned project/model boundary")
        if preview["snapshot_hash"] != snapshot["snapshot_hash"]:
            raise LiveExecutionCapsuleError("Preparation Preview binding is invalid")
        if plan["project_id"] != run["project_id"] or plan["iteration_id"] != intent["iteration_id"]:
            raise LiveExecutionCapsuleError("runner plan crosses its server-owned run boundary")
        if plan["plan_hash"] != snapshot["plan_hash"]:
            raise LiveExecutionCapsuleError("runner plan hash does not match the Preparation Snapshot")
        if request_value.get("status") != "AWAITING_DNS_PREFLIGHT_AUTHORIZATION":
            raise LiveExecutionCapsuleError("DNS Request is not in the preparation wait state")
        if request_value.get("request_hash") not in {None, request["request_hash"]}:
            raise LiveExecutionCapsuleError("DNS Request serialized hash drifted")
        source = snapshot_value.get("source_binding")
        if not isinstance(source, Mapping):
            raise LiveExecutionCapsuleError("source binding is missing")
        caps = snapshot_value.get("caps")
        if not isinstance(caps, Mapping):
            raise LiveExecutionCapsuleError("server-owned cap vector is missing")
        effective = int(caps.get("max_cost_units", 0))
        if effective <= 0 or effective > 729:
            raise LiveExecutionCapsuleError("effective cost cap is outside the governed maximum")
        if int(caps.get("max_provider_calls", 0)) != 1:
            raise LiveExecutionCapsuleError("capsule requires exactly one provider call")
        origin_hash, _ = endpoint_hashes(profile.endpoint_origin, profile.endpoint_path_policy)
        credential_hash = credential_reference_hash(profile.credential_ref)
        release = chain["release"]
        release_hash = canonical_sha256(release)
        if release_hash != snapshot["release_identity_hash"]:
            raise LiveExecutionCapsuleError("release identity hash is invalid")
        if self.expected_release_identity is not None and release != self.expected_release_identity:
            raise LiveExecutionCapsuleError("release identity is not the current server release")
        source_hash = _source_binding_hash(source)
        return {
            "chain": chain,
            "run": run,
            "provider": provider,
            "profile": profile,
            "profile_row": profile_row,
            "snapshot": snapshot,
            "snapshot_value": snapshot_value,
            "preview": preview,
            "preview_value": preview_value,
            "request": request,
            "request_value": request_value,
            "handoff": handoff,
            "intent": intent,
            "plan": plan,
            "manifest": manifest,
            "policy_binding": policy_binding,
            "source": dict(source),
            "source_hash": source_hash,
            "caps": {str(key): int(value) for key, value in caps.items() if isinstance(value, int) and not isinstance(value, bool)},
            "usage": usage,
            "effective_cost_cap": effective,
            "origin_hash": origin_hash,
            "credential_hash": credential_hash,
            "release": release,
            "release_hash": release_hash,
        }

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        capsule: Mapping[str, Any],
        event_type: str,
        payload: Mapping[str, Any],
        actor: Actor,
        now: str,
    ) -> dict[str, Any]:
        if event_type not in {"created", "execution_started", "terminal"}:
            raise LiveExecutionCapsuleError("capsule event type is invalid")
        safe = _safe_mapping(payload, "capsule event")
        prior = connection.execute(
            "SELECT sequence_no,event_hash FROM max_live_execution_capsule_events WHERE capsule_id=? ORDER BY sequence_no DESC LIMIT 1",
            (capsule["capsule_id"],),
        ).fetchone()
        sequence = 1 if prior is None else int(prior["sequence_no"]) + 1
        previous = None if prior is None else prior["event_hash"]
        payload_hash = canonical_sha256(safe)
        created = {
            "capsule_id": capsule["capsule_id"],
            "run_id": capsule["run_id"],
            "sequence_no": sequence,
            "event_type": event_type,
            "payload_hash": payload_hash,
            "previous_event_hash": previous,
            "created_at": now,
        }
        event_hash = canonical_sha256(created)
        event_id = make_stable_id("live_execution_capsule_event", event_hash[:64])
        connection.execute(
            "INSERT INTO max_live_execution_capsule_events(event_id,capsule_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, capsule["capsule_id"], capsule["run_id"], sequence, event_type, canonical_json(safe), payload_hash, previous, event_hash, now, actor.actor_id, actor.actor_kind, actor.session_id),
        )
        return {"event_id": event_id, "event_hash": event_hash, "sequence_no": sequence, "event_type": event_type}

    @staticmethod
    def _set_current(
        connection: sqlite3.Connection,
        *,
        capsule: Mapping[str, Any],
        state: str,
        now: str,
        consumed_at: str | None = None,
    ) -> dict[str, Any]:
        if state not in _CAPSULE_STATES:
            raise LiveExecutionCapsuleError("capsule state is invalid")
        value = {
            "capsule_id": capsule["capsule_id"],
            "capsule_hash": capsule["capsule_hash"],
            "state": state,
            "consumed_at": consumed_at,
            "updated_at": now,
        }
        current_hash = canonical_sha256(value)
        existing = connection.execute(
            "SELECT capsule_id FROM max_live_execution_capsule_current WHERE capsule_id=?",
            (capsule["capsule_id"],),
        ).fetchone()
        if existing is None:
            connection.execute(
                "INSERT INTO max_live_execution_capsule_current(capsule_id,capsule_hash,state,current_json,current_hash,consumed_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                (capsule["capsule_id"], capsule["capsule_hash"], state, canonical_json(value), current_hash, consumed_at, now),
            )
        else:
            connection.execute(
                "UPDATE max_live_execution_capsule_current SET capsule_hash=?,state=?,current_json=?,current_hash=?,consumed_at=?,updated_at=? WHERE capsule_id=?",
                (capsule["capsule_hash"], state, canonical_json(value), current_hash, consumed_at, now, capsule["capsule_id"]),
            )
        return value | {"current_hash": current_hash}

    def _capsule_row(self, connection: sqlite3.Connection, capsule_hash: str) -> tuple[sqlite3.Row, dict[str, Any]]:
        digest = _require_hash(capsule_hash, "capsule_hash")
        row = connection.execute(
            "SELECT * FROM max_live_execution_capsule_previews WHERE capsule_hash=?",
            (digest,),
        ).fetchone()
        if row is None:
            raise LiveExecutionCapsuleError("Live Execution Capsule Preview was not found")
        value = _row_value(row, "capsule_json", "capsule")
        if canonical_sha256(value) != row["capsule_hash"] or row["capsule_id"] != "live_execution_capsule_" + row["capsule_hash"]:
            raise LiveExecutionCapsuleError("capsule hash or ID is invalid")
        phrase = self.phrase_prefix + row["capsule_hash"]
        if row["confirmation_phrase_hash"] != canonical_sha256(phrase):
            raise LiveExecutionCapsuleError("capsule confirmation hash is invalid")
        return row, value

    def _redacted(self, row: sqlite3.Row, *, include_phrase: bool = False, idempotent: bool = False, connection: sqlite3.Connection | None = None) -> dict[str, Any]:
        now = self._now()
        current = connection or self.repository._connect(read_only=True)
        try:
            projection = current.execute(
                "SELECT state,current_hash,consumed_at,updated_at FROM max_live_execution_capsule_current WHERE capsule_id=?",
                (row["capsule_id"],),
            ).fetchone()
        finally:
            if connection is None:
                current.close()
        result = {
            "ok": True,
            "idempotent": idempotent,
            "capsule_id": row["capsule_id"],
            "capsule_hash": row["capsule_hash"],
            "state": row["state"] if projection is None else projection["state"],
            "expires_at": row["expires_at"],
            "remaining_seconds": _remaining(row["expires_at"], now),
            "project_id": row["project_id"],
            "run_id": row["run_id"],
            "provider_name": row["provider_name"],
            "model_identity": row["model_identity"],
            "max_provider_calls": int(row["max_provider_calls"]),
            "max_input_tokens": int(row["max_input_tokens"]),
            "max_output_tokens": int(row["max_output_tokens"]),
            "effective_cost_cap": int(row["effective_cost_cap"]),
            "current_hash": None if projection is None else projection["current_hash"],
            "consumed_at": None if projection is None else projection["consumed_at"],
        }
        if include_phrase:
            result["confirmation"] = self.phrase_prefix + row["capsule_hash"]
        return result

    def create_preview(self, *, preparation_preview_id: str, actor: Actor, ttl_seconds: int = 86_400) -> dict[str, Any]:
        """Create one server-owned capsule Preview from an existing preparation chain."""

        self._admin(actor)
        if not isinstance(preparation_preview_id, str) or not preparation_preview_id.strip():
            raise LiveExecutionCapsuleError("Preparation Preview selector is required")
        ttl = _bounded_ttl(ttl_seconds)
        now_dt = self._now()
        now = self._timestamp()
        expires = (now_dt + timedelta(seconds=ttl)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                context = self._binding_context(connection, preparation_preview_id)
                snapshot = context["snapshot"]
                snapshot_value = context["snapshot_value"]
                preview = context["preview"]
                request = context["request"]
                request_value = context["request_value"]
                handoff = context["handoff"]
                run = context["run"]
                intent = context["intent"]
                manifest = context["manifest"]
                caps = context["caps"]
                # A compact Preview is the first user-level gate.  Existing
                # internal attempts or approvals mean the preparation chain
                # is no longer fresh and must fail closed.
                activity = {
                    "dns_attempts": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempts WHERE preview_id=?", (preview["preview_id"],)).fetchone()[0]),
                    "dns_receipts": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_dns_attempt_receipts WHERE preview_id=?", (preview["preview_id"],)).fetchone()[0]),
                    "approval_previews": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_approval_previews WHERE run_id=?", (run["run_id"],)).fetchone()[0]),
                    "provider_calls": int(connection.execute("SELECT COUNT(*) FROM max_provider_call_records WHERE run_id=?", (run["run_id"],)).fetchone()[0]),
                    "jit": int(connection.execute("SELECT COUNT(*) FROM max_live_canary_native_jit_authorities WHERE run_id=?", (run["run_id"],)).fetchone()[0]),
                }
                if any(activity.values()):
                    raise LiveExecutionCapsuleError("preparation chain already contains execution activity")
                basis = {
                    "schema": _CAPSULE_SCHEMA,
                    "project_id": run["project_id"],
                    "run_id": run["run_id"],
                    "charter_hash": run["charter_hash"],
                    "current_state_hash": run["current_state_hash"],
                    "current_state_version": int(run["state_version"]),
                    "plan_id": intent["plan_id"],
                    "plan_hash": context["plan"]["plan_hash"],
                    "iteration_id": intent["iteration_id"],
                    "group_id": intent["group_id"] if "group_id" in intent.keys() else snapshot_value["group_id"],
                    "intent_id": intent["intent_id"],
                    "intent_hash": intent["intent_hash"],
                    "request_hash": intent["request_hash"],
                    "request_manifest_hash": manifest["manifest_hash"],
                    "snapshot_id": snapshot["snapshot_id"],
                    "snapshot_hash": snapshot["snapshot_hash"],
                    "preparation_preview_id": preview["preview_id"],
                    "preparation_preview_hash": preview["preview_hash"],
                    "handoff_id": handoff["handoff_id"],
                    "handoff_hash": handoff["handoff_hash"],
                    "dns_authority_id": request["authority_id"],
                    "dns_request_id": request["request_id"],
                    "dns_request_hash": request["request_hash"],
                    "dns_policy_hash": request_value["network_policy_hash"],
                    "max_getaddrinfo_calls": int(request_value["max_getaddrinfo_calls"]),
                    "max_dns_candidates": int(request_value["max_dns_candidates"]),
                    "policy_binding_id": context["policy_binding"]["binding_id"],
                    "network_policy_hash": context["policy_binding"]["network_policy_hash"],
                    "endpoint_origin_hash": context["origin_hash"],
                    "provider_profile_hash": context["profile"].profile_hash,
                    "provider_name": context["profile"].provider_name,
                    "model_identity": context["profile"].model_identity,
                    "pricing_hash": context["profile"].pricing.pricing_hash,
                    "source_policy_hash": snapshot["source_policy_hash"],
                    "credential_reference_hash": context["credential_hash"],
                    "release_identity_hash": context["release_hash"],
                    "wheel_hash": snapshot["candidate_wheel_sha256"],
                    "source_tree_hash": snapshot["source_tree_sha256"],
                    "budget_hash": snapshot["budget_hash"],
                    "source_binding_hash": context["source_hash"],
                    "source_document_id": context["source"]["document_id"],
                    "source_passage_id": context["source"]["passage_id"],
                    "source_version": context["source"]["source_version"],
                    "human_cost_ceiling": 1000,
                    "profile_worst_case_cost": context["effective_cost_cap"],
                    "effective_cost_cap": context["effective_cost_cap"],
                    "max_provider_calls": 1,
                    "max_input_tokens": int(caps.get("max_input_tokens", 0)),
                    "max_output_tokens": int(caps.get("max_output_tokens", 0)),
                    "max_cache_read_tokens": int(caps.get("max_cache_read_tokens", context["usage"].get("cache_read_tokens", 0))),
                    "max_reasoning_tokens": int(caps.get("max_reasoning_tokens", context["usage"].get("reasoning_tokens", 0))),
                    "expires_at": expires,
                    "state": "AWAITING_EXECUTION",
                }
                capsule_hash = canonical_sha256(basis)
                capsule_id = "live_execution_capsule_" + capsule_hash
                existing = connection.execute(
                    "SELECT * FROM max_live_execution_capsule_previews WHERE run_id=?",
                    (run["run_id"],),
                ).fetchone()
                if existing is not None:
                    if existing["capsule_hash"] != capsule_hash or existing["capsule_json"] != canonical_json(basis):
                        raise LiveExecutionCapsuleError("Run already has a different capsule Preview")
                    return self._redacted(existing, include_phrase=True, idempotent=True, connection=connection)
                insert_columns = (
                    "capsule_id", "capsule_hash", "project_id", "run_id", "charter_hash", "current_state_hash",
                    "current_state_version", "plan_id", "plan_hash", "iteration_id", "group_id", "intent_id",
                    "intent_hash", "request_hash", "request_manifest_hash", "snapshot_id", "snapshot_hash",
                    "preparation_preview_id", "preparation_preview_hash", "handoff_id", "handoff_hash",
                    "dns_authority_id", "dns_request_id", "dns_request_hash", "dns_policy_hash",
                    "max_getaddrinfo_calls", "max_dns_candidates", "policy_binding_id", "network_policy_hash",
                    "endpoint_origin_hash", "provider_profile_hash", "provider_name", "model_identity", "pricing_hash",
                    "source_policy_hash", "credential_reference_hash", "release_identity_hash", "wheel_hash",
                    "source_tree_hash", "budget_hash", "source_binding_hash", "source_document_id", "source_passage_id",
                    "source_version", "human_cost_ceiling", "profile_worst_case_cost", "effective_cost_cap",
                    "max_provider_calls", "max_input_tokens", "max_output_tokens", "max_cache_read_tokens",
                    "max_reasoning_tokens", "expires_at", "state", "confirmation_phrase_hash", "capsule_json",
                    "created_at", "actor_id", "actor_kind", "actor_session",
                )
                insert_values = {
                    "capsule_id": capsule_id,
                    "capsule_hash": capsule_hash,
                    **{column: basis[column] for column in insert_columns[2:] if column in basis},
                    "confirmation_phrase_hash": canonical_sha256(self.phrase_prefix + capsule_hash),
                    "capsule_json": canonical_json(basis),
                    "created_at": now,
                    "actor_id": actor.actor_id,
                    "actor_kind": actor.actor_kind,
                    "actor_session": actor.session_id,
                }
                connection.execute(
                    f"INSERT INTO max_live_execution_capsule_previews({','.join(insert_columns)}) VALUES ({','.join('?' for _ in insert_columns)})",
                    tuple(insert_values[column] for column in insert_columns),
                )
                capsule = {"capsule_id": capsule_id, "capsule_hash": capsule_hash, "run_id": run["run_id"]}
                self._set_current(connection, capsule=capsule, state="AWAITING_EXECUTION", now=now)
                self._append_event(connection, capsule=capsule, event_type="created", payload={"capsule_hash": capsule_hash, "preparation_preview_hash": preview["preview_hash"], "dns_request_hash": request["request_hash"], "release_identity_hash": context["release_hash"]}, actor=actor, now=now)
                row = connection.execute("SELECT * FROM max_live_execution_capsule_previews WHERE capsule_id=?", (capsule_id,)).fetchone()
                return self._redacted(row, include_phrase=True, idempotent=False, connection=connection)
        except sqlite3.IntegrityError as exc:
            raise LiveExecutionCapsuleError("capsule Preview conflicted with an immutable preparation binding") from exc
        finally:
            connection.close()

    def status(self, *, capsule_hash: str) -> dict[str, Any]:
        connection = self.repository._connect(read_only=True)
        try:
            row, _ = self._capsule_row(connection, capsule_hash)
            projection = connection.execute("SELECT * FROM max_live_execution_capsule_current WHERE capsule_id=?", (row["capsule_id"],)).fetchone()
            result = self._redacted(row, include_phrase=False, connection=connection)
            if projection is not None:
                result["state"] = projection["state"]
                result["current_hash"] = projection["current_hash"]
                result["consumed_at"] = projection["consumed_at"]
            return result
        finally:
            connection.close()

    def _claim_capsule(self, capsule_hash: str, confirmation: str, actor: Actor) -> tuple[dict[str, Any], dict[str, Any]]:
        self._admin(actor)
        if not isinstance(confirmation, str) or "\r" in confirmation or "\n" in confirmation:
            raise LiveExecutionCapsuleError("capsule confirmation is invalid")
        now = self._now()
        now_text = self._timestamp()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row, value = self._capsule_row(connection, capsule_hash)
                expected = self.phrase_prefix + row["capsule_hash"]
                if confirmation != expected:
                    raise LiveExecutionCapsuleError("capsule confirmation is not the exact server-owned phrase")
                expiry = _parse_timestamp(row["expires_at"])
                if expiry is None or expiry <= now:
                    raise LiveExecutionCapsuleError("capsule Preview is expired")
                current = connection.execute("SELECT * FROM max_live_execution_capsule_current WHERE capsule_id=?", (row["capsule_id"],)).fetchone()
                if current is None or current["state"] != "AWAITING_EXECUTION":
                    raise LiveExecutionCapsuleError("capsule is already consumed or terminal")
                consumed = connection.execute("SELECT 1 FROM max_live_execution_capsule_consumptions WHERE capsule_id=?", (row["capsule_id"],)).fetchone()
                if consumed is not None:
                    raise LiveExecutionCapsuleError("capsule has already been consumed")
                # Re-run the complete server-owned preparation/policy check in
                # the same transaction that consumes the capsule fence.
                context = self._binding_context(connection, str(row["preparation_preview_id"]))
                if context["run"]["run_id"] != row["run_id"] or context["release_hash"] != row["release_identity_hash"] or context["source_hash"] != row["source_binding_hash"]:
                    raise LiveExecutionCapsuleError("capsule binding drifted")
                consumption_value = {"schema": "research-kb/mr-convergence-dev19-capsule-consumption/v1", "capsule_id": row["capsule_id"], "capsule_hash": row["capsule_hash"], "run_id": row["run_id"], "consumed_at": now_text}
                consumption_hash = canonical_sha256(consumption_value)
                consumption_id = make_stable_id("live_execution_capsule_consumption", consumption_hash[:64])
                connection.execute(
                    "INSERT INTO max_live_execution_capsule_consumptions(consumption_id,capsule_id,capsule_hash,run_id,consumed_at,actor_id,actor_kind,actor_session,consumption_json,consumption_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (consumption_id, row["capsule_id"], row["capsule_hash"], row["run_id"], now_text, actor.actor_id, actor.actor_kind, actor.session_id, canonical_json(consumption_value), consumption_hash),
                )
                capsule = {"capsule_id": row["capsule_id"], "capsule_hash": row["capsule_hash"], "run_id": row["run_id"]}
                self._set_current(connection, capsule=capsule, state="EXECUTING", now=now_text, consumed_at=now_text)
                event = self._append_event(connection, capsule=capsule, event_type="execution_started", payload={"capsule_hash": row["capsule_hash"], "consumption_hash": consumption_hash}, actor=actor, now=now_text)
                return {"capsule": capsule, "value": value, "context": context, "consumption_id": consumption_id, "event": event}
        finally:
            connection.close()

    def _terminalize(self, capsule: Mapping[str, Any], state: str, actor: Actor, payload: Mapping[str, Any]) -> dict[str, Any]:
        now = self._timestamp()
        connection = self.repository._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT * FROM max_live_execution_capsule_previews WHERE capsule_id=?", (capsule["capsule_id"],)).fetchone()
                if row is None:
                    raise LiveExecutionCapsuleError("capsule disappeared during terminal closure")
                current = connection.execute("SELECT state FROM max_live_execution_capsule_current WHERE capsule_id=?", (capsule["capsule_id"],)).fetchone()
                if current is None or current["state"] != "EXECUTING":
                    raise LiveExecutionCapsuleError("capsule terminal state changed concurrently")
                safe = _safe_mapping(payload, "capsule terminal payload")
                self._set_current(connection, capsule=capsule, state=state, now=now, consumed_at=now)
                event = self._append_event(connection, capsule=capsule, event_type="terminal", payload={"state": state, **safe}, actor=actor, now=now)
                return {"state": state, "event": event}
        finally:
            connection.close()

    def _internal_transport(
        self,
        *,
        resolver: Any,
        transport_factory: Any | None,
        live_network_enabled: bool,
        model_identity: str | None = None,
    ) -> Any:
        if transport_factory is not None:
            return transport_factory
        if self.repository.is_fixture_database():
            # A fixture still has to use the production HTTPS transport class;
            # only its DNS, connector and credential seams are injected.
            from .provider.live import InjectedDNSResolver, InjectedHTTPSConnector, TransportResponse
            response = {
                "id": "mr-convergence-fixture-call",
                "object": "chat.completion",
                # The response must carry the server-owned profile identity;
                # hard-coding a fixture model here would make the compact
                # surface reject its own bound request as a model drift.
                "model": model_identity or "hermetic-model/v1",
                "choices": [{
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": canonical_json({
                            "objects": [], "relations": [], "artifact_links": [],
                            "record_refs": [], "strategy": None,
                            "output_summary": "bounded hermetic result",
                            "role_outputs": [], "deliberation": None,
                        }),
                    },
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
            return FixtureLiveProviderTransportFactory(
                resolver=resolver or InjectedDNSResolver({"opencode.ai": ("93.184.216.34",)}),
                connector=InjectedHTTPSConnector(TransportResponse(200, response, {"content-type": "application/json"}, "mr-convergence-fixture-call", True)),
                credential_resolver=FixtureCredentialResolver(),
            )
        if not live_network_enabled:
            raise LiveExecutionCapsuleError("production transport is disabled")
        return make_convergence_transport_factory(resolver)

    def execute(
        self,
        *,
        capsule_hash: str,
        confirmation: str,
        actor: Actor,
        resolver: Any | None = None,
        transport_factory: Any | None = None,
        usage_authority: ProviderUsageAuthority | None = None,
        live_network_enabled: bool = True,
    ) -> dict[str, Any]:
        """Consume and execute a capsule once; all internal authority is JIT."""

        claim = self._claim_capsule(capsule_hash, confirmation, actor)
        capsule = claim["capsule"]
        context = claim["context"]
        # The compact CLI has no injectable resolver argument.  A fixture
        # database must therefore select the package-owned bounded resolver
        # before the one-shot wrapper is built; otherwise the default
        # stdlib resolver would cross the hermetic test boundary.
        if resolver is None and self.repository.is_fixture_database():
            from .provider.live import InjectedDNSResolver

            resolver = InjectedDNSResolver({"opencode.ai": ("93.184.216.34",)})
        selected_resolver = _OneShotCachingResolver(resolver or StdlibDNSResolver())
        worker = Actor(
            "mr-convergence-dev19-worker",
            "mr-convergence-dev19-worker-session",
            "worker",
            "runner",
            "research-kb-convergence",
        )
        try:
            dns_request = context["request"]
            dns_phrase = "APPROVE MR-4B1 DNS PREFLIGHT " + str(dns_request["request_hash"])
            dns_result = DNSAttemptStore(self.repository).execute(
                preview_id=str(context["preview"]["preview_id"]),
                request_id=str(dns_request["request_id"]),
                confirmation_phrase=dns_phrase,
                actor=actor,
                allow_execute=True,
                resolver=selected_resolver,
            )
            if not dns_result.get("ok"):
                closure = self._terminalize(capsule, "KNOWN_PRE_SEND_FAILURE", actor, {"failure_stage": "dns", "error_code": dns_result.get("error_code"), "dns_state": dns_result.get("state"), "retry_allowed": False})
                return {"ok": False, "outcome": "KNOWN_PRE_SEND_FAILURE", "capsule_hash": capsule["capsule_hash"], "error_stage": "dns", "dns": {key: dns_result.get(key) for key in ("state", "candidate_count", "ipv4_count", "ipv6_count", "bounded_result_hash", "error_code", "resolver_calls", "retries")}, "terminal": closure, "external_actions": {"resolver_calls": int(getattr(selected_resolver, "lookup_count", 0)), "credential_reads": 0, "tcp": 0, "tls": 0, "https": 0, "provider_calls": 0, "cost_units": 0}, "retry_allowed": False}

            live_preview = LiveApprovalPreviewStore(
                self.repository,
                expected_release_identity=context["release"],
            ).create_approval_preview(
                preparation_preview_id=str(context["preview"]["preview_id"]),
                actor=actor,
                preview_ttl_seconds=3600,
                approval_ttl_seconds=3600,
            )
            approval = LiveApprovalPreviewStore(
                self.repository,
                expected_release_identity=context["release"],
            ).authorize(
                approval_preview_id=str(live_preview["approval_preview_id"]),
                confirmation_phrase=str(live_preview["confirmation_phrase"]),
                actor=actor,
            )
            native_executor = NativeLiveCanaryExecutor(
                self.repository,
                admin_actor=actor,
                worker_actor=worker,
                source_database=self.source_database,
                expected_release_identity=context["release"],
                transport_factory=self._internal_transport(
                    resolver=selected_resolver,
                    transport_factory=transport_factory,
                    live_network_enabled=live_network_enabled,
                    model_identity=str(context["profile"].model_identity),
                ),
                request_builder=(
                    ServerOwnedRequestBuilder(gateway=LocalCoreEvidenceGateway(self.source_database))
                    if self.repository.is_fixture_database() and self.source_database is not None
                    else None
                ),
                usage_authority=usage_authority or ProviderUsageAuthority(),
                live_network_enabled=live_network_enabled,
            )
            execution_preview = native_executor.create_execution_preview(approval_id=str(approval["approval_id"]), actor=actor, ttl_seconds=900)
            execution_authorization = native_executor.authorize_execution(execution_preview_id=str(execution_preview["execution_preview_id"]), confirmation_phrase=str(execution_preview["confirmation_phrase"]), actor=actor)
            native_result = native_executor.execute(execution_authorization_id=str(execution_authorization["execution_authorization_id"]), execution_authorization_hash=str(execution_authorization["execution_authorization_hash"]), allow_execute=True)
            outcome = str(native_result.get("outcome", "KNOWN_PROVIDER_FAILURE"))
            terminal_state = "SUCCEEDED" if outcome == "AUTHORITATIVE_PROVIDER_RESULT" else "UNKNOWN_AFTER_SEND" if outcome == "UNKNOWN_AFTER_SEND" else "KNOWN_PROVIDER_FAILURE" if outcome == "KNOWN_PROVIDER_FAILURE" else "KNOWN_PRE_SEND_FAILURE"
            closure = self._terminalize(capsule, terminal_state, actor, {"outcome": outcome, "provider_call_id_hash": None if native_result.get("provider_call_id") is None else canonical_sha256(str(native_result["provider_call_id"])), "usage_hash": native_result.get("usage_hash"), "retry_allowed": False})
            return {"ok": bool(native_result.get("ok")), "outcome": outcome, "capsule_hash": capsule["capsule_hash"], "dns": {key: dns_result.get(key) for key in ("state", "candidate_count", "ipv4_count", "ipv6_count", "bounded_result_hash", "resolver_calls", "retries")}, "internal": {"live_approval_preview_id": live_preview.get("approval_preview_id"), "human_approval_id": approval.get("approval_id"), "execution_preview_id": execution_preview.get("execution_preview_id"), "execution_authorization_id": execution_authorization.get("execution_authorization_id")}, "native": {key: native_result.get(key) for key in ("authority_id", "provider_call_id", "usage_hash", "error_code", "error_stage", "retry_allowed")}, "terminal": closure, "external_actions": {"resolver_calls": int(getattr(selected_resolver, "lookup_count", 0)), "credential_reads": 1 if native_result.get("ok") or native_result.get("outcome") == "UNKNOWN_AFTER_SEND" else 0, "tcp": 1 if native_result.get("ok") or native_result.get("outcome") == "UNKNOWN_AFTER_SEND" else 0, "tls": 1 if native_result.get("ok") or native_result.get("outcome") == "UNKNOWN_AFTER_SEND" else 0, "https": 1 if native_result.get("ok") or native_result.get("outcome") == "UNKNOWN_AFTER_SEND" else 0, "provider_calls": 1 if native_result.get("ok") or native_result.get("outcome") == "UNKNOWN_AFTER_SEND" else 0, "cost_units": 0}, "retry_allowed": False}
        except Exception as exc:
            error_code = getattr(exc, "error_code", None) or getattr(exc, "code", None) or type(exc).__name__
            closure_state = "UNKNOWN_AFTER_SEND" if "send" in str(error_code).lower() or "unknown" in str(error_code).lower() else "KNOWN_PRE_SEND_FAILURE"
            closure = self._terminalize(capsule, closure_state, actor, {"error_code": str(error_code), "retry_allowed": False})
            return {"ok": False, "outcome": closure_state, "capsule_hash": capsule["capsule_hash"], "error_code": str(error_code), "terminal": closure, "external_actions": {"resolver_calls": int(getattr(selected_resolver, "lookup_count", 0)), "credential_reads": 0, "tcp": 0, "tls": 0, "https": 0, "provider_calls": 0, "cost_units": 0}, "retry_allowed": False}

    def recover(self, *, capsule_hash: str, actor: Actor, reason: str = "crash_recovery") -> dict[str, Any]:
        """Close an interrupted execution as unknown; this never retries."""

        self._admin(actor)
        connection = self.repository._connect(read_only=True)
        try:
            row, _ = self._capsule_row(connection, capsule_hash)
            current = connection.execute("SELECT state FROM max_live_execution_capsule_current WHERE capsule_id=?", (row["capsule_id"],)).fetchone()
        finally:
            connection.close()
        if current is None or current["state"] != "EXECUTING":
            raise LiveExecutionCapsuleError("capsule is not interrupted")
        return self._terminalize({"capsule_id": row["capsule_id"], "capsule_hash": row["capsule_hash"], "run_id": row["run_id"]}, "UNKNOWN_AFTER_SEND", actor, {"reason_hash": canonical_sha256(reason), "retry_allowed": False})

    def verify(self, *, capsule_hash: str | None = None) -> dict[str, Any]:
        """Verify capsule, current projection, lineage and server policy binding."""

        connection = self.repository._connect(read_only=True)
        try:
            rows = []
            if capsule_hash is None:
                rows = list(connection.execute("SELECT * FROM max_live_execution_capsule_previews ORDER BY created_at,capsule_id"))
            else:
                row = connection.execute("SELECT * FROM max_live_execution_capsule_previews WHERE capsule_hash=?", (_require_hash(capsule_hash, "capsule_hash"),)).fetchone()
                if row is not None:
                    rows = [row]
            issues: list[str] = []
            event_count = 0
            consumption_count = 0
            states: list[str] = []
            for row in rows:
                try:
                    value = _row_value(row, "capsule_json", "capsule")
                    if canonical_sha256(value) != row["capsule_hash"]:
                        issues.append("capsule_hash")
                    if row["confirmation_phrase_hash"] != canonical_sha256(self.phrase_prefix + row["capsule_hash"]):
                        issues.append("confirmation_phrase_hash")
                    current = connection.execute("SELECT * FROM max_live_execution_capsule_current WHERE capsule_id=?", (row["capsule_id"],)).fetchone()
                    if current is None:
                        issues.append("current_projection_missing")
                    else:
                        states.append(str(current["state"]))
                        current_value = _json_object(current["current_json"], "capsule current")
                        if canonical_sha256(current_value) != current["current_hash"] or current_value.get("state") != current["state"] or current_value.get("capsule_hash") != row["capsule_hash"]:
                            issues.append("current_projection_hash")
                    consumption = list(connection.execute("SELECT * FROM max_live_execution_capsule_consumptions WHERE capsule_id=?", (row["capsule_id"],)))
                    consumption_count += len(consumption)
                    if len(consumption) > 1:
                        issues.append("multiple_consumptions")
                    for item in consumption:
                        value_c = _json_object(item["consumption_json"], "capsule consumption")
                        if canonical_sha256(value_c) != item["consumption_hash"]:
                            issues.append("consumption_hash")
                    events = list(connection.execute("SELECT * FROM max_live_execution_capsule_events WHERE capsule_id=? ORDER BY sequence_no", (row["capsule_id"],)))
                    event_count += len(events)
                    previous = None
                    for expected, event in enumerate(events, 1):
                        payload = _json_object(event["payload_json"], "capsule event")
                        if int(event["sequence_no"]) != expected or event["previous_event_hash"] != previous or canonical_sha256(payload) != event["payload_hash"]:
                            issues.append("event_chain")
                        basis = {"capsule_id": event["capsule_id"], "run_id": event["run_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if canonical_sha256(basis) != event["event_hash"]:
                            issues.append("event_hash")
                        previous = event["event_hash"]
                    if not events or events[0]["event_type"] != "created":
                        issues.append("created_event_missing")
                    # Revalidate the policy object by stable ID/hash, never by
                    # a client-supplied payload.
                    ProviderStore.validate_network_policy_binding(connection, run_id=str(row["run_id"]), expected_release_identity_hash=str(row["release_identity_hash"]))
                except Exception as exc:
                    issues.append(type(exc).__name__ + ":" + str(exc))
            return {"ok": bool(rows) and not issues, "capsule_count": len(rows), "event_count": event_count, "consumption_count": consumption_count, "states": states, "issues": sorted(set(issues)), "internal_authority": "server-owned", "raw_material_persisted": False}
        finally:
            connection.close()


__all__ = ["LiveExecutionCapsuleError", "LiveExecutionCapsuleStore"]
