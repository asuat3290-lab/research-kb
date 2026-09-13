"""MR-4B1B-v11R1 lifetime-separated preparation and JIT boundaries.

This module deliberately does not reuse the schema19 live-canary Preview or
Authority stores.  A preparation snapshot is a durable, non-executable
binding.  Human approval binds that snapshot.  Only ``issue_jit_authority``
creates a lease, invocation claim, and fencing token, and it does so in the
same SQLite transaction as approval consumption and JIT authority creation.

Only identifiers, hashes, bounded counts, and policy metadata cross this
boundary.  No prompt, message, source text, endpoint, or credential value is
persisted or returned.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any, Mapping

from ..policy import Actor
from .contract import RunStatus, canonical_json, canonical_sha256
from .persistence.db import MaxControlError, control_transaction
from .persistence.repository import (
    MaxControlRepository,
    _hash,
    _json,
    _loads,
    _parse_timestamp,
    _timestamp,
    _utc_now,
)
from .provider.live import credential_reference_hash, endpoint_hashes
from .provider.store import ProviderStore
from .release_identity import normalize_release_identity


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_CAP_KEYS = (
    "max_provider_calls", "max_ticks", "max_iterations",
    "max_acquisition_requests", "max_ocr_requests", "max_ingest_operations",
    "max_input_tokens", "max_output_tokens", "max_cache_read_tokens",
    "max_reasoning_tokens", "max_cost_units", "max_wall_clock_seconds",
    "max_source_passages", "max_source_characters",
)
_SOURCE_KEYS = (
    "document_id", "passage_id", "source_version", "document_content_hash",
    "passage_content_hash", "source_role", "evidential_function", "purpose",
)
_FORBIDDEN_SERIALIZED_KEYS = {
    "prompt", "messages", "source_text", "passage_text", "document_text",
    "full_text", "request_body", "body", "endpoint", "endpoint_origin",
    "credential", "credential_value", "api_key", "authorization",
    "fencing_token", "claim_id", "lease_id", "worker_id", "worker_session",
}


class PreparationSnapshotError(MaxControlError):
    """A lifetime-separated preparation boundary failed closed."""


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value.casefold()):
        raise PreparationSnapshotError(f"{name} must be a lowercase SHA-256 digest")
    return value.casefold()


def _text(value: Any, name: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise PreparationSnapshotError(f"{name} is invalid")
    return value.strip()


def _safe_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PreparationSnapshotError(f"{name} must be an object")
    result = dict(value)
    if _serialized_forbidden(result):
        raise PreparationSnapshotError(f"{name} contains an execution or source-body field")
    return result


def _serialized_forbidden(value: Any, path: str = "$") -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).casefold() in _FORBIDDEN_SERIALIZED_KEYS:
                return True
            if _serialized_forbidden(item, path + "." + str(key)):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_serialized_forbidden(item, path + "[]") for item in value)
    return False


def _caps(value: Mapping[str, Any]) -> dict[str, int]:
    raw = _safe_mapping(value, "caps")
    if set(raw) != set(_CAP_KEYS):
        missing = sorted(set(_CAP_KEYS) - set(raw))
        extra = sorted(set(raw) - set(_CAP_KEYS))
        raise PreparationSnapshotError(f"caps are not exact; missing={missing}, extra={extra}")
    result: dict[str, int] = {}
    for key in _CAP_KEYS:
        item = raw[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise PreparationSnapshotError(f"cap {key} is invalid")
        result[key] = int(item)
    if result["max_provider_calls"] != 1 or result["max_ticks"] != 1 or result["max_iterations"] != 1:
        raise PreparationSnapshotError("one-shot caps are not exact")
    if any(result[key] != 0 for key in ("max_acquisition_requests", "max_ocr_requests", "max_ingest_operations")):
        raise PreparationSnapshotError("acquisition/OCR/ingest caps must be zero")
    if result["max_cost_units"] > 729:
        raise PreparationSnapshotError("effective cost cap exceeds 729 micro-USD")
    return result


def _source(value: Mapping[str, Any]) -> dict[str, str]:
    raw = _safe_mapping(value, "source_binding")
    if set(raw) != set(_SOURCE_KEYS):
        raise PreparationSnapshotError("source binding fields are not exact")
    result: dict[str, str] = {}
    for key in _SOURCE_KEYS:
        result[key] = _text(raw[key], key, max_length=512)
    for key in ("document_content_hash", "passage_content_hash"):
        result[key] = _digest(result[key], key)
    return result


def _profile_hash_from_credential_json(value: str) -> str:
    try:
        reference = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PreparationSnapshotError("stored credential reference is invalid") from exc
    return credential_reference_hash(reference)


def _event(
    connection: sqlite3.Connection,
    *,
    snapshot: Mapping[str, Any],
    event_type: str,
    payload: Mapping[str, Any],
    actor: Actor,
    now: str,
) -> dict[str, Any]:
    prior = connection.execute(
        "SELECT sequence_no,event_hash FROM max_live_canary_preparation_snapshot_events WHERE snapshot_id=? ORDER BY sequence_no DESC LIMIT 1",
        (snapshot["snapshot_id"],),
    ).fetchone()
    sequence = int(prior["sequence_no"]) + 1 if prior is not None else 1
    previous_hash = prior["event_hash"] if prior is not None else None
    payload_value = dict(payload)
    payload_json = _json(payload_value)
    payload_hash = _hash(payload_value)
    identity = {
        "snapshot_id": snapshot["snapshot_id"], "run_id": snapshot["run_id"],
        "sequence_no": sequence, "event_type": event_type,
        "payload_hash": payload_hash, "previous_event_hash": previous_hash,
    }
    event_hash = _hash({
        **identity, "payload_json": payload_json, "actor_id": actor.actor_id,
        "actor_kind": actor.actor_kind, "actor_session": actor.session_id,
        "created_at": now,
    })
    event_id = "preparation_snapshot_event_" + event_hash[:48]
    connection.execute(
        "INSERT INTO max_live_canary_preparation_snapshot_events(event_id,snapshot_id,run_id,sequence_no,event_type,payload_json,payload_hash,previous_event_hash,event_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (event_id, snapshot["snapshot_id"], snapshot["run_id"], sequence, event_type,
         payload_json, payload_hash, previous_hash, event_hash, now,
         actor.actor_id, actor.actor_kind, actor.session_id),
    )
    return {"sequence_no": sequence, "event_hash": event_hash}


def _current_projection(
    connection: sqlite3.Connection,
    *,
    snapshot: Mapping[str, Any],
    status: str,
    reason_code: str | None,
    event: Mapping[str, Any],
    now: str,
) -> None:
    current = {
        "snapshot_id": snapshot["snapshot_id"], "run_id": snapshot["run_id"],
        "status": status, "reason_code": reason_code,
        "current_event_sequence": int(event["sequence_no"]),
        "current_event_hash": event["event_hash"],
    }
    current_hash = _hash(current)
    current_json = _json({**current, "current_hash": current_hash})
    row = connection.execute(
        "SELECT snapshot_id FROM max_live_canary_preparation_snapshot_current WHERE run_id=?",
        (snapshot["run_id"],),
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO max_live_canary_preparation_snapshot_current(snapshot_id,run_id,status,reason_code,current_event_sequence,current_event_hash,current_json,current_hash,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (snapshot["snapshot_id"], snapshot["run_id"], status, reason_code,
             int(event["sequence_no"]), event["event_hash"], current_json,
             current_hash, now),
        )
    else:
        connection.execute(
            "UPDATE max_live_canary_preparation_snapshot_current SET snapshot_id=?,status=?,reason_code=?,current_event_sequence=?,current_event_hash=?,current_json=?,current_hash=?,updated_at=? WHERE run_id=?",
            (snapshot["snapshot_id"], status, reason_code, int(event["sequence_no"]),
             event["event_hash"], current_json, current_hash, now, snapshot["run_id"]),
        )


class PreparationSnapshotStore:
    """Server-owned durable Snapshot, Preview, approval, and JIT boundary."""

    def __init__(self, repository: MaxControlRepository, *, source_database: str | Path | None = None) -> None:
        self.repository = repository
        default_source = Path(r"D:\research-kb-pilot\data\research.db")
        self.source_database = Path(source_database) if source_database is not None else default_source

    def _connect(self, *, read_only: bool, verify_schema: bool = True) -> sqlite3.Connection:
        return self.repository._connect(read_only=read_only, verify_schema=verify_schema)

    def _snapshot_row(self, connection: sqlite3.Connection, snapshot_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM max_live_canary_preparation_snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            raise PreparationSnapshotError("preparation snapshot was not found")
        if _hash(_loads(row["snapshot_json"])) != row["snapshot_hash"]:
            raise PreparationSnapshotError("preparation snapshot hash is invalid")
        return row

    def _verify_event_chain(self, connection: sqlite3.Connection, snapshot_id: str) -> list[str]:
        issues: list[str] = []
        previous: str | None = None
        rows = list(connection.execute(
            "SELECT * FROM max_live_canary_preparation_snapshot_events WHERE snapshot_id=? ORDER BY sequence_no",
            (snapshot_id,),
        ))
        for expected, row in enumerate(rows, 1):
            try:
                payload = _loads(row["payload_json"])
                if int(row["sequence_no"]) != expected:
                    issues.append("snapshot event sequence gap")
                if _hash(payload) != row["payload_hash"]:
                    issues.append("snapshot event payload hash mismatch")
                if row["previous_event_hash"] != previous:
                    issues.append("snapshot event previous hash mismatch")
                identity = {
                    "snapshot_id": row["snapshot_id"], "run_id": row["run_id"],
                    "sequence_no": int(row["sequence_no"]), "event_type": row["event_type"],
                    "payload_hash": row["payload_hash"], "previous_event_hash": row["previous_event_hash"],
                }
                expected_hash = _hash({
                    **identity, "payload_json": row["payload_json"],
                    "actor_id": row["actor_id"], "actor_kind": row["actor_kind"],
                    "actor_session": row["actor_session"], "created_at": row["created_at"],
                })
                if expected_hash != row["event_hash"]:
                    issues.append("snapshot event hash mismatch")
                previous = row["event_hash"]
            except Exception:
                issues.append("snapshot event is invalid")
        if not rows:
            issues.append("snapshot event chain is empty")
        return sorted(set(issues))

    def _read_live_binding(self, connection: sqlite3.Connection, run_id: str) -> dict[str, Any]:
        run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
        if run is None:
            raise PreparationSnapshotError("Max Run was not found")
        provider = connection.execute("SELECT * FROM max_run_provider_bindings WHERE run_id=?", (run_id,)).fetchone()
        if provider is None:
            raise PreparationSnapshotError("Run has no immutable provider binding")
        profile = connection.execute("SELECT * FROM max_provider_profiles WHERE profile_hash=?", (provider["profile_hash"],)).fetchone()
        if profile is None:
            raise PreparationSnapshotError("provider profile is not registered")
        try:
            network_policy = ProviderStore.registered_network_policy(
                connection,
                network_policy_hash_value=str(provider["network_policy_hash"]),
            )
        except MaxControlError as exc:
            raise PreparationSnapshotError("Run has no valid server-owned live network policy") from exc
        policy = connection.execute(
            "SELECT * FROM max_source_egress_policies WHERE run_id=? ORDER BY created_at DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if policy is None:
            raise PreparationSnapshotError("Run has no source-egress policy")
        intent = connection.execute(
            "SELECT i.*, p.plan_hash, p.sequence_no, p.round_type AS plan_round_type, b.group_id, b.status AS binding_status "
            "FROM max_model_call_intents i JOIN max_runner_plans p ON p.plan_id=i.plan_id "
            "JOIN max_runner_call_bindings b ON b.logical_call_id=i.logical_call_id "
            "WHERE i.run_id=? AND NOT EXISTS (SELECT 1 FROM max_runner_attempt_outcomes o WHERE o.logical_call_id=i.logical_call_id) "
            "ORDER BY i.created_at DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if intent is None:
            raise PreparationSnapshotError("exactly one unfinished durable intent is required")
        extra = connection.execute(
            "SELECT COUNT(*) FROM max_model_call_intents i WHERE i.run_id=? AND NOT EXISTS (SELECT 1 FROM max_runner_attempt_outcomes o WHERE o.logical_call_id=i.logical_call_id)",
            (run_id,),
        ).fetchone()[0]
        if int(extra) != 1:
            raise PreparationSnapshotError("preparation requires exactly one unfinished intent")
        group = connection.execute("SELECT * FROM max_runner_call_groups WHERE group_id=?", (intent["group_id"],)).fetchone()
        if group is None:
            raise PreparationSnapshotError("durable call group is missing")
        return {"run": run, "provider": provider, "profile": profile, "policy": policy, "network_policy": network_policy, "intent": intent, "group": group}

    def _source_metadata_matches(self, binding: Mapping[str, Any]) -> bool:
        if not self.source_database.is_file():
            return False
        try:
            connection = sqlite3.connect(f"file:{self.source_database.as_posix()}?mode=ro", uri=True)
            try:
                doc = connection.execute(
                    "SELECT document_id,content_hash,source_version FROM documents WHERE document_id=?",
                    (binding["document_id"],),
                ).fetchone()
                passage = connection.execute(
                    "SELECT passage_id,document_id,text_hash FROM passages WHERE passage_id=?",
                    (binding["passage_id"],),
                ).fetchone()
            finally:
                connection.close()
            return bool(
                doc is not None and passage is not None
                and doc[0] == binding["document_id"]
                and doc[1] == binding["document_content_hash"]
                and doc[2] == binding["source_version"]
                and passage[0] == binding["passage_id"]
                and passage[1] == binding["document_id"]
                and passage[2] == binding["passage_content_hash"]
            )
        except (OSError, sqlite3.Error):
            return False

    def _drift(self, connection: sqlite3.Connection, row: sqlite3.Row, *, release_identity: Mapping[str, Any] | None = None) -> list[str]:
        issues: list[str] = []
        binding = _loads(row["snapshot_json"])
        live = self._read_live_binding(connection, row["run_id"])
        run, provider, profile, policy, intent, group = (live[key] for key in ("run", "provider", "profile", "policy", "intent", "group"))
        try:
            network_binding = ProviderStore.validate_network_policy_binding(
                connection,
                run_id=str(row["run_id"]),
                expected_release_identity_hash=str(row["release_identity_hash"]),
            )
            if (
                network_binding["network_policy_hash"] != provider["network_policy_hash"]
                or network_binding["endpoint_origin_hash"] != binding.get("endpoint_origin_hash")
                or network_binding["credential_reference_hash"] != binding.get("credential_reference_hash")
            ):
                issues.append("live_network_policy_binding_drift")
        except MaxControlError:
            issues.append("live_network_policy_binding_invalid")
        if run["status"] != RunStatus.RUNNING.value:
            issues.append("run_not_running")
        for column, actual in (
            ("project_id", run["project_id"]), ("charter_hash", run["charter_hash"]),
            ("research_state_hash", run["current_state_hash"]),
            ("checkpoint_id", run["current_checkpoint_id"]),
            ("state_version", int(run["state_version"])),
            ("provider_profile_hash", provider["profile_hash"]),
            ("model_identity", provider["model_identity"]),
            ("pricing_hash", provider["pricing_hash"]),
            ("budget_hash", provider["budget_hash"]),
            ("network_policy_hash", provider["network_policy_hash"]),
            ("source_egress_policy_hash", policy["policy_hash"]),
            ("plan_id", intent["plan_id"]), ("plan_hash", intent["plan_hash"]),
            ("iteration_id", intent["iteration_id"]), ("group_id", intent["group_id"]),
            ("logical_call_id", intent["logical_call_id"]), ("intent_id", intent["intent_id"]),
            ("intent_hash", intent["intent_hash"]), ("request_hash", intent["request_hash"]),
        ):
            if binding.get(column) != actual:
                issues.append(column + "_drift")
        if profile["model_identity"] != binding.get("model_identity") or profile["pricing_hash"] != binding.get("pricing_hash"):
            issues.append("provider_profile_drift")
        expected_credential_hash = _profile_hash_from_credential_json(profile["credential_ref_json"])
        if binding.get("credential_reference_hash") != expected_credential_hash:
            issues.append("credential_reference_drift")
        try:
            expected_origin, _ = endpoint_hashes(profile["endpoint_origin"], profile["endpoint_path_policy"])
            if binding.get("endpoint_origin_hash") != expected_origin:
                issues.append("endpoint_origin_drift")
        except Exception:
            issues.append("endpoint_binding_invalid")
        try:
            allow_documents = json.loads(policy["allow_document_ids_json"])
            allow_passages = json.loads(policy["allow_passage_ids_json"])
            allow_versions = json.loads(policy["allowed_source_versions_json"])
            source = binding.get("source_binding", {})
            if source.get("document_id") not in allow_documents or source.get("passage_id") not in allow_passages or source.get("source_version") not in allow_versions:
                issues.append("source_allowlist_drift")
        except Exception:
            issues.append("source_policy_invalid")
        if not self._source_metadata_matches(binding.get("source_binding", {})):
            issues.append("source_content_drift_or_unavailable")
        expiry = _parse_timestamp(row["review_expires_at"])
        if expiry is None or expiry <= _utc_now(self.repository.clock):
            issues.append("snapshot_review_expired")
        if release_identity is not None:
            try:
                normalized = normalize_release_identity(release_identity)
                stored = normalize_release_identity(binding["release_identity"])
                if normalized != stored:
                    issues.append("release_identity_drift")
            except Exception:
                issues.append("release_identity_invalid")
        return sorted(set(issues))

    def create_snapshot(
        self,
        *,
        run_id: str,
        source_binding: Mapping[str, Any],
        preparation: Mapping[str, Any],
        caps: Mapping[str, Any],
        release_identity: Mapping[str, Any],
        actor: Actor,
        review_ttl_seconds: int = 7 * 24 * 3600,
    ) -> dict[str, Any]:
        if not actor.is_admin:
            raise PreparationSnapshotError("snapshot creation requires human admin authority")
        run_id = _text(run_id, "run_id", max_length=256)
        source = _source(source_binding)
        cap_vector = _caps(caps)
        release = normalize_release_identity(release_identity)
        prep = _safe_mapping(preparation, "preparation")
        for key in ("wire_request_hash", "request_manifest_hash", "source_manifest_sha256"):
            _digest(prep.get(key), key)
        if review_ttl_seconds < 3600 or review_ttl_seconds > 30 * 24 * 3600:
            raise PreparationSnapshotError("snapshot review TTL is outside its bounded range")
        now = _timestamp(self.repository.clock)
        expires = (_utc_now(self.repository.clock) + timedelta(seconds=review_ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                live = self._read_live_binding(connection, run_id)
                run, provider, profile, policy, intent, group = (live[key] for key in ("run", "provider", "profile", "policy", "intent", "group"))
                if run["status"] != RunStatus.RUNNING.value:
                    raise PreparationSnapshotError("snapshot requires a RUNNING Run")
                if source["document_id"] not in json.loads(policy["allow_document_ids_json"]) or source["passage_id"] not in json.loads(policy["allow_passage_ids_json"]) or source["source_version"] not in json.loads(policy["allowed_source_versions_json"]):
                    raise PreparationSnapshotError("source binding is outside the server-owned source policy")
                if provider["profile_hash"] != profile["profile_hash"] or provider["model_identity"] != profile["model_identity"]:
                    raise PreparationSnapshotError("provider binding is inconsistent")
                endpoint_origin_hash, _ = endpoint_hashes(profile["endpoint_origin"], profile["endpoint_path_policy"])
                credential_hash = _profile_hash_from_credential_json(profile["credential_ref_json"])
                if intent["request_hash"] != prep.get("request_hash", intent["request_hash"]):
                    raise PreparationSnapshotError("request hash drifted before snapshot")
                stable = {
                    "schema": "research-kb/mr4b1b-v11r1-preparation-snapshot/v1",
                    "project_id": run["project_id"], "run_id": run_id,
                    "charter_hash": run["charter_hash"], "research_state_hash": run["current_state_hash"],
                    "checkpoint_id": run["current_checkpoint_id"], "state_version": int(run["state_version"]),
                    "plan_id": intent["plan_id"], "plan_hash": intent["plan_hash"],
                    "iteration_id": intent["iteration_id"], "group_id": intent["group_id"],
                    "logical_call_id": intent["logical_call_id"], "intent_id": intent["intent_id"],
                    "intent_hash": intent["intent_hash"], "request_hash": intent["request_hash"],
                    "wire_request_hash": _digest(prep["wire_request_hash"], "wire_request_hash"),
                    "request_manifest_hash": _digest(prep["request_manifest_hash"], "request_manifest_hash"),
                    "provider_profile_hash": provider["profile_hash"], "model_identity": provider["model_identity"],
                    "network_policy_hash": provider["network_policy_hash"], "credential_reference_hash": credential_hash,
                    "pricing_hash": provider["pricing_hash"], "budget_hash": provider["budget_hash"],
                    "source_egress_policy_hash": policy["policy_hash"], "source_policy_hash": policy["source_policy_hash"],
                    "source_binding": source, "caps": cap_vector, "caps_hash": _hash(cap_vector),
                    "engine_version": release["package_version"], "release_identity": release,
                    "candidate_wheel_sha256": release["wheel_sha256"], "source_manifest_sha256": _digest(prep["source_manifest_sha256"], "source_manifest_sha256"),
                    "source_tree_sha256": release["source_tree_sha256"],
                    "release_metadata_sha256": release["release_manifest_sha256"],
                    "migration_release_manifest_sha256": release["migration_release_manifest_sha256"],
                    "endpoint_origin_hash": endpoint_origin_hash,
                }
                snapshot_hash = _hash(stable)
                snapshot_id = "preparation_snapshot_" + snapshot_hash[:48]
                existing = connection.execute("SELECT snapshot_json,snapshot_hash FROM max_live_canary_preparation_snapshots WHERE snapshot_hash=?", (snapshot_hash,)).fetchone()
                if existing is not None:
                    if existing["snapshot_json"] != _json(stable):
                        raise PreparationSnapshotError("preparation snapshot hash collision")
                    try:
                        ProviderStore.validate_network_policy_binding(
                            connection,
                            run_id=run_id,
                            expected_release_identity_hash=_hash(release),
                        )
                    except MaxControlError as exc:
                        raise PreparationSnapshotError("existing preparation snapshot has no valid live network policy binding") from exc
                    return {"ok": True, "idempotent": True, "snapshot_id": snapshot_id, "snapshot_hash": snapshot_hash, "status": "active", "review_expires_at": None}
                current = connection.execute("SELECT snapshot_id,status FROM max_live_canary_preparation_snapshot_current WHERE run_id=?", (run_id,)).fetchone()
                if current is not None and current["status"] == "active":
                    raise PreparationSnapshotError("an active preparation snapshot already exists for this Run")
                try:
                    ProviderStore.materialize_network_policy_binding(
                        connection,
                        run=run,
                        provider=provider,
                        profile=profile,
                        release_identity_hash=_hash(release),
                        actor=actor,
                        now=now,
                    )
                except MaxControlError as exc:
                    raise PreparationSnapshotError("could not persist server-owned live network policy binding") from exc
                connection.execute(
                    "INSERT INTO max_live_canary_preparation_snapshots(snapshot_id,run_id,project_id,charter_hash,research_state_hash,checkpoint_id,state_version,plan_id,plan_hash,iteration_id,group_id,logical_call_id,intent_id,intent_hash,request_hash,wire_request_hash,request_manifest_hash,provider_profile_hash,model_identity,network_policy_hash,credential_reference_hash,pricing_hash,budget_hash,source_egress_policy_hash,source_version,document_id,passage_id,document_content_hash,passage_content_hash,source_policy_hash,caps_json,caps_hash,engine_version,candidate_wheel_sha256,source_manifest_sha256,source_tree_sha256,release_metadata_sha256,migration_release_manifest_sha256,release_identity_json,release_identity_hash,snapshot_json,snapshot_hash,created_at,review_expires_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (snapshot_id, run_id, run["project_id"], run["charter_hash"], run["current_state_hash"], run["current_checkpoint_id"], int(run["state_version"]), intent["plan_id"], intent["plan_hash"], intent["iteration_id"], intent["group_id"], intent["logical_call_id"], intent["intent_id"], intent["intent_hash"], intent["request_hash"], stable["wire_request_hash"], stable["request_manifest_hash"], provider["profile_hash"], provider["model_identity"], provider["network_policy_hash"], credential_hash, provider["pricing_hash"], provider["budget_hash"], policy["policy_hash"], source["source_version"], source["document_id"], source["passage_id"], source["document_content_hash"], source["passage_content_hash"], policy["source_policy_hash"], _json(cap_vector), _hash(cap_vector), release["package_version"], release["wheel_sha256"], stable["source_manifest_sha256"], release["source_tree_sha256"], release["release_manifest_sha256"], release["migration_release_manifest_sha256"], _json(release), _hash(release), _json(stable), snapshot_hash, now, expires, actor.actor_id, actor.actor_kind, actor.session_id),
                )
                snapshot_ref = {"snapshot_id": snapshot_id, "run_id": run_id}
                ev = _event(connection, snapshot=snapshot_ref, event_type="created", payload={"snapshot_hash": snapshot_hash, "status": "active"}, actor=actor, now=now)
                _current_projection(connection, snapshot=snapshot_ref, status="active", reason_code=None, event=ev, now=now)
                return {"ok": True, "idempotent": False, "snapshot_id": snapshot_id, "snapshot_hash": snapshot_hash, "status": "active", "created_at": now, "review_expires_at": expires, "execution_authority": "none", "lease": 0, "claim": 0}
        except PreparationSnapshotError:
            raise
        except sqlite3.IntegrityError as exc:
            raise PreparationSnapshotError("preparation snapshot write conflicts with an immutable record") from exc
        finally:
            connection.close()

    def status(self, *, snapshot_id: str, release_identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            row = self._snapshot_row(connection, snapshot_id)
            current = connection.execute("SELECT * FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?", (snapshot_id,)).fetchone()
            issues = self._verify_event_chain(connection, snapshot_id)
            if current is None:
                issues.append("snapshot current projection is missing")
            else:
                projection = _loads(current["current_json"])
                stored_projection_hash = projection.pop("current_hash", None) if isinstance(projection, dict) else None
                if stored_projection_hash != current["current_hash"] or _hash(projection) != current["current_hash"]:
                    issues.append("snapshot current projection hash mismatch")
                if current["status"] == "active":
                    issues.extend(self._drift(connection, row, release_identity=release_identity))
                else:
                    issues.append("snapshot is not active")
            return {"ok": not issues, "snapshot_id": snapshot_id, "snapshot_hash": row["snapshot_hash"], "status": current["status"] if current else "unknown", "review_expires_at": row["review_expires_at"], "issues": sorted(set(issues)), "execution_authority": "none", "active_lease_required": False, "active_claim_required": False}
        finally:
            connection.close()

    def invalidate(self, *, snapshot_id: str, reason_code: str, actor: Actor) -> dict[str, Any]:
        if not actor.is_admin:
            raise PreparationSnapshotError("snapshot invalidation requires human admin authority")
        reason_code = _text(reason_code, "reason_code", max_length=128)
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = self._snapshot_row(connection, snapshot_id)
                current = connection.execute("SELECT status FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?", (snapshot_id,)).fetchone()
                if current is None or current["status"] != "active":
                    return {"ok": True, "idempotent": True, "snapshot_id": snapshot_id, "status": current["status"] if current else "unknown"}
                ref = {"snapshot_id": row["snapshot_id"], "run_id": row["run_id"]}
                ev = _event(connection, snapshot=ref, event_type="invalidated", payload={"snapshot_hash": row["snapshot_hash"], "status": "invalidated", "reason_code": reason_code}, actor=actor, now=now)
                _current_projection(connection, snapshot=ref, status="invalidated", reason_code=reason_code, event=ev, now=now)
                return {"ok": True, "idempotent": False, "snapshot_id": snapshot_id, "status": "invalidated", "reason_code": reason_code}
        finally:
            connection.close()

    def preview_from_snapshot(
        self,
        *,
        snapshot_id: str,
        dns_policy: Mapping[str, Any],
        actor: Actor,
        review_ttl_seconds: int = 7 * 24 * 3600,
    ) -> dict[str, Any]:
        if not actor.is_admin:
            raise PreparationSnapshotError("Preview creation requires human admin authority")
        dns = _safe_mapping(dns_policy, "dns_policy")
        if dns.get("scheme") != "https" or dns.get("hostname") != "opencode.ai" or int(dns.get("port", 0)) != 443:
            raise PreparationSnapshotError("DNS policy must be bound to opencode.ai:443 over HTTPS")
        max_candidates = int(dns.get("max_dns_candidates", 0))
        if max_candidates < 1 or max_candidates > 16:
            raise PreparationSnapshotError("DNS candidate cap is outside 1..16")
        for key in ("credential_reads", "tcp_connections", "tls_https_calls", "provider_calls", "cost_units"):
            if int(dns.get(key, 0)) != 0:
                raise PreparationSnapshotError("Preview DNS policy contains a non-zero execution permission")
        if review_ttl_seconds < 3600 or review_ttl_seconds > 30 * 24 * 3600:
            raise PreparationSnapshotError("Preview review TTL is outside its bounded range")
        now = _timestamp(self.repository.clock)
        expires = (_utc_now(self.repository.clock) + timedelta(seconds=review_ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                snapshot = self._snapshot_row(connection, snapshot_id)
                issues = self._verify_event_chain(connection, snapshot_id) + self._drift(connection, snapshot)
                current = connection.execute("SELECT status FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?", (snapshot_id,)).fetchone()
                if current is None or current["status"] != "active" or issues:
                    raise PreparationSnapshotError("Snapshot is not currently valid: " + ", ".join(sorted(set(issues or ["not_active"]))))
                stable = _loads(snapshot["snapshot_json"])
                endpoint_origin_hash = stable["endpoint_origin_hash"]
                network_hash = stable["network_policy_hash"]
                dns_binding = {
                    "schema": "research-kb/mr4b1b-v11r1-dns-policy/v1",
                    "endpoint_origin_hash": endpoint_origin_hash,
                    "network_policy_hash": network_hash,
                    "max_getaddrinfo_calls": 1, "max_dns_candidates": max_candidates,
                    "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0,
                    "provider_calls": 0, "cost_units": 0,
                }
                preview_stable = {
                    "schema": "research-kb/mr4b1b-v11r1-preparation-preview/v1",
                    "snapshot_id": snapshot_id, "snapshot_hash": snapshot["snapshot_hash"],
                    "run_id": snapshot["run_id"], "project_id": snapshot["project_id"],
                    "provider_profile_hash": snapshot["provider_profile_hash"], "model_identity": snapshot["model_identity"],
                    "network_policy_hash": network_hash, "credential_reference_hash": snapshot["credential_reference_hash"],
                    "pricing_hash": snapshot["pricing_hash"], "source_egress_policy_hash": snapshot["source_egress_policy_hash"],
                    "source_binding": stable["source_binding"], "caps": stable["caps"], "caps_hash": snapshot["caps_hash"],
                    "release_identity": stable["release_identity"], "engine_version": snapshot["engine_version"],
                    "candidate_wheel_sha256": snapshot["candidate_wheel_sha256"], "source_manifest_sha256": snapshot["source_manifest_sha256"],
                    "source_tree_sha256": snapshot["source_tree_sha256"], "endpoint_origin_hash": endpoint_origin_hash,
                    "dns_policy": dns_binding, "dns_policy_hash": _hash(dns_binding),
                    "kill_switch_hash": _hash({"pause": True, "drain": True, "stop": True, "revoke": True}),
                    "rollback_policy_hash": _hash({"mode": "append_only_successor_or_restore_backup"}),
                    "incident_policy_hash": _hash({"unknown_after_send": "no_retry"}),
                    "preview_status": "AWAITING_DNS_PREFLIGHT_AUTHORIZATION",
                    "human_approval_consumed": 0, "execution_authority": "none",
                }
                preview_hash = _hash(preview_stable)
                preview_id = "preparation_preview_" + preview_hash[:48]
                existing = connection.execute("SELECT preview_json FROM max_live_canary_preparation_previews WHERE preview_hash=?", (preview_hash,)).fetchone()
                if existing is not None:
                    if existing["preview_json"] != _json(preview_stable):
                        raise PreparationSnapshotError("preparation Preview hash collision")
                    return {"ok": True, "idempotent": True, "preview_id": preview_id, "preview_hash": preview_hash, "snapshot_id": snapshot_id, "status": preview_stable["preview_status"]}
                connection.execute(
                    "INSERT INTO max_live_canary_preparation_previews(preview_id,snapshot_id,snapshot_hash,run_id,project_id,provider_profile_hash,model_identity,network_policy_hash,credential_reference_hash,pricing_hash,source_egress_policy_hash,source_version,document_id,passage_id,document_content_hash,passage_content_hash,caps_json,caps_hash,engine_version,candidate_wheel_sha256,source_manifest_sha256,source_tree_sha256,release_identity_json,release_identity_hash,endpoint_origin_hash,dns_policy_hash,kill_switch_hash,rollback_policy_hash,incident_policy_hash,preview_json,preview_hash,created_at,review_expires_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (preview_id, snapshot_id, snapshot["snapshot_hash"], snapshot["run_id"], snapshot["project_id"], snapshot["provider_profile_hash"], snapshot["model_identity"], network_hash, snapshot["credential_reference_hash"], snapshot["pricing_hash"], snapshot["source_egress_policy_hash"], stable["source_binding"]["source_version"], stable["source_binding"]["document_id"], stable["source_binding"]["passage_id"], stable["source_binding"]["document_content_hash"], stable["source_binding"]["passage_content_hash"], _json(stable["caps"]), stable["caps_hash"], snapshot["engine_version"], snapshot["candidate_wheel_sha256"], snapshot["source_manifest_sha256"], snapshot["source_tree_sha256"], _json(stable["release_identity"]), _hash(stable["release_identity"]), endpoint_origin_hash, preview_stable["dns_policy_hash"], preview_stable["kill_switch_hash"], preview_stable["rollback_policy_hash"], preview_stable["incident_policy_hash"], _json(preview_stable), preview_hash, now, expires, actor.actor_id, actor.actor_kind, actor.session_id),
                )
                return {"ok": True, "idempotent": False, "preview_id": preview_id, "preview_hash": preview_hash, "snapshot_id": snapshot_id, "snapshot_hash": snapshot["snapshot_hash"], "status": preview_stable["preview_status"], "human_approval_consumed": 0, "execution_authority": "none", "created_at": now, "review_expires_at": expires}
        finally:
            connection.close()

    def create_human_approval(self, *, preview_id: str, actor: Actor, expires_at: str, reason_hash: str) -> dict[str, Any]:
        """Create a Snapshot-bound approval for tests/controlled admin use.

        v12 preparation intentionally does not call this method.  It exists
        so the JIT boundary is testable without exposing the old schema19
        approval path.
        """
        if not actor.is_admin:
            raise PreparationSnapshotError("human approval requires admin authority")
        _digest(reason_hash, "reason_hash")
        now = _timestamp(self.repository.clock)
        expiry = _parse_timestamp(expires_at)
        if expiry is None or expiry <= _utc_now(self.repository.clock):
            raise PreparationSnapshotError("human approval expiry is invalid")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                preview = connection.execute("SELECT * FROM max_live_canary_preparation_previews WHERE preview_id=?", (preview_id,)).fetchone()
                if preview is None:
                    raise PreparationSnapshotError("preparation Preview was not found")
                snapshot = self._snapshot_row(connection, preview["snapshot_id"])
                current = connection.execute("SELECT status FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?", (snapshot["snapshot_id"],)).fetchone()
                if current is None or current["status"] != "active":
                    raise PreparationSnapshotError("human approval requires an active Snapshot")
                binding = {"schema": "research-kb/mr4b1b-v11r1-human-approval/v1", "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"], "preview_id": preview_id, "preview_hash": preview["preview_hash"], "provider_profile_hash": preview["provider_profile_hash"], "source_egress_policy_hash": preview["source_egress_policy_hash"], "caps_hash": preview["caps_hash"], "release_identity_hash": preview["release_identity_hash"], "reason_hash": reason_hash}
                approval_hash = _hash(binding)
                approval_id = "preparation_approval_" + approval_hash[:48]
                existing = connection.execute("SELECT approval_json FROM max_live_canary_preparation_approvals WHERE approval_hash=?", (approval_hash,)).fetchone()
                if existing is not None:
                    return {"ok": True, "idempotent": True, "approval_id": approval_id, "approval_hash": approval_hash, "expires_at": expires_at}
                connection.execute(
                    "INSERT INTO max_live_canary_preparation_approvals(approval_id,snapshot_id,snapshot_hash,preview_id,preview_hash,provider_profile_hash,source_egress_policy_hash,caps_hash,release_identity_hash,approval_json,approval_hash,created_at,expires_at,approved_by,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (approval_id, snapshot["snapshot_id"], snapshot["snapshot_hash"], preview_id, preview["preview_hash"], preview["provider_profile_hash"], preview["source_egress_policy_hash"], preview["caps_hash"], preview["release_identity_hash"], _json(binding), approval_hash, now, expires_at, actor.actor_id, actor.actor_kind, actor.session_id),
                )
                return {"ok": True, "idempotent": False, "approval_id": approval_id, "approval_hash": approval_hash, "expires_at": expires_at}
        finally:
            connection.close()

    def issue_jit_authority(self, *, approval_id: str, worker: Actor, ttl_seconds: int = 600) -> dict[str, Any]:
        """Consume approval and create fresh lease/claim/JIT atomically.

        This method stops at the send boundary.  It never opens a socket or
        invokes a Provider.  A caller that cannot continue immediately must
        abort; there is no resumable pause between claim and send.
        """
        if worker.is_admin or worker.actor_kind not in {"runner", "worker", "agent"}:
            raise PreparationSnapshotError("JIT authority requires a non-admin worker actor")
        if ttl_seconds < 300 or ttl_seconds > 900:
            raise PreparationSnapshotError("JIT authority TTL must be 5..15 minutes")
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                approval = connection.execute("SELECT * FROM max_live_canary_preparation_approvals WHERE approval_id=?", (approval_id,)).fetchone()
                if approval is None:
                    raise PreparationSnapshotError("preparation human approval was not found")
                if _parse_timestamp(approval["expires_at"]) is None or _parse_timestamp(approval["expires_at"]) <= _utc_now(self.repository.clock):
                    raise PreparationSnapshotError("human approval is expired")
                consumed = connection.execute("SELECT consumption_id FROM max_live_canary_preparation_approval_consumptions WHERE approval_id=?", (approval_id,)).fetchone()
                if consumed is not None:
                    raise PreparationSnapshotError("human approval has already been consumed")
                snapshot = self._snapshot_row(connection, approval["snapshot_id"])
                issues = self._verify_event_chain(connection, snapshot["snapshot_id"]) + self._drift(connection, snapshot)
                current = connection.execute("SELECT status FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?", (snapshot["snapshot_id"],)).fetchone()
                if current is None or current["status"] != "active" or issues:
                    raise PreparationSnapshotError("JIT execution drifted: " + ", ".join(sorted(set(issues or ["snapshot_not_active"]))))
                preview = connection.execute("SELECT * FROM max_live_canary_preparation_previews WHERE preview_id=?", (approval["preview_id"],)).fetchone()
                if preview is None or preview["snapshot_hash"] != snapshot["snapshot_hash"]:
                    raise PreparationSnapshotError("human approval Preview binding drifted")
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (snapshot["run_id"],)).fetchone()
                if run["status"] != RunStatus.RUNNING.value:
                    raise PreparationSnapshotError("JIT execution requires a RUNNING Run")
                # The existing lease row is a durable fence record.  A fresh
                # owner/expiry/fence is created here and never before this
                # transaction.  No external or human pause is possible.
                lease = self.repository._acquire_lease_connection(
                    connection, run_id=snapshot["run_id"], actor=worker,
                    ttl_seconds=ttl_seconds, now=now, allowed_statuses={RunStatus.RUNNING},
                )
                authority_expires = lease["expires_at"]
                claim_id = "mr4b1b-v11r1-jit-claim_" + approval_id[-32:]
                claim_payload = {"claim_id": claim_id, "run_id": snapshot["run_id"], "actor_id": worker.actor_id, "actor_session": worker.session_id, "fencing_token": int(lease["fencing_token"]), "attempt_id": claim_id, "expires_at": authority_expires, "status": "active"}
                connection.execute(
                    "INSERT INTO max_runner_invocation_claims(claim_id,run_id,actor_id,actor_session,fencing_token,attempt_id,expires_at,status,claim_json,claim_hash,created_at,released_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (claim_id, snapshot["run_id"], worker.actor_id, worker.session_id, int(lease["fencing_token"]), claim_id, authority_expires, "active", _json(claim_payload), _hash(claim_payload), now),
                )
                self.repository._append_event(connection, run_id=snapshot["run_id"], event_type="lease_acquired", payload={"owner_id": worker.actor_id, "session_id": worker.session_id, "fencing_token": int(lease["fencing_token"]), "expires_at": authority_expires, "reason": "mr4b1b-v11r1-jit"}, actor=worker, now=now)
                self.repository._append_event(connection, run_id=snapshot["run_id"], event_type="runner_invocation_claimed", payload={"claim_id": claim_id, "attempt_id": claim_id, "fencing_token": int(lease["fencing_token"]), "expires_at": authority_expires, "reason": "mr4b1b-v11r1-jit"}, actor=worker, now=now)
                consumption_value = {"schema": "research-kb/mr4b1b-v11r1-approval-consumption/v1", "approval_id": approval_id, "snapshot_id": snapshot["snapshot_id"], "preview_id": preview["preview_id"], "consumed_at": now, "execution_authority": "jit-only"}
                consumption_hash = _hash(consumption_value)
                consumption_id = "preparation_approval_consumption_" + consumption_hash[:48]
                connection.execute(
                    "INSERT INTO max_live_canary_preparation_approval_consumptions(consumption_id,approval_id,snapshot_id,preview_id,consumption_json,consumption_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (consumption_id, approval_id, snapshot["snapshot_id"], preview["preview_id"], _json(consumption_value), consumption_hash, now, worker.actor_id, worker.actor_kind, worker.session_id),
                )
                authority_value = {"schema": "research-kb/mr4b1b-v11r1-jit-execution-authority/v1", "approval_id": approval_id, "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"], "preview_id": preview["preview_id"], "preview_hash": preview["preview_hash"], "lease_id": "run-lease:" + snapshot["run_id"], "claim_id": claim_id, "owner_id": worker.actor_id, "owner_session": worker.session_id, "fencing_token": int(lease["fencing_token"]), "authority_expires_at": authority_expires, "ttl_seconds": ttl_seconds, "state": "active", "execution": {"provider": 0, "dns": 0, "credential": 0, "tcp": 0, "tls": 0, "https": 0, "cost": 0}}
                authority_hash = _hash(authority_value)
                authority_id = "jit_execution_authority_" + authority_hash[:48]
                connection.execute(
                    "INSERT INTO max_live_canary_jit_execution_authorities(authority_id,approval_id,snapshot_id,preview_id,lease_id,claim_id,owner_id,owner_session,fencing_token,authority_expires_at,state,authority_json,authority_hash,created_at,consumed_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (authority_id, approval_id, snapshot["snapshot_id"], preview["preview_id"], authority_value["lease_id"], claim_id, worker.actor_id, worker.session_id, int(lease["fencing_token"]), authority_expires, "active", _json(authority_value), authority_hash, now, None, worker.actor_id, worker.actor_kind, worker.session_id),
                )
                ref = {"snapshot_id": snapshot["snapshot_id"], "run_id": snapshot["run_id"]}
                ev = _event(connection, snapshot=ref, event_type="consumed", payload={"snapshot_hash": snapshot["snapshot_hash"], "approval_id": approval_id, "authority_id": authority_id, "status": "consumed"}, actor=worker, now=now)
                _current_projection(connection, snapshot=ref, status="consumed", reason_code="jit_authority_issued", event=ev, now=now)
                return {"ok": True, "authority_id": authority_id, "authority_hash": authority_hash, "approval_id": approval_id, "consumption_id": consumption_id, "lease": {"fencing_token": int(lease["fencing_token"]), "expires_at": authority_expires}, "claim_id": claim_id, "ttl_seconds": ttl_seconds, "must_send_immediately": True, "retry": 0, "execution": authority_value["execution"]}
        except sqlite3.IntegrityError as exc:
            raise PreparationSnapshotError("JIT authority is already consumed or conflicts with an immutable record") from exc
        finally:
            connection.close()

    def create_dns_only_request(self, *, preview_id: str, actor: Actor, ttl_seconds: int = 24 * 3600) -> dict[str, Any]:
        if not actor.is_admin:
            raise PreparationSnapshotError("DNS-only request creation requires human admin authority")
        if ttl_seconds < 3600 or ttl_seconds > 24 * 3600:
            raise PreparationSnapshotError("DNS-only authority TTL is outside its bounded range")
        now = _timestamp(self.repository.clock)
        expires = (_utc_now(self.repository.clock) + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                preview = connection.execute("SELECT * FROM max_live_canary_preparation_previews WHERE preview_id=?", (preview_id,)).fetchone()
                if preview is None:
                    raise PreparationSnapshotError("preparation Preview was not found")
                snapshot = self._snapshot_row(connection, preview["snapshot_id"])
                issues = self._verify_event_chain(connection, snapshot["snapshot_id"]) + self._drift(connection, snapshot)
                current = connection.execute("SELECT status FROM max_live_canary_preparation_snapshot_current WHERE snapshot_id=?", (snapshot["snapshot_id"],)).fetchone()
                if current is None or current["status"] != "active" or issues:
                    raise PreparationSnapshotError("DNS-only request requires a valid active Snapshot")
                request_binding = {
                    "schema": "research-kb/mr4b1b-v11r1-dns-only-request/v1", "hostname": "opencode.ai", "port": 443, "scheme": "https",
                    "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"], "preview_id": preview_id, "preview_hash": preview["preview_hash"],
                    "endpoint_origin_hash": preview["endpoint_origin_hash"], "network_policy_hash": preview["network_policy_hash"],
                    "max_getaddrinfo_calls": 1, "max_dns_candidates": 16, "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0, "provider_calls": 0, "cost_units": 0,
                }
                request_hash = _hash(request_binding)
                request_id = "dns_preflight_request_v11r1_" + request_hash[:48]
                authority_value = {"schema": "research-kb/mr4b1b-v11r1-dns-only-authority/v1", "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"], "preview_id": preview_id, "preview_hash": preview["preview_hash"], "endpoint_origin_hash": preview["endpoint_origin_hash"], "network_policy_hash": preview["network_policy_hash"], "request_hash": request_hash, "max_getaddrinfo_calls": 1, "max_dns_candidates": 16, "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0, "provider_calls": 0, "cost_units": 0, "status": "AWAITING_DNS_PREFLIGHT_AUTHORIZATION", "expires_at": expires}
                authority_hash = _hash(authority_value)
                authority_id = "dns_preflight_authority_v11r1_" + authority_hash[:48]
                existing = connection.execute("SELECT r.request_hash,a.authority_hash FROM max_live_canary_preparation_dns_requests r JOIN max_live_canary_preparation_dns_authorities a ON a.authority_id=r.authority_id WHERE r.preview_hash=?", (preview["preview_hash"],)).fetchone()
                if existing is not None:
                    return {"ok": True, "idempotent": True, "authority_id": authority_id, "authority_hash": authority_hash, "request_id": request_id, "request_hash": request_hash, "expires_at": expires, "status": "AWAITING_DNS_PREFLIGHT_AUTHORIZATION"}
                connection.execute(
                    "INSERT INTO max_live_canary_preparation_dns_authorities(authority_id,snapshot_id,snapshot_hash,preview_id,preview_hash,endpoint_origin_hash,network_policy_hash,request_hash,max_getaddrinfo_calls,max_dns_candidates,credential_reads,tcp_connections,tls_https_calls,provider_calls,cost_units,status,authority_json,authority_hash,created_at,expires_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (authority_id, snapshot["snapshot_id"], snapshot["snapshot_hash"], preview_id, preview["preview_hash"], preview["endpoint_origin_hash"], preview["network_policy_hash"], request_hash, 1, 16, 0, 0, 0, 0, 0, "AWAITING_DNS_PREFLIGHT_AUTHORIZATION", _json(authority_value), authority_hash, now, expires, actor.actor_id, actor.actor_kind, actor.session_id),
                )
                request_json = {**request_binding, "authority_id": authority_id, "authority_hash": authority_hash, "expires_at": expires, "status": "AWAITING_DNS_PREFLIGHT_AUTHORIZATION"}
                connection.execute(
                    "INSERT INTO max_live_canary_preparation_dns_requests(request_id,authority_id,snapshot_hash,preview_hash,request_json,request_hash,status,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (request_id, authority_id, snapshot["snapshot_hash"], preview["preview_hash"], _json(request_json), request_hash, "AWAITING_DNS_PREFLIGHT_AUTHORIZATION", now, actor.actor_id, actor.actor_kind, actor.session_id),
                )
                return {"ok": True, "idempotent": False, "authority_id": authority_id, "authority_hash": authority_hash, "request_id": request_id, "request_hash": request_hash, "expires_at": expires, "status": "AWAITING_DNS_PREFLIGHT_AUTHORIZATION", "dns_executed": 0, "credential_reads": 0, "tcp_connections": 0, "tls_https_calls": 0, "provider_calls": 0, "cost_units": 0}
        except sqlite3.IntegrityError as exc:
            raise PreparationSnapshotError("DNS-only authority/request conflicts with an immutable record") from exc
        finally:
            connection.close()


__all__ = ["PreparationSnapshotError", "PreparationSnapshotStore"]
