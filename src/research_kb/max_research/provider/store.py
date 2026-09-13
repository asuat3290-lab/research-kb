"""Durable MR-2B0 provider/grant/usage control-plane records.

This module is deliberately a small repository over the independent Max
control database.  It does not expose arbitrary SQL and it never resolves a
credential.  Every mutating operation opens its own ``BEGIN IMMEDIATE``
transaction so a provider call or a scheduler process can be restarted
without reconstructing authority from Python memory.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import nullcontext
from dataclasses import replace
from datetime import timedelta
from typing import Any, Mapping

from ...policy import Actor
from ..contract import canonical_json, canonical_sha256, make_stable_id
from ..persistence.db import CONTROL_SCHEMA_VERSION, MaxControlError, control_transaction
from ..persistence.repository import (
    MaxControlRepository,
    _actor_fields,
    _parse_timestamp,
    _timestamp,
    _utc_now,
)
from ..persistence.schema_manifest import verify_schema_manifest
from .contract import (
    PricingSnapshot,
    ProviderContractError,
    ProviderProfile,
    TokenEnvelope,
    token_envelope_within_caps,
    usage_component_totals,
)
from .live import (
    LIVE_EXECUTION_MODE,
    LiveDispatchPermit,
    LiveNetworkAuthorization,
    credential_reference_hash,
    endpoint_hashes,
    network_policy_hash,
    normalize_network_policy,
)
from .usage import PROVIDER_USAGE_AUTHORITY_ID, ProviderCallRecord, ProviderUsageAttestation


_CAP_KEYS = {
    "max_ticks", "max_iterations", "max_wall_clock_seconds",
    "max_consecutive_failures", "max_no_progress", "max_provider_calls",
    "max_input_tokens", "max_output_tokens", "max_cache_read_tokens",
    "max_reasoning_tokens", "max_cost_units",
    "max_acquisition_requests", "max_acquisition_bytes",
}
_REQUIRED_CAP_KEYS = {
    "max_ticks", "max_iterations", "max_wall_clock_seconds",
    "max_consecutive_failures", "max_no_progress", "max_provider_calls",
    "max_input_tokens", "max_output_tokens", "max_cost_units",
}
_PROFILE_COST_CAP_ERROR = "LIVE_AUTH_COST_CAP_EXCEEDS_PROFILE_MAXIMUM"
_TOKEN_ENVELOPE_ERROR = "PROVIDER_RESERVATION_ENVELOPE_MISMATCH"
_REASON_SECRET_RE = re.compile(r"(?:api[_-]?key|authorization|password|secret\s*[:=]|bearer\s+|sk-[A-Za-z0-9_-]{8,})", re.IGNORECASE)
_GRANT_BINDING_KEYS = {
    "run_id", "project_id", "charter_hash", "model_identity", "profile_hash",
    "network_policy_hash", "pricing_hash", "budget_hash", "caps", "reason",
    "granted_at", "expires_at", "authority_id", "authority_kind", "authority_session",
}


def _bounded_identifier(value: Any, name: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or "\r" in value or "\n" in value:
        raise MaxControlError(f"{name} is invalid")
    lowered = value.casefold()
    if any(fragment in lowered for fragment in ("api_key", "apikey", "authorization", "cookie", "password", "secret", "access_token", "refresh_token", "private_key", "token=")):
        raise MaxControlError(f"{name} contains forbidden secret material")
    if lowered.startswith(("file:", "http://", "https://", "\\\\")) or re.match(r"^[a-z]:[\\/]", lowered):
        raise MaxControlError(f"{name} contains a forbidden path or URL")
    return value


def _live_identifier(value: Any, name: str, *, max_length: int = 256) -> str:
    """Validate a server-owned live ID without treating its type label as a secret."""

    if not isinstance(value, str) or not value or len(value) > max_length or "\r" in value or "\n" in value:
        raise MaxControlError(f"{name} is invalid")
    lowered = value.casefold()
    if any(fragment in lowered for fragment in ("api_key", "apikey", "cookie", "password", "secret", "access_token", "refresh_token", "private_key", "token=")):
        raise MaxControlError(f"{name} contains forbidden secret material")
    if lowered.startswith(("file:", "http://", "https://", "\\\\")) or re.match(r"^[a-z]:[\\/]", lowered):
        raise MaxControlError(f"{name} contains a forbidden path or URL")
    return value


def _require_admin(actor: Actor) -> None:
    if not actor.is_admin:
        raise MaxControlError("provider and execution-grant mutations require human admin authority")


def _safe_mapping(value: Any, *, name: str, max_bytes: int = 250_000) -> dict[str, Any]:
    """Bound a provider-owned manifest without accepting secret material."""

    if not isinstance(value, Mapping):
        raise MaxControlError(f"{name} must be an object")

    def walk(item: Any, depth: int = 0) -> None:
        if depth > 16:
            raise MaxControlError(f"{name} is too deeply nested")
        if isinstance(item, Mapping):
            if len(item) > 256:
                raise MaxControlError(f"{name} has too many fields")
            for key, child in item.items():
                key_text = str(key).casefold()
                if any(fragment in key_text for fragment in ("api_key", "apikey", "authorization", "password", "secret", "cookie", "access_token", "refresh_token", "private_key")):
                    raise MaxControlError(f"{name} contains secret material")
                walk(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            if len(item) > 256:
                raise MaxControlError(f"{name} has too many items")
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > 20_000:
                raise MaxControlError(f"{name} contains an oversized text value")
            lowered = item.casefold()
            if lowered.startswith(("file:", "http://", "https://")) and ("api_key" in lowered or "token=" in lowered or "secret=" in lowered):
                raise MaxControlError(f"{name} contains a secret-bearing URL")

    walk(value)
    encoded = canonical_json(value)
    if len(encoded.encode("utf-8")) > max_bytes:
        raise MaxControlError(f"{name} exceeds its byte limit")
    return dict(value)


def _profile_from_row(row: sqlite3.Row) -> ProviderProfile:
    try:
        profile = ProviderProfile.from_mapping(json.loads(row["profile_json"]))
    except Exception as exc:
        raise MaxControlError("stored provider profile is invalid") from exc
    if profile.profile_hash != row["profile_hash"] or profile.pricing.pricing_hash != row["pricing_hash"]:
        raise MaxControlError("stored provider profile hash binding is invalid")
    return profile


def _pricing_from_row(row: sqlite3.Row) -> PricingSnapshot:
    try:
        pricing = PricingSnapshot.from_mapping(json.loads(row["pricing_json"]))
    except Exception as exc:
        raise MaxControlError("stored provider pricing snapshot is invalid") from exc
    if pricing.pricing_hash != row["pricing_hash"]:
        raise MaxControlError("stored provider pricing hash is invalid")
    return pricing


def _caps(value: Mapping[str, Any]) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise MaxControlError("execution grant caps are required")
    unknown = set(str(key) for key in value) - _CAP_KEYS
    if unknown:
        raise MaxControlError("execution grant caps contain unsupported fields")
    missing = _REQUIRED_CAP_KEYS - set(str(key) for key in value)
    if missing:
        raise MaxControlError("execution grant caps are incomplete")
    normalized: dict[str, int] = {}
    for key, raw in value.items():
        minimum = 0 if key in {"max_cache_read_tokens", "max_reasoning_tokens"} else 1
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < minimum or raw > 10_000_000:
            raise MaxControlError("execution grant caps must be bounded positive integers")
        normalized[str(key)] = raw
    return dict(sorted(normalized.items()))


def _redacted_profile(profile: ProviderProfile) -> dict[str, Any]:
    value = profile.to_mapping()
    # The control CLI never prints a provider origin or credential reference
    # that could be copied into a request.  The hash remains the stable
    # identity for audit and binding.
    value["endpoint_origin"] = "[redacted]"
    value["credential_ref"] = {"kind": profile.credential_ref.kind, "name": "[redacted]"}
    value["approved_actor"] = {"actor_id": profile.approved_actor.get("actor_id", "[redacted]"), "actor_kind": profile.approved_actor.get("actor_kind", "[redacted]")}
    return value


def _profile_config(profile: ProviderProfile) -> dict[str, Any]:
    value = profile.to_mapping(include_hash=False)
    value.pop("approved_actor", None)
    value.pop("approved_at", None)
    return value


_NETWORK_POLICY_BINDING_SCHEMA = "research-kb/mr4b1c-live-network-policy-binding/v1"
_NETWORK_POLICY_BINDING_CORE_KEYS = (
    "schema", "run_id", "project_id", "profile_hash", "network_policy_hash",
    "policy_hash", "provider_name", "model_identity", "endpoint_origin_hash",
    "credential_reference_hash", "release_identity_hash", "dns_policy",
)


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone() is not None


def _network_policy_from_connection(
    connection: sqlite3.Connection,
    network_policy_hash_value: str,
) -> dict[str, Any]:
    """Read one canonical policy without accepting a caller-supplied payload."""

    if not _table_exists(connection, "max_live_network_policies"):
        raise MaxControlError("live network policy registry is unavailable")
    row = connection.execute(
        "SELECT network_policy_hash, policy_json, policy_hash, created_at, actor_id, actor_kind, actor_session "
        "FROM max_live_network_policies WHERE network_policy_hash=?",
        (network_policy_hash_value,),
    ).fetchone()
    if row is None:
        raise MaxControlError("live network policy was not found")
    try:
        policy = json.loads(row["policy_json"])
        normalized = normalize_network_policy(policy)
    except Exception as exc:
        raise MaxControlError("live network policy is invalid") from exc
    if (
        canonical_json(policy) != canonical_json(normalized)
        or network_policy_hash(normalized) != row["network_policy_hash"]
        or row["policy_hash"] != row["network_policy_hash"]
    ):
        raise MaxControlError("live network policy hash is invalid")
    return {
        "network_policy_hash": row["network_policy_hash"],
        "policy_hash": row["policy_hash"],
        "policy": normalized,
        "created_at": row["created_at"],
        "actor_id": row["actor_id"],
        "actor_kind": row["actor_kind"],
        "actor_session": row["actor_session"],
    }


def _network_policy_binding_core(
    *,
    run: sqlite3.Row,
    provider: sqlite3.Row,
    profile: ProviderProfile,
    policy_record: Mapping[str, Any],
    release_identity_hash: str,
) -> dict[str, Any]:
    endpoint_origin_hash, _ = endpoint_hashes(profile.endpoint_origin, profile.endpoint_path_policy)
    credential_reference_hash_value = credential_reference_hash(profile.credential_ref)
    policy = policy_record["policy"]
    dns_policy = {
        "max_getaddrinfo_calls": 1,
        "max_dns_candidates": int(policy["max_dns_candidates"]),
    }
    return {
        "schema": _NETWORK_POLICY_BINDING_SCHEMA,
        "run_id": str(run["run_id"]),
        "project_id": str(run["project_id"]),
        "profile_hash": profile.profile_hash,
        "network_policy_hash": profile.network_policy_hash,
        "policy_hash": str(policy_record["policy_hash"]),
        "provider_name": profile.provider_name,
        "model_identity": profile.model_identity,
        "endpoint_origin_hash": endpoint_origin_hash,
        "credential_reference_hash": credential_reference_hash_value,
        "release_identity_hash": release_identity_hash,
        "dns_policy": dns_policy,
    }


def _aggregate_totals(value: Mapping[str, Any]) -> tuple[int, int]:
    envelope = TokenEnvelope.from_mapping(value, require_positive=True)
    return envelope.input_family_tokens, envelope.output_family_tokens


def _token_caps(value: Mapping[str, Any]) -> dict[str, int]:
    return {
        "max_input_tokens": int(value.get("max_input_tokens", value.get("input_tokens", 0))),
        "max_output_tokens": int(value.get("max_output_tokens", value.get("output_tokens", 0))),
        "max_cache_read_tokens": int(value.get("max_cache_read_tokens", value.get("cache_read_tokens", 0))),
        "max_reasoning_tokens": int(value.get("max_reasoning_tokens", value.get("reasoning_tokens", 0))),
    }


def _usage_within_caps(value: Mapping[str, Any], caps: Mapping[str, Any]) -> bool:
    try:
        return token_envelope_within_caps(value, _token_caps(caps))
    except (ProviderContractError, TypeError, ValueError):
        return False


def _projected_grant_usage(current: Mapping[str, Any], additional: Mapping[str, Any] | TokenEnvelope) -> TokenEnvelope:
    def number(key: str) -> int:
        try:
            return int(current[key])
        except (KeyError, IndexError, TypeError):
            return 0

    prior = TokenEnvelope(
        input_tokens=number("settled_input_tokens") + number("reserved_input_tokens"),
        output_tokens=number("settled_output_tokens") + number("reserved_output_tokens"),
        cache_read_tokens=number("settled_cache_read_tokens") + number("reserved_cache_read_tokens"),
        reasoning_tokens=number("settled_reasoning_tokens") + number("reserved_reasoning_tokens"),
    )
    return prior.plus(additional)


def _authority_usage(profile: ProviderProfile) -> dict[str, int]:
    try:
        return profile.authority_maximum_usage()
    except ProviderContractError as exc:
        raise MaxControlError("provider profile lacks explicit token caps; migration is required before execution") from exc


class ProviderStore:
    """Append-only provider metadata and hermetic execution-grant store."""

    def __init__(self, repository: MaxControlRepository) -> None:
        if not isinstance(repository, MaxControlRepository):
            raise TypeError("ProviderStore requires a MaxControlRepository")
        self.repository = repository

    @property
    def settings(self):
        return self.repository.settings

    def _connect(self, *, read_only: bool) -> sqlite3.Connection:
        return self.repository._connect(read_only=read_only)

    @staticmethod
    def registered_network_policy(
        connection: sqlite3.Connection,
        *,
        network_policy_hash_value: str,
    ) -> dict[str, Any]:
        """Return the server-owned policy addressed by a stable hash."""

        return _network_policy_from_connection(connection, network_policy_hash_value)

    @staticmethod
    def materialize_network_policy_binding(
        connection: sqlite3.Connection,
        *,
        run: sqlite3.Row,
        provider: sqlite3.Row,
        profile: sqlite3.Row,
        release_identity_hash: str,
        actor: Actor,
        now: str,
    ) -> dict[str, Any]:
        """Create or replay the immutable policy binding in one transaction.

        The policy payload is read only from ``max_live_network_policies``.
        This method deliberately has no policy argument, so neither a
        Preview nor an execution worker can materialize a policy from client
        content at a later boundary.
        """

        if not _table_exists(connection, "max_live_network_policy_bindings"):
            raise MaxControlError("live network policy binding schema is unavailable")
        if str(run["project_id"]) != str(provider["project_id"]):
            raise MaxControlError("provider binding crosses the project boundary")
        profile_value = _profile_from_row(profile)
        if str(provider["profile_hash"]) != profile_value.profile_hash:
            raise MaxControlError("provider profile binding is invalid")
        if (
            str(run["model_identity"]) != profile_value.model_identity
            or str(provider["model_identity"]) != profile_value.model_identity
            or str(provider["network_policy_hash"]) != profile_value.network_policy_hash
            or str(provider["pricing_hash"]) != profile_value.pricing.pricing_hash
        ):
            raise MaxControlError("provider profile/model/pricing binding is invalid")
        policy_record = _network_policy_from_connection(connection, profile_value.network_policy_hash)
        if profile_value.network_policy is not None:
            if canonical_json(profile_value.network_policy) != canonical_json(policy_record["policy"]):
                raise MaxControlError("provider profile network policy payload drifted")
        core = _network_policy_binding_core(
            run=run,
            provider=provider,
            profile=profile_value,
            policy_record=policy_record,
            release_identity_hash=release_identity_hash,
        )
        binding_hash = canonical_sha256(core)
        binding_id = "live_network_policy_binding_" + binding_hash[:48]
        existing = connection.execute(
            "SELECT * FROM max_live_network_policy_bindings "
            "WHERE run_id=? AND profile_hash=? AND network_policy_hash=?",
            (core["run_id"], core["profile_hash"], core["network_policy_hash"]),
        ).fetchone()
        if existing is not None:
            try:
                existing_value = json.loads(existing["binding_json"])
                existing_core = {key: existing_value[key] for key in _NETWORK_POLICY_BINDING_CORE_KEYS}
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise MaxControlError("stored live network policy binding is invalid") from exc
            if existing["binding_hash"] != binding_hash or existing_core != core:
                raise MaxControlError("live network policy binding is immutable and already differs")
            return {
                "binding_id": existing["binding_id"],
                "binding_hash": existing["binding_hash"],
                "network_policy_hash": existing["network_policy_hash"],
                "idempotent": True,
            }
        if str(release_identity_hash) != core["release_identity_hash"]:
            raise MaxControlError("release identity hash is invalid")
        authority_id, authority_kind, authority_session, _ = _actor_fields(actor)
        value = {
            **core,
            "created_at": now,
            "creation_authority": {
                "authority_id": authority_id,
                "authority_kind": authority_kind,
                "authority_session": authority_session,
            },
        }
        connection.execute(
            "INSERT INTO max_live_network_policy_bindings(" 
            "binding_id,run_id,project_id,profile_hash,network_policy_hash,policy_hash," 
            "provider_name,model_identity,endpoint_origin_hash,credential_reference_hash," 
            "release_identity_hash,dns_policy_hash,max_getaddrinfo_calls,max_dns_candidates," 
            "binding_json,binding_hash,created_at,authority_id,authority_kind,authority_session) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                binding_id, core["run_id"], core["project_id"], core["profile_hash"],
                core["network_policy_hash"], core["policy_hash"], core["provider_name"],
                core["model_identity"], core["endpoint_origin_hash"],
                core["credential_reference_hash"], core["release_identity_hash"],
                canonical_sha256(core["dns_policy"]),
                int(core["dns_policy"]["max_getaddrinfo_calls"]),
                int(core["dns_policy"]["max_dns_candidates"]), canonical_json(value),
                binding_hash, now, authority_id, authority_kind, authority_session,
            ),
        )
        return {
            "binding_id": binding_id,
            "binding_hash": binding_hash,
            "network_policy_hash": core["network_policy_hash"],
            "idempotent": False,
        }

    @staticmethod
    def validate_network_policy_binding(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        expected_release_identity_hash: str | None = None,
    ) -> dict[str, Any]:
        """Fail closed unless the complete server-owned binding is present."""

        if not _table_exists(connection, "max_live_network_policy_bindings"):
            raise MaxControlError("live network policy binding schema is unavailable")
        run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
        provider = connection.execute("SELECT * FROM max_run_provider_bindings WHERE run_id=?", (run_id,)).fetchone()
        if run is None or provider is None:
            raise MaxControlError("run provider binding is missing")
        profile = connection.execute(
            "SELECT * FROM max_provider_profiles WHERE profile_hash=?",
            (provider["profile_hash"],),
        ).fetchone()
        if profile is None:
            raise MaxControlError("provider profile is not registered")
        profile_value = _profile_from_row(profile)
        if str(provider["project_id"]) != str(run["project_id"]):
            raise MaxControlError("provider binding crosses the project boundary")
        if (
            str(run["model_identity"]) != profile_value.model_identity
            or
            provider["model_identity"] != profile_value.model_identity
            or provider["network_policy_hash"] != profile_value.network_policy_hash
            or provider["pricing_hash"] != profile_value.pricing.pricing_hash
        ):
            raise MaxControlError("provider binding does not match its profile")
        policy_record = _network_policy_from_connection(connection, profile_value.network_policy_hash)
        if profile_value.network_policy is not None and canonical_json(profile_value.network_policy) != canonical_json(policy_record["policy"]):
            raise MaxControlError("provider profile network policy payload drifted")
        rows = list(connection.execute(
            "SELECT * FROM max_live_network_policy_bindings WHERE run_id=? AND profile_hash=? AND network_policy_hash=?",
            (run_id, profile_value.profile_hash, profile_value.network_policy_hash),
        ))
        if len(rows) != 1:
            raise MaxControlError("live network policy binding was not found")
        row = rows[0]
        try:
            value = json.loads(row["binding_json"])
            core = {key: value[key] for key in _NETWORK_POLICY_BINDING_CORE_KEYS}
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MaxControlError("stored live network policy binding is invalid") from exc
        expected_core = _network_policy_binding_core(
            run=run,
            provider=provider,
            profile=profile_value,
            policy_record=policy_record,
            release_identity_hash=str(row["release_identity_hash"]),
        )
        if (
            core != expected_core
            or row["binding_hash"] != canonical_sha256(core)
            or row["binding_id"] != "live_network_policy_binding_" + row["binding_hash"][:48]
            or row["policy_hash"] != policy_record["policy_hash"]
            or row["dns_policy_hash"] != canonical_sha256(core["dns_policy"])
            or int(row["max_getaddrinfo_calls"]) != 1
            or int(row["max_dns_candidates"]) != int(policy_record["policy"]["max_dns_candidates"])
            or row["project_id"] != run["project_id"]
        ):
            raise MaxControlError("live network policy binding hash or fields are invalid")
        if expected_release_identity_hash is not None and row["release_identity_hash"] != expected_release_identity_hash:
            raise MaxControlError("live network policy binding release identity drifted")
        return {
            "binding_id": row["binding_id"],
            "binding_hash": row["binding_hash"],
            "network_policy_hash": policy_record["network_policy_hash"],
            "policy": policy_record["policy"],
            "policy_created_at": policy_record["created_at"],
            "release_identity_hash": row["release_identity_hash"],
            "endpoint_origin_hash": row["endpoint_origin_hash"],
            "credential_reference_hash": row["credential_reference_hash"],
            "dns_policy_hash": row["dns_policy_hash"],
            "max_dns_candidates": int(row["max_dns_candidates"]),
        }

    def register_profile(self, *, profile: ProviderProfile | Mapping[str, Any], actor: Actor) -> dict[str, Any]:
        _require_admin(actor)
        candidate = profile if isinstance(profile, ProviderProfile) else ProviderProfile.from_mapping(profile)
        if candidate.network_policy is not None:
            try:
                normalized_policy = normalize_network_policy(candidate.network_policy)
            except Exception as exc:
                raise MaxControlError("provider profile network policy failed strict validation") from exc
            if network_policy_hash(normalized_policy) != candidate.network_policy_hash:
                raise MaxControlError("provider profile network policy hash does not match its payload")
        # Approval metadata is server-owned and therefore not part of the
        # immutable profile-version conflict check.  Normalize an already
        # registered profile back to its pre-registration form before the
        # current server Actor/time are stamped.
        base_mapping = candidate.to_mapping(include_hash=False)
        if candidate.network_policy is not None:
            base_mapping["network_policy"] = normalized_policy
        base_mapping["approved_actor"] = {}
        base_mapping["approved_at"] = "1970-01-01T00:00:00.000Z"
        candidate = ProviderProfile.from_mapping(base_mapping)
        now = _timestamp(self.repository.clock)
        stamped = replace(
            candidate,
            approved_actor={"actor_id": actor.actor_id, "actor_kind": actor.actor_kind, "actor_session": actor.session_id},
            approved_at=now,
            profile_hash="",
        )
        pricing = stamped.pricing
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                existing = connection.execute(
                    "SELECT profile_hash, profile_json, pricing_hash FROM max_provider_profiles WHERE profile_id=? AND profile_version=?",
                    (stamped.profile_id, stamped.profile_version),
                ).fetchone()
                if existing is not None:
                    existing_profile = _profile_from_row(existing)
                    if _profile_config(existing_profile) != _profile_config(stamped):
                        raise MaxControlError("provider profile version is immutable and already differs")
                    if stamped.network_policy is not None:
                        self._register_network_policy_in_connection(
                            connection, policy=stamped.network_policy, actor=actor, now=now,
                        )
                    return {"profile": _redacted_profile(existing_profile), "profile_hash": existing_profile.profile_hash, "pricing_hash": existing_profile.pricing.pricing_hash, "idempotent": True}
                pricing_existing = connection.execute(
                    "SELECT pricing_hash, pricing_json FROM max_provider_pricing_snapshots WHERE pricing_hash=?",
                    (pricing.pricing_hash,),
                ).fetchone()
                if pricing_existing is not None and pricing_existing["pricing_json"] != canonical_json(pricing.to_mapping()):
                    raise MaxControlError("pricing hash collision detected")
                if pricing_existing is None:
                    actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                    connection.execute(
                        "INSERT INTO max_provider_pricing_snapshots(pricing_hash, pricing_id, pricing_version, pricing_json, currency, source_label, effective_at, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (pricing.pricing_hash, pricing.pricing_id, pricing.pricing_version, canonical_json(pricing.to_mapping()), pricing.currency, pricing.source_label, pricing.effective_at, now, actor_id, actor_kind, actor_session),
                    )
                if stamped.network_policy is not None:
                    self._register_network_policy_in_connection(
                        connection, policy=stamped.network_policy, actor=actor, now=now,
                    )
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                value = stamped.to_mapping()
                connection.execute(
                    "INSERT INTO max_provider_profiles(profile_hash, profile_id, profile_version, protocol, provider_name, model_identity, endpoint_origin, endpoint_path_policy, capabilities_json, inference_defaults_json, timeout_policy_json, retry_policy_json, request_limits_json, rate_policy_json, credential_ref_json, network_policy_hash, pricing_hash, profile_json, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (stamped.profile_hash, stamped.profile_id, stamped.profile_version, stamped.protocol, stamped.provider_name, stamped.model_identity, stamped.endpoint_origin, stamped.endpoint_path_policy, canonical_json(stamped.capabilities.to_mapping()), canonical_json(stamped.inference_defaults), canonical_json(stamped.timeout_policy), canonical_json(stamped.retry_policy), canonical_json(stamped.request_limits), canonical_json(stamped.rate_policy), canonical_json(stamped.credential_ref.to_mapping()), stamped.network_policy_hash, pricing.pricing_hash, canonical_json(value), now, actor_id, actor_kind, actor_session),
                )
            return {"profile": _redacted_profile(stamped), "profile_hash": stamped.profile_hash, "pricing_hash": pricing.pricing_hash, "idempotent": False}
        except ProviderContractError as exc:
            raise MaxControlError("provider profile failed strict validation") from exc
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("provider profile conflicts with an immutable record") from exc
        finally:
            connection.close()

    def _register_network_policy_in_connection(
        self,
        connection: sqlite3.Connection,
        *,
        policy: Mapping[str, Any],
        actor: Actor,
        now: str,
    ) -> dict[str, Any]:
        try:
            normalized = normalize_network_policy(policy)
        except Exception as exc:
            raise MaxControlError("network policy failed strict validation") from exc
        policy_hash = network_policy_hash(normalized)
        existing = connection.execute(
            "SELECT policy_json, policy_hash FROM max_live_network_policies WHERE network_policy_hash=?",
            (policy_hash,),
        ).fetchone()
        if existing is not None:
            if existing["policy_json"] != canonical_json(normalized) or existing["policy_hash"] != policy_hash:
                raise MaxControlError("live network policy hash collision")
            return {"network_policy_hash": policy_hash, "policy_hash": policy_hash, "policy": normalized, "idempotent": True}
        actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
        connection.execute(
            "INSERT INTO max_live_network_policies(network_policy_hash, policy_json, policy_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?,?,?,?,?,?,?)",
            (policy_hash, canonical_json(normalized), policy_hash, now, actor_id, actor_kind, actor_session),
        )
        return {"network_policy_hash": policy_hash, "policy_hash": policy_hash, "policy": normalized, "idempotent": False}

    def register_network_policy(self, *, policy: Mapping[str, Any], actor: Actor) -> dict[str, Any]:
        """Persist one immutable network-policy snapshot before Preview.

        Live authorization historically inserted the policy as a side effect
        of issuing network authority.  MR-4B1A-R needs the provider/network
        binding to exist already at Preview time, while keeping the policy
        hash-only and entirely offline.
        """

        _require_admin(actor)
        now = _timestamp(self.repository.clock)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                result = self._register_network_policy_in_connection(
                    connection, policy=policy, actor=actor, now=now,
                )
            return result
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live network policy conflicts with an immutable record") from exc
        finally:
            connection.close()
    def get_profile(self, *, profile_hash: str | None = None, profile_id: str | None = None, profile_version: str | None = None) -> ProviderProfile:
        if not profile_hash and not profile_id:
            raise MaxControlError("a provider profile hash or ID is required")
        connection = self._connect(read_only=True)
        try:
            if profile_hash:
                row = connection.execute("SELECT * FROM max_provider_profiles WHERE profile_hash=?", (profile_hash,)).fetchone()
            else:
                if not profile_version:
                    raise MaxControlError("provider profile version is required with profile ID")
                row = connection.execute("SELECT * FROM max_provider_profiles WHERE profile_id=? AND profile_version=?", (profile_id, profile_version)).fetchone()
            if row is None:
                raise MaxControlError("provider profile was not found")
            return _profile_from_row(row)
        finally:
            connection.close()

    def list_profiles(self) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            values = []
            for row in connection.execute("SELECT * FROM max_provider_profiles ORDER BY profile_id, profile_version"):
                profile = _profile_from_row(row)
                values.append(_redacted_profile(profile))
            return {"profiles": values, "count": len(values)}
        finally:
            connection.close()

    def bind_run_profile(self, *, run_id: str, profile_hash: str, actor: Actor, project_id: str | None = None) -> dict[str, Any]:
        profile = self.get_profile(profile_hash=profile_hash)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None:
                    raise MaxControlError("Max run was not found")
                if project_id is not None and project_id != run["project_id"]:
                    raise MaxControlError("provider binding crosses the project boundary")
                if run["model_identity"] != profile.model_identity:
                    raise MaxControlError("provider model identity does not match the Charter")
                existing = connection.execute("SELECT * FROM max_run_provider_bindings WHERE run_id=?", (run_id,)).fetchone()
                if existing is not None:
                    if existing["profile_hash"] != profile.profile_hash or existing["charter_hash"] != run["charter_hash"] or existing["budget_hash"] != run["budget_hash"]:
                        raise MaxControlError("run provider binding is immutable and conflicts")
                    return {"binding_id": existing["binding_id"], "run_id": run_id, "project_id": run["project_id"], "profile_hash": profile.profile_hash, "model_identity": profile.model_identity, "binding_hash": existing["binding_hash"], "idempotent": True}
                now = _timestamp(self.repository.clock)
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                value = {"run_id": run_id, "project_id": run["project_id"], "charter_hash": run["charter_hash"], "model_identity": profile.model_identity, "profile_hash": profile.profile_hash, "network_policy_hash": profile.network_policy_hash, "pricing_hash": profile.pricing.pricing_hash, "budget_hash": run["budget_hash"]}
                binding_hash = canonical_sha256(value)
                binding_id = make_stable_id("provider_binding", canonical_sha256({"run_id": run_id, "profile_hash": profile.profile_hash})[:64])
                connection.execute("INSERT INTO max_run_provider_bindings(binding_id, run_id, project_id, profile_hash, model_identity, network_policy_hash, pricing_hash, charter_hash, budget_hash, binding_json, binding_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (binding_id, run_id, run["project_id"], profile.profile_hash, profile.model_identity, profile.network_policy_hash, profile.pricing.pricing_hash, run["charter_hash"], run["budget_hash"], canonical_json(value), binding_hash, now, actor_id, actor_kind, actor_session))
                self.repository._append_event(connection, run_id=run_id, event_type="provider_profile_bound", payload={"binding_id": binding_id, "profile_hash": profile.profile_hash, "model_identity": profile.model_identity, "network_policy_hash": profile.network_policy_hash, "pricing_hash": profile.pricing.pricing_hash}, actor=actor, now=now)
            return {"binding_id": binding_id, **value, "binding_hash": binding_hash, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("run provider binding conflicts with an immutable record") from exc
        finally:
            connection.close()

    def get_run_binding(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT * FROM max_run_provider_bindings WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise MaxControlError("run has no provider profile binding")
            value = json.loads(row["binding_json"])
            if canonical_sha256(value) != row["binding_hash"]:
                raise MaxControlError("run provider binding hash is invalid")
            return {"binding_id": row["binding_id"], **value, "binding_hash": row["binding_hash"]}
        finally:
            connection.close()

    @staticmethod
    def _grant_current_value(row: Mapping[str, Any] | None = None) -> dict[str, int]:
        names = (
            "dispatch_count", "reserved_input_tokens", "reserved_output_tokens",
            "reserved_cache_read_tokens", "reserved_reasoning_tokens", "reserved_cost_units",
            "settled_input_tokens", "settled_output_tokens", "settled_cache_read_tokens",
            "settled_reasoning_tokens", "settled_cost_units", "released_cost_units",
        )
        if row is None:
            return {name: 0 for name in names}
        return {name: int(row[name]) for name in names}

    def _ensure_grant_usage_current(self, connection: sqlite3.Connection, *, grant_id: str, run_id: str, project_id: str, now: str) -> None:
        existing = connection.execute("SELECT grant_id FROM max_provider_grant_usage_current WHERE grant_id=?", (grant_id,)).fetchone()
        if existing is not None:
            return
        value = self._grant_current_value()
        connection.execute(
            "INSERT INTO max_provider_grant_usage_current(grant_id, run_id, project_id, dispatch_count, reserved_input_tokens, reserved_output_tokens, reserved_cache_read_tokens, reserved_reasoning_tokens, reserved_cost_units, settled_input_tokens, settled_output_tokens, settled_cache_read_tokens, settled_reasoning_tokens, settled_cost_units, released_cost_units, current_json, current_hash, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (grant_id, run_id, project_id, *(value[name] for name in value), canonical_json(value), canonical_sha256(value), now),
        )

    @staticmethod
    def _append_claim_event(connection: sqlite3.Connection, *, claim_id: str, run_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str) -> dict[str, Any]:
        previous = connection.execute("SELECT sequence_no, event_hash FROM max_provider_call_claim_events WHERE claim_id=? ORDER BY sequence_no DESC LIMIT 1", (claim_id,)).fetchone()
        sequence_no = int(previous["sequence_no"]) + 1 if previous is not None else 1
        previous_hash = previous["event_hash"] if previous is not None else None
        payload_value = dict(payload)
        payload_hash = canonical_sha256(payload_value)
        event_value = {"claim_id": claim_id, "run_id": run_id, "sequence_no": sequence_no, "event_type": event_type, "payload_hash": payload_hash, "previous_event_hash": previous_hash, "created_at": now}
        event_hash = canonical_sha256(event_value)
        event_id = make_stable_id("provider_claim_event", event_hash[:64])
        actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
        connection.execute(
            "INSERT INTO max_provider_call_claim_events(claim_event_id, claim_id, run_id, sequence_no, event_type, payload_json, payload_hash, previous_event_hash, event_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, claim_id, run_id, sequence_no, event_type, canonical_json(payload_value), payload_hash, previous_hash, event_hash, now, actor_id, actor_kind, actor_session),
        )
        return {"claim_event_id": event_id, "sequence_no": sequence_no, "event_hash": event_hash}

    @staticmethod
    def _update_grant_usage_current(connection: sqlite3.Connection, *, grant_id: str, delta: Mapping[str, int], now: str) -> dict[str, int]:
        row = connection.execute("SELECT * FROM max_provider_grant_usage_current WHERE grant_id=?", (grant_id,)).fetchone()
        if row is None:
            raise MaxControlError("grant usage projection is missing")
        value = ProviderStore._grant_current_value(row)
        for key, raw in delta.items():
            if key not in value or isinstance(raw, bool) or not isinstance(raw, int):
                raise MaxControlError("grant usage projection delta is invalid")
            value[key] += raw
            if value[key] < 0:
                raise MaxControlError("grant usage projection would become negative")
        connection.execute(
            "UPDATE max_provider_grant_usage_current SET dispatch_count=?, reserved_input_tokens=?, reserved_output_tokens=?, reserved_cache_read_tokens=?, reserved_reasoning_tokens=?, reserved_cost_units=?, settled_input_tokens=?, settled_output_tokens=?, settled_cache_read_tokens=?, settled_reasoning_tokens=?, settled_cost_units=?, released_cost_units=?, current_json=?, current_hash=?, updated_at=? WHERE grant_id=?",
            tuple(value[name] for name in value) + (canonical_json(value), canonical_sha256(value), now, grant_id),
        )
        return value

    @staticmethod
    def _claim_current_payload(*, state: str, provider_call_id: str | None, call_record_id: str | None, attestation_id: str | None, actual: Mapping[str, int]) -> dict[str, Any]:
        return {
            "state": state,
            "provider_call_id": provider_call_id,
            "call_record_id": call_record_id,
            "attestation_id": attestation_id,
            "actual": {key: int(actual.get(key, 0)) for key in ("input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens", "cost_units")},
        }

    def _set_claim_current(self, connection: sqlite3.Connection, *, claim: Mapping[str, Any], state: str, actor: Actor, now: str, provider_call_id: str | None = None, call_record_id: str | None = None, attestation_id: str | None = None, actual: Mapping[str, int] | None = None) -> dict[str, Any]:
        current = connection.execute("SELECT * FROM max_provider_call_claim_current WHERE claim_id=?", (claim["claim_id"],)).fetchone()
        if current is None:
            raise MaxControlError("provider call claim projection is missing")
        actual_value = {key: int(current[f"actual_{key}"]) for key in ("input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens")}
        actual_value["cost_units"] = int(current["actual_cost_units"])
        if actual is not None:
            actual_value = {key: int(actual.get(key, 0)) for key in ("input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens", "cost_units")}
        provider_call_id = provider_call_id if provider_call_id is not None else current["provider_call_id"]
        call_record_id = call_record_id if call_record_id is not None else current["call_record_id"]
        attestation_id = attestation_id if attestation_id is not None else current["attestation_id"]
        value = self._claim_current_payload(state=state, provider_call_id=provider_call_id, call_record_id=call_record_id, attestation_id=attestation_id, actual=actual_value)
        connection.execute(
            "UPDATE max_provider_call_claim_current SET state=?, provider_call_id=?, call_record_id=?, attestation_id=?, actual_input_tokens=?, actual_output_tokens=?, actual_cache_read_tokens=?, actual_reasoning_tokens=?, actual_cost_units=?, current_json=?, current_hash=?, updated_at=? WHERE claim_id=?",
            (state, provider_call_id, call_record_id, attestation_id, actual_value["input_tokens"], actual_value["output_tokens"], actual_value["cache_read_tokens"], actual_value["reasoning_tokens"], actual_value["cost_units"], canonical_json(value), canonical_sha256(value), now, claim["claim_id"]),
        )
        self._append_claim_event(connection, claim_id=str(claim["claim_id"]), run_id=str(claim["run_id"]), event_type=state, payload=value, actor=actor, now=now)
        return value

    @staticmethod
    def _attempt_current_payload(*, attempt_id: str, claim_id: str, state: str, provider_call_id: str | None, call_record_id: str | None, attestation_id: str | None, actual: Mapping[str, int]) -> dict[str, Any]:
        return {
            "attempt_id": attempt_id,
            "claim_id": claim_id,
            "state": state,
            "provider_call_id": provider_call_id,
            "call_record_id": call_record_id,
            "attestation_id": attestation_id,
            "actual": {key: int(actual.get(key, 0)) for key in ("input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens", "cost_units")},
        }

    @staticmethod
    def _append_attempt_event(connection: sqlite3.Connection, *, attempt_id: str, claim_id: str, run_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str) -> dict[str, Any]:
        previous = connection.execute("SELECT sequence_no, event_hash FROM max_provider_dispatch_attempt_events WHERE attempt_id=? ORDER BY sequence_no DESC LIMIT 1", (attempt_id,)).fetchone()
        sequence_no = int(previous["sequence_no"]) + 1 if previous is not None else 1
        previous_hash = previous["event_hash"] if previous is not None else None
        payload_value = dict(payload)
        payload_hash = canonical_sha256(payload_value)
        event_value = {"attempt_id": attempt_id, "claim_id": claim_id, "run_id": run_id, "sequence_no": sequence_no, "event_type": event_type, "payload_hash": payload_hash, "previous_event_hash": previous_hash, "created_at": now}
        event_hash = canonical_sha256(event_value)
        event_id = make_stable_id("provider_dispatch_attempt_event", event_hash[:64])
        actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
        connection.execute(
            "INSERT INTO max_provider_dispatch_attempt_events(attempt_event_id, attempt_id, claim_id, run_id, sequence_no, event_type, payload_json, payload_hash, previous_event_hash, event_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, attempt_id, claim_id, run_id, sequence_no, event_type, canonical_json(payload_value), payload_hash, previous_hash, event_hash, now, actor_id, actor_kind, actor_session),
        )
        return {"attempt_event_id": event_id, "sequence_no": sequence_no, "event_hash": event_hash}

    def _set_attempt_current(self, connection: sqlite3.Connection, *, attempt: Mapping[str, Any], state: str, actor: Actor, now: str, provider_call_id: str | None = None, call_record_id: str | None = None, attestation_id: str | None = None, actual: Mapping[str, int] | None = None) -> dict[str, Any]:
        current = connection.execute("SELECT * FROM max_provider_dispatch_attempt_current WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()
        if current is None:
            raise MaxControlError("provider dispatch attempt projection is missing")
        actual_value = {key: int(current[f"actual_{key}"]) for key in ("input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens")}
        actual_value["cost_units"] = int(current["actual_cost_units"])
        if actual is not None:
            actual_value = {key: int(actual.get(key, 0)) for key in ("input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens", "cost_units")}
        provider_call_id = provider_call_id if provider_call_id is not None else current["provider_call_id"]
        call_record_id = call_record_id if call_record_id is not None else current["call_record_id"]
        attestation_id = attestation_id if attestation_id is not None else current["attestation_id"]
        value = self._attempt_current_payload(attempt_id=str(attempt["attempt_id"]), claim_id=str(attempt["claim_id"]), state=state, provider_call_id=provider_call_id, call_record_id=call_record_id, attestation_id=attestation_id, actual=actual_value)
        connection.execute(
            "UPDATE max_provider_dispatch_attempt_current SET state=?, provider_call_id=?, call_record_id=?, attestation_id=?, actual_input_tokens=?, actual_output_tokens=?, actual_cache_read_tokens=?, actual_reasoning_tokens=?, actual_cost_units=?, current_json=?, current_hash=?, updated_at=? WHERE attempt_id=?",
            (state, provider_call_id, call_record_id, attestation_id, actual_value["input_tokens"], actual_value["output_tokens"], actual_value["cache_read_tokens"], actual_value["reasoning_tokens"], actual_value["cost_units"], canonical_json(value), canonical_sha256(value), now, attempt["attempt_id"]),
        )
        self._append_attempt_event(connection, attempt_id=str(attempt["attempt_id"]), claim_id=str(attempt["claim_id"]), run_id=str(attempt["run_id"]), event_type=state, payload=value, actor=actor, now=now)
        return value

    @staticmethod
    def _check_attempt_lease(connection: sqlite3.Connection, *, attempt: Mapping[str, Any], actor: Actor, fencing_token: int, now: Any) -> None:
        lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (attempt["run_id"],)).fetchone()
        if attempt["owner_id"] != actor.actor_id or attempt["owner_session"] != actor.session_id or int(attempt["fencing_token"]) != fencing_token or lease is None or lease["owner_id"] != actor.actor_id or lease["session_id"] != actor.session_id or int(lease["fencing_token"]) != fencing_token or lease["released_at"] is not None or _parse_timestamp(lease["expires_at"]) is None or _parse_timestamp(lease["expires_at"]) <= now:
            raise MaxControlError("provider dispatch attempt uses a stale worker fence")

    def _create_physical_attempt(self, connection: sqlite3.Connection, *, claim: Mapping[str, Any], physical_attempt_no: int, reserved: Mapping[str, int], actor: Actor, now: str, fencing_token: int | None = None) -> dict[str, Any]:
        value = {
            "claim_id": claim["claim_id"], "grant_id": claim["grant_id"], "grant_consumption_id": claim["grant_consumption_id"],
            "run_id": claim["run_id"], "project_id": claim["project_id"], "logical_call_id": claim["logical_call_id"],
            "intent_id": claim["intent_id"], "iteration_id": claim["iteration_id"], "intent_hash": claim["intent_hash"],
            "request_hash": claim["request_hash"], "profile_hash": claim["profile_hash"], "model_identity": claim["model_identity"],
            "pricing_hash": claim["pricing_hash"], "idempotency_key": claim["idempotency_key"], "physical_attempt_no": physical_attempt_no,
            "fencing_token": int(fencing_token if fencing_token is not None else claim["fencing_token"]), "owner_id": actor.actor_id, "owner_session": actor.session_id,
            "reserved_input_tokens": int(reserved["reserved_input_tokens"]), "reserved_output_tokens": int(reserved["reserved_output_tokens"]),
            "reserved_cache_read_tokens": int(reserved["reserved_cache_read_tokens"]), "reserved_reasoning_tokens": int(reserved["reserved_reasoning_tokens"]),
            "reserved_cost_units": int(reserved["reserved_cost_units"]),
        }
        attempt_hash = canonical_sha256(value)
        attempt_id = make_stable_id("provider_dispatch_attempt", attempt_hash[:64])
        connection.execute(
            "INSERT INTO max_provider_dispatch_attempts(attempt_id, claim_id, grant_id, grant_consumption_id, run_id, project_id, logical_call_id, intent_id, iteration_id, intent_hash, request_hash, profile_hash, model_identity, pricing_hash, idempotency_key, physical_attempt_no, fencing_token, owner_id, owner_session, reserved_input_tokens, reserved_output_tokens, reserved_cache_read_tokens, reserved_reasoning_tokens, reserved_cost_units, attempt_json, attempt_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (attempt_id, claim["claim_id"], claim["grant_id"], claim["grant_consumption_id"], claim["run_id"], claim["project_id"], claim["logical_call_id"], claim["intent_id"], claim["iteration_id"], claim["intent_hash"], claim["request_hash"], claim["profile_hash"], claim["model_identity"], claim["pricing_hash"], claim["idempotency_key"], physical_attempt_no, value["fencing_token"], value["owner_id"], value["owner_session"], int(reserved["reserved_input_tokens"]), int(reserved["reserved_output_tokens"]), int(reserved["reserved_cache_read_tokens"]), int(reserved["reserved_reasoning_tokens"]), int(reserved["reserved_cost_units"]), canonical_json(value), attempt_hash, now),
        )
        current = self._attempt_current_payload(attempt_id=attempt_id, claim_id=str(claim["claim_id"]), state="reserved", provider_call_id=None, call_record_id=None, attestation_id=None, actual={})
        connection.execute(
            "INSERT INTO max_provider_dispatch_attempt_current(attempt_id, claim_id, grant_id, run_id, state, provider_call_id, call_record_id, attestation_id, actual_input_tokens, actual_output_tokens, actual_cache_read_tokens, actual_reasoning_tokens, actual_cost_units, current_json, current_hash, updated_at) VALUES (?, ?, ?, ?, 'reserved', NULL, NULL, NULL, 0, 0, 0, 0, 0, ?, ?, ?)",
            (attempt_id, claim["claim_id"], claim["grant_id"], claim["run_id"], canonical_json(current), canonical_sha256(current), now),
        )
        self._append_attempt_event(connection, attempt_id=attempt_id, claim_id=str(claim["claim_id"]), run_id=str(claim["run_id"]), event_type="reserved", payload=current, actor=actor, now=now)
        self._update_grant_usage_current(connection, grant_id=str(claim["grant_id"]), delta={"dispatch_count": 1, **dict(reserved)}, now=now)
        return {"attempt_id": attempt_id, "physical_attempt_no": physical_attempt_no, **reserved, "state": "reserved"}

    def mark_provider_call_unknown(self, *, claim_id: str, actor: Actor, fencing_token: int) -> dict[str, Any]:
        """Retain a sent/uncertain slot until an explicit recovery decision."""

        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise MaxControlError("provider call fencing token is invalid")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                attempt = connection.execute("SELECT a.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.claim_id=? ORDER BY a.physical_attempt_no DESC LIMIT 1", (claim_id,)).fetchone()
                if attempt is None:
                    raise MaxControlError("provider call claim was not found")
                self._check_attempt_lease(connection, attempt=attempt, actor=actor, fencing_token=fencing_token, now=_utc_now(self.repository.clock))
                if attempt["state"] in {"failed", "settled", "cancelled", "disputed"}:
                    return {"claim_id": claim_id, "attempt_id": attempt["attempt_id"], "state": attempt["state"], "idempotent": True}
                now = _timestamp(self.repository.clock)
                value = self._set_attempt_current(connection, attempt=attempt, state="unknown", actor=actor, now=now, provider_call_id=attempt["provider_call_id"], call_record_id=attempt["call_record_id"], attestation_id=attempt["attestation_id"])
                claim = connection.execute("SELECT c.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.claim_id=?", (claim_id,)).fetchone()
                if claim is None:
                    raise MaxControlError("provider call claim was not found")
                self._set_claim_current(connection, claim=claim, state="unknown", actor=actor, now=now, provider_call_id=claim["provider_call_id"], call_record_id=claim["call_record_id"], attestation_id=claim["attestation_id"])
            return {"claim_id": claim_id, "attempt_id": attempt["attempt_id"], "state": "unknown", "current": value, "idempotent": False}
        finally:
            connection.close()

    def abort_live_dispatch_before_send(
        self,
        *,
        permit: LiveDispatchPermit,
        actor: Actor,
        fencing_token: int,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Close a dispatch reservation when durable evidence proves no send.

        This is deliberately different from ``mark_provider_call_unknown``:
        it is only valid while the physical attempt is still reserved or
        dispatching and it never creates a network-attempt record.  The
        claim is made non-recoverable, the physical slot is cancelled, and
        its reservation is released from the grant projection.
        """

        if not isinstance(permit, LiveDispatchPermit) or not permit._is_server_owned():
            raise MaxControlError("pre-send dispatch abort requires a server-issued permit")
        if permit.worker_id != actor.actor_id or permit.worker_session != actor.session_id or permit.fencing_token != fencing_token:
            raise MaxControlError("pre-send dispatch abort worker binding mismatch")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise MaxControlError("pre-send dispatch abort fencing token is invalid")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute(
                    "SELECT p.*, c.state, c.current_json, c.current_hash FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.permit_id=?",
                    (permit.permit_id,),
                ).fetchone()
                if row is None:
                    raise MaxControlError("live dispatch permit was not found")
                current = self._permit_from_row(row, row)
                if current.permit_hash != permit.permit_hash or current.worker_id != actor.actor_id or current.worker_session != actor.session_id or current.fencing_token != fencing_token:
                    raise MaxControlError("pre-send dispatch abort binding mismatch")
                if current.state == "failed":
                    return {"permit_id": current.permit_id, "state": "failed", "attempt_state": "cancelled", "claim_state": "released", "idempotent": True}
                if current.state not in {"ready", "send_started"}:
                    raise MaxControlError("pre-send dispatch abort cannot change the current permit state")
                attempt = connection.execute(
                    "SELECT a.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.attempt_id=? AND a.claim_id=?",
                    (current.attempt_id, current.claim_id),
                ).fetchone()
                if attempt is None:
                    raise MaxControlError("pre-send physical attempt is missing")
                self._check_attempt_lease(
                    connection,
                    attempt=attempt,
                    actor=actor,
                    fencing_token=fencing_token,
                    now=_utc_now(self.repository.clock),
                )
                if attempt["state"] not in {"reserved", "dispatching", "cancelled"}:
                    raise MaxControlError("pre-send abort found a sending or terminal physical attempt")
                now = _timestamp(self.repository.clock)
                if attempt["state"] != "cancelled":
                    self._set_attempt_current(
                        connection,
                        attempt=attempt,
                        state="cancelled",
                        actor=actor,
                        now=now,
                        provider_call_id=attempt["provider_call_id"],
                        call_record_id=attempt["call_record_id"],
                        attestation_id=attempt["attestation_id"],
                    )
                    self._update_grant_usage_current(
                        connection,
                        grant_id=str(attempt["grant_id"]),
                        delta={
                            "reserved_input_tokens": -int(attempt["reserved_input_tokens"]),
                            "reserved_output_tokens": -int(attempt["reserved_output_tokens"]),
                            "reserved_cache_read_tokens": -int(attempt["reserved_cache_read_tokens"]),
                            "reserved_reasoning_tokens": -int(attempt["reserved_reasoning_tokens"]),
                            "reserved_cost_units": -int(attempt["reserved_cost_units"]),
                            "released_cost_units": int(attempt["reserved_cost_units"]),
                        },
                        now=now,
                    )
                claim = connection.execute(
                    "SELECT c.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.claim_id=?",
                    (current.claim_id,),
                ).fetchone()
                if claim is None:
                    raise MaxControlError("pre-send provider claim is missing")
                if claim["state"] != "released":
                    self._set_claim_current(
                        connection,
                        claim=claim,
                        state="released",
                        actor=actor,
                        now=now,
                        provider_call_id=claim["provider_call_id"],
                        call_record_id=claim["call_record_id"],
                        attestation_id=claim["attestation_id"],
                    )
                safe_details = dict(details or {})
                safe_details.update({"send_boundary_reached": False, "failure_class": "KNOWN_PRE_SEND_FAILURE"})
                self._set_live_permit_current(
                    connection,
                    permit=current.to_mapping(),
                    state="failed",
                    actor=actor,
                    now=now,
                    details=safe_details,
                )
            return {"permit_id": current.permit_id, "state": "failed", "attempt_state": "cancelled", "claim_state": "released", "idempotent": False}
        finally:
            connection.close()

    def start_provider_dispatch_attempt(self, *, attempt_id: str, actor: Actor, fencing_token: int, _connection: sqlite3.Connection | None = None) -> dict[str, Any]:
        """Fence and mark one reserved physical slot immediately before send()."""

        _bounded_identifier(attempt_id, "attempt_id")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise MaxControlError("provider dispatch fencing token is invalid")
        connection = _connection or self._connect(read_only=False)
        try:
            with (control_transaction(connection) if _connection is None else nullcontext(connection)):
                attempt = connection.execute("SELECT a.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.attempt_id=?", (attempt_id,)).fetchone()
                if attempt is None:
                    raise MaxControlError("provider dispatch attempt was not found")
                self._check_attempt_lease(connection, attempt=attempt, actor=actor, fencing_token=fencing_token, now=_utc_now(self.repository.clock))
                if attempt["state"] == "dispatching":
                    return {"attempt_id": attempt_id, "state": "dispatching", "send": False, "idempotent": True}
                if attempt["state"] != "reserved":
                    raise MaxControlError("provider dispatch attempt is not reserved for a first send")
                now = _timestamp(self.repository.clock)
                current = self._set_attempt_current(connection, attempt=attempt, state="dispatching", actor=actor, now=now, provider_call_id=attempt["provider_call_id"], call_record_id=attempt["call_record_id"], attestation_id=attempt["attestation_id"])
                claim = connection.execute("SELECT c.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.claim_id=?", (attempt["claim_id"],)).fetchone()
                if claim is not None:
                    self._set_claim_current(connection, claim=claim, state="dispatching", actor=actor, now=now, provider_call_id=claim["provider_call_id"], call_record_id=claim["call_record_id"], attestation_id=claim["attestation_id"])
            return {"attempt_id": attempt_id, "state": "dispatching", "current": current, "send": True, "idempotent": False}
        finally:
            if _connection is None:
                connection.close()

    def claim_provider_call(
        self,
        *,
        grant_id: str,
        run_id: str,
        project_id: str,
        profile_hash: str,
        model_identity: str,
        pricing_hash: str,
        logical_call_id: str,
        idempotency_key: str,
        actor: Actor,
        fencing_token: int,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        """Atomically reserve one durable provider-call slot before send()."""

        for value, name in ((grant_id, "grant_id"), (run_id, "run_id"), (project_id, "project_id"), (profile_hash, "profile_hash"), (model_identity, "model_identity"), (pricing_hash, "pricing_hash"), (logical_call_id, "logical_call_id"), (idempotency_key, "idempotency_key")):
            _bounded_identifier(value, name)
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise MaxControlError("provider call fencing token is invalid")
        connection = _connection or self._connect(read_only=False)
        try:
            with (control_transaction(connection) if _connection is None else nullcontext(connection)):
                closed_grant = connection.execute(
                    "SELECT closure_id FROM max_live_execution_grant_closures WHERE grant_id=?",
                    (grant_id,),
                ).fetchone()
                if closed_grant is not None:
                    raise MaxControlError("execution grant is terminally closed and cannot dispatch")
                existing = connection.execute("SELECT c.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.run_id=? AND c.idempotency_key=?", (run_id, idempotency_key)).fetchone()
                if existing is not None:
                    expected = {"grant_id": grant_id, "project_id": project_id, "profile_hash": profile_hash, "model_identity": model_identity, "pricing_hash": pricing_hash, "logical_call_id": logical_call_id}
                    if any(existing[key] != value for key, value in expected.items()):
                        raise MaxControlError("provider call idempotency key conflicts with its durable claim")
                    if existing["state"] in {"disputed", "released", "failed"}:
                        raise MaxControlError("provider call claim is not recoverable")
                    attempt = connection.execute("SELECT a.*, u.state AS attempt_state, u.provider_call_id AS attempt_provider_call_id, u.call_record_id AS attempt_call_record_id, u.attestation_id AS attempt_attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.claim_id=? ORDER BY a.physical_attempt_no DESC LIMIT 1", (existing["claim_id"],)).fetchone()
                    if attempt is None:
                        raise MaxControlError("provider call physical attempt is missing")
                    lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                    lease_valid = lease is not None and lease["owner_id"] == actor.actor_id and lease["session_id"] == actor.session_id and int(lease["fencing_token"]) == fencing_token and lease["released_at"] is None and _parse_timestamp(lease["expires_at"]) is not None and _parse_timestamp(lease["expires_at"]) > _utc_now(self.repository.clock)
                    if not lease_valid:
                        raise MaxControlError("provider call retry uses a stale worker fence")
                    maximum_usage = json.loads(existing["claim_json"]).get("maximum_usage", {})
                    common = {"claim_id": existing["claim_id"], "grant_id": grant_id, "grant_consumption_id": existing["grant_consumption_id"], "run_id": run_id, "project_id": project_id, "logical_call_id": logical_call_id, "intent_id": existing["intent_id"], "iteration_id": existing["iteration_id"], "intent_hash": existing["intent_hash"], "request_hash": existing["request_hash"], "profile_hash": profile_hash, "model_identity": model_identity, "pricing_hash": pricing_hash, "attempt_no": int(existing["attempt_no"]), "attempt_id": attempt["attempt_id"], "physical_attempt_no": int(attempt["physical_attempt_no"]), "fencing_token": int(existing["fencing_token"]), "maximum_usage": maximum_usage, "reserved_cost_units": int(attempt["reserved_cost_units"])}
                    if existing["state"] == "settled" and existing["call_record_id"]:
                        return {**common, "provider_call_id": existing["provider_call_id"], "call_record_id": existing["call_record_id"], "attestation_id": existing["attestation_id"], "replay": True, "idempotent": True}
                    if attempt["attempt_state"] == "reserved":
                        self._check_attempt_lease(connection, attempt=attempt, actor=actor, fencing_token=fencing_token, now=_utc_now(self.repository.clock))
                        return {**common, "replay": False, "idempotent": True}
                    recovery = connection.execute("SELECT consumed_at FROM max_runner_recovery_consumptions WHERE run_id=? AND logical_call_id=? AND decision='retry' ORDER BY consumed_at DESC LIMIT 1", (run_id, logical_call_id)).fetchone()
                    last_event = connection.execute("SELECT created_at FROM max_provider_dispatch_attempt_events WHERE attempt_id=? AND event_type IN ('unknown','dispatching') ORDER BY sequence_no DESC LIMIT 1", (attempt["attempt_id"],)).fetchone()
                    if existing["state"] not in {"unknown", "dispatching"} or recovery is None or last_event is None or recovery["consumed_at"] < last_event["created_at"]:
                        raise MaxControlError("provider call claim awaits an explicit admin recovery decision")
                    grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                    current = connection.execute("SELECT * FROM max_provider_grant_usage_current WHERE grant_id=?", (grant_id,)).fetchone()
                    caps = json.loads(grant["caps_json"]) if grant is not None else {}
                    if current is None or int(current["dispatch_count"]) + 1 > int(caps.get("max_provider_calls", 0)):
                        raise MaxControlError("provider physical call cap is exhausted")
                    if not _usage_within_caps(_projected_grant_usage(current, maximum_usage).to_mapping(), caps) or int(current["settled_cost_units"]) + int(current["reserved_cost_units"]) + int(attempt["reserved_cost_units"]) > int(caps.get("max_cost_units", 0)):
                        raise MaxControlError("provider aggregate budget cap is exhausted")
                    reserved = {"reserved_input_tokens": int(attempt["reserved_input_tokens"]), "reserved_output_tokens": int(attempt["reserved_output_tokens"]), "reserved_cache_read_tokens": int(attempt["reserved_cache_read_tokens"]), "reserved_reasoning_tokens": int(attempt["reserved_reasoning_tokens"]), "reserved_cost_units": int(attempt["reserved_cost_units"])}
                    physical_no = int(connection.execute("SELECT COALESCE(MAX(physical_attempt_no), 0) FROM max_provider_dispatch_attempts WHERE grant_id=?", (grant_id,)).fetchone()[0]) + 1
                    if int(lease["fencing_token"]) < int(attempt["fencing_token"]):
                        raise MaxControlError("provider retry requires a newer takeover fencing token")
                    new_attempt = self._create_physical_attempt(connection, claim=existing, physical_attempt_no=physical_no, reserved=reserved, actor=actor, now=_timestamp(self.repository.clock), fencing_token=fencing_token)
                    self._set_claim_current(connection, claim=existing, state="claimed", actor=actor, now=_timestamp(self.repository.clock), provider_call_id=None, call_record_id=None, attestation_id=None)
                    return {**common, "attempt_id": new_attempt["attempt_id"], "physical_attempt_no": physical_no, "fencing_token": fencing_token, "replay": False, "idempotent": True}
                grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                if grant is None:
                    raise MaxControlError("execution grant was not found")
                if any(grant[key] != value for key, value in {"run_id": run_id, "project_id": project_id, "profile_hash": profile_hash, "model_identity": model_identity, "pricing_hash": pricing_hash}.items()):
                    raise MaxControlError("provider call grant binding mismatch")
                if _parse_timestamp(grant["expires_at"]) is None or _parse_timestamp(grant["expires_at"]) <= _utc_now(self.repository.clock):
                    raise MaxControlError("execution grant has expired")
                consumption = connection.execute("SELECT * FROM max_live_execution_grant_consumptions WHERE grant_id=? AND run_id=? AND project_id=? AND grant_hash=?", (grant_id, run_id, project_id, grant["grant_hash"])).fetchone()
                if consumption is None:
                    raise MaxControlError("provider call requires a consumed execution grant")
                run = connection.execute("SELECT status, project_id, model_identity FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None or run["project_id"] != project_id or run["model_identity"] != model_identity or run["status"] != "RUNNING":
                    raise MaxControlError("provider call run binding is not active")
                lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                if lease is None or lease["owner_id"] != actor.actor_id or lease["session_id"] != actor.session_id or int(lease["fencing_token"]) != fencing_token or lease["released_at"] is not None or _parse_timestamp(lease["expires_at"]) is None or _parse_timestamp(lease["expires_at"]) <= _utc_now(self.repository.clock):
                    raise MaxControlError("provider call uses a stale or missing runner fence")
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE run_id=? AND logical_call_id=?", (run_id, logical_call_id)).fetchone()
                if intent is None or intent["project_id"] != project_id or intent["model_identity"] != model_identity:
                    raise MaxControlError("provider call references an unknown or mismatched model intent")
                manifest = connection.execute("SELECT * FROM max_runner_intent_manifests WHERE intent_id=? AND logical_call_id=? AND run_id=?", (intent["intent_id"], logical_call_id, run_id)).fetchone()
                if manifest is None:
                    raise MaxControlError("provider call intent manifest is missing")
                try:
                    manifest_value = json.loads(manifest["manifest_json"])
                except Exception as exc:
                    raise MaxControlError("provider call intent manifest is invalid") from exc
                if canonical_sha256(manifest_value) != manifest["manifest_hash"] or manifest_value.get("intent_hash") != intent["intent_hash"] or manifest_value.get("request_hash") != intent["request_hash"]:
                    raise MaxControlError("provider call intent manifest binding is invalid")
                iteration = connection.execute("SELECT run_id, project_id FROM max_iterations WHERE iteration_id=?", (intent["iteration_id"],)).fetchone()
                if iteration is None or iteration["run_id"] != run_id or iteration["project_id"] != project_id:
                    raise MaxControlError("provider call iteration binding is invalid")
                binding = connection.execute("SELECT b.*, g.project_id AS group_project_id, g.iteration_id AS group_iteration_id FROM max_runner_call_bindings b JOIN max_runner_call_groups g ON g.group_id=b.group_id WHERE b.run_id=? AND b.logical_call_id=?", (run_id, logical_call_id)).fetchone()
                if binding is None or binding["iteration_id"] != intent["iteration_id"] or binding["group_project_id"] != project_id or binding["group_iteration_id"] != intent["iteration_id"] or binding["intent_hash"] != intent["intent_hash"]:
                    raise MaxControlError("provider call group/binding is missing or inconsistent")
                profile_row = connection.execute("SELECT * FROM max_provider_profiles WHERE profile_hash=?", (profile_hash,)).fetchone()
                if profile_row is None:
                    raise MaxControlError("provider call references an unknown profile")
                profile = _profile_from_row(profile_row)
                if profile.model_identity != model_identity or profile.pricing.pricing_hash != pricing_hash:
                    raise MaxControlError("provider call profile/model/pricing binding is invalid")
                maximum_usage = _authority_usage(profile)
                maximum_cost = profile.pricing.cost_units_for_usage(maximum_usage)
                caps = json.loads(grant["caps_json"])
                if not _usage_within_caps(maximum_usage, caps) or maximum_cost > int(caps["max_cost_units"]):
                    raise MaxControlError(
                        "provider reservation envelope does not fit the server-derived component/family grant ceiling",
                        error_code=_TOKEN_ENVELOPE_ERROR,
                    )
                current = connection.execute("SELECT * FROM max_provider_grant_usage_current WHERE grant_id=?", (grant_id,)).fetchone()
                if current is None:
                    self._ensure_grant_usage_current(connection, grant_id=grant_id, run_id=run_id, project_id=project_id, now=_timestamp(self.repository.clock))
                    current = connection.execute("SELECT * FROM max_provider_grant_usage_current WHERE grant_id=?", (grant_id,)).fetchone()
                if current is None:
                    raise MaxControlError("grant usage projection is missing")
                if int(current["dispatch_count"]) + 1 > int(caps["max_provider_calls"]):
                    raise MaxControlError("provider call cap is exhausted")
                reserved_checks = {
                    "reserved_input_tokens": maximum_usage.get("input_tokens", 0),
                    "reserved_output_tokens": maximum_usage.get("output_tokens", 0),
                    "reserved_cache_read_tokens": maximum_usage.get("cache_read_tokens", 0),
                    "reserved_reasoning_tokens": maximum_usage.get("reasoning_tokens", 0),
                    "reserved_cost_units": maximum_cost,
                }
                if not _usage_within_caps(_projected_grant_usage(current, maximum_usage).to_mapping(), caps) or int(current["settled_cost_units"]) + int(current["reserved_cost_units"]) + maximum_cost > int(caps["max_cost_units"]):
                    raise MaxControlError("provider aggregate budget cap is exhausted")
                attempt_no = int(connection.execute("SELECT COALESCE(MAX(attempt_no), 0) FROM max_provider_call_claims WHERE grant_id=? AND logical_call_id=?", (grant_id, logical_call_id)).fetchone()[0]) + 1
                now = _timestamp(self.repository.clock)
                claim_value = {"grant_id": grant_id, "grant_hash": grant["grant_hash"], "grant_consumption_id": consumption["consumption_id"], "run_id": run_id, "project_id": project_id, "logical_call_id": logical_call_id, "intent_id": intent["intent_id"], "iteration_id": intent["iteration_id"], "intent_hash": intent["intent_hash"], "request_hash": intent["request_hash"], "profile_hash": profile_hash, "model_identity": model_identity, "pricing_hash": pricing_hash, "idempotency_key": idempotency_key, "attempt_no": attempt_no, "fencing_token": fencing_token, "owner_id": actor.actor_id, "owner_session": actor.session_id, "maximum_usage": maximum_usage, "reserved_cost_units": maximum_cost}
                claim_hash = canonical_sha256(claim_value)
                claim_id = make_stable_id("provider_call_claim", claim_hash[:64])
                connection.execute("INSERT INTO max_provider_call_claims(claim_id, grant_id, grant_consumption_id, run_id, project_id, logical_call_id, intent_id, iteration_id, intent_hash, request_hash, profile_hash, model_identity, pricing_hash, idempotency_key, attempt_no, fencing_token, owner_id, owner_session, reserved_input_tokens, reserved_output_tokens, reserved_cache_read_tokens, reserved_reasoning_tokens, reserved_cost_units, claim_json, claim_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (claim_id, grant_id, consumption["consumption_id"], run_id, project_id, logical_call_id, intent["intent_id"], intent["iteration_id"], intent["intent_hash"], intent["request_hash"], profile_hash, model_identity, pricing_hash, idempotency_key, attempt_no, fencing_token, actor.actor_id, actor.session_id, reserved_checks["reserved_input_tokens"], reserved_checks["reserved_output_tokens"], reserved_checks["reserved_cache_read_tokens"], reserved_checks["reserved_reasoning_tokens"], maximum_cost, canonical_json(claim_value), claim_hash, now))
                current_value = self._claim_current_payload(state="claimed", provider_call_id=None, call_record_id=None, attestation_id=None, actual={})
                connection.execute("INSERT INTO max_provider_call_claim_current(claim_id, grant_id, run_id, state, provider_call_id, call_record_id, attestation_id, actual_input_tokens, actual_output_tokens, actual_cache_read_tokens, actual_reasoning_tokens, actual_cost_units, current_json, current_hash, updated_at) VALUES (?, ?, ?, 'claimed', NULL, NULL, NULL, 0, 0, 0, 0, 0, ?, ?, ?)", (claim_id, grant_id, run_id, canonical_json(current_value), canonical_sha256(current_value), now))
                self._append_claim_event(connection, claim_id=claim_id, run_id=run_id, event_type="claimed", payload=claim_value, actor=actor, now=now)
                physical_no = int(connection.execute("SELECT COALESCE(MAX(physical_attempt_no), 0) FROM max_provider_dispatch_attempts WHERE grant_id=?", (grant_id,)).fetchone()[0]) + 1
                attempt = self._create_physical_attempt(connection, claim={**claim_value, "claim_id": claim_id}, physical_attempt_no=physical_no, reserved=reserved_checks, actor=actor, now=now)
            return {"claim_id": claim_id, "grant_id": grant_id, "grant_consumption_id": consumption["consumption_id"], "run_id": run_id, "project_id": project_id, "logical_call_id": logical_call_id, "intent_id": intent["intent_id"], "iteration_id": intent["iteration_id"], "intent_hash": intent["intent_hash"], "request_hash": intent["request_hash"], "profile_hash": profile_hash, "model_identity": model_identity, "pricing_hash": pricing_hash, "attempt_no": attempt_no, "attempt_id": attempt["attempt_id"], "physical_attempt_no": physical_no, "fencing_token": fencing_token, "maximum_usage": maximum_usage, "reserved_cost_units": maximum_cost, "replay": False, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("provider call claim was concurrently created or conflicted") from exc
        finally:
            if _connection is None:
                connection.close()

    def issue_live_execution_grant(
        self,
        *,
        run_id: str,
        actor: Actor,
        profile_hash: str | None = None,
        caps: Mapping[str, Any],
        reason: str,
        ttl_seconds: int = 3600,
        expires_at: str | None = None,
        network_policy_hash: str | None = None,
        pricing_hash: str | None = None,
        budget_hash: str | None = None,
    ) -> dict[str, Any]:
        _require_admin(actor)
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 2_000 or "\r" in reason or "\n" in reason or _REASON_SECRET_RE.search(reason):
            raise MaxControlError("execution grant reason is required and bounded")
        if ttl_seconds < 1 or ttl_seconds > 86_400:
            raise MaxControlError("execution grant TTL is outside the supported range")
        normalized_caps = _caps(caps)
        binding = self.get_run_binding(run_id=run_id)
        selected_profile_hash = profile_hash or str(binding["profile_hash"])
        if selected_profile_hash != binding["profile_hash"]:
            raise MaxControlError("execution grant profile differs from the run binding")
        profile = self.get_profile(profile_hash=selected_profile_hash)
        if network_policy_hash is not None and network_policy_hash != profile.network_policy_hash:
            raise MaxControlError("execution grant network policy differs from the profile")
        if pricing_hash is not None and pricing_hash != profile.pricing.pricing_hash:
            raise MaxControlError("execution grant pricing differs from the profile")
        if budget_hash is not None and budget_hash != binding["budget_hash"]:
            raise MaxControlError("execution grant budget differs from the Charter")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None:
                    raise MaxControlError("Max run was not found")
                if run["project_id"] != binding["project_id"] or run["charter_hash"] != binding["charter_hash"] or run["model_identity"] != profile.model_identity:
                    raise MaxControlError("execution grant does not bind the stored run")
                if run["status"] not in {"APPROVED", "RUNNING"}:
                    raise MaxControlError("execution grant requires an APPROVED or RUNNING run")
                try:
                    charter = json.loads(run["charter_json"])
                    charter_budget = charter.get("budget") if isinstance(charter, Mapping) else None
                except Exception as exc:
                    raise MaxControlError("stored Charter budget is invalid") from exc
                if not isinstance(charter_budget, Mapping):
                    raise MaxControlError("stored Charter budget is missing")
                budget_cap_aliases = {
                    "max_ticks": ("iteration_count", "max_ticks"),
                    "max_iterations": ("iteration_count", "max_iterations"),
                    "max_wall_clock_seconds": ("wall_clock_seconds", "max_wall_clock_seconds"),
                    "max_provider_calls": ("provider_calls", "max_provider_calls", "call_count"),
                    "max_input_tokens": ("input_tokens", "max_input_tokens"),
                    "max_output_tokens": ("output_tokens", "max_output_tokens"),
                    "max_cost_units": ("cost_units", "max_cost_units"),
                }
                for cap_name, budget_names in budget_cap_aliases.items():
                    for budget_name in budget_names:
                        if budget_name in charter_budget:
                            raw_budget = charter_budget[budget_name]
                            if isinstance(raw_budget, bool) or not isinstance(raw_budget, (int, float)) or int(normalized_caps[cap_name]) > int(raw_budget):
                                raise MaxControlError("execution grant cap exceeds the Charter budget")
                            break
                now_dt = _utc_now(self.repository.clock)
                now = _timestamp(self.repository.clock)
                if expires_at is None:
                    expires = (now_dt + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
                else:
                    expires = expires_at
                    parsed = _parse_timestamp(expires)
                    if parsed is None or parsed <= now_dt or parsed > now_dt + timedelta(seconds=86_400):
                        raise MaxControlError("execution grant expiry is invalid")
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                value = {"run_id": run_id, "project_id": binding["project_id"], "charter_hash": binding["charter_hash"], "model_identity": profile.model_identity, "profile_hash": profile.profile_hash, "network_policy_hash": profile.network_policy_hash, "pricing_hash": profile.pricing.pricing_hash, "budget_hash": binding["budget_hash"], "caps": normalized_caps, "reason": reason.strip(), "granted_at": now, "expires_at": expires, "authority_id": actor_id, "authority_kind": actor_kind, "authority_session": actor_session}
                grant_hash = canonical_sha256(value)
                grant_id = make_stable_id("execution_grant", grant_hash[:64])
                existing = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                if existing is not None:
                    closed = connection.execute("SELECT closure_id, terminal_state FROM max_live_execution_grant_closures WHERE grant_id=?", (grant_id,)).fetchone()
                    if closed is not None:
                        raise MaxControlError("execution grant is terminally closed and cannot be reused")
                    self._ensure_grant_usage_current(connection, grant_id=grant_id, run_id=run_id, project_id=binding["project_id"], now=now)
                    return {"grant_id": grant_id, **value, "grant_hash": grant_hash, "idempotent": True}
                connection.execute("INSERT INTO max_live_execution_grants(grant_id, run_id, project_id, charter_hash, model_identity, profile_hash, network_policy_hash, pricing_hash, budget_hash, caps_json, grant_json, grant_hash, granted_at, expires_at, reason, authority_id, authority_kind, authority_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (grant_id, run_id, binding["project_id"], binding["charter_hash"], profile.model_identity, profile.profile_hash, profile.network_policy_hash, profile.pricing.pricing_hash, binding["budget_hash"], canonical_json(normalized_caps), canonical_json(value), grant_hash, now, expires, reason.strip(), actor_id, actor_kind, actor_session))
                self._ensure_grant_usage_current(connection, grant_id=grant_id, run_id=run_id, project_id=binding["project_id"], now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="execution_grant_issued", payload={"grant_id": grant_id, "grant_hash": grant_hash, "profile_hash": profile.profile_hash, "caps": normalized_caps, "expires_at": expires, "reason_hash": canonical_sha256(reason.strip())}, actor=actor, now=now)
            return {"grant_id": grant_id, **value, "grant_hash": grant_hash, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("execution grant conflicts with an immutable record") from exc
        finally:
            connection.close()

    # Stable aliases used by the admin/service layer and by fixture tests.
    grant_live = issue_live_execution_grant
    create_live_execution_grant = issue_live_execution_grant

    def consume_execution_grant(
        self,
        *,
        grant_id: str,
        run_id: str,
        project_id: str,
        profile_hash: str,
        model_identity: str,
        network_policy_hash: str,
        pricing_hash: str,
        budget_hash: str,
        consumer: Actor,
    ) -> dict[str, Any]:
        if consumer.actor_kind == "model" or consumer.role == "model":
            raise MaxControlError("model actors cannot consume an execution grant")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                if grant is None:
                    raise MaxControlError("execution grant was not found")
                closed = connection.execute(
                    "SELECT closure_id FROM max_live_execution_grant_closures WHERE grant_id=?",
                    (grant_id,),
                ).fetchone()
                if closed is not None:
                    raise MaxControlError("execution grant is terminally closed and cannot be consumed")
                expected = {"run_id": run_id, "project_id": project_id, "profile_hash": profile_hash, "model_identity": model_identity, "network_policy_hash": network_policy_hash, "pricing_hash": pricing_hash, "budget_hash": budget_hash}
                actual = {key: grant[key] for key in expected}
                if actual != expected:
                    raise MaxControlError("execution grant binding mismatch")
                if _parse_timestamp(grant["expires_at"]) is None or _parse_timestamp(grant["expires_at"]) <= _utc_now(self.repository.clock):
                    raise MaxControlError("execution grant has expired")
                existing = connection.execute("SELECT * FROM max_live_execution_grant_consumptions WHERE grant_id=?", (grant_id,)).fetchone()
                if existing is not None:
                    if existing["consumer_id"] == consumer.actor_id and existing["consumer_session"] == consumer.session_id:
                        value = json.loads(existing["consumption_json"])
                        return {"consumption_id": existing["consumption_id"], **value, "consumption_hash": existing["consumption_hash"], "idempotent": True}
                    raise MaxControlError("execution grant has already been consumed")
                now = _timestamp(self.repository.clock)
                value = {"grant_id": grant_id, "run_id": run_id, "project_id": project_id, "grant_hash": grant["grant_hash"], "consumer_id": consumer.actor_id, "consumer_kind": consumer.actor_kind, "consumer_session": consumer.session_id, "consumed_at": now}
                consumption_hash = canonical_sha256(value)
                consumption_id = make_stable_id("grant_consumption", consumption_hash[:64])
                connection.execute("INSERT INTO max_live_execution_grant_consumptions(consumption_id, grant_id, run_id, project_id, grant_hash, consumer_id, consumer_kind, consumer_session, consumed_at, consumption_json, consumption_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (consumption_id, grant_id, run_id, project_id, grant["grant_hash"], consumer.actor_id, consumer.actor_kind, consumer.session_id, now, canonical_json(value), consumption_hash))
                self.repository._append_event(connection, run_id=run_id, event_type="execution_grant_consumed", payload={"grant_id": grant_id, "consumption_id": consumption_id, "grant_hash": grant["grant_hash"], "consumer_id": consumer.actor_id}, actor=consumer, now=now)
            return {"consumption_id": consumption_id, **value, "consumption_hash": consumption_hash, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("execution grant was concurrently consumed") from exc
        finally:
            connection.close()

    consume_grant = consume_execution_grant

    def close_execution_grant_before_send(
        self,
        *,
        grant_id: str,
        actor: Actor,
        failure_stage: str,
        error_code: str,
        reason: str = "known_pre_send_failure",
    ) -> dict[str, Any]:
        """Make a consumed grant terminally unused after a proven pre-send failure.

        The immutable grant and consumption remain intact.  The closure row is
        the durable negative authority that prevents a later claim or replay
        from dispatching through the same grant.
        """

        _bounded_identifier(grant_id, "grant_id")
        if not isinstance(failure_stage, str) or not failure_stage or len(failure_stage) > 128 or "\n" in failure_stage or "\r" in failure_stage:
            raise MaxControlError("grant closure failure stage is invalid")
        if not isinstance(error_code, str) or not error_code or len(error_code) > 128 or "\n" in error_code or "\r" in error_code:
            raise MaxControlError("grant closure error code is invalid")
        if not isinstance(reason, str) or not reason or len(reason) > 256 or "\n" in reason or "\r" in reason or _REASON_SECRET_RE.search(reason):
            raise MaxControlError("grant closure reason is invalid")
        now = _timestamp(self.repository.clock)
        actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                if grant is None:
                    raise MaxControlError("execution grant was not found")
                existing = connection.execute("SELECT * FROM max_live_execution_grant_closures WHERE grant_id=?", (grant_id,)).fetchone()
                if existing is not None:
                    return {
                        "closure_id": existing["closure_id"],
                        "grant_id": grant_id,
                        "run_id": existing["run_id"],
                        "state": existing["terminal_state"],
                        "usage": json.loads(existing["usage_json"]),
                        "reservation": json.loads(existing["reservation_json"]),
                        "cost_units": int(existing["cost_units"]),
                        "idempotent": True,
                    }
                consumption = connection.execute(
                    "SELECT consumption_id FROM max_live_execution_grant_consumptions WHERE grant_id=?",
                    (grant_id,),
                ).fetchone()
                usage = {
                    "dispatch_count": 0,
                    "reserved_input_tokens": 0,
                    "reserved_output_tokens": 0,
                    "reserved_cache_read_tokens": 0,
                    "reserved_reasoning_tokens": 0,
                    "reserved_cost_units": 0,
                    "settled_input_tokens": 0,
                    "settled_output_tokens": 0,
                    "settled_cache_read_tokens": 0,
                    "settled_reasoning_tokens": 0,
                    "settled_cost_units": 0,
                    "released_cost_units": 0,
                }
                reservation = {"provider_calls": 0, "input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "reasoning_tokens": 0, "cost_units": 0}
                value = {
                    "grant_id": grant_id,
                    "grant_hash": grant["grant_hash"],
                    "grant_consumption_id": None if consumption is None else consumption["consumption_id"],
                    "run_id": grant["run_id"],
                    "project_id": grant["project_id"],
                    "terminal_state": "terminal-unused/pre-send-aborted",
                    "failure_stage": failure_stage,
                    "error_code": error_code,
                    "reason": reason,
                    "usage": usage,
                    "reservation": reservation,
                    "cost_units": 0,
                    "created_at": now,
                }
                closure_hash = canonical_sha256(value)
                closure_id = make_stable_id("execution_grant_closure", closure_hash[:64])
                value["closure_id"] = closure_id
                connection.execute(
                    "INSERT INTO max_live_execution_grant_closures(closure_id,grant_id,grant_consumption_id,run_id,project_id,terminal_state,failure_stage,error_code,usage_json,reservation_json,cost_units,closure_json,closure_hash,created_at,actor_id,actor_kind,actor_session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (closure_id, grant_id, value["grant_consumption_id"], grant["run_id"], grant["project_id"], value["terminal_state"], failure_stage, error_code, canonical_json(usage), canonical_json(reservation), 0, canonical_json(value), closure_hash, now, actor_id, actor_kind, actor_session),
                )
                self.repository._append_event(
                    connection,
                    run_id=grant["run_id"],
                    event_type="execution_grant_terminal_unused",
                    payload={"grant_id": grant_id, "closure_id": closure_id, "failure_stage": failure_stage, "error_code": error_code},
                    actor=actor,
                    now=now,
                )
            return {"closure_id": closure_id, "grant_id": grant_id, "run_id": grant["run_id"], "state": value["terminal_state"], "usage": usage, "reservation": reservation, "cost_units": 0, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("execution grant closure conflicted with an immutable record") from exc
        finally:
            connection.close()

    def grant_status(self, *, run_id: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            grants = []
            for row in connection.execute("SELECT grant_id, run_id, project_id, profile_hash, model_identity, network_policy_hash, pricing_hash, budget_hash, caps_json, grant_hash, granted_at, expires_at, reason, authority_id, authority_kind FROM max_live_execution_grants WHERE run_id=? ORDER BY granted_at", (run_id,)):
                consumption = connection.execute("SELECT consumption_id, consumer_id, consumer_kind, consumed_at, consumption_hash FROM max_live_execution_grant_consumptions WHERE grant_id=?", (row["grant_id"],)).fetchone()
                closure = connection.execute("SELECT closure_id, terminal_state, failure_stage, error_code FROM max_live_execution_grant_closures WHERE grant_id=?", (row["grant_id"],)).fetchone()
                grants.append({"grant_id": row["grant_id"], "run_id": row["run_id"], "project_id": row["project_id"], "profile_hash": row["profile_hash"], "model_identity": row["model_identity"], "network_policy_hash": row["network_policy_hash"], "pricing_hash": row["pricing_hash"], "budget_hash": row["budget_hash"], "caps": json.loads(row["caps_json"]), "grant_hash": row["grant_hash"], "granted_at": row["granted_at"], "expires_at": row["expires_at"], "reason_hash": canonical_sha256(row["reason"]), "authority_id": row["authority_id"], "authority_kind": row["authority_kind"], "active": closure is None and _parse_timestamp(row["expires_at"]) is not None and _parse_timestamp(row["expires_at"]) > _utc_now(self.repository.clock), "terminal_closure": None if closure is None else {"closure_id": closure["closure_id"], "state": closure["terminal_state"], "failure_stage": closure["failure_stage"], "error_code": closure["error_code"]}, "consumption": None if consumption is None else {"consumption_id": consumption["consumption_id"], "consumer_id": consumption["consumer_id"], "consumer_kind": consumption["consumer_kind"], "consumed_at": consumption["consumed_at"], "consumption_hash": consumption["consumption_hash"]}})
            return {"run_id": run_id, "grants": grants, "count": len(grants)}
        finally:
            connection.close()

    def grant_usage(self, *, grant_id: str) -> dict[str, Any]:
        """Read the server-owned grant usage projection and frozen caps."""

        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT g.run_id, g.project_id, g.caps_json, g.grant_hash, u.* FROM max_live_execution_grants g JOIN max_provider_grant_usage_current u ON u.grant_id=g.grant_id WHERE g.grant_id=?", (grant_id,)).fetchone()
            if row is None:
                raise MaxControlError("execution grant usage projection was not found")
            value = self._grant_current_value(row)
            current_json = json.loads(row["current_json"])
            if canonical_sha256(current_json) != row["current_hash"] or current_json != value:
                raise MaxControlError("execution grant usage projection hash is invalid")
            closure = connection.execute("SELECT closure_id, terminal_state, failure_stage, error_code, closure_hash FROM max_live_execution_grant_closures WHERE grant_id=?", (grant_id,)).fetchone()
            return {"grant_id": grant_id, "run_id": row["run_id"], "project_id": row["project_id"], "grant_hash": row["grant_hash"], "caps": json.loads(row["caps_json"]), "usage": value, "current_hash": row["current_hash"], "updated_at": row["updated_at"], "dispatchable": closure is None, "terminal_closure": None if closure is None else {"closure_id": closure["closure_id"], "state": closure["terminal_state"], "failure_stage": closure["failure_stage"], "error_code": closure["error_code"], "closure_hash": closure["closure_hash"]}}
        finally:
            connection.close()

    # ------------------------------------------------------------------
    # MR-2B1 live-network authorization.  These methods are intentionally
    # separate from the existing hermetic grant/adapter path.  They persist
    # hashes and server-owned audit facts only; no method resolves a secret or
    # opens a network connection.

    @staticmethod
    def _live_caps(value: Mapping[str, Any]) -> dict[str, int]:
        if not isinstance(value, Mapping):
            raise MaxControlError("live network authorization caps are required")
        allowed = {"max_provider_calls", "max_input_tokens", "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens", "max_cost_units"}
        if set(value) != allowed:
            raise MaxControlError("live network authorization caps are incomplete")
        result: dict[str, int] = {}
        for key, raw in value.items():
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0 or raw > 10_000_000:
                raise MaxControlError("live network authorization caps are invalid")
            if key == "max_provider_calls" and raw < 1:
                raise MaxControlError("live network authorization provider-call cap is invalid")
            result[str(key)] = int(raw)
        return result

    @staticmethod
    def _live_access_event(connection: sqlite3.Connection, *, authorization_id: str, run_id: str, project_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str) -> dict[str, Any]:
        value = _safe_mapping(payload, name="live access event payload", max_bytes=50_000)
        previous = connection.execute("SELECT event_hash, sequence_no FROM max_live_network_access_events WHERE authorization_id=? ORDER BY sequence_no DESC LIMIT 1", (authorization_id,)).fetchone()
        sequence_no = int(previous["sequence_no"]) + 1 if previous is not None else 1
        payload_hash = canonical_sha256(value)
        event_value = {"authorization_id": authorization_id, "run_id": run_id, "project_id": project_id, "sequence_no": sequence_no, "event_type": event_type, "payload_hash": payload_hash, "previous_event_hash": previous["event_hash"] if previous is not None else None, "created_at": now}
        event_hash = canonical_sha256(event_value)
        event_id = make_stable_id("live_network_access_event", event_hash[:64])
        actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
        connection.execute(
            """INSERT INTO max_live_network_access_events(
                access_event_id, authorization_id, run_id, project_id, sequence_no,
                event_type, payload_json, payload_hash, previous_event_hash,
                event_hash, created_at, actor_id, actor_kind, actor_session
            ) VALUES (
                :access_event_id, :authorization_id, :run_id, :project_id, :sequence_no,
                :event_type, :payload_json, :payload_hash, :previous_event_hash,
                :event_hash, :created_at, :actor_id, :actor_kind, :actor_session
            )""",
            {
                "access_event_id": event_id, "authorization_id": authorization_id,
                "run_id": run_id, "project_id": project_id, "sequence_no": sequence_no,
                "event_type": event_type, "payload_json": canonical_json(value),
                "payload_hash": payload_hash, "previous_event_hash": event_value["previous_event_hash"],
                "event_hash": event_hash, "created_at": now, "actor_id": actor_id,
                "actor_kind": actor_kind, "actor_session": actor_session,
            },
        )
        return {"access_event_id": event_id, **event_value, "event_hash": event_hash}

    @staticmethod
    def _live_current_value(*, authorization_id: str, run_id: str, project_id: str, state: str, consumption_id: str | None) -> dict[str, Any]:
        return {"authorization_id": authorization_id, "run_id": run_id, "project_id": project_id, "state": state, "consumption_id": consumption_id}

    @staticmethod
    def _live_permit_current_value(*, permit_id: str, run_id: str, project_id: str, state: str) -> dict[str, Any]:
        return {"permit_id": permit_id, "run_id": run_id, "project_id": project_id, "state": state}

    @staticmethod
    def _live_permit_event(connection: sqlite3.Connection, *, permit_id: str, run_id: str, project_id: str, event_type: str, payload: Mapping[str, Any], actor: Actor, now: str) -> dict[str, Any]:
        value = _safe_mapping(payload, name="live dispatch permit event payload", max_bytes=50_000)
        previous = connection.execute("SELECT event_hash, sequence_no FROM max_live_dispatch_permit_events WHERE permit_id=? ORDER BY sequence_no DESC LIMIT 1", (permit_id,)).fetchone()
        sequence_no = int(previous["sequence_no"]) + 1 if previous is not None else 1
        payload_hash = canonical_sha256(value)
        event_value = {"permit_id": permit_id, "run_id": run_id, "project_id": project_id, "sequence_no": sequence_no, "event_type": event_type, "payload_hash": payload_hash, "previous_event_hash": previous["event_hash"] if previous is not None else None, "created_at": now}
        event_hash = canonical_sha256(event_value)
        event_id = make_stable_id("live_dispatch_permit_event", event_hash[:64])
        actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
        connection.execute(
            "INSERT INTO max_live_dispatch_permit_events(permit_event_id, permit_id, run_id, project_id, sequence_no, event_type, payload_json, payload_hash, previous_event_hash, event_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, permit_id, run_id, project_id, sequence_no, event_type, canonical_json(value), payload_hash, event_value["previous_event_hash"], event_hash, now, actor_id, actor_kind, actor_session),
        )
        return {"permit_event_id": event_id, **event_value, "event_hash": event_hash}

    @staticmethod
    def _permit_from_row(row: Mapping[str, Any], current: Mapping[str, Any]) -> LiveDispatchPermit:
        try:
            value = json.loads(row["permit_json"])
        except Exception as exc:
            raise MaxControlError("stored live dispatch permit is invalid") from exc
        if not isinstance(value, Mapping) or value.get("permit_hash") != row["permit_hash"]:
            raise MaxControlError("stored live dispatch permit hash is invalid")
        column_bindings = (
            "permit_id", "authorization_id", "consumption_id", "run_id", "project_id", "grant_id",
            "grant_consumption_id", "profile_hash", "provider_name", "model_identity", "pricing_hash",
            "budget_hash", "claim_id", "attempt_id", "request_hash", "wire_request_hash", "intent_hash",
            "logical_call_id", "idempotency_key_hash", "endpoint_origin_hash", "endpoint_path_policy_hash",
            "network_policy_hash", "credential_ref_hash", "fencing_token", "worker_id", "worker_session",
            "created_at", "expires_at",
        )
        if any(value.get(column) != row[column] for column in column_bindings):
            raise MaxControlError("stored live dispatch permit column binding is invalid")
        if current["current_hash"] != canonical_sha256(json.loads(current["current_json"])):
            raise MaxControlError("live dispatch permit projection hash is invalid")
        current_value = json.loads(current["current_json"])
        if current_value != ProviderStore._live_permit_current_value(permit_id=row["permit_id"], run_id=row["run_id"], project_id=row["project_id"], state=current["state"]):
            raise MaxControlError("live dispatch permit projection binding is invalid")
        value = dict(value)
        value["state"] = current["state"]
        try:
            return LiveDispatchPermit._from_server_mapping(value)
        except Exception as exc:
            raise MaxControlError("stored live dispatch permit failed strict validation") from exc

    def _set_live_permit_current(self, connection: sqlite3.Connection, *, permit: Mapping[str, Any], state: str, actor: Actor, now: str, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if state not in LiveDispatchPermit._STATES:
            raise MaxControlError("live dispatch permit state is invalid")
        current = self._live_permit_current_value(permit_id=str(permit["permit_id"]), run_id=str(permit["run_id"]), project_id=str(permit["project_id"]), state=state)
        connection.execute("UPDATE max_live_dispatch_permit_current SET state=?, current_json=?, current_hash=?, updated_at=? WHERE permit_id=?", (state, canonical_json(current), canonical_sha256(current), now, permit["permit_id"]))
        self._live_permit_event(connection, permit_id=str(permit["permit_id"]), run_id=str(permit["run_id"]), project_id=str(permit["project_id"]), event_type=state, payload={"permit_hash": permit["permit_hash"], **(dict(details or {}))}, actor=actor, now=now)
        return current

    def issue_live_network_authorization(
        self,
        *,
        run_id: str,
        grant_id: str,
        caps: Mapping[str, Any],
        network_policy: Mapping[str, Any],
        reason: str,
        actor: Actor,
        ttl_seconds: int = 900,
        expires_at: str | None = None,
        profile_hash: str | None = None,
    ) -> dict[str, Any]:
        """Issue a hash-only live HTTPS authority; never resolve credentials."""

        _require_admin(actor)
        _bounded_identifier(run_id, "run_id")
        _bounded_identifier(grant_id, "grant_id")
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 2_000 or "\r" in reason or "\n" in reason or _REASON_SECRET_RE.search(reason):
            raise MaxControlError("live network authorization reason is required and bounded")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 3_600:
            raise MaxControlError("live network authorization TTL is outside the supported range")
        normalized_caps = self._live_caps(caps)
        try:
            normalized_policy = normalize_network_policy(network_policy)
        except Exception as exc:
            raise MaxControlError("live network policy failed strict validation") from exc
        policy_hash = canonical_sha256(normalized_policy)
        binding = self.get_run_binding(run_id=run_id)
        selected_profile_hash = profile_hash or str(binding["profile_hash"])
        if selected_profile_hash != binding["profile_hash"]:
            raise MaxControlError("live authorization profile differs from the run binding")
        profile = self.get_profile(profile_hash=selected_profile_hash)
        if policy_hash != profile.network_policy_hash:
            raise MaxControlError("live network policy does not match the registered profile hash")
        try:
            origin_hash, path_hash = endpoint_hashes(profile.endpoint_origin, profile.endpoint_path_policy)
            credential_hash = credential_reference_hash(profile.credential_ref)
            maximum_usage = _authority_usage(profile)
            maximum_cost = profile.pricing.cost_units_for_usage(maximum_usage)
        except Exception as exc:
            raise MaxControlError("live authorization profile binding is invalid") from exc
        if normalized_caps["max_cost_units"] > maximum_cost:
            raise MaxControlError(
                "live authorization cap exceeds the registered provider profile",
                error_code=_PROFILE_COST_CAP_ERROR,
            )
        if normalized_caps["max_input_tokens"] > maximum_usage["input_tokens"] or normalized_caps["max_output_tokens"] > maximum_usage["output_tokens"] or normalized_caps["max_cache_read_tokens"] > maximum_usage["cache_read_tokens"] or normalized_caps["max_reasoning_tokens"] > maximum_usage["reasoning_tokens"]:
            raise MaxControlError("live authorization cap exceeds the registered provider profile")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                run = connection.execute("SELECT * FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                grant_consumption = connection.execute("SELECT * FROM max_live_execution_grant_consumptions WHERE grant_id=?", (grant_id,)).fetchone()
                if run is None or grant is None:
                    raise MaxControlError("live authorization run or grant was not found")
                if grant_consumption is None:
                    raise MaxControlError("live authorization requires a consumed execution grant")
                if run["project_id"] != binding["project_id"] or run["charter_hash"] != binding["charter_hash"] or run["status"] not in {"APPROVED", "RUNNING"}:
                    raise MaxControlError("live authorization run binding is not eligible")
                if any(grant[key] != expected for key, expected in {"run_id": run_id, "project_id": binding["project_id"], "profile_hash": profile.profile_hash, "model_identity": profile.model_identity, "network_policy_hash": profile.network_policy_hash, "pricing_hash": profile.pricing.pricing_hash, "budget_hash": binding["budget_hash"]}.items()):
                    raise MaxControlError("live authorization grant binding mismatch")
                grant_caps = json.loads(grant["caps_json"])
                for key in ("max_provider_calls", "max_input_tokens", "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens", "max_cost_units"):
                    if normalized_caps[key] > int(grant_caps.get(key, 0)):
                        raise MaxControlError("live authorization cap exceeds the execution grant")
                now_dt = _utc_now(self.repository.clock)
                now = _timestamp(self.repository.clock)
                if expires_at is None:
                    expires = (now_dt + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
                else:
                    expires = expires_at
                    parsed = _parse_timestamp(expires)
                    if parsed is None or parsed <= now_dt or parsed > now_dt + timedelta(seconds=3_600):
                        raise MaxControlError("live authorization expiry is invalid")
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                value = {
                    "run_id": run_id, "project_id": binding["project_id"], "charter_hash": binding["charter_hash"],
                    "profile_hash": profile.profile_hash, "provider_name": profile.provider_name,
                    "model_identity": profile.model_identity,
                    "endpoint_origin_hash": origin_hash, "endpoint_path_policy_hash": path_hash,
                    "network_policy_hash": policy_hash, "credential_ref_hash": credential_hash,
                    "pricing_hash": profile.pricing.pricing_hash, "budget_hash": binding["budget_hash"],
                    "grant_id": grant_id, **normalized_caps, "issued_at": now, "expires_at": expires,
                    "reason_hash": canonical_sha256(reason.strip()), "execution_mode": LIVE_EXECUTION_MODE,
                }
                authorization_hash = canonical_sha256({"authorization_id": "pending", **value})
                authorization_id = make_stable_id("live_network_authorization", authorization_hash[:64])
                auth = LiveNetworkAuthorization(authorization_id=authorization_id, authorization_hash="", **value)
                existing = connection.execute("SELECT authorization_json, authorization_hash FROM max_live_network_authorizations WHERE authorization_id=?", (authorization_id,)).fetchone()
                if existing is not None:
                    if existing["authorization_hash"] != auth.authorization_hash:
                        raise MaxControlError("live authorization ID collision")
                    return {**auth.to_mapping(), "idempotent": True, "state": "active"}
                policy_existing = connection.execute("SELECT policy_json, policy_hash FROM max_live_network_policies WHERE network_policy_hash=?", (policy_hash,)).fetchone()
                if policy_existing is not None and (policy_existing["policy_json"] != canonical_json(normalized_policy) or policy_existing["policy_hash"] != policy_hash):
                    raise MaxControlError("live network policy hash collision")
                if policy_existing is None:
                    connection.execute("INSERT INTO max_live_network_policies(network_policy_hash, policy_json, policy_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?)", (policy_hash, canonical_json(normalized_policy), policy_hash, now, actor_id, actor_kind, actor_session))
                connection.execute(
                    """INSERT INTO max_live_network_authorizations(
                        authorization_id, run_id, project_id, charter_hash, profile_hash,
                        provider_name, model_identity, endpoint_origin_hash, endpoint_path_policy_hash,
                        network_policy_hash, credential_ref_hash, pricing_hash, budget_hash,
                        grant_id, max_provider_calls, max_input_tokens, max_output_tokens,
                        max_cache_read_tokens, max_reasoning_tokens, max_cost_units,
                        issued_at, expires_at, reason_hash, execution_mode,
                        authorization_json, authorization_hash, actor_id, actor_kind,
                        actor_session
                    ) VALUES (
                        :authorization_id, :run_id, :project_id, :charter_hash, :profile_hash,
                        :provider_name, :model_identity, :endpoint_origin_hash, :endpoint_path_policy_hash,
                        :network_policy_hash, :credential_ref_hash, :pricing_hash, :budget_hash,
                        :grant_id, :max_provider_calls, :max_input_tokens, :max_output_tokens,
                        :max_cache_read_tokens, :max_reasoning_tokens, :max_cost_units,
                        :issued_at, :expires_at, :reason_hash, :execution_mode,
                        :authorization_json, :authorization_hash, :actor_id, :actor_kind,
                        :actor_session
                    )""",
                    {
                        "authorization_id": authorization_id, "run_id": run_id,
                        "project_id": binding["project_id"], "charter_hash": binding["charter_hash"],
                        "profile_hash": profile.profile_hash, "provider_name": profile.provider_name,
                        "model_identity": profile.model_identity,
                        "endpoint_origin_hash": origin_hash, "endpoint_path_policy_hash": path_hash,
                        "network_policy_hash": policy_hash, "credential_ref_hash": credential_hash,
                        "pricing_hash": profile.pricing.pricing_hash, "budget_hash": binding["budget_hash"],
                        "grant_id": grant_id, "max_provider_calls": normalized_caps["max_provider_calls"],
                        "max_input_tokens": normalized_caps["max_input_tokens"], "max_output_tokens": normalized_caps["max_output_tokens"],
                        "max_cache_read_tokens": normalized_caps["max_cache_read_tokens"], "max_reasoning_tokens": normalized_caps["max_reasoning_tokens"],
                        "max_cost_units": normalized_caps["max_cost_units"], "issued_at": now, "expires_at": expires,
                        "reason_hash": value["reason_hash"], "execution_mode": LIVE_EXECUTION_MODE,
                        "authorization_json": canonical_json(auth.to_mapping()), "authorization_hash": auth.authorization_hash,
                        "actor_id": actor_id, "actor_kind": actor_kind, "actor_session": actor_session,
                    },
                )
                current = self._live_current_value(authorization_id=authorization_id, run_id=run_id, project_id=binding["project_id"], state="active", consumption_id=None)
                connection.execute("INSERT INTO max_live_network_authorization_current(authorization_id, run_id, project_id, state, consumption_id, current_json, current_hash, updated_at) VALUES (?, ?, ?, 'active', NULL, ?, ?, ?)", (authorization_id, run_id, binding["project_id"], canonical_json(current), canonical_sha256(current), now))
                self._live_access_event(connection, authorization_id=authorization_id, run_id=run_id, project_id=binding["project_id"], event_type="issued", payload={"authz_hash": auth.authorization_hash, "grant_id": grant_id, "profile_hash": profile.profile_hash, "provider_name": profile.provider_name, "network_policy_hash": policy_hash, "execution_mode": LIVE_EXECUTION_MODE}, actor=actor, now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="live_network_authorization_issued", payload={"authorization_id": authorization_id, "authorization_hash": auth.authorization_hash, "grant_id": grant_id, "profile_hash": profile.profile_hash, "provider_name": profile.provider_name, "network_policy_hash": policy_hash}, actor=actor, now=now)
            return {**auth.to_mapping(), "idempotent": False, "state": "active"}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live network authorization conflicts with an immutable record") from exc
        finally:
            connection.close()

    create_live_network_authorization = issue_live_network_authorization

    def consume_live_network_authorization(
        self,
        *,
        authorization_id: str,
        run_id: str,
        project_id: str,
        grant_id: str,
        profile_hash: str,
        provider_name: str,
        model_identity: str,
        endpoint_origin: str,
        endpoint_path_policy: str,
        credential_ref: Any,
        consumer: Actor,
        fencing_token: int | None = None,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        """Atomically consume a live authority before credential resolution."""

        _live_identifier(authorization_id, "authorization_id")
        for value, name in ((run_id, "run_id"), (project_id, "project_id"), (grant_id, "grant_id"), (profile_hash, "profile_hash"), (provider_name, "provider_name"), (model_identity, "model_identity")):
            _bounded_identifier(value, name)
        if consumer.actor_kind == "model" or consumer.role == "model":
            raise MaxControlError("model actors cannot consume live authorization")
        try:
            origin_hash, path_hash = endpoint_hashes(endpoint_origin, endpoint_path_policy)
            credential_hash = credential_reference_hash(credential_ref)
        except Exception as exc:
            raise MaxControlError("live authorization request binding is invalid") from exc
        connection = _connection or self._connect(read_only=False)
        try:
            with (control_transaction(connection) if _connection is None else nullcontext(connection)):
                auth_row = connection.execute("SELECT * FROM max_live_network_authorizations WHERE authorization_id=?", (authorization_id,)).fetchone()
                current = connection.execute("SELECT * FROM max_live_network_authorization_current WHERE authorization_id=?", (authorization_id,)).fetchone()
                if auth_row is None or current is None:
                    raise MaxControlError("live network authorization was not found")
                expected = {"run_id": run_id, "project_id": project_id, "grant_id": grant_id, "profile_hash": profile_hash, "provider_name": provider_name, "model_identity": model_identity, "endpoint_origin_hash": origin_hash, "endpoint_path_policy_hash": path_hash, "credential_ref_hash": credential_hash}
                if any(auth_row[key] != value for key, value in expected.items()):
                    raise MaxControlError("live network authorization binding mismatch")
                auth = LiveNetworkAuthorization.from_mapping(json.loads(auth_row["authorization_json"]))
                if auth.authorization_hash != auth_row["authorization_hash"] or auth.provider_name != auth_row["provider_name"]:
                    raise MaxControlError("live network authorization hash is invalid")
                existing = connection.execute("SELECT * FROM max_live_network_authorization_consumptions WHERE authorization_id=?", (authorization_id,)).fetchone()
                if existing is not None:
                    if any(existing[key] != value for key, value in {"run_id": run_id, "project_id": project_id, "grant_id": grant_id, "profile_hash": profile_hash, "provider_name": provider_name, "model_identity": model_identity, "endpoint_origin_hash": origin_hash, "endpoint_path_policy_hash": path_hash, "credential_ref_hash": credential_hash}.items()):
                        raise MaxControlError("live network authorization replay binding mismatch")
                    return {"consumption_id": existing["consumption_id"], **json.loads(existing["consumption_json"]), "consumption_hash": existing["consumption_hash"], "idempotent": True}
                if current["state"] != "active" or current["consumption_id"] is not None:
                    raise MaxControlError("live network authorization is not active")
                now_dt = _utc_now(self.repository.clock)
                if _parse_timestamp(auth.expires_at) is None or _parse_timestamp(auth.expires_at) <= now_dt:
                    raise MaxControlError("live network authorization has expired")
                run = connection.execute("SELECT status, project_id, charter_hash, model_identity FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
                if run is None or run["status"] != "RUNNING" or run["project_id"] != project_id or run["charter_hash"] != auth.charter_hash or run["model_identity"] != model_identity:
                    raise MaxControlError("live authorization run is not actively approved")
                approval_count = connection.execute("SELECT COUNT(*) FROM max_approval_consumptions WHERE run_id=?", (run_id,)).fetchone()[0]
                if int(approval_count) != 1:
                    raise MaxControlError("live authorization requires the consumed StartApproval")
                grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (grant_id,)).fetchone()
                grant_consumption = connection.execute("SELECT consumption_id FROM max_live_execution_grant_consumptions WHERE grant_id=?", (grant_id,)).fetchone()
                if grant is None or grant_consumption is None or any(grant[key] != value for key, value in {"run_id": run_id, "project_id": project_id, "profile_hash": profile_hash, "model_identity": model_identity}.items()):
                    raise MaxControlError("live authorization requires the consumed execution grant")
                lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (run_id,)).fetchone()
                effective_fence = int(fencing_token) if fencing_token is not None else (int(lease["fencing_token"]) if lease is not None and lease["owner_id"] == consumer.actor_id and lease["session_id"] == consumer.session_id else 0)
                if lease is None or effective_fence < 1 or lease["owner_id"] != consumer.actor_id or lease["session_id"] != consumer.session_id or int(lease["fencing_token"]) != effective_fence or lease["released_at"] is not None or _parse_timestamp(lease["expires_at"]) is None or _parse_timestamp(lease["expires_at"]) <= now_dt:
                    raise MaxControlError("live authorization uses a stale or missing worker fence")
                now = _timestamp(self.repository.clock)
                value = {"authorization_id": authorization_id, "run_id": run_id, "project_id": project_id, "grant_id": grant_id, "grant_consumption_id": grant_consumption["consumption_id"], "profile_hash": profile_hash, "provider_name": provider_name, "model_identity": model_identity, "endpoint_origin_hash": origin_hash, "endpoint_path_policy_hash": path_hash, "credential_ref_hash": credential_hash, "consumer_id": consumer.actor_id, "consumer_kind": consumer.actor_kind, "consumer_session": consumer.session_id, "fencing_token": effective_fence, "consumed_at": now}
                consumption_hash = canonical_sha256(value)
                consumption_id = make_stable_id("live_network_consumption", consumption_hash[:64])
                connection.execute("INSERT INTO max_live_network_authorization_consumptions(consumption_id, authorization_id, run_id, project_id, grant_id, profile_hash, provider_name, model_identity, endpoint_origin_hash, endpoint_path_policy_hash, credential_ref_hash, consumer_id, consumer_kind, consumer_session, consumed_at, consumption_json, consumption_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (consumption_id, authorization_id, run_id, project_id, grant_id, profile_hash, provider_name, model_identity, origin_hash, path_hash, credential_hash, consumer.actor_id, consumer.actor_kind, consumer.session_id, now, canonical_json(value), consumption_hash))
                current_value = self._live_current_value(authorization_id=authorization_id, run_id=run_id, project_id=project_id, state="consumed", consumption_id=consumption_id)
                connection.execute("UPDATE max_live_network_authorization_current SET state='consumed', consumption_id=?, current_json=?, current_hash=?, updated_at=? WHERE authorization_id=?", (consumption_id, canonical_json(current_value), canonical_sha256(current_value), now, authorization_id))
                self._live_access_event(connection, authorization_id=authorization_id, run_id=run_id, project_id=project_id, event_type="consumed", payload={"authz_hash": auth.authorization_hash, "consumption_id": consumption_id, "consumption_hash": consumption_hash, "provider_name": provider_name, "fencing_token": effective_fence}, actor=consumer, now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="live_network_authorization_consumed", payload={"authorization_id": authorization_id, "consumption_id": consumption_id, "consumption_hash": consumption_hash, "provider_name": provider_name}, actor=consumer, now=now)
            return {"consumption_id": consumption_id, **value, "consumption_hash": consumption_hash, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live network authorization was concurrently consumed") from exc
        finally:
            if _connection is None:
                connection.close()

    consume_live_authorization = consume_live_network_authorization

    def prepare_live_dispatch(
        self,
        *,
        authorization_id: str,
        run_id: str,
        project_id: str,
        grant_id: str,
        profile: ProviderProfile,
        request_hash: str,
        wire_request_hash: str,
        intent_hash: str,
        logical_call_id: str,
        idempotency_key: str,
        actor: Actor,
        fencing_token: int,
        permit_ttl_seconds: int = 120,
        live_bundle_id: str | None = None,
        live_assignment_id: str | None = None,
    ) -> dict[str, Any]:
        """Atomically reserve a live physical call and issue its permit.

        The existing claim/grant/usage and live-authorization routines are
        reused on one connection.  No subroutine commits while ``_connection``
        is supplied, so a failure at any point rolls back the claim, budget
        reservation and authorization consumption together.
        """

        _live_identifier(authorization_id, "authorization_id")
        for value, name in ((run_id, "run_id"), (project_id, "project_id"), (grant_id, "grant_id"), (request_hash, "request_hash"), (wire_request_hash, "wire_request_hash"), (intent_hash, "intent_hash"), (logical_call_id, "logical_call_id"), (idempotency_key, "idempotency_key")):
            _bounded_identifier(value, name)
        if not isinstance(profile, ProviderProfile):
            raise MaxControlError("live dispatch requires a registered ProviderProfile")
        for value, name in ((request_hash, "request_hash"), (wire_request_hash, "wire_request_hash"), (intent_hash, "intent_hash")):
            if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                raise MaxControlError(f"{name} is not a SHA-256 hash")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
            raise MaxControlError("live dispatch fencing token is invalid")
        if isinstance(permit_ttl_seconds, bool) or not isinstance(permit_ttl_seconds, int) or not 1 <= permit_ttl_seconds <= 3_600:
            raise MaxControlError("live dispatch permit TTL is invalid")
        if actor.actor_kind == "model" or actor.role == "model":
            raise MaxControlError("model actors cannot prepare live dispatch")
        if (live_bundle_id is None) != (live_assignment_id is None):
            raise MaxControlError("live bundle and assignment bindings must be supplied together")
        if live_bundle_id is not None:
            _live_identifier(live_bundle_id, "live_bundle_id")
            _live_identifier(live_assignment_id, "live_assignment_id")

        idempotency_hash = canonical_sha256(idempotency_key)
        origin_hash, path_hash = endpoint_hashes(profile.endpoint_origin, profile.endpoint_path_policy)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                if live_bundle_id is not None:
                    run_budget = connection.execute(
                        "SELECT budget_hash FROM max_runs WHERE run_id=? AND project_id=?",
                        (run_id, project_id),
                    ).fetchone()
                    if run_budget is None:
                        raise MaxControlError("live dispatch run budget binding was not found")
                    bundle_binding = connection.execute(
                        "SELECT a.*, b.grant_id AS bundle_grant_id, b.profile_hash AS bundle_profile_hash, b.model_identity AS bundle_model_identity, b.pricing_hash AS bundle_pricing_hash, b.budget_hash AS bundle_budget_hash, b.expires_at AS bundle_expires_at, c.state AS bundle_state FROM max_live_authorization_assignments a JOIN max_live_authorization_bundles b ON b.bundle_id=a.bundle_id JOIN max_live_authorization_bundle_current c ON c.bundle_id=b.bundle_id WHERE a.assignment_id=? AND a.bundle_id=?",
                        (live_assignment_id, live_bundle_id),
                    ).fetchone()
                    if bundle_binding is None:
                        raise MaxControlError("live dispatch authorization assignment was not found")
                    expected_bundle = {
                        "authorization_id": authorization_id,
                        "run_id": run_id,
                        "project_id": project_id,
                        "logical_call_id": logical_call_id,
                        "intent_hash": intent_hash,
                        "idempotency_key_hash": idempotency_hash,
                        "bundle_grant_id": grant_id,
                        "bundle_profile_hash": profile.profile_hash,
                        "bundle_model_identity": profile.model_identity,
                        "bundle_pricing_hash": profile.pricing.pricing_hash,
                        "bundle_budget_hash": run_budget["budget_hash"],
                    }
                    if any(bundle_binding[key] != value for key, value in expected_bundle.items()):
                        raise MaxControlError("live dispatch authorization assignment binding mismatch")
                    if bundle_binding["bundle_state"] not in {"active", "exhausted"}:
                        raise MaxControlError("live authorization bundle is no longer executable")
                    if _parse_timestamp(bundle_binding["bundle_expires_at"]) is None or _parse_timestamp(bundle_binding["bundle_expires_at"]) <= _utc_now(self.repository.clock):
                        raise MaxControlError("live authorization bundle has expired")
                existing = connection.execute(
                    "SELECT p.*, c.state, c.current_json, c.current_hash FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.run_id=? AND p.idempotency_key_hash=?",
                    (run_id, idempotency_hash),
                ).fetchone()
                if existing is not None:
                    permit = self._permit_from_row(existing, existing)
                    existing_auth = connection.execute(
                        "SELECT a.*, c.state AS auth_state, c.consumption_id AS auth_consumption_id FROM max_live_network_authorizations a JOIN max_live_network_authorization_current c ON c.authorization_id=a.authorization_id WHERE a.authorization_id=?",
                        (permit.authorization_id,),
                    ).fetchone()
                    existing_grant_consumption = connection.execute(
                        "SELECT consumption_id FROM max_live_execution_grant_consumptions WHERE grant_id=? AND run_id=? AND project_id=? AND grant_hash=(SELECT grant_hash FROM max_live_execution_grants WHERE grant_id=?)",
                        (permit.grant_id, permit.run_id, permit.project_id, permit.grant_id),
                    ).fetchone()
                    grant_row = connection.execute(
                        "SELECT * FROM max_live_execution_grants WHERE grant_id=?",
                        (permit.grant_id,),
                    ).fetchone()
                    if (
                        existing_auth is None
                        or existing_auth["auth_state"] != "consumed"
                        or existing_auth["auth_consumption_id"] != permit.consumption_id
                        or existing_auth["grant_id"] != permit.grant_id
                        or existing_auth["budget_hash"] != permit.budget_hash
                        or grant_row is None
                        or grant_row["run_id"] != permit.run_id
                        or grant_row["project_id"] != permit.project_id
                        or grant_row["profile_hash"] != permit.profile_hash
                        or grant_row["model_identity"] != permit.model_identity
                        or grant_row["pricing_hash"] != permit.pricing_hash
                        or grant_row["budget_hash"] != permit.budget_hash
                        or existing_grant_consumption is None
                        or existing_grant_consumption["consumption_id"] != permit.grant_consumption_id
                    ):
                        raise MaxControlError("live dispatch permit authority binding is invalid")
                    expected = {
                        "authorization_id": authorization_id, "run_id": run_id, "project_id": project_id,
                        "grant_id": grant_id, "profile_hash": profile.profile_hash,
                        "provider_name": profile.provider_name, "model_identity": profile.model_identity,
                        "pricing_hash": profile.pricing.pricing_hash, "request_hash": request_hash,
                        "wire_request_hash": wire_request_hash, "intent_hash": intent_hash,
                        "logical_call_id": logical_call_id, "network_policy_hash": profile.network_policy_hash,
                        "credential_ref_hash": credential_reference_hash(profile.credential_ref),
                        "endpoint_origin_hash": origin_hash, "endpoint_path_policy_hash": path_hash,
                        "fencing_token": fencing_token, "worker_id": actor.actor_id,
                        "worker_session": actor.session_id,
                    }
                    if any(getattr(permit, key) != value for key, value in expected.items()):
                        raise MaxControlError("live dispatch permit binding mismatch")
                    if permit.state in {"revoked", "expired", "failed", "unknown", "disputed"}:
                        raise MaxControlError("live dispatch permit is not recoverable")
                    if permit.state == "send_started":
                        raise MaxControlError("live physical dispatch is already in progress")
                    if _parse_timestamp(permit.expires_at) is None or _parse_timestamp(permit.expires_at) <= _utc_now(self.repository.clock):
                        raise MaxControlError("live dispatch permit has expired")
                    return {"permit": permit, "permit_mapping": permit.to_mapping(), "idempotent": True, "claim_id": permit.claim_id, "attempt_id": permit.attempt_id}

                auth_current = connection.execute("SELECT * FROM max_live_network_authorization_current WHERE authorization_id=?", (authorization_id,)).fetchone()
                auth_row = connection.execute("SELECT * FROM max_live_network_authorizations WHERE authorization_id=?", (authorization_id,)).fetchone()
                if auth_row is None or auth_current is None:
                    raise MaxControlError("live network authorization was not found")
                if auth_current["state"] != "active" or auth_current["consumption_id"] is not None:
                    raise MaxControlError("live network authorization is not available")

                claim = self.claim_provider_call(
                    grant_id=grant_id, run_id=run_id, project_id=project_id,
                    profile_hash=profile.profile_hash, model_identity=profile.model_identity,
                    pricing_hash=profile.pricing.pricing_hash, logical_call_id=logical_call_id,
                    idempotency_key=idempotency_key, actor=actor, fencing_token=fencing_token,
                    _connection=connection,
                )
                if claim.get("replay"):
                    return {"claim": claim, "replay": True, "idempotent": True}
                if claim.get("idempotent"):
                    raise MaxControlError("provider call already has no recoverable live permit")
                if claim.get("request_hash") != request_hash or claim.get("intent_hash") != intent_hash:
                    raise MaxControlError("live dispatch request is not bound to the durable intent")

                consumed = self.consume_live_network_authorization(
                    authorization_id=authorization_id, run_id=run_id, project_id=project_id,
                    grant_id=grant_id, profile_hash=profile.profile_hash,
                    provider_name=profile.provider_name, model_identity=profile.model_identity,
                    endpoint_origin=profile.endpoint_origin, endpoint_path_policy=profile.endpoint_path_policy,
                    credential_ref=profile.credential_ref, consumer=actor,
                    fencing_token=fencing_token, _connection=connection,
                )
                now_dt = _utc_now(self.repository.clock)
                now = _timestamp(self.repository.clock)
                expires_dt = now_dt + timedelta(seconds=permit_ttl_seconds)
                auth_expiry = _parse_timestamp(auth_row["expires_at"])
                if auth_expiry is None or expires_dt > auth_expiry:
                    expires_dt = auth_expiry
                if expires_dt is None or expires_dt <= now_dt:
                    raise MaxControlError("live dispatch permit cannot outlive authorization")
                expires = expires_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
                permit_value: dict[str, Any] = {
                    "permit_id": "pending", "authorization_id": authorization_id,
                    "consumption_id": consumed["consumption_id"], "run_id": run_id,
                    "project_id": project_id, "grant_id": grant_id,
                    "grant_consumption_id": claim["grant_consumption_id"],
                    "profile_hash": profile.profile_hash, "provider_name": profile.provider_name,
                    "model_identity": profile.model_identity, "pricing_hash": profile.pricing.pricing_hash,
                    "budget_hash": auth_row["budget_hash"], "claim_id": claim["claim_id"],
                    "attempt_id": claim["attempt_id"], "request_hash": request_hash,
                    "wire_request_hash": wire_request_hash, "intent_hash": intent_hash,
                    "logical_call_id": logical_call_id, "idempotency_key_hash": idempotency_hash,
                    "endpoint_origin_hash": origin_hash, "endpoint_path_policy_hash": path_hash,
                    "network_policy_hash": profile.network_policy_hash,
                    "credential_ref_hash": credential_reference_hash(profile.credential_ref),
                    "fencing_token": fencing_token, "worker_id": actor.actor_id,
                    "worker_session": actor.session_id, "created_at": now, "expires_at": expires,
                    "state": "ready",
                }
                permit_hash = canonical_sha256({key: value for key, value in permit_value.items() if key != "state"})
                permit_id = make_stable_id("live_dispatch_permit", permit_hash[:64])
                permit_value["permit_id"] = permit_id
                permit = LiveDispatchPermit._from_server_mapping(permit_value)
                permit_json = canonical_json(permit.to_mapping())
                connection.execute(
                    "INSERT INTO max_live_dispatch_permits(permit_id, authorization_id, consumption_id, run_id, project_id, grant_id, grant_consumption_id, profile_hash, provider_name, model_identity, pricing_hash, budget_hash, claim_id, attempt_id, request_hash, wire_request_hash, intent_hash, logical_call_id, idempotency_key_hash, endpoint_origin_hash, endpoint_path_policy_hash, network_policy_hash, credential_ref_hash, fencing_token, worker_id, worker_session, created_at, expires_at, permit_json, permit_hash) VALUES (:permit_id, :authorization_id, :consumption_id, :run_id, :project_id, :grant_id, :grant_consumption_id, :profile_hash, :provider_name, :model_identity, :pricing_hash, :budget_hash, :claim_id, :attempt_id, :request_hash, :wire_request_hash, :intent_hash, :logical_call_id, :idempotency_key_hash, :endpoint_origin_hash, :endpoint_path_policy_hash, :network_policy_hash, :credential_ref_hash, :fencing_token, :worker_id, :worker_session, :created_at, :expires_at, :permit_json, :permit_hash)",
                    {"permit_id": permit.permit_id, "authorization_id": permit.authorization_id, "consumption_id": permit.consumption_id, "run_id": permit.run_id, "project_id": permit.project_id, "grant_id": permit.grant_id, "grant_consumption_id": permit.grant_consumption_id, "profile_hash": permit.profile_hash, "provider_name": permit.provider_name, "model_identity": permit.model_identity, "pricing_hash": permit.pricing_hash, "budget_hash": permit.budget_hash, "claim_id": permit.claim_id, "attempt_id": permit.attempt_id, "request_hash": permit.request_hash, "wire_request_hash": permit.wire_request_hash, "intent_hash": permit.intent_hash, "logical_call_id": permit.logical_call_id, "idempotency_key_hash": permit.idempotency_key_hash, "endpoint_origin_hash": permit.endpoint_origin_hash, "endpoint_path_policy_hash": permit.endpoint_path_policy_hash, "network_policy_hash": permit.network_policy_hash, "credential_ref_hash": permit.credential_ref_hash, "fencing_token": permit.fencing_token, "worker_id": permit.worker_id, "worker_session": permit.worker_session, "created_at": permit.created_at, "expires_at": permit.expires_at, "permit_json": permit_json, "permit_hash": permit.permit_hash},
                )
                current = self._live_permit_current_value(permit_id=permit.permit_id, run_id=run_id, project_id=project_id, state="ready")
                connection.execute("INSERT INTO max_live_dispatch_permit_current(permit_id, run_id, project_id, state, current_json, current_hash, updated_at) VALUES (?, ?, ?, 'ready', ?, ?, ?)", (permit.permit_id, run_id, project_id, canonical_json(current), canonical_sha256(current), now))
                self._live_permit_event(connection, permit_id=permit.permit_id, run_id=run_id, project_id=project_id, event_type="ready", payload={"permit_hash": permit.permit_hash, "authz_id": authorization_id, "consumption_id": consumed["consumption_id"], "claim_id": claim["claim_id"], "attempt_id": claim["attempt_id"], "request_hash": request_hash, "wire_request_hash": wire_request_hash, "fencing_token": fencing_token}, actor=actor, now=now)
                self.repository._append_event(connection, run_id=run_id, event_type="live_dispatch_permit_created", payload={"permit_id": permit.permit_id, "permit_hash": permit.permit_hash, "authorization_id": authorization_id, "claim_id": claim["claim_id"], "attempt_id": claim["attempt_id"]}, actor=actor, now=now)
            return {"permit": permit, "permit_mapping": permit.to_mapping(), "claim": claim, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live dispatch permit conflicted with an immutable authority record") from exc
        finally:
            connection.close()

    def start_live_dispatch(self, *, permit: LiveDispatchPermit, actor: Actor, fencing_token: int) -> LiveDispatchPermit:
        if not isinstance(permit, LiveDispatchPermit) or not permit._is_server_owned():
            raise MaxControlError("live dispatch requires a server-issued permit")
        if permit.worker_id != actor.actor_id or permit.worker_session != actor.session_id or permit.fencing_token != fencing_token:
            raise MaxControlError("live dispatch permit worker binding mismatch")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT p.*, c.state, c.current_json, c.current_hash FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.permit_id=?", (permit.permit_id,)).fetchone()
                if row is None:
                    raise MaxControlError("live dispatch permit was not found")
                current = self._permit_from_row(row, row)
                if current.permit_hash != permit.permit_hash or current.state != "ready":
                    raise MaxControlError("live dispatch permit is stale or already started")
                if _parse_timestamp(current.expires_at) is None or _parse_timestamp(current.expires_at) <= _utc_now(self.repository.clock):
                    raise MaxControlError("live dispatch permit has expired")
                auth = connection.execute("SELECT state, consumption_id FROM max_live_network_authorization_current WHERE authorization_id=?", (current.authorization_id,)).fetchone()
                if auth is None or auth["state"] != "consumed" or auth["consumption_id"] != current.consumption_id:
                    raise MaxControlError("live dispatch authorization is no longer consumed for this permit")
                attempt = connection.execute("SELECT a.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.attempt_id=?", (current.attempt_id,)).fetchone()
                if attempt is None:
                    raise MaxControlError("live dispatch physical attempt is missing")
                self._check_attempt_lease(connection, attempt=attempt, actor=actor, fencing_token=fencing_token, now=_utc_now(self.repository.clock))
                if attempt["state"] != "reserved":
                    raise MaxControlError("live dispatch physical attempt is not reserved")
                now = _timestamp(self.repository.clock)
                self._set_attempt_current(connection, attempt=attempt, state="dispatching", actor=actor, now=now, provider_call_id=attempt["provider_call_id"], call_record_id=attempt["call_record_id"], attestation_id=attempt["attestation_id"])
                claim = connection.execute("SELECT c.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.claim_id=?", (current.claim_id,)).fetchone()
                if claim is None:
                    raise MaxControlError("live dispatch claim is missing")
                self._set_claim_current(connection, claim=claim, state="dispatching", actor=actor, now=now, provider_call_id=claim["provider_call_id"], call_record_id=claim["call_record_id"], attestation_id=claim["attestation_id"])
                self._set_live_permit_current(connection, permit=current.to_mapping(), state="send_started", actor=actor, now=now, details={"attempt_id": current.attempt_id, "claim_id": current.claim_id})
                refreshed = LiveDispatchPermit._from_server_mapping({**current.to_mapping(), "state": "send_started"})
            return refreshed
        finally:
            connection.close()

    def validate_live_dispatch_permit(self, permit: LiveDispatchPermit) -> dict[str, Any]:
        if not isinstance(permit, LiveDispatchPermit) or not permit._is_server_owned():
            raise MaxControlError("live dispatch permit is not server-owned")
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT p.*, c.state, c.current_json, c.current_hash FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.permit_id=?", (permit.permit_id,)).fetchone()
            if row is None:
                raise MaxControlError("live dispatch permit was not found")
            current = self._permit_from_row(row, row)
            if current.permit_hash != permit.permit_hash or current.to_mapping(include_state=False) != permit.to_mapping(include_state=False):
                raise MaxControlError("live dispatch permit binding mismatch")
            if current.state != "send_started":
                raise MaxControlError("live dispatch permit is not in send-started state")
            if _parse_timestamp(current.expires_at) is None or _parse_timestamp(current.expires_at) <= _utc_now(self.repository.clock):
                raise MaxControlError("live dispatch permit has expired")
            auth = connection.execute("SELECT state, consumption_id FROM max_live_network_authorization_current WHERE authorization_id=?", (current.authorization_id,)).fetchone()
            if auth is None or auth["state"] != "consumed" or auth["consumption_id"] != current.consumption_id:
                raise MaxControlError("live dispatch authorization binding is invalid")
            lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (current.run_id,)).fetchone()
            if lease is None or lease["owner_id"] != current.worker_id or lease["session_id"] != current.worker_session or int(lease["fencing_token"]) != current.fencing_token or lease["released_at"] is not None or _parse_timestamp(lease["expires_at"]) is None or _parse_timestamp(lease["expires_at"]) <= _utc_now(self.repository.clock):
                raise MaxControlError("live dispatch permit uses a stale worker fence")
            return {"ok": True, "permit_id": current.permit_id, "permit_hash": current.permit_hash, "state": current.state, "run_id": current.run_id, "fencing_token": current.fencing_token}
        finally:
            connection.close()

    def live_dispatch_permit_for_request(self, *, run_id: str, idempotency_key: str) -> dict[str, Any] | None:
        """Read one persisted permit for recovery without consuming authority."""

        _bounded_identifier(run_id, "run_id")
        _bounded_identifier(idempotency_key, "idempotency_key")
        idempotency_hash = canonical_sha256(idempotency_key)
        connection = self._connect(read_only=True)
        try:
            row = connection.execute(
                "SELECT p.*, c.state, c.current_json, c.current_hash FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.run_id=? AND p.idempotency_key_hash=?",
                (run_id, idempotency_hash),
            ).fetchone()
            if row is None:
                return None
            permit = self._permit_from_row(row, row)
            if permit.run_id != run_id or permit.idempotency_key_hash != idempotency_hash:
                raise MaxControlError("live dispatch recovery permit binding mismatch")
            return {"permit": permit, "permit_mapping": permit.to_mapping(), "state": permit.state}
        finally:
            connection.close()

    def live_dispatch_context(self, *, permit: LiveDispatchPermit) -> dict[str, Any]:
        """Read the server-owned intent/attempt projection for one permit.

        The production one-shot bridge uses this projection to build a
        ProviderCallRecord without trusting client-supplied intent IDs.  It
        exposes hashes and identifiers only; request bodies and response
        content never enter this context object.
        """

        if not isinstance(permit, LiveDispatchPermit) or not permit._is_server_owned():
            raise MaxControlError("live dispatch context requires a server-issued permit")
        connection = self._connect(read_only=True)
        try:
            row = connection.execute(
                "SELECT a.*, u.state AS attempt_state, c.intent_id AS claim_intent_id, c.iteration_id AS claim_iteration_id, c.intent_hash AS claim_intent_hash, c.request_hash AS claim_request_hash, cu.state AS claim_state FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id JOIN max_provider_call_claims c ON c.claim_id=a.claim_id JOIN max_provider_call_claim_current cu ON cu.claim_id=c.claim_id WHERE a.attempt_id=? AND a.claim_id=?",
                (permit.attempt_id, permit.claim_id),
            ).fetchone()
            if row is None:
                raise MaxControlError("live dispatch intent context was not found")
            expected = {
                "run_id": permit.run_id,
                "project_id": permit.project_id,
                "logical_call_id": permit.logical_call_id,
                "intent_hash": permit.intent_hash,
                "request_hash": permit.request_hash,
                "claim_id": permit.claim_id,
                "attempt_id": permit.attempt_id,
            }
            actual = {key: row[key] for key in expected}
            if actual != expected or row["claim_intent_id"] != row["intent_id"] or row["claim_iteration_id"] != row["iteration_id"] or row["claim_intent_hash"] != row["intent_hash"] or row["claim_request_hash"] != row["request_hash"]:
                raise MaxControlError("live dispatch intent context binding is invalid")
            return {
                "claim_id": row["claim_id"], "attempt_id": row["attempt_id"],
                "intent_id": row["intent_id"], "iteration_id": row["iteration_id"],
                "logical_call_id": row["logical_call_id"], "intent_hash": row["intent_hash"],
                "request_hash": row["request_hash"], "run_id": row["run_id"],
                "project_id": row["project_id"], "profile_hash": row["profile_hash"],
                "model_identity": row["model_identity"], "pricing_hash": row["pricing_hash"],
                "attempt_state": row["attempt_state"], "claim_state": row["claim_state"],
            }
        finally:
            connection.close()

    def mark_live_dispatch_outcome(self, *, permit: LiveDispatchPermit, state: str, actor: Actor, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if state not in {"settled", "failed", "unknown", "disputed"}:
            raise MaxControlError("live dispatch outcome is invalid")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT p.*, c.state, c.current_json, c.current_hash FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.permit_id=?", (permit.permit_id,)).fetchone()
                if row is None:
                    raise MaxControlError("live dispatch permit was not found")
                current = self._permit_from_row(row, row)
                if current.permit_hash != permit.permit_hash or current.worker_id != actor.actor_id or current.worker_session != actor.session_id:
                    raise MaxControlError("live dispatch outcome binding mismatch")
                if current.fencing_token < 1:
                    raise MaxControlError("live dispatch outcome fencing token is invalid")
                attempt = connection.execute(
                    "SELECT a.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.attempt_id=?",
                    (current.attempt_id,),
                ).fetchone()
                if attempt is None:
                    raise MaxControlError("live dispatch physical attempt is missing")
                self._check_attempt_lease(
                    connection, attempt=attempt, actor=actor,
                    fencing_token=current.fencing_token,
                    now=_utc_now(self.repository.clock),
                )
                if current.state == state:
                    return {"permit_id": current.permit_id, "state": state, "idempotent": True}
                if current.state not in {"send_started", "ready"}:
                    raise MaxControlError("live dispatch outcome cannot change the current state")
                now = _timestamp(self.repository.clock)
                self._set_live_permit_current(connection, permit=current.to_mapping(), state=state, actor=actor, now=now, details=details)
            return {"permit_id": current.permit_id, "state": state, "idempotent": False}
        finally:
            connection.close()

    def live_authorization_status(self, *, run_id: str, authorization_id: str | None = None) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            query = "SELECT a.*, c.state, c.consumption_id, c.current_hash FROM max_live_network_authorizations a JOIN max_live_network_authorization_current c ON c.authorization_id=a.authorization_id WHERE a.run_id=?"
            parameters: tuple[Any, ...] = (run_id,)
            if authorization_id is not None:
                query += " AND a.authorization_id=?"
                parameters += (authorization_id,)
            values = []
            for row in connection.execute(query + " ORDER BY a.issued_at, a.authorization_id", parameters):
                values.append({"authorization_id": row["authorization_id"], "run_id": row["run_id"], "project_id": row["project_id"], "charter_hash": row["charter_hash"], "profile_hash": row["profile_hash"], "provider_name": row["provider_name"], "model_identity": row["model_identity"], "endpoint_origin_hash": row["endpoint_origin_hash"], "endpoint_path_policy_hash": row["endpoint_path_policy_hash"], "network_policy_hash": row["network_policy_hash"], "credential_ref_hash": row["credential_ref_hash"], "pricing_hash": row["pricing_hash"], "budget_hash": row["budget_hash"], "grant_id": row["grant_id"], "caps": {"max_provider_calls": row["max_provider_calls"], "max_input_tokens": row["max_input_tokens"], "max_output_tokens": row["max_output_tokens"], "max_cache_read_tokens": row["max_cache_read_tokens"], "max_reasoning_tokens": row["max_reasoning_tokens"], "max_cost_units": row["max_cost_units"]}, "issued_at": row["issued_at"], "expires_at": row["expires_at"], "reason_hash": row["reason_hash"], "execution_mode": row["execution_mode"], "authorization_hash": row["authorization_hash"], "state": row["state"], "consumption_id": row["consumption_id"], "current_hash": row["current_hash"]})
            return {"run_id": run_id, "authorizations": values, "count": len(values)}
        finally:
            connection.close()

    def _change_live_authorization_state(self, *, authorization_id: str, actor: Actor, target_state: str, reason: str) -> dict[str, Any]:
        _require_admin(actor)
        _live_identifier(authorization_id, "authorization_id")
        if target_state not in {"revoked", "expired"}:
            raise MaxControlError("live authorization terminal state is invalid")
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 2_000 or "\r" in reason or "\n" in reason or _REASON_SECRET_RE.search(reason):
            raise MaxControlError("live authorization reason is required and bounded")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                row = connection.execute("SELECT a.*, c.state, c.consumption_id FROM max_live_network_authorizations a JOIN max_live_network_authorization_current c ON c.authorization_id=a.authorization_id WHERE a.authorization_id=?", (authorization_id,)).fetchone()
                if row is None:
                    raise MaxControlError("live network authorization was not found")
                if row["state"] == target_state:
                    return {"authorization_id": authorization_id, "state": target_state, "idempotent": True}
                if row["state"] != "active":
                    raise MaxControlError("consumed or terminal live authorization cannot be restored or changed")
                if target_state == "expired" and (_parse_timestamp(row["expires_at"]) is None or _parse_timestamp(row["expires_at"]) > _utc_now(self.repository.clock)):
                    raise MaxControlError("live authorization has not expired")
                now = _timestamp(self.repository.clock)
                current = self._live_current_value(authorization_id=authorization_id, run_id=row["run_id"], project_id=row["project_id"], state=target_state, consumption_id=None)
                connection.execute("UPDATE max_live_network_authorization_current SET state=?, current_json=?, current_hash=?, updated_at=? WHERE authorization_id=?", (target_state, canonical_json(current), canonical_sha256(current), now, authorization_id))
                self._live_access_event(connection, authorization_id=authorization_id, run_id=row["run_id"], project_id=row["project_id"], event_type=target_state, payload={"authz_hash": row["authorization_hash"], "reason_hash": canonical_sha256(reason.strip())}, actor=actor, now=now)
                self.repository._append_event(connection, run_id=row["run_id"], event_type=f"live_network_authorization_{target_state}", payload={"authorization_id": authorization_id, "authz_hash": row["authorization_hash"], "reason_hash": canonical_sha256(reason.strip())}, actor=actor, now=now)
                permits = list(connection.execute("SELECT p.*, c.state, c.current_json, c.current_hash FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id WHERE p.authorization_id=? AND c.state='ready'", (authorization_id,)))
                for permit in permits:
                    self._set_live_permit_current(connection, permit=permit, state=target_state, actor=actor, now=now, details={"authz_id": authorization_id})
            return {"authorization_id": authorization_id, "run_id": row["run_id"], "state": target_state, "reason_hash": canonical_sha256(reason.strip()), "idempotent": False}
        finally:
            connection.close()

    def revoke_live_network_authorization(self, *, authorization_id: str, actor: Actor, reason: str) -> dict[str, Any]:
        return self._change_live_authorization_state(authorization_id=authorization_id, actor=actor, target_state="revoked", reason=reason)

    def expire_live_network_authorization(self, *, authorization_id: str, actor: Actor, reason: str = "expired by admin") -> dict[str, Any]:
        return self._change_live_authorization_state(authorization_id=authorization_id, actor=actor, target_state="expired", reason=reason)

    def provider_live_preflight(self, *, run_id: str, authorization_id: str | None = None, grant_id: str | None = None) -> dict[str, Any]:
        """Read-only static gate report.  It never resolves, consumes, or probes."""

        connection = self._connect(read_only=True)
        try:
            reasons: list[str] = []
            run = connection.execute("SELECT project_id, charter_hash, model_identity, status FROM max_runs WHERE run_id=?", (run_id,)).fetchone()
            binding = connection.execute("SELECT * FROM max_run_provider_bindings WHERE run_id=?", (run_id,)).fetchone()
            auth = None
            if authorization_id:
                auth = connection.execute("SELECT a.*, c.state, c.consumption_id FROM max_live_network_authorizations a JOIN max_live_network_authorization_current c ON c.authorization_id=a.authorization_id WHERE a.authorization_id=? AND a.run_id=?", (authorization_id, run_id)).fetchone()
                if auth is None:
                    reasons.append("authorization_not_found")
            elif grant_id:
                auth = connection.execute("SELECT a.*, c.state, c.consumption_id FROM max_live_network_authorizations a JOIN max_live_network_authorization_current c ON c.authorization_id=a.authorization_id WHERE a.grant_id=? AND a.run_id=? ORDER BY a.issued_at DESC LIMIT 1", (grant_id, run_id)).fetchone()
                if auth is None:
                    reasons.append("authorization_not_found")
            else:
                reasons.append("authorization_id_required")
            if run is None:
                reasons.append("run_not_found")
            elif run["status"] != "RUNNING":
                reasons.append("run_not_running")
            if binding is None:
                reasons.append("provider_binding_missing")
            if auth is not None:
                if run is not None and (auth["project_id"] != run["project_id"] or auth["charter_hash"] != run["charter_hash"] or auth["model_identity"] != run["model_identity"]):
                    reasons.append("run_binding_mismatch")
                if binding is not None and (auth["profile_hash"] != binding["profile_hash"] or auth["pricing_hash"] != binding["pricing_hash"] or auth["budget_hash"] != binding["budget_hash"]):
                    reasons.append("profile_or_budget_binding_mismatch")
                if _parse_timestamp(auth["expires_at"]) is None or _parse_timestamp(auth["expires_at"]) <= _utc_now(self.repository.clock):
                    reasons.append("authorization_expired")
                if auth["state"] != "active":
                    reasons.append("authorization_not_active")
                grant = connection.execute("SELECT * FROM max_live_execution_grants WHERE grant_id=?", (auth["grant_id"],)).fetchone()
                if grant is None:
                    reasons.append("grant_not_found")
                else:
                    grant_consumption = connection.execute("SELECT consumption_id FROM max_live_execution_grant_consumptions WHERE grant_id=?", (grant["grant_id"],)).fetchone()
                    if grant_consumption is None:
                        reasons.append("grant_not_consumed")
            return {"run_id": run_id, "authorization_id": None if auth is None else auth["authorization_id"], "ok": not reasons, "block_reasons": reasons, "network": {"calls": 0, "dns_lookups": 0, "credential_reads": 0}, "authorization": None if auth is None else {"authorization_id": auth["authorization_id"], "authorization_hash": auth["authorization_hash"], "charter_hash": auth["charter_hash"], "profile_hash": auth["profile_hash"], "provider_name": auth["provider_name"], "model_identity": auth["model_identity"], "endpoint_origin_hash": auth["endpoint_origin_hash"], "endpoint_path_policy_hash": auth["endpoint_path_policy_hash"], "network_policy_hash": auth["network_policy_hash"], "credential_ref_hash": auth["credential_ref_hash"], "pricing_hash": auth["pricing_hash"], "budget_hash": auth["budget_hash"], "grant_id": auth["grant_id"], "caps": {"max_provider_calls": auth["max_provider_calls"], "max_input_tokens": auth["max_input_tokens"], "max_output_tokens": auth["max_output_tokens"], "max_cache_read_tokens": auth["max_cache_read_tokens"], "max_reasoning_tokens": auth["max_reasoning_tokens"], "max_cost_units": auth["max_cost_units"]}, "issued_at": auth["issued_at"], "expires_at": auth["expires_at"], "reason_hash": auth["reason_hash"], "execution_mode": auth["execution_mode"], "state": auth["state"], "consumption_id": auth["consumption_id"]}}
        finally:
            connection.close()

    def network_policy_status(self, *, network_policy_hash_value: str) -> dict[str, Any]:
        connection = self._connect(read_only=True)
        try:
            record = _network_policy_from_connection(connection, network_policy_hash_value)
            return {
                "network_policy_hash": record["network_policy_hash"],
                "policy": record["policy"],
                "created_at": record["created_at"],
            }
        finally:
            connection.close()

    live_network_policy_show = network_policy_status

    def record_live_network_attempt(self, *, authorization_id: str, run_id: str, project_id: str, outcome: str, actor: Actor, provider_attempt_id: str | None = None, claim_id: str | None = None, fencing_token: int | None = None, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if outcome not in {"not_dispatched", "settled", "unknown", "disputed"}:
            raise MaxControlError("live network attempt outcome is invalid")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                auth = connection.execute("SELECT authorization_hash FROM max_live_network_authorizations WHERE authorization_id=? AND run_id=? AND project_id=?", (authorization_id, run_id, project_id)).fetchone()
                consumption = connection.execute("SELECT consumption_id FROM max_live_network_authorization_consumptions WHERE authorization_id=?", (authorization_id,)).fetchone()
                if auth is None or consumption is None:
                    raise MaxControlError("live network attempt requires a consumed authorization")
                if claim_id is not None or provider_attempt_id is not None:
                    if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
                        raise MaxControlError("live network attempt fencing token is invalid")
                    attempt_query = "SELECT a.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.run_id=?"
                    attempt_parameters: tuple[Any, ...] = (run_id,)
                    if provider_attempt_id is not None:
                        attempt_query += " AND a.attempt_id=?"
                        attempt_parameters += (provider_attempt_id,)
                    elif claim_id is not None:
                        attempt_query += " AND a.claim_id=? ORDER BY a.physical_attempt_no DESC LIMIT 1"
                        attempt_parameters += (claim_id,)
                    attempt = connection.execute(attempt_query, attempt_parameters).fetchone()
                    if attempt is None or (claim_id is not None and attempt["claim_id"] != claim_id):
                        raise MaxControlError("live network attempt binding is missing")
                    self._check_attempt_lease(connection, attempt=attempt, actor=actor, fencing_token=fencing_token, now=_utc_now(self.repository.clock))
                if provider_attempt_id is not None:
                    _bounded_identifier(provider_attempt_id, "provider_attempt_id")
                if claim_id is not None:
                    _bounded_identifier(claim_id, "claim_id")
                safe_details = _safe_mapping(details or {}, name="live attempt details", max_bytes=25_000)
                if any(key.casefold() in {"body", "request", "response", "prompt", "source", "token", "secret", "authorization", "header"} for key in safe_details):
                    raise MaxControlError("live attempt details contain forbidden material")
                now = _timestamp(self.repository.clock)
                value = {"authorization_id": authorization_id, "run_id": run_id, "project_id": project_id, "outcome": outcome, "provider_attempt_id": provider_attempt_id, "claim_id": claim_id, "details": safe_details}
                outcome_hash = canonical_sha256(value)
                attempt_id = make_stable_id("live_network_attempt", outcome_hash[:64])
                existing = connection.execute("SELECT outcome_hash, outcome_json FROM max_live_network_attempt_records WHERE live_attempt_id=?", (attempt_id,)).fetchone()
                if existing is not None:
                    if existing["outcome_hash"] != outcome_hash:
                        raise MaxControlError("live attempt replay differs")
                    return {"live_attempt_id": attempt_id, **json.loads(existing["outcome_json"]), "outcome_hash": outcome_hash, "idempotent": True}
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                connection.execute("INSERT INTO max_live_network_attempt_records(live_attempt_id, authorization_id, run_id, project_id, provider_attempt_id, claim_id, outcome, outcome_json, outcome_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (attempt_id, authorization_id, run_id, project_id, provider_attempt_id, claim_id, outcome, canonical_json(value), outcome_hash, now, actor_id, actor_kind, actor_session))
                self._live_access_event(connection, authorization_id=authorization_id, run_id=run_id, project_id=project_id, event_type=f"attempt_{outcome}", payload={"live_attempt_id": attempt_id, "outcome": outcome, "outcome_hash": outcome_hash, "provider_attempt_id": provider_attempt_id, "claim_id": claim_id}, actor=actor, now=now)
            return {"live_attempt_id": attempt_id, **value, "outcome_hash": outcome_hash, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live network attempt conflicts with an immutable record") from exc
        finally:
            connection.close()

    def record_live_network_access_event(
        self,
        *,
        authorization_id: str,
        run_id: str,
        project_id: str,
        event_type: str,
        actor: Actor,
        provider_attempt_id: str | None = None,
        claim_id: str | None = None,
        fencing_token: int | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one bounded pre-send/network boundary audit event.

        This is intentionally separate from ``record_live_network_attempt``:
        DNS and credential phases are durable audit facts, not provider-call
        outcomes.  The method requires the consumed authorization and current
        attempt lease, rejects request/source/credential material, and stores
        only the caller-supplied bounded metadata and its hash.
        """

        if not isinstance(event_type, str) or not event_type or len(event_type) > 128 or "\r" in event_type or "\n" in event_type:
            raise MaxControlError("live network access event type is invalid")
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                auth = connection.execute(
                    "SELECT a.authorization_hash, c.state, c.consumption_id FROM max_live_network_authorizations a JOIN max_live_network_authorization_current c ON c.authorization_id=a.authorization_id WHERE a.authorization_id=? AND a.run_id=? AND a.project_id=?",
                    (authorization_id, run_id, project_id),
                ).fetchone()
                if auth is None or auth["state"] != "consumed" or not auth["consumption_id"]:
                    raise MaxControlError("live network access event requires a consumed authorization")
                if provider_attempt_id is not None or claim_id is not None:
                    if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 1:
                        raise MaxControlError("live network access event fencing token is invalid")
                    attempt_query = "SELECT a.*, u.state, u.provider_call_id, u.call_record_id, u.attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.run_id=?"
                    parameters: tuple[Any, ...] = (run_id,)
                    if provider_attempt_id is not None:
                        attempt_query += " AND a.attempt_id=?"
                        parameters += (provider_attempt_id,)
                    elif claim_id is not None:
                        attempt_query += " AND a.claim_id=? ORDER BY a.physical_attempt_no DESC LIMIT 1"
                        parameters += (claim_id,)
                    attempt = connection.execute(attempt_query, parameters).fetchone()
                    if attempt is None or (claim_id is not None and attempt["claim_id"] != claim_id) or attempt["project_id"] != project_id:
                        raise MaxControlError("live network access event attempt binding is missing")
                    self._check_attempt_lease(connection, attempt=attempt, actor=actor, fencing_token=fencing_token, now=_utc_now(self.repository.clock))
                safe_details = _safe_mapping(details or {}, name="live access event details", max_bytes=25_000)
                forbidden = {"body", "request", "response", "prompt", "source", "token", "secret", "authorization", "header", "stack_trace", "exception_text"}
                if any(str(key).casefold() in forbidden for key in safe_details):
                    raise MaxControlError("live access event details contain forbidden material")
                now = _timestamp(self.repository.clock)
                payload = {"event_type": event_type, "provider_attempt_id": provider_attempt_id, "claim_id": claim_id, **safe_details}
                event = self._live_access_event(
                    connection,
                    authorization_id=authorization_id,
                    run_id=run_id,
                    project_id=project_id,
                    event_type=event_type,
                    payload=payload,
                    actor=actor,
                    now=now,
                )
            return {**event, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("live network access event conflicts with immutable history") from exc
        finally:
            connection.close()

    def verify_live_network(self, *, run_id: str | None = None) -> dict[str, Any]:
        try:
            connection = self.repository._connect(read_only=True, verify_schema=False)
        except MaxControlError:
            return {
                "ok": False,
                "schema_version": CONTROL_SCHEMA_VERSION,
                "run_id": run_id,
                "counts": {"policies": 0, "policy_bindings": 0, "authorizations": 0, "consumptions": 0, "events": 0, "attempts": 0, "permits": 0, "permit_events": 0},
                "issues": ["Max control database schema manifest verification failed"],
            }
        schema_check = verify_schema_manifest(connection)
        issues: list[str] = []
        counts = {"policies": 0, "policy_bindings": 0, "authorizations": 0, "consumptions": 0, "events": 0, "attempts": 0, "permits": 0, "permit_events": 0}
        try:
            if not schema_check["ok"]:
                issues.extend(str(item) for item in schema_check.get("issues", ()))
            for row in connection.execute("SELECT * FROM max_live_network_policies"):
                counts["policies"] += 1
                try:
                    policy = json.loads(row["policy_json"])
                    normalized = normalize_network_policy(policy)
                    if canonical_json(policy) != canonical_json(normalized) or network_policy_hash(normalized) != row["network_policy_hash"] or row["policy_hash"] != row["network_policy_hash"]:
                        issues.append("live network policy hash mismatch")
                except Exception:
                    issues.append("live network policy is invalid")
            if _table_exists(connection, "max_live_network_policy_bindings"):
                for row in connection.execute("SELECT * FROM max_live_network_policy_bindings ORDER BY created_at, binding_id"):
                    if run_id is not None and row["run_id"] != run_id:
                        continue
                    counts["policy_bindings"] += 1
                    try:
                        value = json.loads(row["binding_json"])
                        core = {key: value[key] for key in _NETWORK_POLICY_BINDING_CORE_KEYS}
                        if canonical_sha256(core) != row["binding_hash"] or row["binding_id"] != "live_network_policy_binding_" + row["binding_hash"][:48]:
                            issues.append("live network policy binding hash mismatch")
                        self.validate_network_policy_binding(
                            connection,
                            run_id=str(row["run_id"]),
                            expected_release_identity_hash=str(row["release_identity_hash"]),
                        )
                    except Exception:
                        issues.append("live network policy binding is invalid")
                # A native preparation graph is a policy consumer even before
                # it creates a Live Approval.  The old verifier only checked
                # policy rows and any binding rows that happened to exist, so
                # a preparation with a missing policy/binding could still
                # report green and fail much later at JIT lookup.  Require
                # every prepared Run to have one resolvable, canonical,
                # release-bound policy binding.  Legacy non-native runs do
                # not enter this check because they have no preparation
                # snapshot and therefore do not claim a live policy boundary.
                prepared_query = (
                    "SELECT DISTINCT run_id FROM max_live_canary_preparation_snapshots"
                    + (" WHERE run_id=?" if run_id is not None else "")
                )
                prepared_parameters = (run_id,) if run_id is not None else ()
                for prepared in connection.execute(prepared_query, prepared_parameters):
                    try:
                        self.validate_network_policy_binding(
                            connection,
                            run_id=str(prepared["run_id"]),
                        )
                    except Exception:
                        issues.append("prepared Run lacks a valid live network policy binding")
            for row in connection.execute("SELECT * FROM max_live_network_authorizations ORDER BY issued_at, authorization_id"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                counts["authorizations"] += 1
                try:
                    auth = LiveNetworkAuthorization.from_mapping(json.loads(row["authorization_json"]))
                    if auth.authorization_hash != row["authorization_hash"] or auth.authorization_id != row["authorization_id"] or auth.run_id != row["run_id"] or auth.project_id != row["project_id"]:
                        issues.append("live authorization hash or binding mismatch")
                    current = connection.execute("SELECT * FROM max_live_network_authorization_current WHERE authorization_id=?", (row["authorization_id"],)).fetchone()
                    if current is None:
                        issues.append("live authorization current projection is missing")
                    else:
                        current_value = json.loads(current["current_json"])
                        if canonical_sha256(current_value) != current["current_hash"] or current_value.get("state") != current["state"] or current_value.get("consumption_id") != current["consumption_id"]:
                            issues.append("live authorization current projection mismatch")
                except Exception:
                    issues.append("live authorization is invalid")
            for row in connection.execute("SELECT * FROM max_live_network_authorization_consumptions ORDER BY consumed_at, consumption_id"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                counts["consumptions"] += 1
                try:
                    value = json.loads(row["consumption_json"])
                    if canonical_sha256(value) != row["consumption_hash"] or value.get("authorization_id") != row["authorization_id"] or value.get("provider_name") != row["provider_name"] or value.get("fencing_token", 0) < 1:
                        issues.append("live authorization consumption mismatch")
                except Exception:
                    issues.append("live authorization consumption is invalid")
            auth_ids = [row["authorization_id"] for row in connection.execute("SELECT authorization_id FROM max_live_network_authorizations" + (" WHERE run_id=?" if run_id is not None else ""), ((run_id,) if run_id is not None else ())) ]
            for authorization_id in auth_ids:
                events = list(connection.execute("SELECT * FROM max_live_network_access_events WHERE authorization_id=? ORDER BY sequence_no", (authorization_id,)))
                counts["events"] += len(events)
                previous = None
                for expected, event in enumerate(events, 1):
                    try:
                        payload = json.loads(event["payload_json"])
                        event_value = {"authorization_id": event["authorization_id"], "run_id": event["run_id"], "project_id": event["project_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if int(event["sequence_no"]) != expected or canonical_sha256(payload) != event["payload_hash"] or event["previous_event_hash"] != previous or canonical_sha256(event_value) != event["event_hash"]:
                            issues.append("live network access event chain mismatch")
                        previous = event["event_hash"]
                    except Exception:
                        issues.append("live network access event is invalid")
            for row in connection.execute("SELECT * FROM max_live_network_attempt_records" + (" WHERE run_id=?" if run_id is not None else ""), ((run_id,) if run_id is not None else ())) :
                counts["attempts"] += 1
                try:
                    value = json.loads(row["outcome_json"])
                    if canonical_sha256(value) != row["outcome_hash"] or value.get("outcome") != row["outcome"]:
                        issues.append("live network attempt outcome mismatch")
                except Exception:
                    issues.append("live network attempt outcome is invalid")
            permit_rows = connection.execute("SELECT p.*, c.state, c.current_json, c.current_hash FROM max_live_dispatch_permits p JOIN max_live_dispatch_permit_current c ON c.permit_id=p.permit_id" + (" WHERE p.run_id=?" if run_id is not None else "") + " ORDER BY p.created_at, p.permit_id", ((run_id,) if run_id is not None else ()))
            for row in permit_rows:
                counts["permits"] += 1
                try:
                    current = self._permit_from_row(row, row)
                    if current.permit_id != row["permit_id"] or current.authorization_id != row["authorization_id"] or current.consumption_id != row["consumption_id"] or current.attempt_id != row["attempt_id"] or current.credential_ref_hash != row["credential_ref_hash"]:
                        issues.append("live dispatch permit binding mismatch")
                    auth = connection.execute("SELECT state, consumption_id FROM max_live_network_authorization_current WHERE authorization_id=?", (row["authorization_id"],)).fetchone()
                    if auth is None or (row["state"] not in {"revoked", "expired"} and (auth["state"] != "consumed" or auth["consumption_id"] != row["consumption_id"])):
                        issues.append("live dispatch permit authorization binding mismatch")
                except Exception:
                    issues.append("live dispatch permit is invalid")
                events = list(connection.execute("SELECT * FROM max_live_dispatch_permit_events WHERE permit_id=? ORDER BY sequence_no", (row["permit_id"],)))
                counts["permit_events"] += len(events)
                previous = None
                for expected, event in enumerate(events, 1):
                    try:
                        payload = json.loads(event["payload_json"])
                        event_value = {"permit_id": event["permit_id"], "run_id": event["run_id"], "project_id": event["project_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if int(event["sequence_no"]) != expected or canonical_sha256(payload) != event["payload_hash"] or event["previous_event_hash"] != previous or canonical_sha256(event_value) != event["event_hash"]:
                            issues.append("live dispatch permit event chain mismatch")
                        previous = event["event_hash"]
                    except Exception:
                        issues.append("live dispatch permit event is invalid")
                if events and row["state"] != events[-1]["event_type"]:
                    issues.append("live dispatch permit current state is not the event-chain tip")
            return {"ok": not issues, "schema_version": CONTROL_SCHEMA_VERSION, "run_id": run_id, "counts": counts, "issues": sorted(set(issues))}
        finally:
            connection.close()

    def record_provider_call(self, *, record: ProviderCallRecord, actor: Actor, proposal: Mapping[str, Any] | None = None, attempt_id: str | None = None) -> dict[str, Any]:
        _safe_mapping(record.response_manifest, name="provider response manifest")
        if proposal is not None:
            _safe_mapping(proposal, name="provider typed result")
        for value, name in ((record.call_record_id, "call_record_id"), (record.provider_call_id, "provider_call_id"), (record.run_id, "run_id"), (record.project_id, "project_id"), (record.profile_hash, "profile_hash"), (record.model_identity, "model_identity"), (record.intent_hash, "intent_hash"), (record.request_hash, "request_hash"), (record.idempotency_key, "idempotency_key"), (record.pricing_hash, "pricing_hash"), (record.logical_call_id, "logical_call_id"), (record.intent_id, "intent_id"), (record.iteration_id, "iteration_id")):
            _bounded_identifier(value, name)
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                profile_row = connection.execute("SELECT * FROM max_provider_profiles WHERE profile_hash=?", (record.profile_hash,)).fetchone()
                if profile_row is None:
                    raise MaxControlError("provider call references an unknown profile")
                profile = _profile_from_row(profile_row)
                run = connection.execute("SELECT project_id, model_identity, status FROM max_runs WHERE run_id=?", (record.run_id,)).fetchone()
                if run is None or run["project_id"] != record.project_id or run["model_identity"] != record.model_identity:
                    raise MaxControlError("provider call is outside the run/project/model binding")
                binding = connection.execute("SELECT profile_hash, pricing_hash FROM max_run_provider_bindings WHERE run_id=?", (record.run_id,)).fetchone()
                if binding is None or binding["profile_hash"] != record.profile_hash or binding["pricing_hash"] != record.pricing_hash or profile.pricing.pricing_hash != record.pricing_hash:
                    raise MaxControlError("provider call is outside the persisted provider binding")
                existing = connection.execute("SELECT * FROM max_provider_call_records WHERE run_id=? AND idempotency_key=?", (record.run_id, record.idempotency_key)).fetchone()
                if existing is not None:
                    if existing["record_hash"] != record.record_hash:
                        raise MaxControlError("provider idempotency key was reused with different content")
                    return {"call_record_id": existing["call_record_id"], "record_hash": existing["record_hash"], "idempotent": True}
                if not record.logical_call_id or not record.intent_id or not record.iteration_id:
                    raise MaxControlError("provider call requires a durable logical call, intent, and iteration")
                intent = connection.execute("SELECT * FROM max_model_call_intents WHERE run_id=? AND logical_call_id=? AND intent_id=?", (record.run_id, record.logical_call_id, record.intent_id)).fetchone()
                if intent is None or intent["project_id"] != record.project_id or intent["iteration_id"] != record.iteration_id or intent["model_identity"] != record.model_identity or intent["intent_hash"] != record.intent_hash or intent["request_hash"] != record.request_hash or intent["idempotency_key"] != record.idempotency_key:
                    raise MaxControlError("provider call is not bound to a durable model intent")
                manifest = connection.execute("SELECT * FROM max_runner_intent_manifests WHERE intent_id=? AND logical_call_id=? AND run_id=? AND iteration_id=?", (record.intent_id, record.logical_call_id, record.run_id, record.iteration_id)).fetchone()
                if manifest is None:
                    raise MaxControlError("provider call intent manifest is missing")
                try:
                    manifest_value = json.loads(manifest["manifest_json"])
                except Exception as exc:
                    raise MaxControlError("provider call intent manifest is invalid") from exc
                if canonical_sha256(manifest_value) != manifest["manifest_hash"] or manifest_value.get("intent_hash") != record.intent_hash or manifest_value.get("request_hash") != record.request_hash:
                    raise MaxControlError("provider call intent manifest hash binding is invalid")
                iteration = connection.execute("SELECT run_id, project_id FROM max_iterations WHERE iteration_id=?", (record.iteration_id,)).fetchone()
                if iteration is None or iteration["run_id"] != record.run_id or iteration["project_id"] != record.project_id:
                    raise MaxControlError("provider call iteration is missing or crosses the project boundary")
                group_binding = connection.execute("SELECT b.*, g.project_id AS group_project_id, g.iteration_id AS group_iteration_id FROM max_runner_call_bindings b JOIN max_runner_call_groups g ON g.group_id=b.group_id WHERE b.run_id=? AND b.logical_call_id=?", (record.run_id, record.logical_call_id)).fetchone()
                if group_binding is None or group_binding["iteration_id"] != record.iteration_id or group_binding["group_project_id"] != record.project_id or group_binding["group_iteration_id"] != record.iteration_id or group_binding["intent_hash"] != record.intent_hash:
                    raise MaxControlError("provider call group binding is missing or inconsistent")
                claim = connection.execute("SELECT c.*, u.state, u.provider_call_id AS current_provider_call_id, u.call_record_id AS current_call_record_id, u.attestation_id AS current_attestation_id FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.run_id=? AND c.idempotency_key=?", (record.run_id, record.idempotency_key)).fetchone()
                if claim is None or claim["grant_id"] is None or claim["logical_call_id"] != record.logical_call_id or claim["intent_id"] != record.intent_id or claim["iteration_id"] != record.iteration_id or claim["intent_hash"] != record.intent_hash or claim["request_hash"] != record.request_hash or claim["profile_hash"] != record.profile_hash or claim["model_identity"] != record.model_identity or claim["pricing_hash"] != record.pricing_hash:
                    raise MaxControlError("provider call has no valid durable grant-call claim")
                attempt = connection.execute("SELECT a.*, u.state AS attempt_state, u.provider_call_id AS attempt_provider_call_id, u.call_record_id AS attempt_call_record_id, u.attestation_id AS attempt_attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.claim_id=? ORDER BY a.physical_attempt_no DESC LIMIT 1", (claim["claim_id"],)).fetchone()
                if attempt is None or (attempt_id is not None and attempt["attempt_id"] != attempt_id):
                    raise MaxControlError("provider call physical attempt binding is missing")
                if claim["state"] not in {"claimed", "dispatching", "unknown"} or attempt["attempt_state"] not in {"reserved", "dispatching", "unknown"}:
                    raise MaxControlError("provider call claim is not in a dispatchable state")
                if actor.actor_id != attempt["owner_id"] or actor.session_id != attempt["owner_session"]:
                    raise MaxControlError("provider call actor does not own the durable claim")
                lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (record.run_id,)).fetchone()
                if lease is None or lease["owner_id"] != attempt["owner_id"] or lease["session_id"] != attempt["owner_session"] or int(lease["fencing_token"]) != int(attempt["fencing_token"]) or lease["released_at"] is not None or _parse_timestamp(lease["expires_at"]) is None or _parse_timestamp(lease["expires_at"]) <= _utc_now(self.repository.clock):
                    raise MaxControlError("provider call claim uses a stale worker fence")
                acknowledgement = connection.execute("SELECT dispatch_status, dispatch_known, provider_call_id FROM max_model_dispatch_acks WHERE logical_call_id=? AND run_id=?", (record.logical_call_id, record.run_id)).fetchone()
                if acknowledgement is not None and acknowledgement["provider_call_id"] not in {None, record.provider_call_id}:
                    raise MaxControlError("provider call ID conflicts with the durable dispatch acknowledgement")
                if record.terminal_status == "succeeded" and not record.usage:
                    raise MaxControlError("successful provider call has no usage fact")
                now = _timestamp(self.repository.clock)
                actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                usage_json = canonical_json(record.usage)
                manifest_json = canonical_json(record.response_manifest)
                connection.execute("INSERT INTO max_provider_call_records(call_record_id, provider_call_id, logical_call_id, intent_id, run_id, project_id, iteration_id, profile_hash, model_identity, intent_hash, request_hash, idempotency_key, transport_status, terminal_status, usage_json, usage_hash, response_manifest_json, response_manifest_hash, pricing_hash, record_json, record_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (record.call_record_id, record.provider_call_id, record.logical_call_id or None, record.intent_id or None, record.run_id, record.project_id, record.iteration_id or None, record.profile_hash, record.model_identity, record.intent_hash, record.request_hash, record.idempotency_key, record.transport_status, record.terminal_status, usage_json, canonical_sha256(record.usage), manifest_json, canonical_sha256(record.response_manifest), record.pricing_hash, canonical_json(record.to_mapping()), record.record_hash, now, actor_id, actor_kind, actor_session))
                binding_value = {"call_record_id": record.call_record_id, "attempt_id": attempt["attempt_id"], "run_id": record.run_id, "project_id": record.project_id}
                binding_hash = canonical_sha256(binding_value)
                connection.execute("INSERT INTO max_provider_call_attempt_bindings(call_record_id, attempt_id, run_id, project_id, binding_json, binding_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (record.call_record_id, attempt["attempt_id"], record.run_id, record.project_id, canonical_json(binding_value), binding_hash, now))
                if record.terminal_status == "succeeded":
                    if proposal is None:
                        raise MaxControlError("successful provider call has no durable typed result for replay")
                    result_value = {"call_record_id": record.call_record_id, "attempt_id": attempt["attempt_id"], "run_id": record.run_id, "project_id": record.project_id, "proposal": dict(proposal), "proposal_hash": canonical_sha256(proposal)}
                    result_hash = canonical_sha256(result_value)
                    connection.execute("INSERT INTO max_provider_call_results(call_record_id, attempt_id, run_id, project_id, proposal_json, proposal_hash, result_json, result_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (record.call_record_id, attempt["attempt_id"], record.run_id, record.project_id, canonical_json(proposal), canonical_sha256(proposal), canonical_json(result_value), result_hash, now, actor_id, actor_kind, actor_session))
                if record.terminal_status == "succeeded":
                    self._set_attempt_current(connection, attempt=attempt, state="succeeded", actor=actor, now=now, provider_call_id=record.provider_call_id, call_record_id=record.call_record_id)
                    self._set_claim_current(connection, claim=claim, state="dispatched", actor=actor, now=now, provider_call_id=record.provider_call_id, call_record_id=record.call_record_id)
                else:
                    release_delta = {
                        "reserved_input_tokens": -int(attempt["reserved_input_tokens"]),
                        "reserved_output_tokens": -int(attempt["reserved_output_tokens"]),
                        "reserved_cache_read_tokens": -int(attempt["reserved_cache_read_tokens"]),
                        "reserved_reasoning_tokens": -int(attempt["reserved_reasoning_tokens"]),
                        "reserved_cost_units": -int(attempt["reserved_cost_units"]),
                        "released_cost_units": int(attempt["reserved_cost_units"]),
                    }
                    self._update_grant_usage_current(connection, grant_id=str(claim["grant_id"]), delta=release_delta, now=now)
                    self._set_attempt_current(connection, attempt=attempt, state="failed", actor=actor, now=now, provider_call_id=record.provider_call_id, call_record_id=record.call_record_id)
                    self._set_claim_current(connection, claim=claim, state="failed", actor=actor, now=now, provider_call_id=record.provider_call_id, call_record_id=record.call_record_id)
                self.repository._append_event(connection, run_id=record.run_id, event_type="provider_call_recorded", payload={"call_record_id": record.call_record_id, "provider_call_id": record.provider_call_id, "logical_call_id": record.logical_call_id, "intent_hash": record.intent_hash, "request_hash": record.request_hash, "profile_hash": record.profile_hash, "terminal_status": record.terminal_status, "usage_hash": canonical_sha256(record.usage), "record_hash": record.record_hash}, actor=actor, now=now)
            return {"call_record_id": record.call_record_id, "record_hash": record.record_hash, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("provider call conflicts with an immutable record") from exc
        finally:
            connection.close()

    append_provider_call = record_provider_call

    def record_provider_attestation(self, *, attestation: ProviderUsageAttestation, actor: Actor) -> dict[str, Any]:
        dispute_message: str | None = None
        connection = self._connect(read_only=False)
        try:
            with control_transaction(connection):
                call = connection.execute("SELECT * FROM max_provider_call_records WHERE call_record_id=?", (attestation.call_record_id,)).fetchone()
                if call is None or call["provider_call_id"] != attestation.provider_call_id or call["run_id"] != attestation.run_id or call["profile_hash"] != attestation.profile_hash or call["pricing_hash"] != attestation.pricing_hash or call["terminal_status"] != "succeeded":
                    raise MaxControlError("usage attestation is not bound to the provider call")
                profile_row = connection.execute("SELECT * FROM max_provider_profiles WHERE profile_hash=?", (attestation.profile_hash,)).fetchone()
                if profile_row is None:
                    raise MaxControlError("usage attestation references an unknown profile")
                profile = _profile_from_row(profile_row)
                if attestation.authority_id != PROVIDER_USAGE_AUTHORITY_ID or canonical_sha256(attestation.usage) != call["usage_hash"] or json.loads(call["usage_json"]) != dict(attestation.usage) or profile.pricing.cost_units_for_usage(attestation.usage) != attestation.cost_units:
                    raise MaxControlError("provider cost is not the server-recomputed pricing result")
                claim = connection.execute("SELECT c.*, u.state FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.run_id=? AND c.idempotency_key=? AND c.logical_call_id=?", (call["run_id"], call["idempotency_key"], call["logical_call_id"])).fetchone()
                if claim is None or claim["intent_id"] != call["intent_id"] or claim["iteration_id"] != call["iteration_id"] or claim["intent_hash"] != call["intent_hash"] or claim["request_hash"] != call["request_hash"] or claim["profile_hash"] != call["profile_hash"] or claim["pricing_hash"] != call["pricing_hash"] or claim["state"] not in {"dispatched", "attested"}:
                    raise MaxControlError("usage attestation has no valid provider-call authority chain")
                attempt = connection.execute("SELECT a.*, u.state AS attempt_state, u.provider_call_id AS attempt_provider_call_id, u.call_record_id AS attempt_call_record_id, u.attestation_id AS attempt_attestation_id FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id JOIN max_provider_call_attempt_bindings b ON b.attempt_id=a.attempt_id WHERE b.call_record_id=?", (attestation.call_record_id,)).fetchone()
                if attempt is None or attempt["attempt_state"] not in {"succeeded", "settled"}:
                    raise MaxControlError("usage attestation has no physical attempt binding")
                if actor.actor_id != attempt["owner_id"] or actor.session_id != attempt["owner_session"]:
                    raise MaxControlError("usage attestation actor does not own the durable claim")
                lease = connection.execute("SELECT owner_id, session_id, fencing_token, expires_at, released_at FROM max_leases WHERE run_id=?", (call["run_id"],)).fetchone()
                if lease is None or lease["owner_id"] != attempt["owner_id"] or lease["session_id"] != attempt["owner_session"] or int(lease["fencing_token"]) != int(attempt["fencing_token"]) or lease["released_at"] is not None or _parse_timestamp(lease["expires_at"]) is None or _parse_timestamp(lease["expires_at"]) <= _utc_now(self.repository.clock):
                    raise MaxControlError("usage attestation uses a stale worker fence")
                maximum_usage = _authority_usage(profile)
                caps = json.loads(connection.execute("SELECT caps_json FROM max_live_execution_grants WHERE grant_id=?", (claim["grant_id"],)).fetchone()[0])
                if not _usage_within_caps(attestation.usage, caps) or not _usage_within_caps(attestation.usage, maximum_usage) or attestation.cost_units > int(attempt["reserved_cost_units"]):
                    now = _timestamp(self.repository.clock)
                    self._set_attempt_current(connection, attempt=attempt, state="disputed", actor=actor, now=now, provider_call_id=attestation.provider_call_id, call_record_id=attestation.call_record_id, actual={**dict(attestation.usage), "cost_units": int(attestation.cost_units)})
                    self._set_claim_current(connection, claim=claim, state="disputed", actor=actor, now=now, provider_call_id=attestation.provider_call_id, call_record_id=attestation.call_record_id, actual={**dict(attestation.usage), "cost_units": int(attestation.cost_units)})
                    self.repository._append_event(connection, run_id=attestation.run_id, event_type="provider_usage_disputed", payload={"call_record_id": attestation.call_record_id, "provider_call_id": attestation.provider_call_id, "usage_hash": canonical_sha256(attestation.usage), "reservation_retained": True}, actor=actor, now=now)
                    dispute_message = "provider usage exceeds the frozen aggregate profile or grant budget; reservation retained and run requires pause"
                existing = connection.execute("SELECT * FROM max_provider_usage_attestations WHERE call_record_id=?", (attestation.call_record_id,)).fetchone()
                if dispute_message is not None:
                    existing = None
                if dispute_message is not None:
                    pass
                elif existing is not None:
                    if existing["attestation_hash"] != attestation.attestation_hash:
                        raise MaxControlError("usage attestation replay differs")
                    return {"attestation_id": existing["attestation_id"], "attestation_hash": existing["attestation_hash"], "cost_units": existing["cost_units"], "idempotent": True}
                elif existing is None:
                    now = _timestamp(self.repository.clock)
                    actor_id, actor_kind, actor_session, _ = _actor_fields(actor)
                    connection.execute("INSERT INTO max_provider_usage_attestations(attestation_id, call_record_id, provider_call_id, run_id, profile_hash, pricing_hash, usage_json, usage_hash, cost_units, authority_id, attestation_json, attestation_hash, created_at, actor_id, actor_kind, actor_session) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (attestation.attestation_id, attestation.call_record_id, attestation.provider_call_id, attestation.run_id, attestation.profile_hash, attestation.pricing_hash, canonical_json(attestation.usage), canonical_sha256(attestation.usage), attestation.cost_units, attestation.authority_id, canonical_json(attestation.to_mapping()), attestation.attestation_hash, now, actor_id, actor_kind, actor_session))
                    usage_delta = {"input_tokens": int(attestation.usage.get("input_tokens", 0)), "output_tokens": int(attestation.usage.get("output_tokens", 0)), "cache_read_tokens": int(attestation.usage.get("cache_read_tokens", 0)), "reasoning_tokens": int(attestation.usage.get("reasoning_tokens", 0)), "cost_units": int(attestation.cost_units)}
                    self._update_grant_usage_current(connection, grant_id=str(claim["grant_id"]), delta={"reserved_input_tokens": -int(attempt["reserved_input_tokens"]), "reserved_output_tokens": -int(attempt["reserved_output_tokens"]), "reserved_cache_read_tokens": -int(attempt["reserved_cache_read_tokens"]), "reserved_reasoning_tokens": -int(attempt["reserved_reasoning_tokens"]), "reserved_cost_units": -int(attempt["reserved_cost_units"]), "settled_input_tokens": usage_delta["input_tokens"], "settled_output_tokens": usage_delta["output_tokens"], "settled_cache_read_tokens": usage_delta["cache_read_tokens"], "settled_reasoning_tokens": usage_delta["reasoning_tokens"], "settled_cost_units": usage_delta["cost_units"], "released_cost_units": max(0, int(attempt["reserved_cost_units"]) - usage_delta["cost_units"])}, now=now)
                    self._set_attempt_current(connection, attempt=attempt, state="settled", actor=actor, now=now, provider_call_id=attestation.provider_call_id, call_record_id=attestation.call_record_id, attestation_id=attestation.attestation_id, actual=usage_delta)
                    self._set_claim_current(connection, claim=claim, state="settled", actor=actor, now=now, provider_call_id=attestation.provider_call_id, call_record_id=attestation.call_record_id, attestation_id=attestation.attestation_id, actual=usage_delta)
                    self.repository._append_event(connection, run_id=attestation.run_id, event_type="provider_usage_attested", payload={"attestation_id": attestation.attestation_id, "call_record_id": attestation.call_record_id, "provider_call_id": attestation.provider_call_id, "profile_hash": attestation.profile_hash, "pricing_hash": attestation.pricing_hash, "usage_hash": canonical_sha256(attestation.usage), "cost_units": attestation.cost_units, "attestation_hash": attestation.attestation_hash}, actor=actor, now=now)
            if dispute_message is not None:
                raise MaxControlError(dispute_message)
            return {"attestation_id": attestation.attestation_id, "attestation_hash": attestation.attestation_hash, "cost_units": attestation.cost_units, "idempotent": False}
        except sqlite3.IntegrityError as exc:
            raise MaxControlError("provider usage attestation conflicts with an immutable record") from exc
        finally:
            connection.close()

    append_provider_attestation = record_provider_attestation

    def provider_call(self, *, run_id: str, idempotency_key: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute("SELECT call_record_id, provider_call_id, logical_call_id, intent_id, iteration_id, run_id, project_id, profile_hash, model_identity, intent_hash, request_hash, idempotency_key, transport_status, terminal_status, usage_json, usage_hash, response_manifest_json, response_manifest_hash, pricing_hash, record_json, record_hash, created_at FROM max_provider_call_records WHERE run_id=? AND idempotency_key=?", (run_id, idempotency_key)).fetchone()
            if row is None:
                return None
            # Only a succeeded record can be used as durable replay input.  Older
            # MR-2B0 recovery rows may intentionally describe an unfinished or
            # unknown observation whose record hash predates the strict replay
            # projection.  Preserve that metadata for recovery/status callers,
            # while keeping the settled replay path fail-closed and canonical.
            if row["terminal_status"] == "succeeded":
                try:
                    record_value = json.loads(row["record_json"])
                    if not isinstance(record_value, Mapping):
                        raise ValueError("provider call record is not an object")
                    allowed_record_fields = set(ProviderCallRecord.__dataclass_fields__)  # type: ignore[attr-defined]
                    if set(record_value) != allowed_record_fields:
                        raise ValueError("provider call record fields are not canonical")
                    record = ProviderCallRecord(**{key: record_value[key] for key in allowed_record_fields})
                    column_bindings = {
                        "call_record_id": row["call_record_id"], "provider_call_id": row["provider_call_id"],
                        "run_id": row["run_id"], "project_id": row["project_id"], "profile_hash": row["profile_hash"],
                        "model_identity": row["model_identity"], "intent_hash": row["intent_hash"],
                        "request_hash": row["request_hash"], "idempotency_key": row["idempotency_key"],
                        "transport_status": row["transport_status"], "terminal_status": row["terminal_status"],
                        "pricing_hash": row["pricing_hash"], "logical_call_id": row["logical_call_id"],
                        "intent_id": row["intent_id"], "iteration_id": row["iteration_id"],
                    }
                    if any(getattr(record, key) != expected for key, expected in column_bindings.items()):
                        raise ValueError("provider call record columns are not bound")
                    if canonical_sha256(record.usage) != row["usage_hash"] or canonical_sha256(record.response_manifest) != row["response_manifest_hash"]:
                        raise ValueError("provider call record projections are not bound")
                except Exception as exc:
                    raise MaxControlError("stored provider replay call record hash is invalid") from exc
                value = record.to_mapping()
            else:
                try:
                    usage = json.loads(row["usage_json"])
                    response_manifest = json.loads(row["response_manifest_json"])
                    if not isinstance(usage, Mapping) or not isinstance(response_manifest, Mapping):
                        raise ValueError("provider call metadata is not object-shaped")
                except Exception as exc:
                    raise MaxControlError("stored provider call metadata is invalid") from exc
                value = {
                    "call_record_id": row["call_record_id"], "provider_call_id": row["provider_call_id"],
                    "run_id": row["run_id"], "project_id": row["project_id"], "profile_hash": row["profile_hash"],
                    "model_identity": row["model_identity"], "intent_hash": row["intent_hash"],
                    "request_hash": row["request_hash"], "idempotency_key": row["idempotency_key"],
                    "transport_status": row["transport_status"], "terminal_status": row["terminal_status"],
                    "usage": dict(usage), "response_manifest": dict(response_manifest),
                    "pricing_hash": row["pricing_hash"], "logical_call_id": row["logical_call_id"] or "",
                    "intent_id": row["intent_id"] or "", "iteration_id": row["iteration_id"] or "",
                    "created_at": row["created_at"], "record_hash": row["record_hash"],
                }
            result = connection.execute("SELECT proposal_json, proposal_hash, result_json, result_hash, attempt_id FROM max_provider_call_results WHERE call_record_id=?", (row["call_record_id"],)).fetchone()
            if result is not None:
                if row["terminal_status"] != "succeeded":
                    raise MaxControlError("non-successful provider call has a replay result")
                proposal = json.loads(result["proposal_json"])
                result_value = json.loads(result["result_json"])
                if canonical_sha256(proposal) != result["proposal_hash"] or canonical_sha256(result_value) != result["result_hash"] or result_value.get("proposal") != proposal:
                    raise MaxControlError("stored provider replay result hash is invalid")
                value.update({"proposal": proposal, "proposal_hash": result["proposal_hash"], "result_hash": result["result_hash"], "attempt_id": result["attempt_id"]})
            attestation = connection.execute("SELECT attestation_json, attestation_hash FROM max_provider_usage_attestations WHERE call_record_id=?", (row["call_record_id"],)).fetchone()
            if attestation is not None:
                try:
                    attestation_mapping = json.loads(attestation["attestation_json"])
                    if not isinstance(attestation_mapping, Mapping):
                        raise ValueError("attestation is not an object")
                    allowed_attestation_fields = set(ProviderUsageAttestation.__dataclass_fields__)  # type: ignore[attr-defined]
                    if set(attestation_mapping) - allowed_attestation_fields:
                        raise ValueError("attestation contains unsupported fields")
                    attestation_value = ProviderUsageAttestation(**dict(attestation_mapping))
                except Exception as exc:
                    raise MaxControlError("stored provider replay attestation hash is invalid") from exc
                if attestation_value.attestation_hash != attestation["attestation_hash"]:
                    raise MaxControlError("stored provider replay attestation hash is invalid")
                value["attestation"] = attestation_value.to_mapping()
            return value
        finally:
            connection.close()

    def verify(self, *, run_id: str | None = None) -> dict[str, Any]:
        try:
            connection = self._connect(read_only=True)
        except MaxControlError:
            return {
                "ok": False,
                "schema_version": CONTROL_SCHEMA_VERSION,
                "run_id": run_id,
                "counts": {
                    "profiles": 0,
                    "grants": 0,
                    "consumptions": 0,
                    "calls": 0,
                    "attestations": 0,
                    "call_claims": 0,
                    "call_claim_events": 0,
                    "physical_attempts": 0,
                    "physical_attempt_events": 0,
                    "replay_results": 0,
                    "live_network": {},
                },
                "live_network": {
                    "ok": False,
                    "schema_version": CONTROL_SCHEMA_VERSION,
                    "run_id": run_id,
                    "counts": {
                        "policies": 0,
                        "authorizations": 0,
                        "consumptions": 0,
                        "events": 0,
                        "attempts": 0,
                        "permits": 0,
                        "permit_events": 0,
                    },
                    "issues": ["Max control database schema manifest verification failed"],
                },
                "issues": ["Max control database schema manifest verification failed"],
            }
        issues: list[str] = []
        counts = {"profiles": 0, "grants": 0, "consumptions": 0, "calls": 0, "attestations": 0, "call_claims": 0, "call_claim_events": 0, "physical_attempts": 0, "physical_attempt_events": 0, "replay_results": 0}
        try:
            profile_hashes: dict[str, ProviderProfile] = {}
            for row in connection.execute("SELECT * FROM max_provider_profiles"):
                counts["profiles"] += 1
                try:
                    profile_hashes[row["profile_hash"]] = _profile_from_row(row)
                except MaxControlError:
                    issues.append("provider profile hash mismatch")
            for row in connection.execute("SELECT * FROM max_provider_pricing_snapshots"):
                try:
                    _pricing_from_row(row)
                except MaxControlError:
                    issues.append("provider pricing hash mismatch")
            for row in connection.execute("SELECT * FROM max_run_provider_bindings"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                try:
                    value = json.loads(row["binding_json"])
                    if canonical_sha256(value) != row["binding_hash"] or row["profile_hash"] not in profile_hashes:
                        issues.append("run provider binding hash mismatch")
                except Exception:
                    issues.append("run provider binding is not canonical")
            for row in connection.execute("SELECT * FROM max_live_execution_grants"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                counts["grants"] += 1
                try:
                    value = json.loads(row["grant_json"])
                    if canonical_sha256(value) != row["grant_hash"] or row["profile_hash"] not in profile_hashes:
                        issues.append("execution grant hash or profile binding mismatch")
                except Exception:
                    issues.append("execution grant is not canonical")
            for row in connection.execute("SELECT * FROM max_live_execution_grant_consumptions"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                counts["consumptions"] += 1
                try:
                    value = json.loads(row["consumption_json"])
                    if canonical_sha256(value) != row["consumption_hash"] or value.get("grant_id") != row["grant_id"]:
                        issues.append("execution grant consumption hash mismatch")
                except Exception:
                    issues.append("execution grant consumption is not canonical")
            for row in connection.execute("SELECT * FROM max_provider_call_records"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                counts["calls"] += 1
                try:
                    value = json.loads(row["record_json"])
                    record = ProviderCallRecord(**{key: value[key] for key in ("call_record_id", "provider_call_id", "run_id", "project_id", "profile_hash", "model_identity", "intent_hash", "request_hash", "idempotency_key", "transport_status", "terminal_status", "usage", "response_manifest", "pricing_hash", "logical_call_id", "intent_id", "iteration_id", "created_at", "record_hash")})
                    if record.record_hash != row["record_hash"] or canonical_sha256(record.usage) != row["usage_hash"] or canonical_sha256(record.response_manifest) != row["response_manifest_hash"]:
                        issues.append("provider call record hash mismatch")
                except Exception:
                    issues.append("provider call record is invalid")
            for row in connection.execute("SELECT * FROM max_provider_usage_attestations"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                counts["attestations"] += 1
                try:
                    value = json.loads(row["attestation_json"])
                    attestation = ProviderUsageAttestation(**{key: value[key] for key in ("attestation_id", "call_record_id", "provider_call_id", "run_id", "profile_hash", "pricing_hash", "usage", "cost_units", "authority_id", "created_at", "attestation_hash")})
                    profile = profile_hashes.get(attestation.profile_hash)
                    if profile is None or profile.pricing.cost_units_for_usage(attestation.usage) != attestation.cost_units or attestation.attestation_hash != row["attestation_hash"] or canonical_sha256(attestation.usage) != row["usage_hash"]:
                        issues.append("provider usage attestation mismatch")
                except Exception:
                    issues.append("provider usage attestation is invalid")
            attempt_rows = list(connection.execute("SELECT * FROM max_provider_dispatch_attempts ORDER BY run_id, grant_id, physical_attempt_no, attempt_id"))
            for attempt in attempt_rows:
                if run_id is not None and attempt["run_id"] != run_id:
                    continue
                counts["physical_attempts"] += 1
                try:
                    attempt_value = json.loads(attempt["attempt_json"])
                    if canonical_sha256(attempt_value) != attempt["attempt_hash"]:
                        issues.append("provider physical attempt hash mismatch")
                    for key in ("claim_id", "grant_id", "grant_consumption_id", "run_id", "project_id", "logical_call_id", "intent_id", "iteration_id", "intent_hash", "request_hash", "profile_hash", "model_identity", "pricing_hash", "idempotency_key", "physical_attempt_no", "fencing_token", "owner_id", "owner_session"):
                        if attempt_value.get(key) != attempt[key]:
                            issues.append("provider physical attempt binding mismatch")
                            break
                    current = connection.execute("SELECT * FROM max_provider_dispatch_attempt_current WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()
                    if current is None:
                        issues.append("provider physical attempt current projection is missing")
                    else:
                        current_value = json.loads(current["current_json"])
                        actual = {"input_tokens": int(current["actual_input_tokens"]), "output_tokens": int(current["actual_output_tokens"]), "cache_read_tokens": int(current["actual_cache_read_tokens"]), "reasoning_tokens": int(current["actual_reasoning_tokens"]), "cost_units": int(current["actual_cost_units"])}
                        if canonical_sha256(current_value) != current["current_hash"] or current_value.get("attempt_id") != attempt["attempt_id"] or current_value.get("claim_id") != attempt["claim_id"] or current_value.get("state") != current["state"] or current_value.get("provider_call_id") != current["provider_call_id"] or current_value.get("call_record_id") != current["call_record_id"] or current_value.get("attestation_id") != current["attestation_id"] or current_value.get("actual") != actual:
                            issues.append("provider physical attempt current binding mismatch")
                    events = list(connection.execute("SELECT * FROM max_provider_dispatch_attempt_events WHERE attempt_id=? ORDER BY sequence_no", (attempt["attempt_id"],)))
                    counts["physical_attempt_events"] += len(events)
                    previous_hash = None
                    for expected_sequence, event in enumerate(events, start=1):
                        payload = json.loads(event["payload_json"])
                        event_value = {"attempt_id": event["attempt_id"], "claim_id": event["claim_id"], "run_id": event["run_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if int(event["sequence_no"]) != expected_sequence or event["claim_id"] != attempt["claim_id"] or event["run_id"] != attempt["run_id"] or canonical_sha256(payload) != event["payload_hash"] or event["previous_event_hash"] != previous_hash or canonical_sha256(event_value) != event["event_hash"]:
                            issues.append("provider physical attempt event chain mismatch")
                        previous_hash = event["event_hash"]
                    if current is not None and (not events or current["state"] != events[-1]["event_type"]):
                        issues.append("provider physical attempt current state is not the event-chain tip")
                except Exception:
                    issues.append("provider physical attempt is invalid")
            for row in connection.execute("SELECT * FROM max_provider_call_attempt_bindings"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                try:
                    value = json.loads(row["binding_json"])
                    if canonical_sha256(value) != row["binding_hash"] or value.get("call_record_id") != row["call_record_id"] or value.get("attempt_id") != row["attempt_id"]:
                        issues.append("provider call physical binding hash mismatch")
                except Exception:
                    issues.append("provider call physical binding is invalid")
            for row in connection.execute("SELECT * FROM max_provider_call_results"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                counts["replay_results"] += 1
                try:
                    proposal = json.loads(row["proposal_json"])
                    result_value = json.loads(row["result_json"])
                    if canonical_sha256(proposal) != row["proposal_hash"] or canonical_sha256(result_value) != row["result_hash"] or result_value.get("proposal") != proposal or result_value.get("attempt_id") != row["attempt_id"]:
                        issues.append("provider replay result hash mismatch")
                except Exception:
                    issues.append("provider replay result is invalid")
            claim_rows = list(connection.execute("SELECT * FROM max_provider_call_claims ORDER BY run_id, created_at, claim_id"))
            claim_current: dict[str, sqlite3.Row] = {}
            for row in connection.execute("SELECT * FROM max_provider_call_claim_current"):
                claim_current[str(row["claim_id"])] = row
            for claim in claim_rows:
                if run_id is not None and claim["run_id"] != run_id:
                    continue
                counts["call_claims"] += 1
                try:
                    claim_value = json.loads(claim["claim_json"])
                    if canonical_sha256(claim_value) != claim["claim_hash"]:
                        issues.append("provider call claim hash mismatch")
                    for key in ("grant_id", "grant_consumption_id", "run_id", "project_id", "logical_call_id", "intent_id", "iteration_id", "intent_hash", "request_hash", "profile_hash", "model_identity", "pricing_hash", "idempotency_key", "attempt_no", "fencing_token", "owner_id", "owner_session"):
                        expected = claim[key]
                        if claim_value.get(key) != expected:
                            issues.append("provider call claim binding mismatch")
                            break
                    current = claim_current.get(str(claim["claim_id"]))
                    if current is None:
                        issues.append("provider call claim current projection is missing")
                    else:
                        current_value = json.loads(current["current_json"])
                        if canonical_sha256(current_value) != current["current_hash"]:
                            issues.append("provider call claim current hash mismatch")
                        actual = {"input_tokens": int(current["actual_input_tokens"]), "output_tokens": int(current["actual_output_tokens"]), "cache_read_tokens": int(current["actual_cache_read_tokens"]), "reasoning_tokens": int(current["actual_reasoning_tokens"]), "cost_units": int(current["actual_cost_units"])}
                        if current_value.get("state") != current["state"] or current_value.get("provider_call_id") != current["provider_call_id"] or current_value.get("call_record_id") != current["call_record_id"] or current_value.get("attestation_id") != current["attestation_id"] or current_value.get("actual") != actual:
                            issues.append("provider call claim current binding mismatch")
                    intent = connection.execute("SELECT intent_hash, request_hash, iteration_id, project_id FROM max_model_call_intents WHERE run_id=? AND logical_call_id=? AND intent_id=?", (claim["run_id"], claim["logical_call_id"], claim["intent_id"])).fetchone()
                    manifest = connection.execute("SELECT manifest_json, manifest_hash FROM max_runner_intent_manifests WHERE run_id=? AND logical_call_id=? AND intent_id=?", (claim["run_id"], claim["logical_call_id"], claim["intent_id"])).fetchone()
                    iteration = connection.execute("SELECT run_id, project_id FROM max_iterations WHERE iteration_id=?", (claim["iteration_id"],)).fetchone()
                    if intent is None or manifest is None or iteration is None or intent["intent_hash"] != claim["intent_hash"] or intent["request_hash"] != claim["request_hash"] or intent["iteration_id"] != claim["iteration_id"] or intent["project_id"] != claim["project_id"] or iteration["run_id"] != claim["run_id"] or iteration["project_id"] != claim["project_id"]:
                        issues.append("provider call claim is not bound to runner intent/iteration")
                    else:
                        manifest_value = json.loads(manifest["manifest_json"])
                        if canonical_sha256(manifest_value) != manifest["manifest_hash"] or manifest_value.get("intent_hash") != claim["intent_hash"] or manifest_value.get("request_hash") != claim["request_hash"]:
                            issues.append("provider call claim manifest binding mismatch")
                    group_binding = connection.execute("SELECT b.intent_hash, b.iteration_id, g.project_id, g.iteration_id AS group_iteration_id FROM max_runner_call_bindings b JOIN max_runner_call_groups g ON g.group_id=b.group_id WHERE b.run_id=? AND b.logical_call_id=?", (claim["run_id"], claim["logical_call_id"])).fetchone()
                    if group_binding is None or group_binding["intent_hash"] != claim["intent_hash"] or group_binding["iteration_id"] != claim["iteration_id"] or group_binding["project_id"] != claim["project_id"] or group_binding["group_iteration_id"] != claim["iteration_id"]:
                        issues.append("provider call claim group binding mismatch")
                except Exception:
                    issues.append("provider call claim is invalid")
                events = list(connection.execute("SELECT * FROM max_provider_call_claim_events WHERE claim_id=? ORDER BY sequence_no", (claim["claim_id"],)))
                if run_id is None or claim["run_id"] == run_id:
                    counts["call_claim_events"] += len(events)
                previous_hash = None
                for expected_sequence, event in enumerate(events, start=1):
                    try:
                        payload = json.loads(event["payload_json"])
                        event_value = {"claim_id": event["claim_id"], "run_id": event["run_id"], "sequence_no": int(event["sequence_no"]), "event_type": event["event_type"], "payload_hash": event["payload_hash"], "previous_event_hash": event["previous_event_hash"], "created_at": event["created_at"]}
                        if int(event["sequence_no"]) != expected_sequence or event["run_id"] != claim["run_id"] or canonical_sha256(payload) != event["payload_hash"] or event["previous_event_hash"] != previous_hash or canonical_sha256(event_value) != event["event_hash"]:
                            issues.append("provider call claim event chain mismatch")
                        previous_hash = event["event_hash"]
                    except Exception:
                        issues.append("provider call claim event is invalid")
                current = claim_current.get(str(claim["claim_id"]))
                if current is not None and events and current["state"] != events[-1]["event_type"]:
                    issues.append("provider call claim current state is not the event-chain tip")
            for grant in connection.execute("SELECT * FROM max_provider_grant_usage_current"):
                if run_id is not None and grant["run_id"] != run_id:
                    continue
                try:
                    current_value = json.loads(grant["current_json"])
                    if canonical_sha256(current_value) != grant["current_hash"]:
                        issues.append("provider grant usage projection hash mismatch")
                    attempts = list(connection.execute("SELECT a.*, u.state, u.actual_input_tokens, u.actual_output_tokens, u.actual_cache_read_tokens, u.actual_reasoning_tokens, u.actual_cost_units FROM max_provider_dispatch_attempts a JOIN max_provider_dispatch_attempt_current u ON u.attempt_id=a.attempt_id WHERE a.grant_id=?", (grant["grant_id"],)))
                    recomputed = self._grant_current_value()
                    recomputed["dispatch_count"] = len(attempts)
                    active_states = {"reserved", "dispatching", "succeeded", "unknown", "disputed"}
                    for attempt in attempts:
                        if attempt["state"] in active_states:
                            for name in ("input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens"):
                                recomputed[f"reserved_{name}"] += int(attempt[f"reserved_{name}"])
                            recomputed["reserved_cost_units"] += int(attempt["reserved_cost_units"])
                        elif attempt["state"] == "settled":
                            for name in ("input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens"):
                                recomputed[f"settled_{name}"] += int(attempt[f"actual_{name}"])
                            recomputed["settled_cost_units"] += int(attempt["actual_cost_units"])
                            recomputed["released_cost_units"] += max(0, int(attempt["reserved_cost_units"]) - int(attempt["actual_cost_units"]))
                        elif attempt["state"] in {"failed", "cancelled"}:
                            recomputed["released_cost_units"] += int(attempt["reserved_cost_units"])
                    if recomputed != {key: int(current_value.get(key, -1)) for key in recomputed}:
                        issues.append("provider grant usage projection cannot be reconstructed")
                except Exception:
                    issues.append("provider grant usage projection is invalid")
            for row in connection.execute("SELECT * FROM max_provider_call_records"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                claim = connection.execute("SELECT c.*, u.state, u.call_record_id FROM max_provider_call_claims c JOIN max_provider_call_claim_current u ON u.claim_id=c.claim_id WHERE c.run_id=? AND c.idempotency_key=?", (row["run_id"], row["idempotency_key"])).fetchone()
                if claim is None or claim["call_record_id"] not in {None, row["call_record_id"]}:
                    issues.append("provider call record is not bound to a call claim")
                if row["terminal_status"] == "succeeded":
                    ack = connection.execute("SELECT dispatch_status, dispatch_known, provider_call_id FROM max_model_dispatch_acks WHERE run_id=? AND logical_call_id=?", (row["run_id"], row["logical_call_id"])).fetchone()
                    direct_ack = ack is not None and ack["dispatch_status"] == "dispatched" and bool(int(ack["dispatch_known"])) and ack["provider_call_id"] == row["provider_call_id"]
                    # The first runner acknowledgement is an immutable
                    # observation.  When it is ``unknown``, a later
                    # provider-idempotent retry or result query cannot
                    # rewrite that row; it resolves the observation through
                    # append-only recovery and attempt records instead.
                    recovery_ack = False
                    if not direct_ack and ack is not None and ack["dispatch_status"] == "unknown" and not bool(int(ack["dispatch_known"])):
                        resolved = connection.execute(
                            "SELECT 1 FROM max_runner_recovery_decisions WHERE run_id=? AND logical_call_id=? AND disposition IN ('reuse_intent','query_provider_result','consume_stored_result','idempotent_success') LIMIT 1",
                            (row["run_id"], row["logical_call_id"]),
                        ).fetchone()
                        dispatched_attempt = connection.execute(
                            "SELECT 1 FROM max_model_call_attempts WHERE run_id=? AND logical_call_id=? AND stage='dispatched' LIMIT 1",
                            (row["run_id"], row["logical_call_id"]),
                        ).fetchone()
                        recovery_ack = resolved is not None and dispatched_attempt is not None
                    if not direct_ack and not recovery_ack:
                        issues.append("successful provider call lacks a matching dispatch acknowledgement")
            for row in connection.execute("SELECT * FROM max_provider_usage_attestations"):
                if run_id is not None and row["run_id"] != run_id:
                    continue
                call = connection.execute("SELECT * FROM max_provider_call_records WHERE call_record_id=?", (row["call_record_id"],)).fetchone()
                if call is None or row["provider_call_id"] != call["provider_call_id"] or row["usage_hash"] != call["usage_hash"] or row["authority_id"] != PROVIDER_USAGE_AUTHORITY_ID:
                    issues.append("provider attestation is not bound to call usage or authority")
            live = self.verify_live_network(run_id=run_id)
            issues.extend(str(item) for item in live.get("issues", ()))
            counts["live_network"] = live.get("counts", {})
            # Imported lazily to keep the low-level provider store usable while
            # migration/bootstrap code imports this module.
            from .bundle import LiveAuthorizationBundleStore
            from .execution import LiveIterationApprovalStore

            bundles = LiveAuthorizationBundleStore(self).verify(run_id=run_id)
            issues.extend(str(item) for item in bundles.get("issues", ()))
            counts["live_authorization_bundles"] = bundles.get("counts", {})
            live_iterations = LiveIterationApprovalStore(self.repository).verify(run_id=run_id)
            issues.extend(str(item) for item in live_iterations.get("issues", ()))
            counts["live_iteration_approvals"] = live_iterations.get("counts", {})
            return {"ok": not issues, "schema_version": CONTROL_SCHEMA_VERSION, "run_id": run_id, "counts": counts, "live_network": live, "live_authorization_bundles": bundles, "live_iteration_approvals": live_iterations, "issues": sorted(set(issues))}
        finally:
            connection.close()

    verify_provider = verify


__all__ = ["ProviderStore"]
