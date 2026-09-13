"""Strict, provider-neutral MR-2B0 contracts.

The objects in this module are deliberately independent from any provider
SDK.  They accept only the fields needed by the control plane and expose
canonical mappings suitable for hashing and append-only persistence.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from typing import Any, Mapping
from urllib.parse import urlsplit

from ..contract import canonical_json, canonical_sha256


class ProviderContractError(ValueError):
    """A user/provider payload failed the frozen MR-2B0 contract."""

    def __init__(self, message: str, *, code: str = "INVALID_PROVIDER_CONTRACT") -> None:
        super().__init__(message)
        self.code = code


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_REF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_CRLF_RE = re.compile(r"[\r\n]")
_SECRET_KEY_RE = re.compile(
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|authorization|cookie|private[_-]?key)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(r"(?:bearer\s+|sk-[A-Za-z0-9_-]{8,}|-----BEGIN|api[_-]?key\s*[:=])", re.IGNORECASE)


def _strict_mapping(value: Any, allowed: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProviderContractError(f"{name} must be an object")
    unknown = {str(key) for key in value} - allowed
    if unknown:
        raise ProviderContractError(f"{name} contains unsupported fields")
    return value


def _text(value: Any, name: str, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or _CRLF_RE.search(value):
        raise ProviderContractError(f"{name} must be a bounded non-empty string")
    return value


def _hash(value: Any, name: str) -> str:
    text = _text(value, name, max_length=64)
    if not _SHA256_RE.fullmatch(text):
        raise ProviderContractError(f"{name} must be a SHA-256 hex value")
    return text.lower()


def _bounded_mapping(value: Any, name: str, *, allowed: set[str], max_items: int = 32) -> dict[str, Any]:
    raw = _strict_mapping(value, allowed, name)
    if len(raw) > max_items:
        raise ProviderContractError(f"{name} is too large")
    result = {str(key): raw[key] for key in raw}
    _reject_secret_material(result, name)
    return result


def _reject_secret_material(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if _SECRET_KEY_RE.search(key_text):
                # credential_ref is handled by CredentialRef and is the only
                # permitted occurrence of the word credential in a profile.
                if key_text not in {"credential_ref", "credential_reference"}:
                    raise ProviderContractError(f"{path}.{key_text} contains secret material")
            _reject_secret_material(child, f"{path}.{key_text}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_secret_material(child, f"{path}[{index}]")
    elif isinstance(value, str) and _SECRET_VALUE_RE.search(value):
        raise ProviderContractError(f"{path} contains secret material")


def _number(value: Any, name: str, *, minimum: Decimal | None = None, maximum: Decimal | None = None) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise ProviderContractError(f"{name} must be a finite number")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ProviderContractError(f"{name} must be a finite number") from exc
    if not parsed.is_finite() or (minimum is not None and parsed < minimum) or (maximum is not None and parsed > maximum):
        raise ProviderContractError(f"{name} is outside its allowed range")
    return parsed


def _decimal_string(value: Decimal) -> str:
    normalized = value.normalize()
    text = format(normalized, "f")
    return text if "." in text else text + ".0"


@dataclass(frozen=True, repr=False)
class CredentialRef:
    """A reference to a secret source; never the secret value itself."""

    kind: str
    name: str

    def __post_init__(self) -> None:
        kind = _text(self.kind, "credential_ref.kind", max_length=32).lower()
        if kind not in {"environment", "external", "injected"}:
            raise ProviderContractError("credential_ref.kind is unsupported")
        name = _text(self.name, "credential_ref.name", max_length=128)
        if not _REF_RE.fullmatch(name):
            raise ProviderContractError("credential_ref.name is not a safe reference name")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "name", name)

    @property
    def source_kind(self) -> str:
        return self.kind

    @property
    def reference_name(self) -> str:
        return self.name

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CredentialRef":
        raw = _strict_mapping(value, {"kind", "name", "source_kind", "reference_name"}, "credential_ref")
        kind = raw.get("kind", raw.get("source_kind"))
        name = raw.get("name", raw.get("reference_name"))
        if raw.get("kind") is not None and raw.get("source_kind") is not None and raw["kind"] != raw["source_kind"]:
            raise ProviderContractError("credential_ref kind aliases conflict")
        if raw.get("name") is not None and raw.get("reference_name") is not None and raw["name"] != raw["reference_name"]:
            raise ProviderContractError("credential_ref name aliases conflict")
        return cls(kind, name)

    def to_mapping(self) -> dict[str, str]:
        return {"kind": self.kind, "name": self.name}

    def __repr__(self) -> str:
        return f"CredentialRef(kind={self.kind!r}, name={self.name!r}, value=<redacted>)"


@dataclass(frozen=True)
class ProviderCapabilities:
    structured_json: bool
    idempotency: bool
    result_query: bool
    usage_reporting: bool
    streaming: bool = False
    tool_calling: bool = False
    provider_file_fetch: bool = False
    provider_url_fetch: bool = False

    def __post_init__(self) -> None:
        for name in ("structured_json", "idempotency", "result_query", "usage_reporting", "streaming", "tool_calling", "provider_file_fetch", "provider_url_fetch"):
            if not isinstance(getattr(self, name), bool):
                raise ProviderContractError(f"capabilities.{name} must be boolean")
        if self.streaming or self.tool_calling or self.provider_file_fetch or self.provider_url_fetch:
            raise ProviderContractError("MR-2B0 forbids streaming, tool calling and provider-side fetch")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProviderCapabilities":
        raw = _strict_mapping(value, {"structured_json", "idempotency", "result_query", "usage_reporting", "streaming", "tool_calling", "provider_file_fetch", "provider_url_fetch"}, "capabilities")
        required = ("structured_json", "idempotency", "result_query", "usage_reporting")
        if any(key not in raw for key in required):
            raise ProviderContractError("capabilities are incomplete")
        return cls(*(raw.get(key, False) for key in ("structured_json", "idempotency", "result_query", "usage_reporting", "streaming", "tool_calling", "provider_file_fetch", "provider_url_fetch")))

    def to_mapping(self) -> dict[str, bool]:
        return {"structured_json": self.structured_json, "idempotency": self.idempotency, "result_query": self.result_query, "usage_reporting": self.usage_reporting, "streaming": self.streaming, "tool_calling": self.tool_calling, "provider_file_fetch": self.provider_file_fetch, "provider_url_fetch": self.provider_url_fetch}


@dataclass(frozen=True)
class PricingSnapshot:
    pricing_id: str
    pricing_version: str
    currency: str
    unit: str
    input_per_1k: Decimal | str | int | float
    output_per_1k: Decimal | str | int | float
    cache_per_1k: Decimal | str | int | float = 0
    reasoning_per_1k: Decimal | str | int | float = 0
    effective_at: str = "1970-01-01T00:00:00.000Z"
    source_label: str = "fixture"
    pricing_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "pricing_id", _text(self.pricing_id, "pricing_id"))
        object.__setattr__(self, "pricing_version", _text(self.pricing_version, "pricing_version"))
        object.__setattr__(self, "currency", _text(self.currency, "pricing.currency", max_length=8).upper())
        object.__setattr__(self, "unit", _text(self.unit, "pricing.unit", max_length=32))
        if len(self.currency) != 3:
            raise ProviderContractError("pricing.currency must be an ISO-like three-letter code")
        for field_name in ("input_per_1k", "output_per_1k", "cache_per_1k", "reasoning_per_1k"):
            object.__setattr__(self, field_name, _number(getattr(self, field_name), f"pricing.{field_name}", minimum=Decimal("0")))
        object.__setattr__(self, "effective_at", _text(self.effective_at, "pricing.effective_at"))
        object.__setattr__(self, "source_label", _text(self.source_label, "pricing.source_label"))
        value = self.to_mapping(include_hash=False)
        expected = canonical_sha256(value)
        if self.pricing_hash and self.pricing_hash.lower() != expected:
            raise ProviderContractError("pricing hash is not canonical")
        object.__setattr__(self, "pricing_hash", expected)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PricingSnapshot":
        raw = _strict_mapping(value, {"pricing_id", "pricing_version", "currency", "unit", "input_per_1k", "output_per_1k", "cache_per_1k", "reasoning_per_1k", "effective_at", "source_label", "pricing_hash"}, "pricing")
        return cls(raw.get("pricing_id"), raw.get("pricing_version"), raw.get("currency"), raw.get("unit", "cost_units"), raw.get("input_per_1k"), raw.get("output_per_1k"), raw.get("cache_per_1k", 0), raw.get("reasoning_per_1k", 0), raw.get("effective_at", "1970-01-01T00:00:00.000Z"), raw.get("source_label", "fixture"), raw.get("pricing_hash", ""))

    def to_mapping(self, *, include_hash: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "pricing_id": self.pricing_id, "pricing_version": self.pricing_version, "currency": self.currency, "unit": self.unit,
            "input_per_1k": _decimal_string(self.input_per_1k), "output_per_1k": _decimal_string(self.output_per_1k),
            "cache_per_1k": _decimal_string(self.cache_per_1k), "reasoning_per_1k": _decimal_string(self.reasoning_per_1k),
            "effective_at": self.effective_at, "source_label": self.source_label,
        }
        if include_hash:
            result["pricing_hash"] = self.pricing_hash
        return result

    def cost_units_for_usage(self, usage: Mapping[str, Any]) -> int:
        allowed = {"input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens"}
        if not isinstance(usage, Mapping):
            raise ProviderContractError("usage must be an object", code="USAGE_DISPUTE")
        unknown = set(str(key) for key in usage) - allowed
        if unknown:
            raise ProviderContractError("usage contains unsupported token categories", code="USAGE_DISPUTE")
        total = Decimal("0")
        rates = {"input_tokens": self.input_per_1k, "output_tokens": self.output_per_1k, "cache_read_tokens": self.cache_per_1k, "reasoning_tokens": self.reasoning_per_1k}
        for key, raw in usage.items():
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0 or raw > 2_000_000_000:
                raise ProviderContractError("usage token counts must be non-negative integers", code="USAGE_DISPUTE")
            total += Decimal(raw) * rates[key] / Decimal(1000)
        # A reservation and a settlement may never understate a fractional
        # priced unit.  Decimal plus ceiling is deliberately used instead of
        # binary float or half-up rounding.
        return int(total.to_integral_value(rounding=ROUND_CEILING))


def _validate_endpoint(origin: str, path_policy: str) -> tuple[str, str]:
    origin = _text(origin, "endpoint_origin", max_length=512)
    path_policy = _text(path_policy, "endpoint_path_policy", max_length=256)
    try:
        parsed = urlsplit(origin)
    except ValueError as exc:
        raise ProviderContractError("endpoint_origin is not a valid URL") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProviderContractError("endpoint_origin must be a credential-free HTTPS origin")
    if parsed.path not in {"", "/"}:
        raise ProviderContractError("endpoint_origin must not contain a request path")
    host = parsed.hostname
    try:
        ascii_host = host.encode("ascii").decode("ascii")
    except UnicodeEncodeError as exc:
        raise ProviderContractError("endpoint host must use an explicit ASCII/IDNA-safe form") from exc
    if host != ascii_host:
        raise ProviderContractError("endpoint host must use an explicit ASCII/IDNA-safe form")
    host = host.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ProviderContractError("endpoint host is not allowed")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified or ip.is_multicast):
        raise ProviderContractError("endpoint host is a private or reserved address")
    if not path_policy.startswith("/") or "?" in path_policy or "#" in path_policy or "\\" in path_policy or _CRLF_RE.search(path_policy):
        raise ProviderContractError("endpoint_path_policy is invalid")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProviderContractError("endpoint port is invalid") from exc
    return f"https://{host}{f':{port}' if port else ''}", path_policy.rstrip("/") or "/"


@dataclass(frozen=True)
class ProviderProfile:
    profile_id: str
    profile_version: str
    protocol: str
    provider_name: str
    model_id: str
    model_revision: str | None
    endpoint_origin: str
    endpoint_path_policy: str
    capabilities: ProviderCapabilities
    inference_defaults: Mapping[str, Any]
    timeout_policy: Mapping[str, Any]
    retry_policy: Mapping[str, Any]
    request_limits: Mapping[str, Any]
    rate_policy: Mapping[str, Any]
    credential_ref: CredentialRef
    network_policy_hash: str
    pricing: PricingSnapshot
    # A profile may carry the reviewed policy payload only at the
    # server-owned registration boundary.  Execution and Preview paths use
    # the immutable policy row addressed by ``network_policy_hash``; they
    # never accept a policy payload from the client.
    network_policy: Mapping[str, Any] | None = None
    approved_actor: Mapping[str, Any] = field(default_factory=dict)
    approved_at: str = "1970-01-01T00:00:00.000Z"
    profile_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile_id", _text(self.profile_id, "profile_id"))
        object.__setattr__(self, "profile_version", _text(self.profile_version, "profile_version"))
        if self.protocol != "openai-compatible/v1":
            raise ProviderContractError("only openai-compatible/v1 is supported in MR-2B0")
        object.__setattr__(self, "provider_name", _text(self.provider_name, "provider_name"))
        object.__setattr__(self, "model_id", _text(self.model_id, "model_id"))
        if self.model_revision is not None:
            object.__setattr__(self, "model_revision", _text(self.model_revision, "model_revision", max_length=128))
        origin, path_policy = _validate_endpoint(self.endpoint_origin, self.endpoint_path_policy)
        object.__setattr__(self, "endpoint_origin", origin)
        object.__setattr__(self, "endpoint_path_policy", path_policy)
        if not isinstance(self.capabilities, ProviderCapabilities):
            object.__setattr__(self, "capabilities", ProviderCapabilities.from_mapping(self.capabilities))
        object.__setattr__(self, "inference_defaults", _bounded_mapping(self.inference_defaults, "inference_defaults", allowed={"temperature", "top_p", "max_output_tokens", "max_input_tokens", "max_cache_read_tokens", "max_reasoning_tokens", "seed", "reasoning_mode"}))
        object.__setattr__(self, "timeout_policy", _bounded_mapping(self.timeout_policy, "timeout_policy", allowed={"connect_ms", "write_ms", "read_ms", "total_ms"}))
        object.__setattr__(self, "retry_policy", _bounded_mapping(self.retry_policy, "retry_policy", allowed={"max_attempts", "backoff_ms", "retry_statuses"}))
        object.__setattr__(self, "request_limits", _bounded_mapping(self.request_limits, "request_limits", allowed={"max_request_bytes", "max_response_bytes", "max_prompt_chars", "max_json_depth", "max_input_tokens", "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens"}))
        object.__setattr__(self, "rate_policy", _bounded_mapping(self.rate_policy, "rate_policy", allowed={"max_concurrency", "per_minute"}))
        token_limit_keys = {"max_input_tokens", "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens"}
        for name, values in (("timeout_policy", self.timeout_policy), ("request_limits", self.request_limits), ("rate_policy", self.rate_policy)):
            for key, value in values.items():
                if name == "request_limits" and key in token_limit_keys:
                    continue
                if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                    raise ProviderContractError(f"{name}.{key} must be a positive integer")
        if "max_attempts" in self.retry_policy and (isinstance(self.retry_policy["max_attempts"], bool) or not isinstance(self.retry_policy["max_attempts"], int) or not 1 <= self.retry_policy["max_attempts"] <= 3):
            raise ProviderContractError("retry_policy.max_attempts must be 1..3")
        if "retry_statuses" in self.retry_policy:
            statuses = self.retry_policy["retry_statuses"]
            if not isinstance(statuses, (list, tuple)) or not all(isinstance(item, int) and 100 <= item <= 599 for item in statuses):
                raise ProviderContractError("retry_policy.retry_statuses is invalid")
        if "temperature" in self.inference_defaults:
            _number(self.inference_defaults["temperature"], "inference_defaults.temperature", minimum=Decimal("0"), maximum=Decimal("2"))
        if "top_p" in self.inference_defaults:
            _number(self.inference_defaults["top_p"], "inference_defaults.top_p", minimum=Decimal("0"), maximum=Decimal("1"))
        if "max_output_tokens" in self.inference_defaults:
            if isinstance(self.inference_defaults["max_output_tokens"], bool) or not isinstance(self.inference_defaults["max_output_tokens"], int) or not 1 <= self.inference_defaults["max_output_tokens"] <= 1_000_000:
                raise ProviderContractError("inference_defaults.max_output_tokens is invalid")
        for key in ("max_input_tokens", "max_cache_read_tokens", "max_reasoning_tokens"):
            if key in self.inference_defaults and (isinstance(self.inference_defaults[key], bool) or not isinstance(self.inference_defaults[key], int) or not 0 <= self.inference_defaults[key] <= 2_000_000_000):
                raise ProviderContractError(f"inference_defaults.{key} is invalid")
        for key in ("max_input_tokens", "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens"):
            if key in self.request_limits and (isinstance(self.request_limits[key], bool) or not isinstance(self.request_limits[key], int) or not 0 <= self.request_limits[key] <= 2_000_000_000):
                raise ProviderContractError(f"request_limits.{key} is invalid")
        if not isinstance(self.credential_ref, CredentialRef):
            object.__setattr__(self, "credential_ref", CredentialRef.from_mapping(self.credential_ref))
        object.__setattr__(self, "network_policy_hash", _hash(self.network_policy_hash, "network_policy_hash"))
        if self.network_policy is not None:
            if not isinstance(self.network_policy, Mapping):
                raise ProviderContractError("network_policy must be an object")
            # Keep construction deterministic while avoiding a module import
            # cycle: the canonical policy normalizer lives in provider.live.
            try:
                from .live import normalize_network_policy
            except ImportError:
                normalized_policy = dict(self.network_policy)
            else:
                normalized_policy = normalize_network_policy(self.network_policy)
            object.__setattr__(self, "network_policy", normalized_policy)
        if not isinstance(self.pricing, PricingSnapshot):
            object.__setattr__(self, "pricing", PricingSnapshot.from_mapping(self.pricing))
        actor = _strict_mapping(self.approved_actor, {"actor_id", "actor_kind", "actor_session"}, "approved_actor")
        # A profile may be validated before registration.  The persistence
        # boundary replaces this empty pre-registration marker with the
        # server-owned approving Actor and UTC timestamp in one transaction.
        if actor and any(not isinstance(actor.get(key), str) or not actor[key] for key in ("actor_id", "actor_kind", "actor_session")):
            raise ProviderContractError("approved_actor is incomplete")
        object.__setattr__(self, "approved_actor", dict(actor))
        object.__setattr__(self, "approved_at", _text(self.approved_at, "approved_at"))
        # Approval actor/time are server-owned audit metadata, not provider
        # configuration.  Excluding them keeps one immutable profile version
        # on one stable profile hash even when an idempotent registration is
        # retried by a different administrator.
        hash_value = self.to_mapping(include_hash=False)
        hash_value.pop("approved_actor", None)
        hash_value.pop("approved_at", None)
        expected = canonical_sha256(hash_value)
        if self.profile_hash and self.profile_hash.lower() != expected:
            raise ProviderContractError("profile hash is not canonical")
        object.__setattr__(self, "profile_hash", expected)

    @property
    def model_identity(self) -> str:
        return self.model_id if not self.model_revision else f"{self.model_id}@{self.model_revision}"

    def maximum_usage(self) -> dict[str, int]:
        """Return only explicitly declared per-call token bounds.

        ``max_prompt_chars // 4`` is intentionally not a token authority.  It
        may still be used by a UI as an estimate, but it is never returned by
        this method and therefore cannot silently enter a grant, reservation,
        scheduler budget, or provider price calculation.

        The public method remains tolerant of legacy profile construction so a
        migration diagnostic can inspect such a profile.  Authority paths use
        :meth:`authority_maximum_usage`, which rejects an incomplete profile.
        """

        names = {
            "max_input_tokens": "input_tokens",
            "max_output_tokens": "output_tokens",
            "max_cache_read_tokens": "cache_read_tokens",
            "max_reasoning_tokens": "reasoning_tokens",
        }
        values: dict[str, int] = {}
        for source, target in names.items():
            if source not in self.request_limits:
                continue
            raw = self.request_limits[source]
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0 or raw > 2_000_000_000:
                raise ProviderContractError(f"profile maximum {source} is invalid")
            values[target] = raw
        return dict(sorted(values.items()))

    def authority_maximum_usage(self) -> dict[str, int]:
        """Return the complete token authority or fail closed.

        All four component caps are persisted in ``request_limits``.  Zero is
        an explicit declaration that a provider profile does not authorize a
        cache-read or reasoning component; omission is a migration error, not
        an invitation to derive a cap from characters or inference defaults.
        """

        required = ("max_input_tokens", "max_output_tokens", "max_cache_read_tokens", "max_reasoning_tokens")
        missing = [key for key in required if key not in self.request_limits]
        if missing:
            raise ProviderContractError(
                "provider profile requires explicit token caps; migrate request_limits: " + ", ".join(missing),
                code="PROFILE_TOKEN_CAP_REQUIRED",
            )
        maximum = self.maximum_usage()
        values = {
            "input_tokens": int(maximum["input_tokens"]),
            "output_tokens": int(maximum["output_tokens"]),
            "cache_read_tokens": int(maximum["cache_read_tokens"]),
            "reasoning_tokens": int(maximum["reasoning_tokens"]),
        }
        if values["input_tokens"] < 1 or values["output_tokens"] < 1:
            raise ProviderContractError("provider profile input/output token caps must be positive", code="PROFILE_TOKEN_CAP_REQUIRED")
        return values

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProviderProfile":
        allowed = {"profile_id", "profile_version", "protocol", "provider_name", "model_id", "model_identity", "model_revision", "endpoint_origin", "endpoint_path_policy", "capabilities", "inference_defaults", "timeout_policy", "retry_policy", "request_limits", "rate_policy", "credential_ref", "network_policy_hash", "network_policy", "pricing", "pricing_snapshot", "pricing_hash", "approved_actor", "approved_at", "profile_hash"}
        raw = _strict_mapping(value, allowed, "provider profile")
        model_id = raw.get("model_id")
        revision = raw.get("model_revision")
        supplied_identity = raw.get("model_identity")
        if model_id is not None and supplied_identity is not None:
            if not isinstance(supplied_identity, str):
                raise ProviderContractError("model_identity must be text")
            expected_identity = model_id if revision is None else f"{model_id}@{revision}"
            if supplied_identity != expected_identity:
                raise ProviderContractError("model_id/model_revision and model_identity aliases conflict")
        if model_id is None and isinstance(supplied_identity, str):
            identity = supplied_identity
            model_id, separator, revision_value = identity.partition("@")
            revision = revision_value if separator else None
        if raw.get("pricing") is None and raw.get("pricing_snapshot") is not None:
            raw = {**raw, "pricing": raw["pricing_snapshot"]}
        pricing = PricingSnapshot.from_mapping(raw.get("pricing"))
        if raw.get("pricing_hash") is not None and raw.get("pricing_hash") != pricing.pricing_hash:
            raise ProviderContractError("provider profile pricing hash is not canonical")
        return cls(raw.get("profile_id"), raw.get("profile_version"), raw.get("protocol", "openai-compatible/v1"), raw.get("provider_name"), model_id, revision, raw.get("endpoint_origin"), raw.get("endpoint_path_policy", "/v1/chat/completions"), ProviderCapabilities.from_mapping(raw.get("capabilities")), raw.get("inference_defaults", {}), raw.get("timeout_policy", {}), raw.get("retry_policy", {}), raw.get("request_limits", {}), raw.get("rate_policy", {}), CredentialRef.from_mapping(raw.get("credential_ref")), raw.get("network_policy_hash"), pricing, raw.get("network_policy"), raw.get("approved_actor", {}), raw.get("approved_at", "1970-01-01T00:00:00.000Z"), raw.get("profile_hash", ""))

    def to_mapping(self, *, include_hash: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "profile_id": self.profile_id, "profile_version": self.profile_version, "protocol": self.protocol,
            "provider_name": self.provider_name, "model_id": self.model_id, "model_revision": self.model_revision,
            "model_identity": self.model_identity, "endpoint_origin": self.endpoint_origin, "endpoint_path_policy": self.endpoint_path_policy,
            "capabilities": self.capabilities.to_mapping(), "inference_defaults": dict(self.inference_defaults),
            "timeout_policy": dict(self.timeout_policy), "retry_policy": dict(self.retry_policy), "request_limits": dict(self.request_limits),
            "rate_policy": dict(self.rate_policy), "credential_ref": self.credential_ref.to_mapping(), "network_policy_hash": self.network_policy_hash,
            "pricing_hash": self.pricing.pricing_hash, "pricing": self.pricing.to_mapping(), "approved_actor": dict(self.approved_actor), "approved_at": self.approved_at,
        }
        if self.network_policy is not None:
            result["network_policy"] = dict(self.network_policy)
        if include_hash:
            result["profile_hash"] = self.profile_hash
        return result


TOKEN_COMPONENTS = ("input_tokens", "cache_read_tokens", "output_tokens", "reasoning_tokens")
TOKEN_CAP_KEYS = {
    "input_tokens": "max_input_tokens",
    "cache_read_tokens": "max_cache_read_tokens",
    "output_tokens": "max_output_tokens",
    "reasoning_tokens": "max_reasoning_tokens",
}
_TOKEN_MAX = 2_000_000_000


def _token_count(value: Any, name: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > _TOKEN_MAX:
        raise ProviderContractError("token envelope contains an invalid count", code="USAGE_DISPUTE")
    return int(value)


@dataclass(frozen=True)
class TokenEnvelope:
    """Canonical four-component token envelope.

    The two family ceilings are derived from the four independent component
    caps.  They are intentionally not accepted as caller-supplied fields.
    """

    input_tokens: int = 0
    cache_read_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0

    def __post_init__(self) -> None:
        for component in TOKEN_COMPONENTS:
            object.__setattr__(self, component, _token_count(getattr(self, component), component))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | "TokenEnvelope", *, require_positive: bool = False) -> "TokenEnvelope":
        if isinstance(value, cls):
            envelope = value
        else:
            if not isinstance(value, Mapping):
                raise ProviderContractError("usage must be an object", code="USAGE_DISPUTE")
            keys = {str(key) for key in value}
            if keys - set(TOKEN_COMPONENTS):
                raise ProviderContractError("usage contains unsupported categories", code="USAGE_DISPUTE")
            envelope = cls(**{component: _token_count(value.get(component, 0), component) for component in TOKEN_COMPONENTS})
        if require_positive and not any(getattr(envelope, component) for component in TOKEN_COMPONENTS):
            raise ProviderContractError("usage must contain a positive token count", code="USAGE_DISPUTE")
        return envelope

    @classmethod
    def from_caps(cls, value: Mapping[str, Any]) -> "TokenEnvelope":
        if not isinstance(value, Mapping):
            raise ProviderContractError("token caps must be an object", code="PROVIDER_RESERVATION_ENVELOPE_MISMATCH")
        return cls(**{
            component: _token_count(value.get(cap_key, 0), cap_key)
            for component, cap_key in TOKEN_CAP_KEYS.items()
        })

    def to_mapping(self, *, include_zero: bool = True) -> dict[str, int]:
        value = {component: int(getattr(self, component)) for component in TOKEN_COMPONENTS}
        if include_zero:
            return value
        return {key: number for key, number in value.items() if number}

    def to_usage_mapping(self) -> dict[str, int]:
        """Return the normalized usage shape used by receipts and pricing."""

        value = {
            "input_tokens": int(self.input_tokens),
            "output_tokens": int(self.output_tokens),
        }
        if self.cache_read_tokens:
            value["cache_read_tokens"] = int(self.cache_read_tokens)
        if self.reasoning_tokens:
            value["reasoning_tokens"] = int(self.reasoning_tokens)
        return dict(sorted(value.items()))

    @property
    def input_family_tokens(self) -> int:
        return self.input_tokens + self.cache_read_tokens

    @property
    def output_family_tokens(self) -> int:
        return self.output_tokens + self.reasoning_tokens

    def family_totals(self) -> dict[str, int]:
        return {
            "input_family_tokens": self.input_family_tokens,
            "output_family_tokens": self.output_family_tokens,
        }

    def plus(self, other: Mapping[str, Any] | "TokenEnvelope") -> "TokenEnvelope":
        right = TokenEnvelope.from_mapping(other)
        return TokenEnvelope(**{
            component: getattr(self, component) + getattr(right, component)
            for component in TOKEN_COMPONENTS
        })


def token_envelope_within_caps(value: Mapping[str, Any] | TokenEnvelope, caps: Mapping[str, Any]) -> bool:
    """Check components and server-derived input/output family ceilings."""

    usage = TokenEnvelope.from_mapping(value)
    maximum = TokenEnvelope.from_caps(caps)
    return (
        all(getattr(usage, component) <= getattr(maximum, component) for component in TOKEN_COMPONENTS)
        and usage.input_family_tokens <= maximum.input_family_tokens
        and usage.output_family_tokens <= maximum.output_family_tokens
    )


def assert_token_envelope_within_caps(value: Mapping[str, Any] | TokenEnvelope, caps: Mapping[str, Any]) -> None:
    if not token_envelope_within_caps(value, caps):
        raise ProviderContractError(
            "token envelope exceeds its component or derived family ceiling",
            code="PROVIDER_RESERVATION_ENVELOPE_MISMATCH",
        )


def normalize_usage(value: Mapping[str, Any]) -> dict[str, int]:
    """Normalize the already-canonical four-component usage shape."""

    envelope = TokenEnvelope.from_mapping(value, require_positive=True)
    return envelope.to_usage_mapping()


def _raw_usage_count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > _TOKEN_MAX:
        raise ProviderContractError("provider usage contains an invalid count", code="USAGE_DISPUTE")
    return int(value)


def _usage_alias_value(raw: Mapping[str, Any], names: tuple[str, ...]) -> int | None:
    values: list[int] = []
    for name in names:
        if name in raw:
            values.append(_raw_usage_count(raw[name]))
    if values and any(item != values[0] for item in values[1:]):
        raise ProviderContractError("provider usage aliases conflict", code="USAGE_DISPUTE")
    return values[0] if values else None


def _usage_detail_value(raw: Mapping[str, Any], detail_names: tuple[str, ...], expected_key: str) -> int | None:
    values: list[int] = []
    for name in detail_names:
        if name not in raw:
            continue
        detail = raw[name]
        if not isinstance(detail, Mapping) or set(str(key) for key in detail) - {expected_key}:
            raise ProviderContractError("provider usage details contain unsupported fields", code="USAGE_DISPUTE")
        if expected_key in detail:
            values.append(_raw_usage_count(detail[expected_key]))
    if values and any(item != values[0] for item in values[1:]):
        raise ProviderContractError("provider usage details conflict", code="USAGE_DISPUTE")
    return values[0] if values else None


def normalize_openai_compatible_usage(value: Mapping[str, Any]) -> dict[str, int]:
    """Normalize all accepted OpenAI-compatible usage aliases in one place."""

    if not isinstance(value, Mapping):
        raise ProviderContractError("provider usage is not an object", code="USAGE_DISPUTE")
    allowed = {
        "prompt_tokens", "input_tokens", "completion_tokens", "output_tokens", "total_tokens",
        "cache_read_tokens", "reasoning_tokens", "prompt_tokens_details", "input_tokens_details",
        "completion_tokens_details", "output_tokens_details",
    }
    if set(str(key) for key in value) - allowed:
        raise ProviderContractError("provider usage contains unsupported fields", code="USAGE_DISPUTE")
    prompt_total = _usage_alias_value(value, ("prompt_tokens", "input_tokens"))
    completion_total = _usage_alias_value(value, ("completion_tokens", "output_tokens"))
    cached_direct = _usage_alias_value(value, ("cache_read_tokens",))
    reasoning_direct = _usage_alias_value(value, ("reasoning_tokens",))
    cached_detail = _usage_detail_value(value, ("prompt_tokens_details", "input_tokens_details"), "cached_tokens")
    reasoning_detail = _usage_detail_value(value, ("completion_tokens_details", "output_tokens_details"), "reasoning_tokens")
    if prompt_total is None or completion_total is None:
        raise ProviderContractError("provider usage is missing input/output totals", code="USAGE_DISPUTE")
    if cached_direct is not None and cached_detail is not None and cached_direct != cached_detail:
        raise ProviderContractError("provider cached-token aliases conflict", code="USAGE_DISPUTE")
    if reasoning_direct is not None and reasoning_detail is not None and reasoning_direct != reasoning_detail:
        raise ProviderContractError("provider reasoning-token aliases conflict", code="USAGE_DISPUTE")
    cached = cached_direct if cached_direct is not None else cached_detail or 0
    reasoning = reasoning_direct if reasoning_direct is not None else reasoning_detail or 0
    if cached > prompt_total or reasoning > completion_total:
        raise ProviderContractError("provider usage details exceed their totals", code="USAGE_DISPUTE")
    envelope = TokenEnvelope(
        input_tokens=prompt_total - cached,
        cache_read_tokens=cached,
        output_tokens=completion_total - reasoning,
        reasoning_tokens=reasoning,
    )
    if "total_tokens" in value:
        supplied_total = _raw_usage_count(value["total_tokens"])
        if supplied_total != prompt_total + completion_total or supplied_total != sum(envelope.to_mapping().values()):
            raise ProviderContractError("provider usage total is inconsistent", code="USAGE_DISPUTE")
    return normalize_usage(envelope.to_mapping())


def usage_component_totals(value: Mapping[str, Any]) -> dict[str, int]:
    """Return authoritative family totals derived from the envelope."""

    envelope = TokenEnvelope.from_mapping(value, require_positive=True)
    return {
        "input_total_tokens": envelope.input_family_tokens,
        "output_total_tokens": envelope.output_family_tokens,
    }


__all__ = [
    "CredentialRef", "PricingSnapshot", "ProviderCapabilities", "ProviderContractError", "ProviderProfile",
    "TOKEN_COMPONENTS", "TOKEN_CAP_KEYS", "TokenEnvelope", "assert_token_envelope_within_caps",
    "normalize_openai_compatible_usage", "normalize_usage", "token_envelope_within_caps", "usage_component_totals",
]
