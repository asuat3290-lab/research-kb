"""MR-2B1 production-provider security boundary.

This module contains the provider-neutral pieces that are safe to exercise
offline.  The default factory remains disabled.  A real HTTPS connector and
resolver must be injected explicitly by the later live stage; no import,
CLI command, or readiness check creates either one.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from ...policy import Actor
from ..contract import canonical_json, canonical_sha256, make_stable_id
from .contract import CredentialRef, ProviderContractError, ProviderProfile
from .transport import (
    BoundHostEnvironmentCredentialResolver,
    DisabledLiveTransport,
    ProviderTransportError,
    SecureEnvironmentCredentialResolver,
    TransportResponse,
)


LIVE_EXECUTION_MODE = "live_https"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CRLF_RE = re.compile(r"[\r\n]")
_ENV_REF_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_FORBIDDEN_HEADER_NAMES = {
    "authorization", "cookie", "proxy-authorization", "host", "connection",
    "transfer-encoding", "content-length",
}
_ALLOWED_REQUEST_HEADERS = {"content-type", "accept", "idempotency-key"}
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_LIVE_PERMIT_TOKEN = object()

# These codes are deliberately shared by the live transport and the adapter.
# A failure with one of these codes is known not to have crossed the physical
# HTTP connector boundary.  ``DNS_RESULT_INVALID`` is retained only as a
# compatibility spelling for pre-MR-4B1B callers; new code emits the more
# specific DNS codes below.
DNS_ERROR_CODES = frozenset({
    "DNS_RESOLUTION_FAILED",
    "DNS_RESULT_EMPTY",
    "DNS_CANDIDATE_LIMIT_EXCEEDED",
    "DNS_ADDRESS_INVALID",
    "DNS_RESULT_INVALID",
    "SSRF_ADDRESS_BLOCKED",
})
PRE_SEND_ERROR_CODES = frozenset({
    *DNS_ERROR_CODES,
    "DNS_AUDIT_FAILED",
    "CREDENTIAL_RESOLUTION_FAILED",
    "CREDENTIAL_RESOLUTION_DISABLED",
    "CREDENTIAL_RESOLUTION_RETRY_FORBIDDEN",
    "CREDENTIAL_REFERENCE_FORBIDDEN",
    "CREDENTIAL_REFERENCE_INVALID",
    "CREDENTIAL_REFERENCE_BINDING_MISMATCH",
    "LIVE_CREDENTIAL_RESOLVER_INJECTION_FORBIDDEN",
    "REQUEST_TOO_LARGE",
    "REQUEST_JSON_INVALID",
    "REQUEST_PAYLOAD_FORBIDDEN",
    "REQUEST_HEADER_FORBIDDEN",
    "REQUEST_HEADER_DUPLICATE",
    "REQUEST_HEADER_INVALID",
    "LIVE_PROVIDER_DISABLED",
    "LIVE_PERMIT_INVALID",
    "LIVE_PERMIT_VALIDATION_REQUIRED",
    "LIVE_PERMIT_BINDING_MISMATCH",
    "LIVE_NETWORK_POLICY_BINDING_MISMATCH",
    "LIVE_PROFILE_NOT_REGISTERED",
    "LIVE_PROFILE_BINDING_MISMATCH",
    "LIVE_TRANSPORT_FACTORY_INVALID",
    "HTTP_BOUNDARY_CALLBACK_FAILED",
    "HTTP_BOUNDARY_ALREADY_CROSSED",
    "REDIRECT_FORBIDDEN",
})


def _safe_text(value: Any, name: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or _CRLF_RE.search(value):
        raise ProviderContractError(f"{name} is invalid")
    return value


def _hash(value: Any, name: str) -> str:
    text = _safe_text(value, name, maximum=64).lower()
    if not _SHA256_RE.fullmatch(text):
        raise ProviderContractError(f"{name} must be a SHA-256 hash")
    return text


def _positive_int(value: Any, name: str, *, maximum: int = 2_000_000_000, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if allow_zero else 1) or value > maximum:
        raise ProviderContractError(f"{name} is invalid")
    return int(value)


@dataclass(frozen=True, repr=False)
class LiveNetworkAuthorization:
    """The server-owned, hash-only authority for one future HTTPS send."""

    authorization_id: str
    run_id: str
    project_id: str
    charter_hash: str
    profile_hash: str
    provider_name: str
    model_identity: str
    endpoint_origin_hash: str
    endpoint_path_policy_hash: str
    network_policy_hash: str
    credential_ref_hash: str
    pricing_hash: str
    budget_hash: str
    grant_id: str
    max_provider_calls: int
    max_input_tokens: int
    max_output_tokens: int
    max_cache_read_tokens: int
    max_reasoning_tokens: int
    max_cost_units: int
    issued_at: str
    expires_at: str
    reason_hash: str
    execution_mode: str = LIVE_EXECUTION_MODE
    authorization_hash: str = ""

    def __post_init__(self) -> None:
        for value, name in (
            (self.authorization_id, "authorization_id"), (self.run_id, "run_id"),
            (self.project_id, "project_id"), (self.model_identity, "model_identity"),
            (self.grant_id, "grant_id"), (self.issued_at, "issued_at"),
            (self.expires_at, "expires_at"),
        ):
            _safe_text(value, name)
        _safe_text(self.provider_name, "provider_name")
        for value, name in (
            (self.charter_hash, "charter_hash"), (self.profile_hash, "profile_hash"),
            (self.endpoint_origin_hash, "endpoint_origin_hash"),
            (self.endpoint_path_policy_hash, "endpoint_path_policy_hash"),
            (self.network_policy_hash, "network_policy_hash"),
            (self.credential_ref_hash, "credential_ref_hash"),
            (self.pricing_hash, "pricing_hash"), (self.budget_hash, "budget_hash"),
            (self.reason_hash, "reason_hash"),
        ):
            _hash(value, name)
        if self.execution_mode != LIVE_EXECUTION_MODE:
            raise ProviderContractError("live execution mode is invalid")
        for value, name in (
            (self.max_provider_calls, "max_provider_calls"),
            (self.max_input_tokens, "max_input_tokens"),
            (self.max_output_tokens, "max_output_tokens"),
            (self.max_cache_read_tokens, "max_cache_read_tokens"),
            (self.max_reasoning_tokens, "max_reasoning_tokens"),
            (self.max_cost_units, "max_cost_units"),
        ):
            _positive_int(value, name, allow_zero=name != "max_provider_calls")
        expected = canonical_sha256(self.to_mapping(include_hash=False))
        if self.authorization_hash and self.authorization_hash.lower() != expected:
            raise ProviderContractError("live authorization hash is not canonical")
        object.__setattr__(self, "authorization_hash", expected)

    def to_mapping(self, *, include_hash: bool = True) -> dict[str, Any]:
        value = {
            "authorization_id": self.authorization_id, "run_id": self.run_id,
            "project_id": self.project_id, "charter_hash": self.charter_hash,
            "profile_hash": self.profile_hash, "provider_name": self.provider_name,
            "model_identity": self.model_identity,
            "endpoint_origin_hash": self.endpoint_origin_hash,
            "endpoint_path_policy_hash": self.endpoint_path_policy_hash,
            "network_policy_hash": self.network_policy_hash,
            "credential_ref_hash": self.credential_ref_hash,
            "pricing_hash": self.pricing_hash, "budget_hash": self.budget_hash,
            "grant_id": self.grant_id, "max_provider_calls": self.max_provider_calls,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_cache_read_tokens": self.max_cache_read_tokens,
            "max_reasoning_tokens": self.max_reasoning_tokens,
            "max_cost_units": self.max_cost_units, "issued_at": self.issued_at,
            "expires_at": self.expires_at, "reason_hash": self.reason_hash,
            "execution_mode": self.execution_mode,
        }
        if include_hash:
            value["authorization_hash"] = self.authorization_hash
        return value

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "LiveNetworkAuthorization":
        if not isinstance(value, Mapping):
            raise ProviderContractError("live authorization must be an object")
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        if set(value) - allowed:
            raise ProviderContractError("live authorization contains unsupported fields")
        return cls(**dict(value))

    def __repr__(self) -> str:
        return f"LiveNetworkAuthorization(authorization_id={self.authorization_id!r}, authorization_hash={self.authorization_hash!r}, execution_mode='live_https')"


@dataclass(frozen=True, repr=False)
class LiveDispatchPermit:
    """A single server-issued physical-send capability.

    The private authority token is deliberately absent from serialized data.
    A caller can construct a Python object with similar-looking fields, but
    the production transport rejects it before DNS or credential resolution.
    The control store additionally revalidates every binding against the
    current projections and fencing lease.
    """

    permit_id: str
    authorization_id: str
    consumption_id: str
    run_id: str
    project_id: str
    grant_id: str
    grant_consumption_id: str
    profile_hash: str
    provider_name: str
    model_identity: str
    pricing_hash: str
    budget_hash: str
    claim_id: str
    attempt_id: str
    request_hash: str
    wire_request_hash: str
    intent_hash: str
    logical_call_id: str
    idempotency_key_hash: str
    endpoint_origin_hash: str
    endpoint_path_policy_hash: str
    network_policy_hash: str
    credential_ref_hash: str
    fencing_token: int
    worker_id: str
    worker_session: str
    created_at: str
    expires_at: str
    permit_hash: str = ""
    state: str = "ready"
    _authority_token: object = field(default=None, repr=False, compare=False)

    _STATES = frozenset({"ready", "send_started", "settled", "failed", "unknown", "disputed", "revoked", "expired"})

    def __post_init__(self) -> None:
        for value, name in (
            (self.permit_id, "permit_id"), (self.authorization_id, "authorization_id"),
            (self.consumption_id, "consumption_id"), (self.run_id, "run_id"),
            (self.project_id, "project_id"), (self.grant_id, "grant_id"),
            (self.grant_consumption_id, "grant_consumption_id"), (self.claim_id, "claim_id"),
            (self.attempt_id, "attempt_id"), (self.logical_call_id, "logical_call_id"),
            (self.worker_id, "worker_id"), (self.worker_session, "worker_session"),
            (self.created_at, "created_at"), (self.expires_at, "expires_at"),
        ):
            _safe_text(value, name)
        _safe_text(self.provider_name, "provider_name")
        for value, name in (
            (self.profile_hash, "profile_hash"), (self.pricing_hash, "pricing_hash"),
            (self.budget_hash, "budget_hash"), (self.request_hash, "request_hash"),
            (self.wire_request_hash, "wire_request_hash"), (self.intent_hash, "intent_hash"),
            (self.idempotency_key_hash, "idempotency_key_hash"),
            (self.endpoint_origin_hash, "endpoint_origin_hash"),
            (self.endpoint_path_policy_hash, "endpoint_path_policy_hash"),
            (self.network_policy_hash, "network_policy_hash"),
            (self.credential_ref_hash, "credential_ref_hash"),
        ):
            _hash(value, name)
        if isinstance(self.fencing_token, bool) or not isinstance(self.fencing_token, int) or self.fencing_token < 1:
            raise ProviderContractError("permit fencing token is invalid")
        if self.state not in self._STATES:
            raise ProviderContractError("permit state is invalid")
        hash_basis = self.to_mapping(include_hash=False, include_state=False)
        # The permit ID is derived from this hash, so the server uses the
        # fixed pending marker for the canonical identity calculation.
        hash_basis["permit_id"] = "pending"
        expected = canonical_sha256(hash_basis)
        if self.permit_hash and self.permit_hash.lower() != expected:
            raise ProviderContractError("permit hash is not canonical")
        object.__setattr__(self, "permit_hash", expected)

    def to_mapping(self, *, include_hash: bool = True, include_state: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "permit_id": self.permit_id, "authorization_id": self.authorization_id,
            "consumption_id": self.consumption_id, "run_id": self.run_id,
            "project_id": self.project_id, "grant_id": self.grant_id,
            "grant_consumption_id": self.grant_consumption_id, "profile_hash": self.profile_hash,
            "provider_name": self.provider_name, "model_identity": self.model_identity,
            "pricing_hash": self.pricing_hash, "budget_hash": self.budget_hash,
            "claim_id": self.claim_id, "attempt_id": self.attempt_id,
            "request_hash": self.request_hash, "wire_request_hash": self.wire_request_hash,
            "intent_hash": self.intent_hash, "logical_call_id": self.logical_call_id,
            "idempotency_key_hash": self.idempotency_key_hash,
            "endpoint_origin_hash": self.endpoint_origin_hash,
            "endpoint_path_policy_hash": self.endpoint_path_policy_hash,
            "network_policy_hash": self.network_policy_hash,
            "credential_ref_hash": self.credential_ref_hash,
            "fencing_token": self.fencing_token, "worker_id": self.worker_id,
            "worker_session": self.worker_session, "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        if include_state:
            value["state"] = self.state
        if include_hash:
            value["permit_hash"] = self.permit_hash
        return value

    @classmethod
    def _from_server_mapping(cls, value: Mapping[str, Any]) -> "LiveDispatchPermit":
        if not isinstance(value, Mapping):
            raise ProviderContractError("live dispatch permit must be an object")
        allowed = set(cls.__dataclass_fields__) - {"_authority_token"}
        if set(value) - allowed:
            raise ProviderContractError("live dispatch permit contains unsupported fields")
        return cls(**dict(value), _authority_token=_LIVE_PERMIT_TOKEN)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "LiveDispatchPermit":
        raise ProviderContractError("live dispatch permits are server-owned")

    def _is_server_owned(self) -> bool:
        return self._authority_token is _LIVE_PERMIT_TOKEN

    def __repr__(self) -> str:
        return f"LiveDispatchPermit(permit_id={self.permit_id!r}, permit_hash={self.permit_hash!r}, state={self.state!r})"


_NETWORK_POLICY_ALLOWED = {
    "policy_version", "allowed_schemes", "allow_redirects", "allow_proxy_env",
    "resolve_all_candidates", "reject_private_addresses", "max_dns_candidates",
    "max_request_bytes", "max_response_bytes", "max_json_depth", "timeout_ms",
}

_DEFAULT_MAX_DNS_CANDIDATES = 4
_MAX_ALLOWED_DNS_CANDIDATES = 16


def normalize_network_policy(value: Mapping[str, Any] | None) -> dict[str, Any]:
    raw = {} if value is None else value
    if not isinstance(raw, Mapping) or set(raw) - _NETWORK_POLICY_ALLOWED:
        raise ProviderContractError("network policy contains unsupported fields")
    schemes = raw.get("allowed_schemes", ["https"])
    if not isinstance(schemes, (list, tuple)) or list(schemes) != ["https"]:
        raise ProviderContractError("network policy must allow HTTPS only")
    result = {
        "policy_version": _safe_text(raw.get("policy_version", "mr2b1/v1"), "policy_version", maximum=32),
        "allowed_schemes": ["https"],
        "allow_redirects": False,
        "allow_proxy_env": False,
        "resolve_all_candidates": True,
        "reject_private_addresses": True,
        # Keep the historical default at four.  A new policy may opt into a
        # bounded higher cap, but normalization never accepts a value above
        # the reviewed sixteen-candidate ceiling.
        "max_dns_candidates": _DEFAULT_MAX_DNS_CANDIDATES,
        "max_request_bytes": 1_000_000,
        "max_response_bytes": 4_000_000,
        "max_json_depth": 16,
        "timeout_ms": 120_000,
    }
    required_boolean_values = {
        "allow_redirects": False,
        "allow_proxy_env": False,
        "resolve_all_candidates": True,
        "reject_private_addresses": True,
    }
    for key, expected in required_boolean_values.items():
        if key in raw and (not isinstance(raw[key], bool) or raw[key] is not expected):
            raise ProviderContractError(f"network policy {key} has an unsafe value")
    for key in ("max_dns_candidates", "max_request_bytes", "max_response_bytes", "max_json_depth", "timeout_ms"):
        if key in raw:
            maximum = _MAX_ALLOWED_DNS_CANDIDATES if key == "max_dns_candidates" else 10_000_000
            result[key] = _positive_int(raw[key], f"network policy {key}", maximum=maximum)
    return result


def network_policy_hash(value: Mapping[str, Any] | None) -> str:
    return canonical_sha256(normalize_network_policy(value))


def credential_reference_hash(reference: CredentialRef | Mapping[str, Any]) -> str:
    ref = reference if isinstance(reference, CredentialRef) else CredentialRef.from_mapping(reference)
    return canonical_sha256(ref.to_mapping())


def endpoint_hashes(origin: str, path_policy: str) -> tuple[str, str]:
    normalized_origin, normalized_path = validate_endpoint_static(origin, path_policy)
    return canonical_sha256(normalized_origin), canonical_sha256(normalized_path)


def validate_endpoint_static(origin: str, path_policy: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(_safe_text(origin, "endpoint_origin"))
    except ValueError as exc:
        raise ProviderContractError("endpoint origin is invalid") from exc
    if parsed.scheme.lower() != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ProviderContractError("endpoint origin must be a credential-free HTTPS origin")
    if not parsed.hostname:
        raise ProviderContractError("endpoint origin host is missing")
    try:
        host = parsed.hostname.encode("ascii").decode("ascii").lower()
    except UnicodeEncodeError as exc:
        raise ProviderContractError("endpoint origin host must be ASCII") from exc
    if host == "localhost" or host.endswith(".local"):
        raise ProviderContractError("endpoint origin host is not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified):
        raise ProviderContractError("endpoint origin address is not allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProviderContractError("endpoint origin port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ProviderContractError("endpoint origin port is invalid")
    path = _safe_text(path_policy, "endpoint_path_policy", maximum=256)
    if not path.startswith("/") or "?" in path or "#" in path or "\\" in path:
        raise ProviderContractError("endpoint path policy is invalid")
    return f"https://{host}{f':{port}' if port else ''}", path.rstrip("/") or "/"


def _resolved_address_text(raw: Any) -> str:
    """Extract an address from either a plain value or a getaddrinfo sockaddr."""

    if isinstance(raw, str):
        return raw
    if isinstance(raw, (tuple, list)) and raw and isinstance(raw[0], str):
        # IPv4 sockaddr is (host, port); IPv6 sockaddr is
        # (host, port, flowinfo, scopeid).  Only the host is retained.
        return raw[0]
    raise ProviderTransportError("DNS_ADDRESS_INVALID", "DNS resolution returned a malformed address", dispatch_known=True)


def _resolved_address_stats(addresses: Any) -> tuple[int, int, int]:
    """Return bounded counts without ever persisting the address values."""

    try:
        values = list(addresses or ())
    except Exception:
        return 0, 0, 0
    ipv4 = 0
    ipv6 = 0
    for raw in values:
        try:
            address = ipaddress.ip_address(_resolved_address_text(raw))
        except Exception:
            continue
        if address.version == 4:
            ipv4 += 1
        else:
            ipv6 += 1
    return len(values), ipv4, ipv6


def validate_resolved_addresses(addresses: Sequence[str], *, max_candidates: int = _DEFAULT_MAX_DNS_CANDIDATES) -> tuple[str, ...]:
    """Normalize all resolver candidates and apply SSRF checks to all of them."""

    try:
        values = list(addresses or ())
    except Exception as exc:
        raise ProviderTransportError("DNS_ADDRESS_INVALID", "DNS resolution returned a malformed address collection", dispatch_known=True) from exc
    if not values:
        raise ProviderTransportError("DNS_RESULT_EMPTY", "DNS resolution returned no candidates", dispatch_known=True)
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= _MAX_ALLOWED_DNS_CANDIDATES:
        raise ProviderTransportError("DNS_CANDIDATE_LIMIT_EXCEEDED", "DNS candidate policy is invalid", dispatch_known=True)
    normalized: set[str] = set()
    for raw in values:
        try:
            address = ipaddress.ip_address(_resolved_address_text(raw))
        except ProviderTransportError:
            raise
        except (TypeError, ValueError) as exc:
            raise ProviderTransportError("DNS_ADDRESS_INVALID", "DNS resolution returned an invalid address", dispatch_known=True) from exc
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified or not address.is_global:
            raise ProviderTransportError("SSRF_ADDRESS_BLOCKED", "DNS resolution returned a blocked address", dispatch_known=True)
        normalized.add(str(address))
    if len(normalized) > max_candidates:
        raise ProviderTransportError("DNS_CANDIDATE_LIMIT_EXCEEDED", "DNS resolution returned too many candidates", dispatch_known=True)
    return tuple(sorted(normalized, key=lambda value: (ipaddress.ip_address(value).version, value)))


class DNSResolver(Protocol):
    lookup_count: int

    def resolve(self, host: str, port: int) -> Sequence[str]:
        ...


class HTTPSConnector(Protocol):
    network_call_count: int

    def request(self, *, host: str, origin: str, path: str, address: str, port: int, body: bytes, headers: Mapping[str, str], timeout_ms: int, max_response_bytes: int) -> TransportResponse:
        ...


class InjectedDNSResolver:
    """Deterministic DNS seam; it never calls the operating-system resolver."""

    def __init__(self, answers: Mapping[str, Sequence[str]]) -> None:
        self.answers = {str(key): tuple(value) for key, value in answers.items()}
        self.lookup_count = 0

    def resolve(self, host: str, port: int) -> Sequence[str]:
        self.lookup_count += 1
        return self.answers.get(host, ())


class StdlibDNSResolver:
    def __init__(self) -> None:
        self.lookup_count = 0

    def resolve(self, host: str, port: int) -> Sequence[str]:
        self.lookup_count += 1
        return tuple(item[4] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))


class InjectedHTTPSConnector:
    """Deterministic HTTPS seam; it never opens a socket."""

    def __init__(self, response: TransportResponse | None = None, *, error: Exception | None = None) -> None:
        self.response = response or TransportResponse(200, b"{}", {"content-type": "application/json"}, "injected-provider-call", True)
        self.error = error
        self.network_call_count = 0
        self.requests: list[dict[str, Any]] = []

    def request(self, *, host: str, origin: str, path: str, address: str, port: int, body: bytes, headers: Mapping[str, str], timeout_ms: int, max_response_bytes: int) -> TransportResponse:
        self.network_call_count += 1
        # The injected connector receives the credential-bearing wire header
        # so a fixture can model the final request, but it must never retain
        # that value in its request transcript.
        safe_headers = {
            str(key).lower(): "[redacted]" if str(key).casefold() == "authorization" else str(value)
            for key, value in headers.items()
            if str(key).casefold() != "authorization"
        }
        self.requests.append({"host": host, "origin": origin, "path": path, "address": address, "port": port, "body_hash": hashlib.sha256(body).hexdigest(), "headers": safe_headers, "timeout_ms": timeout_ms})
        if self.error is not None:
            raise self.error
        return self.response


class StdlibHTTPSConnector:
    """Provider-neutral HTTPS POST connector with explicit DNS pinning."""

    def __init__(self) -> None:
        self.network_call_count = 0

    def request(self, *, host: str, origin: str, path: str, address: str, port: int, body: bytes, headers: Mapping[str, str], timeout_ms: int, max_response_bytes: int) -> TransportResponse:
        self.network_call_count += 1
        timeout = timeout_ms / 1000.0
        raw_socket = None
        secure_socket = None
        connection = None
        try:
            raw_socket = socket.create_connection((address, port), timeout=timeout)
            context = ssl.create_default_context()
            secure_socket = context.wrap_socket(raw_socket, server_hostname=host)
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
            connection.sock = secure_socket
            connection.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", host if port == 443 else f"{host}:{port}")
            for key, value in headers.items():
                connection.putheader(key, value)
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders()
            connection.send(body)
            response = connection.getresponse()
            payload = response.read(max_response_bytes + 1)
            if len(payload) > max_response_bytes:
                raise ProviderTransportError("RESPONSE_TOO_LARGE", "provider response exceeded its bounded limit", dispatch_known=True)
            safe_headers = {str(key).lower(): str(value) for key, value in response.getheaders() if str(key).lower() in {"content-type", "x-request-id", "retry-after"}}
            provider_call_id = safe_headers.get("x-request-id", "")
            return TransportResponse(response.status, payload, safe_headers, provider_call_id, True)
        except socket.timeout as exc:
            raise ProviderTransportError("PROVIDER_TIMEOUT", "provider request outcome is unknown", dispatch_known=False) from exc
        except ProviderTransportError:
            raise
        except OSError as exc:
            raise ProviderTransportError("PROVIDER_CONNECTION_FAILED", "provider connection failed", dispatch_known=False) from exc
        finally:
            if connection is not None:
                connection.close()
            elif secure_socket is not None:
                secure_socket.close()
            elif raw_socket is not None:
                raw_socket.close()


class _DisabledDNSResolver:
    lookup_count = 0

    def resolve(self, host: str, port: int) -> Sequence[str]:
            raise ProviderTransportError("LIVE_PROVIDER_DISABLED", "live provider DNS is disabled", dispatch_known=True)


class OpenAICompatibleHTTPSLiveTransport:
    """HTTPS transport bound to one server-issued physical-send permit."""

    hermetic = False

    def __init__(self, *, endpoint_origin: str, endpoint_path_policy: str, credential_ref: CredentialRef, network_policy: Mapping[str, Any], credential_resolver: Any, permit: LiveDispatchPermit, permit_validator: Callable[[LiveDispatchPermit], Mapping[str, Any] | None], dns_resolver: DNSResolver | None = None, connector: HTTPSConnector | None = None, network_event_callback: Callable[[str, Mapping[str, Any]], None] | None = None, send_boundary_callback: Callable[[LiveDispatchPermit], None] | None = None) -> None:
        self.endpoint_origin, self.endpoint_path_policy = validate_endpoint_static(endpoint_origin, endpoint_path_policy)
        self.credential_ref = credential_ref if isinstance(credential_ref, CredentialRef) else CredentialRef.from_mapping(credential_ref)
        self.network_policy = normalize_network_policy(network_policy)
        self.credential_resolver = credential_resolver
        if not isinstance(permit, LiveDispatchPermit) or not permit._is_server_owned():
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "live HTTPS transport requires a server-issued permit", dispatch_known=True)
        if not callable(permit_validator):
            raise ProviderTransportError("LIVE_PERMIT_VALIDATION_REQUIRED", "live HTTPS transport requires an authority validator", dispatch_known=True)
        self.permit = permit
        self.permit_validator = permit_validator
        self.dns_resolver = dns_resolver or _DisabledDNSResolver()
        self.connector = connector
        if network_event_callback is not None and not callable(network_event_callback):
            raise ProviderTransportError("LIVE_AUDIT_CALLBACK_INVALID", "live network event callback is invalid", dispatch_known=True)
        if send_boundary_callback is not None and not callable(send_boundary_callback):
            raise ProviderTransportError("LIVE_BOUNDARY_CALLBACK_INVALID", "live send boundary callback is invalid", dispatch_known=True)
        self.network_event_callback = network_event_callback
        self.send_boundary_callback = send_boundary_callback
        self.network_call_count = 0
        self.credential_read_count = 0
        self.credential_resolution_attempts = 0
        self.credential_reads_succeeded = 0
        self.dns_lookup_count = 0
        self._physical_call_started = False
        self._boundary_crossed = False
        self._send_lock = threading.Lock()

    def _audit(self, event_type: str, payload: Mapping[str, Any]) -> None:
        callback = self.network_event_callback
        if callback is None:
            return
        try:
            callback(event_type, dict(payload))
        except ProviderTransportError:
            raise
        except Exception as exc:
            raise ProviderTransportError("DNS_AUDIT_FAILED", "durable network audit failed", dispatch_known=True) from exc

    def _sync_credential_counters(self, *, succeeded: bool) -> None:
        resolver = self.credential_resolver
        attempts = getattr(resolver, "credential_resolution_attempts", None)
        successes = getattr(resolver, "credential_reads_succeeded", None)
        if isinstance(attempts, int) and not isinstance(attempts, bool):
            self.credential_resolution_attempts = attempts
        else:
            self.credential_resolution_attempts = int(getattr(resolver, "read_count", self.credential_resolution_attempts))
        if isinstance(successes, int) and not isinstance(successes, bool):
            self.credential_reads_succeeded = successes
        elif succeeded:
            self.credential_reads_succeeded = int(getattr(resolver, "read_count", self.credential_reads_succeeded + 1))
        self.credential_read_count = self.credential_reads_succeeded

    def _credential_audit_payload(self, *, outcome: str, reason_code: str, policy_hash: str) -> dict[str, Any]:
        source_category = getattr(self.credential_resolver, "last_source_category", None)
        if source_category not in {"process_environment", "windows_user_environment"}:
            source_category = None
        return {
            "outcome": outcome,
            "reason_code": reason_code,
            "credential_ref_hash": credential_reference_hash(self.credential_ref),
            "policy_hash": policy_hash,
            "credential_resolution_attempts": self.credential_resolution_attempts,
            "credential_reads_succeeded": self.credential_reads_succeeded,
            "resolver_source_category": source_category,
        }

    def _cross_http_boundary(self, permit: LiveDispatchPermit) -> None:
        if self._boundary_crossed:
            raise ProviderTransportError("HTTP_BOUNDARY_ALREADY_CROSSED", "physical provider retry is forbidden", dispatch_known=False)
        callback = self.send_boundary_callback
        if callback is not None:
            try:
                callback(permit)
            except ProviderTransportError:
                raise
            except Exception as exc:
                raise ProviderTransportError("HTTP_BOUNDARY_CALLBACK_FAILED", "durable HTTP boundary callback failed", dispatch_known=True) from exc
        self._boundary_crossed = True

    def configure_boundary_callbacks(
        self,
        *,
        network_event_callback: Callable[[str, Mapping[str, Any]], None] | None = None,
        send_boundary_callback: Callable[[LiveDispatchPermit], None] | None = None,
    ) -> None:
        """Bind server-owned audit callbacks before the first send.

        The fixture bridge may receive an already-created transport, while the
        production factory binds callbacks in the constructor.  Both paths use
        the same transport-owned DNS/credential and HTTP-boundary ordering.
        Rebinding after any physical boundary is forbidden.
        """

        if self._physical_call_started or self._boundary_crossed:
            raise ProviderTransportError("HTTP_BOUNDARY_ALREADY_CROSSED", "transport callbacks cannot be rebound after send", dispatch_known=False)
        if network_event_callback is not None and not callable(network_event_callback):
            raise ProviderTransportError("LIVE_AUDIT_CALLBACK_INVALID", "live network event callback is invalid", dispatch_known=True)
        if send_boundary_callback is not None and not callable(send_boundary_callback):
            raise ProviderTransportError("LIVE_BOUNDARY_CALLBACK_INVALID", "live send boundary callback is invalid", dispatch_known=True)
        self.network_event_callback = network_event_callback
        self.send_boundary_callback = send_boundary_callback

    def bind_server_permit(self, permit: LiveDispatchPermit) -> None:
        """Bind a store-issued permit; forged objects are rejected."""

        if not isinstance(permit, LiveDispatchPermit) or not permit._is_server_owned():
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "live HTTPS transport requires a server-issued permit", dispatch_known=True)
        self.permit = permit

    def _require_permit(self) -> LiveDispatchPermit:
        permit = self.permit
        if not isinstance(permit, LiveDispatchPermit) or not permit._is_server_owned() or not callable(self.permit_validator):
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "live HTTPS send requires a server-issued permit and validator", dispatch_known=True)
        return permit

    def send(self, request: bytes, *, headers: Mapping[str, str], timeout_ms: int, idempotency_key: str) -> TransportResponse:
        if not self._send_lock.acquire(blocking=False):
            raise ProviderTransportError("PHYSICAL_CALL_RETRY_FORBIDDEN", "physical provider retry is forbidden", dispatch_known=False)
        try:
            return self._send_impl(request, headers=headers, timeout_ms=timeout_ms, idempotency_key=idempotency_key)
        finally:
            self._send_lock.release()

    def _send_impl(self, request: bytes, *, headers: Mapping[str, str], timeout_ms: int, idempotency_key: str) -> TransportResponse:
        if self._physical_call_started:
            raise ProviderTransportError("PHYSICAL_CALL_RETRY_FORBIDDEN", "physical provider retry is forbidden", dispatch_known=False)
        if not isinstance(request, bytes) or len(request) > int(self.network_policy["max_request_bytes"]):
            raise ProviderTransportError("REQUEST_TOO_LARGE", "provider request exceeded its bounded limit", dispatch_known=True)
        if not isinstance(idempotency_key, str) or not idempotency_key or _CRLF_RE.search(idempotency_key):
            raise ProviderTransportError("INVALID_IDEMPOTENCY_KEY", "provider idempotency key is invalid", dispatch_known=True)
        permit = self._require_permit()
        if permit.state != "send_started":
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "live HTTPS send requires a current send-start permit", dispatch_known=True)
        try:
            authority = self.permit_validator(permit)
        except ProviderTransportError:
            raise
        except Exception as exc:
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "live dispatch permit validation failed", dispatch_known=True) from exc
        if not isinstance(authority, Mapping) or authority.get("ok") is not True:
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "live dispatch permit is not currently valid", dispatch_known=True)
        expected_origin_hash, expected_path_hash = endpoint_hashes(self.endpoint_origin, self.endpoint_path_policy)
        if expected_origin_hash != permit.endpoint_origin_hash or expected_path_hash != permit.endpoint_path_policy_hash or network_policy_hash(self.network_policy) != permit.network_policy_hash or credential_reference_hash(self.credential_ref) != permit.credential_ref_hash:
            raise ProviderTransportError("LIVE_PERMIT_BINDING_MISMATCH", "live dispatch permit endpoint binding is invalid", dispatch_known=True)
        if hashlib.sha256(request).hexdigest() != permit.wire_request_hash:
            raise ProviderTransportError("LIVE_PERMIT_BINDING_MISMATCH", "live dispatch permit request binding is invalid", dispatch_known=True)
        if canonical_sha256(idempotency_key) != permit.idempotency_key_hash:
            raise ProviderTransportError("LIVE_PERMIT_BINDING_MISMATCH", "live dispatch permit idempotency binding is invalid", dispatch_known=True)
        try:
            import json
            request_value = json.loads(request.decode("utf-8"))
        except Exception as exc:
            raise ProviderTransportError("REQUEST_JSON_INVALID", "provider request JSON is invalid", dispatch_known=True) from exc

        def inspect_payload(value: Any) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    key_text = str(key)
                    if _CRLF_RE.search(key_text) or key_text.casefold() in _FORBIDDEN_HEADER_NAMES or key_text.casefold() in {"api_key", "apikey", "proxy_auth", "proxy-authorization"}:
                        raise ProviderTransportError("REQUEST_PAYLOAD_FORBIDDEN", "provider request contains forbidden credential or header material", dispatch_known=True)
                    inspect_payload(child)
            elif isinstance(value, (list, tuple)):
                for child in value:
                    inspect_payload(child)
        inspect_payload(request_value)
        if not isinstance(headers, Mapping):
            raise ProviderTransportError("REQUEST_HEADER_INVALID", "provider request headers are invalid", dispatch_known=True)
        safe_headers: dict[str, str] = {}
        for key, value in headers.items():
            if not isinstance(key, str):
                raise ProviderTransportError("REQUEST_HEADER_INVALID", "provider request header name is invalid", dispatch_known=True)
            key_text = key.lower()
            if key_text in _FORBIDDEN_HEADER_NAMES or key_text not in _ALLOWED_REQUEST_HEADERS:
                raise ProviderTransportError("REQUEST_HEADER_FORBIDDEN", "provider request header is not allowed", dispatch_known=True)
            if key_text in safe_headers:
                raise ProviderTransportError("REQUEST_HEADER_DUPLICATE", "provider request header is duplicated", dispatch_known=True)
            if not isinstance(value, str) or _CRLF_RE.search(value) or len(value) > 256:
                raise ProviderTransportError("REQUEST_HEADER_INVALID", "provider request header is invalid", dispatch_known=True)
            if key_text == "idempotency-key" and value != idempotency_key:
                raise ProviderTransportError("LIVE_PERMIT_BINDING_MISMATCH", "provider request idempotency header is invalid", dispatch_known=True)
            safe_headers[key_text] = value
        parsed = urlsplit(self.endpoint_origin)
        host = parsed.hostname or ""
        port = parsed.port or 443
        policy_hash = network_policy_hash(self.network_policy)
        max_candidates = int(self.network_policy["max_dns_candidates"])
        self._audit(
            "transport_preflight_started",
            {
                "attempt_id": permit.attempt_id,
                "claim_id": permit.claim_id,
                "request_hash": permit.request_hash,
                "idempotency_key_hash": permit.idempotency_key_hash,
                "policy_hash": policy_hash,
            },
        )
        self._audit("dns_resolution_started", {"host": host, "port": port, "max_dns_candidates": max_candidates, "policy_hash": policy_hash})
        addresses: Sequence[Any] = ()
        try:
            addresses = tuple(self.dns_resolver.resolve(host, port))
            self.dns_lookup_count = int(getattr(self.dns_resolver, "lookup_count", self.dns_lookup_count + 1))
            safe_addresses = validate_resolved_addresses(addresses, max_candidates=max_candidates)
        except ProviderTransportError as exc:
            self.dns_lookup_count = int(getattr(self.dns_resolver, "lookup_count", self.dns_lookup_count + 1))
            code = exc.code if exc.code in DNS_ERROR_CODES else "DNS_RESOLUTION_FAILED"
            candidate_count, ipv4_count, ipv6_count = _resolved_address_stats(addresses)
            self._audit("dns_resolution_completed", {"host": host, "candidate_count": candidate_count, "ipv4_count": ipv4_count, "ipv6_count": ipv6_count, "reason_code": code, "policy_hash": policy_hash, "resolver_outcome_hash": canonical_sha256({"reason_code": code, "candidate_count": candidate_count})})
            if code != exc.code:
                raise ProviderTransportError(code, "DNS resolution failed", dispatch_known=True) from exc
            raise
        except Exception as exc:
            self.dns_lookup_count = int(getattr(self.dns_resolver, "lookup_count", self.dns_lookup_count + 1))
            candidate_count, ipv4_count, ipv6_count = _resolved_address_stats(addresses)
            code = "DNS_RESOLUTION_FAILED"
            self._audit("dns_resolution_completed", {"host": host, "candidate_count": candidate_count, "ipv4_count": ipv4_count, "ipv6_count": ipv6_count, "reason_code": code, "policy_hash": policy_hash, "resolver_outcome_hash": canonical_sha256({"reason_code": code, "exception_type": type(exc).__name__})})
            raise ProviderTransportError(code, "DNS resolution failed", dispatch_known=True) from exc
        candidate_count, ipv4_count, ipv6_count = _resolved_address_stats(addresses)
        self._audit("dns_resolution_completed", {"host": host, "candidate_count": candidate_count, "ipv4_count": ipv4_count, "ipv6_count": ipv6_count, "reason_code": "DNS_RESOLUTION_SUCCEEDED", "policy_hash": policy_hash, "resolver_outcome_hash": canonical_sha256({"addresses": safe_addresses})})
        self._audit("credential_resolution_started", {"credential_ref_hash": credential_reference_hash(self.credential_ref), "policy_hash": policy_hash})
        try:
            secret = self.credential_resolver.resolve(self.credential_ref)
        except ProviderTransportError as exc:
            self._sync_credential_counters(succeeded=False)
            self._audit("credential_resolution_completed", self._credential_audit_payload(outcome="failed", reason_code="CREDENTIAL_RESOLUTION_FAILED", policy_hash=policy_hash))
            raise ProviderTransportError("CREDENTIAL_RESOLUTION_FAILED", "provider credential could not be resolved", dispatch_known=True) from exc
        except Exception as exc:
            self._sync_credential_counters(succeeded=False)
            self._audit("credential_resolution_completed", self._credential_audit_payload(outcome="failed", reason_code="CREDENTIAL_RESOLUTION_FAILED", policy_hash=policy_hash))
            raise ProviderTransportError("CREDENTIAL_RESOLUTION_FAILED", "provider credential could not be resolved", dispatch_known=True) from exc
        self._sync_credential_counters(succeeded=True)
        if not isinstance(secret, str) or not secret or len(secret) > 8192 or _CRLF_RE.search(secret):
            self.credential_reads_succeeded = 0
            self.credential_read_count = 0
            self._audit("credential_resolution_completed", self._credential_audit_payload(outcome="failed", reason_code="CREDENTIAL_RESOLUTION_FAILED", policy_hash=policy_hash))
            raise ProviderTransportError("CREDENTIAL_RESOLUTION_FAILED", "provider credential could not be resolved", dispatch_known=True)
        self._audit("credential_resolution_completed", self._credential_audit_payload(outcome="succeeded", reason_code="CREDENTIAL_RESOLUTION_SUCCEEDED", policy_hash=policy_hash))
        safe_headers.update({"accept": safe_headers.get("accept", "application/json"), "content-type": safe_headers.get("content-type", "application/json"), "idempotency-key": idempotency_key, "authorization": f"Bearer {secret}"})
        if self.connector is None:
            raise ProviderTransportError("LIVE_PROVIDER_DISABLED", "live provider HTTPS connector is disabled", dispatch_known=True)
        self._cross_http_boundary(permit)
        self._physical_call_started = True
        self.network_call_count += 1
        try:
            response = self.connector.request(host=host, origin=self.endpoint_origin, path=self.endpoint_path_policy, address=safe_addresses[0], port=port, body=request, headers=safe_headers, timeout_ms=min(int(timeout_ms), int(self.network_policy["timeout_ms"])), max_response_bytes=int(self.network_policy["max_response_bytes"]))
        except ProviderTransportError:
            raise
        except TimeoutError as exc:
            raise ProviderTransportError("PROVIDER_TIMEOUT", "provider request outcome is unknown", dispatch_known=False) from exc
        except Exception as exc:
            raise ProviderTransportError("PROVIDER_CONNECTION_FAILED", "provider connection failed", dispatch_known=False) from exc
        if response.status_code in _REDIRECT_CODES:
            raise ProviderTransportError("REDIRECT_FORBIDDEN", "provider redirects are forbidden", dispatch_known=True)
        if len(response.body_bytes()) > int(self.network_policy["max_response_bytes"]):
            raise ProviderTransportError("RESPONSE_TOO_LARGE", "provider response exceeded its bounded limit", dispatch_known=True)
        return response

    def query(self, *, idempotency_key: str) -> TransportResponse | None:
        raise ProviderTransportError("LIVE_RESULT_QUERY_DISABLED", "live provider result queries are disabled in MR-2B1")


ProductionHTTPSProviderTransport = OpenAICompatibleHTTPSLiveTransport
OpenAICompatibleHTTPSTransport = OpenAICompatibleHTTPSLiveTransport


def default_live_transport() -> DisabledLiveTransport:
    """The only transport returned by the current production-shaped factory."""

    return DisabledLiveTransport()


class LiveProviderTransportFactory:
    """Production-shaped factory kept disabled until MR-2B1-LIVE."""

    @staticmethod
    def create(*args: Any, **kwargs: Any) -> DisabledLiveTransport:
        return default_live_transport()

    @staticmethod
    def create_for_permit(*, profile: ProviderProfile, permit: LiveDispatchPermit, provider_store: Any, network_event_callback: Callable[[str, Mapping[str, Any]], None] | None = None, send_boundary_callback: Callable[[LiveDispatchPermit], None] | None = None, dns_resolver: DNSResolver | None = None, connector: HTTPSConnector | None = None, credential_resolver: Any | None = None, use_bound_host_credential_resolver: bool = False) -> OpenAICompatibleHTTPSLiveTransport:
        from .store import ProviderStore

        if not isinstance(profile, ProviderProfile) or not isinstance(permit, LiveDispatchPermit) or not permit._is_server_owned():
            raise ProviderTransportError("LIVE_PERMIT_INVALID", "production live factory requires a server-issued permit", dispatch_known=True)
        if not isinstance(provider_store, ProviderStore):
            raise ProviderTransportError("LIVE_STORE_REQUIRED", "production live factory requires the Max provider store", dispatch_known=True)
        try:
            registered = provider_store.get_profile(profile_hash=profile.profile_hash)
            binding = provider_store.get_run_binding(run_id=permit.run_id)
        except Exception as exc:
            raise ProviderTransportError("LIVE_PROFILE_NOT_REGISTERED", "production live factory requires a registered run-bound profile", dispatch_known=True) from exc
        if registered.profile_hash != profile.profile_hash or binding.get("profile_hash") != registered.profile_hash or binding.get("project_id") != permit.project_id or binding.get("model_identity") != registered.model_identity:
            raise ProviderTransportError("LIVE_PROFILE_BINDING_MISMATCH", "registered provider profile is not bound to the permit run", dispatch_known=True)
        profile = registered
        expected_origin_hash, expected_path_hash = endpoint_hashes(profile.endpoint_origin, profile.endpoint_path_policy)
        if permit.profile_hash != profile.profile_hash or permit.provider_name != profile.provider_name or permit.model_identity != profile.model_identity or permit.pricing_hash != profile.pricing.pricing_hash or permit.network_policy_hash != profile.network_policy_hash or permit.credential_ref_hash != credential_reference_hash(profile.credential_ref) or permit.endpoint_origin_hash != expected_origin_hash or permit.endpoint_path_policy_hash != expected_path_hash:
            raise ProviderTransportError("LIVE_PERMIT_BINDING_MISMATCH", "registered profile does not match the live permit", dispatch_known=True)
        # Production permit validation is a required control-store method,
        # never an optional getattr-based seam.  A missing implementation is
        # a release defect and fails before credential/DNS/transport setup.
        validator = provider_store.validate_live_dispatch_permit
        validator(permit)
        policy_record = provider_store.network_policy_status(network_policy_hash_value=profile.network_policy_hash)
        policy = policy_record.get("policy") if isinstance(policy_record, Mapping) else None
        if not isinstance(policy, Mapping) or network_policy_hash(policy) != profile.network_policy_hash:
            raise ProviderTransportError("LIVE_NETWORK_POLICY_BINDING_MISMATCH", "registered network policy does not match the live permit", dispatch_known=True)
        if use_bound_host_credential_resolver:
            if credential_resolver is not None:
                raise ProviderTransportError("LIVE_CREDENTIAL_RESOLVER_INJECTION_FORBIDDEN", "package-owned credential resolver is required", dispatch_known=True)
            credential_resolver = BoundHostEnvironmentCredentialResolver(
                profile.credential_ref,
                credential_reference_hash(profile.credential_ref),
            )
        elif credential_resolver is None:
            credential_resolver = SecureEnvironmentCredentialResolver(enabled=True)
        return OpenAICompatibleHTTPSLiveTransport(
            endpoint_origin=profile.endpoint_origin,
            endpoint_path_policy=profile.endpoint_path_policy,
            credential_ref=profile.credential_ref,
            network_policy=policy,
            credential_resolver=credential_resolver,
            permit=permit,
            permit_validator=validator,
            dns_resolver=dns_resolver or StdlibDNSResolver(),
            connector=connector or StdlibHTTPSConnector(),
            network_event_callback=network_event_callback,
            send_boundary_callback=send_boundary_callback,
        )


# The convergence capsule performs one bounded DNS lookup before the native
# live adapter is constructed.  The same resolver object must be supplied to
# the package-owned HTTPS transport so the transport cannot silently perform a
# second lookup.  This type is deliberately private and is accepted by the
# adapter/executor by nominal type, never by a caller-controlled marker
# attribute.  The formal CLI constructs it internally; it has no CLI injection
# surface.
class _ConvergenceLiveProviderTransportFactory(LiveProviderTransportFactory):
    __slots__ = ("_resolver", "_connector", "_credential_resolver")

    def __init__(
        self,
        resolver: DNSResolver,
        *,
        connector: HTTPSConnector | None = None,
        credential_resolver: Any | None = None,
    ) -> None:
        if not callable(getattr(resolver, "resolve", None)):
            raise TypeError("convergence transport factory requires a DNS resolver")
        self._resolver = resolver
        self._connector = connector
        self._credential_resolver = credential_resolver

    def create_for_permit(self, **kwargs: Any) -> OpenAICompatibleHTTPSLiveTransport:
        if self._credential_resolver is not None:
            connector = self._connector
            if type(connector) is not InjectedHTTPSConnector:
                raise ProviderTransportError("LIVE_CREDENTIAL_RESOLVER_INJECTION_FORBIDDEN", "explicit credential resolver requires the package-owned hermetic connector", dispatch_known=True)
        return LiveProviderTransportFactory.create_for_permit(
            **kwargs,
            dns_resolver=self._resolver,
            connector=self._connector,
            credential_resolver=self._credential_resolver,
            use_bound_host_credential_resolver=self._credential_resolver is None,
        )


def make_convergence_transport_factory(
    resolver: DNSResolver,
    *,
    connector: HTTPSConnector | None = None,
    credential_resolver: Any | None = None,
) -> LiveProviderTransportFactory:
    """Construct the package-owned one-shot convergence transport factory."""

    return _ConvergenceLiveProviderTransportFactory(
        resolver,
        connector=connector,
        credential_resolver=credential_resolver,
    )


def is_trusted_live_transport_factory(value: Any) -> bool:
    """Return whether *value* is one of the package-owned production types.

    Exact nominal type checks are intentional.  A user-defined subclass or an
    object that merely sets a ``convergence_owned`` flag must not cross the
    production adapter boundary.
    """

    return type(value) in {
        LiveProviderTransportFactory,
        _ConvergenceLiveProviderTransportFactory,
    }


ProductionProviderTransportFactory = LiveProviderTransportFactory


__all__ = [
    "DNSResolver", "DNS_ERROR_CODES", "PRE_SEND_ERROR_CODES", "InjectedDNSResolver", "InjectedHTTPSConnector", "LIVE_EXECUTION_MODE",
    "LiveNetworkAuthorization", "LiveDispatchPermit", "OpenAICompatibleHTTPSLiveTransport", "OpenAICompatibleHTTPSTransport",
    "ProductionHTTPSProviderTransport", "StdlibDNSResolver", "StdlibHTTPSConnector",
    "credential_reference_hash", "default_live_transport", "endpoint_hashes",
    "network_policy_hash", "normalize_network_policy", "validate_endpoint_static",
    "validate_resolved_addresses", "LiveProviderTransportFactory", "ProductionProviderTransportFactory",
    "is_trusted_live_transport_factory", "make_convergence_transport_factory",
]
