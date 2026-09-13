"""Dependency-injected provider transports.

There is intentionally no socket implementation in MR-2B0.  The only
transport that can dispatch is :class:`HermeticTransport`, which stays inside
the process.  The production-shaped transport is an explicit disabled
sentinel so accidental credentials or endpoints cannot cause network I/O.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from ..contract import canonical_json, canonical_sha256
from .contract import CredentialRef


class ProviderTransportError(RuntimeError):
    def __init__(self, code: str, message: str, *, dispatch_known: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.dispatch_known = dispatch_known


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    body: bytes | str | Mapping[str, Any]
    headers: Mapping[str, str] = None  # type: ignore[assignment]
    provider_call_id: str = ""
    dispatch_known: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int) or not 100 <= self.status_code <= 599:
            raise ProviderTransportError("INVALID_TRANSPORT_RESPONSE", "transport status is invalid")
        headers = dict(self.headers or {})
        if any("authorization" in str(key).casefold() or "cookie" in str(key).casefold() for key in headers):
            raise ProviderTransportError("INVALID_TRANSPORT_RESPONSE", "transport response contains forbidden credential headers")
        if not isinstance(self.dispatch_known, bool):
            raise ProviderTransportError("INVALID_TRANSPORT_RESPONSE", "transport dispatch_known is invalid")
        object.__setattr__(self, "headers", headers)
        if self.provider_call_id and (not isinstance(self.provider_call_id, str) or len(self.provider_call_id) > 256 or "\r" in self.provider_call_id or "\n" in self.provider_call_id):
            raise ProviderTransportError("INVALID_TRANSPORT_RESPONSE", "provider call ID is invalid")

    def body_bytes(self) -> bytes:
        if isinstance(self.body, bytes):
            return self.body
        if isinstance(self.body, str):
            return self.body.encode("utf-8")
        return canonical_json(self.body).encode("utf-8")

    @property
    def response_manifest(self) -> dict[str, Any]:
        body = self.body_bytes()
        return {
            "status_code": self.status_code,
            "provider_call_id": self.provider_call_id,
            "dispatch_known": self.dispatch_known,
            "content_type": next((value for key, value in self.headers.items() if str(key).casefold() == "content-type"), ""),
            "byte_count": len(body),
            "body_hash": __import__("hashlib").sha256(body).hexdigest(),
        }


class ProviderTransport(Protocol):
    network_call_count: int
    credential_read_count: int

    def send(
        self,
        request: bytes,
        *,
        headers: Mapping[str, str],
        timeout_ms: int,
        idempotency_key: str,
    ) -> TransportResponse:
        ...

    def query(self, *, idempotency_key: str) -> TransportResponse | None:
        ...


class HermeticTransport:
    """An in-memory transport with deterministic counters and response queue."""

    hermetic = True

    def __init__(
        self,
        responses: list[TransportResponse | Mapping[str, Any]] | None = None,
        *,
        handler: Callable[[bytes, Mapping[str, str], str], TransportResponse] | None = None,
    ) -> None:
        self._responses = list(responses or [])
        self._handler = handler
        self.requests: list[dict[str, Any]] = []
        self.network_call_count = 0
        self.credential_read_count = 0
        self.query_count = 0

    def enqueue(self, response: TransportResponse | Mapping[str, Any]) -> None:
        self._responses.append(response)

    @staticmethod
    def _coerce(value: TransportResponse | Mapping[str, Any]) -> TransportResponse:
        if isinstance(value, TransportResponse):
            return value
        if not isinstance(value, Mapping):
            raise ProviderTransportError("INVALID_TRANSPORT_RESPONSE", "hermetic response is invalid")
        allowed = {"status_code", "body", "headers", "provider_call_id", "dispatch_known"}
        if set(value) - allowed:
            raise ProviderTransportError("INVALID_TRANSPORT_RESPONSE", "hermetic response contains unsupported fields")
        return TransportResponse(value.get("status_code", 200), value.get("body", {}), value.get("headers", {}), value.get("provider_call_id", ""), value.get("dispatch_known", True))

    def send(self, request: bytes, *, headers: Mapping[str, str], timeout_ms: int, idempotency_key: str) -> TransportResponse:
        if not isinstance(request, bytes):
            raise ProviderTransportError("INVALID_TRANSPORT_REQUEST", "transport request must be bytes")
        if any(str(key).casefold() in {"authorization", "cookie", "proxy-authorization"} for key in headers):
            raise ProviderTransportError("CREDENTIAL_HEADER_FORBIDDEN", "credential headers are forbidden in hermetic transport")
        self.requests.append({"request_hash": canonical_sha256(request.decode("utf-8", errors="replace")), "byte_count": len(request), "timeout_ms": timeout_ms, "idempotency_key": idempotency_key})
        if self._handler is not None:
            response = self._handler(request, dict(headers), idempotency_key)
        elif self._responses:
            response = self._responses.pop(0)
        else:
            response = TransportResponse(200, {"id": "hermetic-call", "model": "", "choices": [], "usage": {"input_tokens": 1, "output_tokens": 1}})
        return self._coerce(response)

    def query(self, *, idempotency_key: str) -> TransportResponse | None:
        self.query_count += 1
        return None


class InjectedHermeticTransport(HermeticTransport):
    """Name used by callers that want to make the injection boundary explicit."""


class DisabledLiveTransport:
    """Production-shaped transport that can never open a socket in MR-2B0."""

    hermetic = False

    def __init__(self) -> None:
        self.network_call_count = 0
        self.credential_read_count = 0

    def send(self, request: bytes, *, headers: Mapping[str, str], timeout_ms: int, idempotency_key: str) -> TransportResponse:
        raise ProviderTransportError("LIVE_PROVIDER_DISABLED", "live provider transport is disabled in MR-2B0", dispatch_known=False)

    def query(self, *, idempotency_key: str) -> TransportResponse | None:
        raise ProviderTransportError("LIVE_PROVIDER_DISABLED", "live provider transport is disabled in MR-2B0", dispatch_known=False)


class CredentialResolver(Protocol):
    read_count: int

    def resolve(self, reference_name: str | CredentialRef) -> str:
        ...


class NullCredentialResolver:
    """A resolver that never reads environment variables or local stores."""

    read_count = 0

    def resolve(self, reference_name: str | CredentialRef) -> str:
        raise ProviderTransportError("CREDENTIAL_RESOLUTION_DISABLED", "credential resolution is disabled")


_SAFE_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_MISSING_CREDENTIAL = object()


def _valid_credential_value(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\r" not in value and "\n" not in value and len(value) <= 8192


def _bound_credential_reference_hash(reference: CredentialRef) -> str:
    return canonical_sha256(reference.to_mapping())


class BoundHostEnvironmentCredentialResolver:
    """Resolve one server-bound environment credential at the host boundary.

    The resolver deliberately performs no environment or registry enumeration.
    It first performs an exact process-environment lookup and, on Windows only,
    optionally performs one exact HKCU ``Environment`` value lookup.  The
    mapping and registry callback arguments are test seams; production callers
    leave them unset so the package owns the host lookup.
    """

    def __init__(
        self,
        credential_ref: CredentialRef,
        credential_reference_hash: str,
        *,
        environment: Mapping[str, Any] | None = None,
        registry_query: Callable[[str], tuple[Any, Any] | None] | None = None,
        platform: str | None = None,
    ) -> None:
        if type(credential_ref) is not CredentialRef or credential_ref.kind != "environment":
            raise ProviderTransportError("CREDENTIAL_REFERENCE_FORBIDDEN", "credential reference kind is not allowed")
        name = _credential_name(credential_ref)
        expected_hash = _bound_credential_reference_hash(credential_ref)
        if not isinstance(credential_reference_hash, str) or credential_reference_hash != expected_hash:
            raise ProviderTransportError("CREDENTIAL_REFERENCE_BINDING_MISMATCH", "credential reference binding is invalid")
        if environment is not None and not isinstance(environment, Mapping):
            raise ProviderTransportError("CREDENTIAL_RESOLVER_INVALID", "credential resolver is invalid")
        if registry_query is not None and not callable(registry_query):
            raise ProviderTransportError("CREDENTIAL_RESOLVER_INVALID", "credential resolver is invalid")
        self._credential_ref = credential_ref
        self._name = name
        self.credential_reference_hash = credential_reference_hash
        self._environment = os.environ if environment is None else environment
        self._registry_query = registry_query
        self._platform = sys.platform if platform is None else platform
        self.credential_resolution_attempts = 0
        self.credential_reads_succeeded = 0
        # ``read_count`` remains the compatibility counter, but unlike the
        # legacy resolver it counts successful reads only.
        self.read_count = 0
        self.last_source_category: str | None = None

    @staticmethod
    def _raise_resolution_failed() -> None:
        raise ProviderTransportError("CREDENTIAL_RESOLUTION_FAILED", "credential resolution failed")

    @staticmethod
    def _query_windows_user_environment(name: str) -> tuple[Any, Any] | None:
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ) as key:
                # QueryValueEx addresses only the bound value.  It does not
                # enumerate the Environment key and never touches HKLM.
                return winreg.QueryValueEx(key, name)
        except (ImportError, OSError):
            return None

    @staticmethod
    def _registry_value_is_reg_sz(value_type: Any) -> bool:
        if value_type == "REG_SZ":
            return True
        # Windows winreg.REG_SZ is 1.  Keeping this integer comparison local
        # also lets the isolated fake registry seam use a stable type value.
        return value_type == 1

    def _registry_lookup(self) -> tuple[Any, Any] | None:
        query = self._registry_query or self._query_windows_user_environment
        return query(self._name)

    def resolve(self, reference_name: str | CredentialRef) -> str:
        if type(reference_name) is not CredentialRef:
            raise ProviderTransportError("CREDENTIAL_REFERENCE_FORBIDDEN", "credential reference is not bound")
        if reference_name.kind != "environment" or reference_name != self._credential_ref:
            raise ProviderTransportError("CREDENTIAL_REFERENCE_BINDING_MISMATCH", "credential reference binding is invalid")
        if self.credential_resolution_attempts:
            raise ProviderTransportError("CREDENTIAL_RESOLUTION_RETRY_FORBIDDEN", "credential resolution retry is forbidden")

        self.credential_resolution_attempts = 1
        self.last_source_category = None
        process_value = self._environment.get(self._name, _MISSING_CREDENTIAL)
        process_present = process_value is not _MISSING_CREDENTIAL
        if process_present:
            if not _valid_credential_value(process_value):
                self._raise_resolution_failed()
            self.last_source_category = "process_environment"
        elif self._platform == "win32":
            try:
                registry_result = self._registry_lookup()
            except Exception:
                registry_result = None
            if not isinstance(registry_result, tuple) or len(registry_result) != 2:
                self._raise_resolution_failed()
            registry_value, registry_type = registry_result
            if not self._registry_value_is_reg_sz(registry_type) or not _valid_credential_value(registry_value):
                self._raise_resolution_failed()
            process_value = registry_value
            self.last_source_category = "windows_user_environment"
        else:
            self._raise_resolution_failed()

        self.credential_reads_succeeded = 1
        self.read_count = 1
        return process_value


def _credential_name(reference: str | CredentialRef) -> str:
    if isinstance(reference, CredentialRef):
        if reference.kind not in {"environment", "injected"}:
            raise ProviderTransportError("CREDENTIAL_REFERENCE_FORBIDDEN", "credential reference kind is not allowed")
        name = reference.name
    elif isinstance(reference, str):
        name = reference
    else:
        raise ProviderTransportError("CREDENTIAL_REFERENCE_INVALID", "credential reference is invalid")
    if not _SAFE_ENV_NAME_RE.fullmatch(name):
        raise ProviderTransportError("CREDENTIAL_REFERENCE_INVALID", "credential reference is invalid")
    return name


class EnvironmentCredentialResolver:
    """Explicit, non-enumerating environment resolver.

    It is disabled by default and accepts an explicit mapping in tests or in
    a later, separately approved live stage.  It never reads ``os.environ``
    implicitly and never exposes the referenced name in an error.
    """

    def __init__(self, environment: Mapping[str, str] | None = None, *, enabled: bool = False) -> None:
        self._environment = dict(environment or {})
        self.enabled = bool(enabled)
        self.read_count = 0

    def resolve(self, reference_name: str | CredentialRef) -> str:
        _credential_name(reference_name)
        if not self.enabled:
            raise ProviderTransportError("CREDENTIAL_RESOLUTION_DISABLED", "credential resolution is disabled")
        name = _credential_name(reference_name)
        self.read_count += 1
        value = self._environment.get(name)
        if not isinstance(value, str) or not value or "\r" in value or "\n" in value or len(value) > 8192:
            raise ProviderTransportError("CREDENTIAL_RESOLUTION_FAILED", "credential resolution failed")
        return value


class InjectedCredentialResolver:
    """Explicit fake resolver for hermetic adversarial tests only."""

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)
        self.read_count = 0

    def resolve(self, reference_name: str | CredentialRef) -> str:
        name = _credential_name(reference_name)
        self.read_count += 1
        value = self._values.get(name)
        if not isinstance(value, str) or not value or "\r" in value or "\n" in value or len(value) > 8192:
            raise ProviderTransportError("CREDENTIAL_RESOLUTION_FAILED", "credential resolution failed")
        return value


SecureEnvironmentCredentialResolver = EnvironmentCredentialResolver


def is_injected_hermetic_transport(value: Any) -> bool:
    """Return whether ``value`` is one of the two closed transport classes.

    ``isinstance`` and a mutable ``hermetic`` marker are intentionally not
    authority checks: a subclass can override ``send`` and turn the boundary
    into an arbitrary dispatch capability.  Only the package-owned concrete
    classes are accepted at runtime; callers may inject responses or a handler
    through their constructor without subclassing the authority boundary.
    """

    return type(value) in {HermeticTransport, InjectedHermeticTransport}


__all__ = [
    "BoundHostEnvironmentCredentialResolver", "CredentialResolver", "DisabledLiveTransport", "EnvironmentCredentialResolver", "HermeticTransport",
    "InjectedCredentialResolver", "InjectedHermeticTransport", "NullCredentialResolver",
    "ProviderTransport", "ProviderTransportError", "SecureEnvironmentCredentialResolver", "TransportResponse",
    "is_injected_hermetic_transport",
]
