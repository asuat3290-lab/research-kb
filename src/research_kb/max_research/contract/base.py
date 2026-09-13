"""Small dependency-free primitives shared by the MR-0 contracts."""

from __future__ import annotations

import dataclasses
import datetime as _datetime
import decimal
import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterator


def model_to_dict(value: Any) -> Any:
    """Convert contract values to plain JSON-compatible Python values.

    This is intentionally independent of a serializer library.  It is used
    both for public projections and for the charter/source-policy hashes, so
    it never includes object addresses or runtime metadata.
    """

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: model_to_dict(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return model_to_dict(value.value)
    if isinstance(value, Mapping):
        return {str(key): model_to_dict(item) for key, item in value.items()}
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite floats are not contract values")
        return value
    if isinstance(value, decimal.Decimal):
        return format(value, "f")
    if isinstance(value, (_datetime.datetime, _datetime.date, _datetime.time)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("raw bytes are not JSON contract values")
    if isinstance(value, Set):
        values = [model_to_dict(item) for item in value]
        return sorted(
            values,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ),
        )
    if isinstance(value, Sequence):
        return [model_to_dict(item) for item in value]
    raise TypeError(f"unsupported contract value: {type(value).__name__}")


def _normalise(value: Any) -> Any:
    value = model_to_dict(value)
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        keys = [unicodedata.normalize("NFC", str(key)) for key in value]
        if len(keys) != len(set(keys)):
            raise ValueError("contract mapping has colliding normalized keys")
        return {
            key: _normalise(value[original])
            for key, original in sorted(zip(keys, value), key=lambda pair: pair[0])
        }
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Return the deterministic UTF-8 JSON representation used by MR-0."""

    return json.dumps(
        _normalise(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_sha256(value: Any) -> str:
    """Return a lower-case, unprefixed SHA-256 of :func:`canonical_json`."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def deep_freeze(value: Any) -> Any:
    """Return a recursively immutable contract snapshot.

    Frozen dataclasses alone do not freeze dictionaries and lists supplied by
    callers.  Contract objects use this boundary helper for every value that
    participates in a hash, an authorization decision, or a state rebuild.
    """

    if isinstance(value, Mapping):
        return MappingProxyType({deep_freeze(key): deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(deep_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(deep_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(deep_freeze(item) for item in value)
    if isinstance(value, frozenset):
        return frozenset(deep_freeze(item) for item in value)
    return value


def require_mapping_fields(
    value: Any,
    *,
    allowed: Set[str],
    required: Set[str] = frozenset(),
    path: str = "$",
) -> Mapping[str, Any]:
    """Validate a mapping parser boundary without silently dropping input."""

    if not isinstance(value, Mapping):
        raise ContractValidationError(
            ValidationIssue("mapping.type", path, "contract input must be a mapping")
        )
    unknown = sorted(str(key) for key in value if key not in allowed)
    missing = sorted(str(key) for key in required if key not in value)
    issues: list[ValidationIssue] = []
    for key in unknown:
        issues.append(
            ValidationIssue(
                "mapping.unknown_field",
                f"{path}.{key}",
                f"unknown contract field: {key}",
            )
        )
    for key in missing:
        issues.append(
            ValidationIssue(
                "mapping.required_field",
                f"{path}.{key}",
                f"required contract field is missing: {key}",
            )
        )
    if issues:
        raise ContractValidationError(issues)
    return value


@dataclass(frozen=True)
class ValidationIssue:
    """One deterministic, machine-readable contract failure."""

    code: str
    path: str
    message: str
    severity: str = "ERROR"

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class ValidationResult:
    """Boolean-friendly validation result with stable issue ordering."""

    issues: tuple[ValidationIssue, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        return self.issues

    def __bool__(self) -> bool:
        return self.ok

    def __iter__(self) -> Iterator[ValidationIssue]:
        return iter(self.issues)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "issues": [issue.as_dict() for issue in self.issues]}

    def raise_if_invalid(self) -> "ValidationResult":
        if not self.ok:
            raise ContractValidationError(self.issues)
        return self


class ContractValidationError(ValueError):
    """Raised by ``require_*`` helpers when an MR-0 value is invalid."""

    def __init__(self, issues: Sequence[ValidationIssue] | ValidationIssue | str):
        if isinstance(issues, ValidationIssue):
            normalized = (issues,)
        elif isinstance(issues, str):
            normalized = (ValidationIssue("contract.invalid", "$", issues),)
        else:
            normalized = tuple(issues)
        self.issues = normalized
        message = "; ".join(issue.message for issue in normalized) or "invalid contract"
        super().__init__(message)


class _IssueCollector:
    """Internal helper kept private so validators expose one consistent API."""

    def __init__(self) -> None:
        self.issues: list[ValidationIssue] = []

    def add(self, code: str, path: str, message: str, severity: str = "ERROR") -> None:
        self.issues.append(ValidationIssue(code, path, message, severity))

    def result(self) -> ValidationResult:
        return ValidationResult(tuple(self.issues))


def issue_collector() -> _IssueCollector:
    return _IssueCollector()


__all__ = [
    "ContractValidationError",
    "ValidationIssue",
    "ValidationResult",
    "canonical_json",
    "canonical_sha256",
    "deep_freeze",
    "issue_collector",
    "model_to_dict",
    "require_mapping_fields",
]
