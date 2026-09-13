"""Fail-closed release identity checks for governed candidate artifacts.

The control plane binds a candidate to package version, artifact hashes,
source identity, and schema identity.  This module keeps the comparison logic
small and pure so build/evidence tooling can reject a version collision before
any Preview is created.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


_HEX64_FIELDS = (
    "wheel_sha256",
    "sdist_sha256",
    "source_tree_sha256",
    "release_manifest_sha256",
    "migration_release_manifest_sha256",
)
_REQUIRED_FIELDS = (
    "package",
    "package_version",
    "wheel_sha256",
    "sdist_sha256",
    "source_tree_sha256",
    "release_manifest_sha256",
    "migration_release_manifest_sha256",
    "core_schema_version",
    "max_control_schema_version",
)
_LEGACY_SCHEMA_FIELD = "control_schema_version"
_ALLOWED_FIELDS = set(_REQUIRED_FIELDS) | {_LEGACY_SCHEMA_FIELD}


class ReleaseIdentityError(ValueError):
    """A candidate release identity is incomplete, drifted, or ambiguous."""


def normalize_release_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a bounded canonical release identity or fail closed."""

    if not isinstance(value, Mapping):
        raise ReleaseIdentityError("release identity must be an object")
    unknown = sorted(set(value) - _ALLOWED_FIELDS)
    if unknown:
        raise ReleaseIdentityError("release identity contains unknown fields: " + ", ".join(str(item) for item in unknown))
    schema_value = value.get("max_control_schema_version", value.get(_LEGACY_SCHEMA_FIELD))
    if "max_control_schema_version" in value and _LEGACY_SCHEMA_FIELD in value and value["max_control_schema_version"] != value[_LEGACY_SCHEMA_FIELD]:
        raise ReleaseIdentityError("max_control_schema_version and control_schema_version conflict")
    if schema_value is None:
        raise ReleaseIdentityError("release identity is missing: max_control_schema_version")
    missing = [key for key in _REQUIRED_FIELDS if key not in value]
    missing = [key for key in missing if key != "max_control_schema_version"]
    if missing:
        raise ReleaseIdentityError("release identity is missing: " + ", ".join(missing))
    result: dict[str, Any] = {}
    for key in ("package", "package_version"):
        item = value[key]
        if not isinstance(item, str) or not item.strip() or len(item) > 128:
            raise ReleaseIdentityError(f"{key} is invalid")
        result[key] = item.strip()
    for key in _HEX64_FIELDS:
        item = value[key]
        if not isinstance(item, str) or len(item) != 64 or any(ch not in "0123456789abcdef" for ch in item.casefold()):
            raise ReleaseIdentityError(f"{key} must be a lowercase/uppercase SHA-256 hex digest")
        result[key] = item.casefold()
    for key in ("core_schema_version",):
        item = value[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 1:
            raise ReleaseIdentityError(f"{key} must be a positive integer")
        result[key] = item
    if isinstance(schema_value, bool) or not isinstance(schema_value, int) or schema_value < 1:
        raise ReleaseIdentityError("max_control_schema_version must be a positive integer")
    result["max_control_schema_version"] = schema_value
    return result


def release_identity_key(value: Mapping[str, Any]) -> tuple[str, str]:
    """Return the immutable package/version key used for drift detection."""

    normalized = normalize_release_identity(value)
    return normalized["package"], normalized["package_version"]


def validate_release_identity_unique(
    candidate: Mapping[str, Any],
    registered: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Reject version drift or two wheel hashes for one package/version.

    A different package version is a distinct release identity.  The same
    package/version must match every immutable release field, especially the
    wheel hash; otherwise the caller must publish a new version.
    """

    current = normalize_release_identity(candidate)
    key = release_identity_key(current)
    for prior in registered:
        existing = normalize_release_identity(prior)
        if release_identity_key(existing) != key:
            continue
        differences = sorted(
            field for field in current
            if current[field] != existing[field]
        )
        if differences:
            raise ReleaseIdentityError(
                f"registered release identity drifted for {key[0]} {key[1]}: "
                + ", ".join(differences)
            )
    return current


def assert_preview_release_binding(
    preview: Mapping[str, Any],
    release: Mapping[str, Any],
) -> None:
    """Require the Preview's package, artifact, and schema bindings."""

    identity = normalize_release_identity(release)
    expected = {
        "engine_package": identity["package"],
        "engine_version": identity["package_version"],
        "candidate_wheel_sha256": identity["wheel_sha256"],
        "source_tree_sha256": identity["source_tree_sha256"],
        "core_schema_version": identity["core_schema_version"],
        "max_control_schema_version": identity["max_control_schema_version"],
    }
    for key, expected_value in expected.items():
        actual = preview.get(key)
        if key == "max_control_schema_version" and actual is None:
            actual = preview.get("control_schema_version")
        if actual != expected_value:
            raise ReleaseIdentityError(f"Preview release binding mismatch: {key}")


__all__ = [
    "ReleaseIdentityError",
    "assert_preview_release_binding",
    "normalize_release_identity",
    "release_identity_key",
    "validate_release_identity_unique",
]
