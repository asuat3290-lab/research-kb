"""Read-only verification of the packaged current Max control schema shape.

The manifest is a recovery/release-integrity check.  It detects accidental
omission, addition, or definition drift in a database that the application
can read.  It is not a protection against a same-account process that can
rewrite the SQLite file and its manifest together.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from functools import lru_cache
from typing import Any

from ..._resources import PackagedResourceError, read_json_resource
from .version import CONTROL_SCHEMA_VERSION


MANIFEST_RESOURCE = ("max_research", f"schema_manifest_v{CONTROL_SCHEMA_VERSION}.json")
_OBJECT_TYPES = ("index", "table", "trigger")


class SchemaManifestError(RuntimeError):
    """The packaged schema manifest cannot be trusted."""


def _normalize_sql(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value.strip())
    # sqlite_master preserves the migration author's formatting.  The
    # manifest compares definitions, not insignificant whitespace, so
    # punctuation spacing is removed before hashing.  Object names and SQL
    # tokens remain visible to the stable hash.
    return re.sub(r"\s*([(),])\s*", r"\1", normalized)


def _object_hash(sql: str) -> str:
    return hashlib.sha256(_normalize_sql(sql).encode("utf-8")).hexdigest()


def _aggregate(items: list[dict[str, str]]) -> str:
    payload = json.dumps(items, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_schema_manifest() -> dict[str, Any]:
    try:
        manifest = read_json_resource(*MANIFEST_RESOURCE)
    except PackagedResourceError as exc:
        raise SchemaManifestError("Max schema manifest is unavailable") from exc
    if (
        manifest.get("schema") != "max-control-schema-manifest/v1"
        or manifest.get("manifest_version") != 1
        or manifest.get("control_schema_version") != CONTROL_SCHEMA_VERSION
    ):
        raise SchemaManifestError("Max schema manifest is invalid")
    policy = manifest.get("sqlite_master_policy")
    if not isinstance(policy, dict) or policy.get("included_types") != list(_OBJECT_TYPES):
        raise SchemaManifestError("Max schema manifest is invalid")
    if policy.get("exclude_internal_names") is not True or policy.get("exclude_autoindexes") is not True or policy.get("require_sql_definition") is not True:
        raise SchemaManifestError("Max schema manifest is invalid")
    objects = manifest.get("objects")
    if not isinstance(objects, dict) or set(objects) != set(_OBJECT_TYPES):
        raise SchemaManifestError("Max schema manifest is invalid")
    for kind in _OBJECT_TYPES:
        entry = objects.get(kind)
        names = entry.get("names") if isinstance(entry, dict) else None
        aggregate = entry.get("aggregate_sql_sha256") if isinstance(entry, dict) else None
        if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
            raise SchemaManifestError("Max schema manifest is invalid")
        if names != sorted(set(names)) or not isinstance(aggregate, str) or not re.fullmatch(r"[0-9a-f]{64}", aggregate):
            raise SchemaManifestError("Max schema manifest is invalid")
    return manifest


def schema_inventory(connection: sqlite3.Connection) -> dict[str, list[dict[str, str]]]:
    """Return the application-owned sqlite_master inventory only."""

    inventory = {kind: [] for kind in _OBJECT_TYPES}
    rows = connection.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE type IN ('table','index','trigger') "
        "AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL "
        "ORDER BY type, name"
    )
    for row in rows:
        kind, name, sql = str(row[0]), str(row[1]), row[2]
        if kind not in inventory or name.startswith("sqlite_autoindex_") or not isinstance(sql, str):
            continue
        inventory[kind].append({"name": name, "sql_sha256": _object_hash(sql)})
    return inventory


@lru_cache(maxsize=1)
def _reference_inventory() -> dict[str, list[dict[str, str]]]:
    """Build the reviewed reference shape in memory for per-object diagnostics."""

    from .migrations import apply_migrations

    reference = sqlite3.connect(":memory:")
    try:
        reference.row_factory = sqlite3.Row
        apply_migrations(reference)
        return schema_inventory(reference)
    finally:
        reference.close()


def verify_schema_manifest(connection: sqlite3.Connection) -> dict[str, Any]:
    """Compare a control DB with the packaged schema manifest, fail closed."""

    manifest = load_schema_manifest()
    actual = schema_inventory(connection)
    expected_objects = manifest["objects"]
    issues: list[str] = []
    for kind in _OBJECT_TYPES:
        expected_names = list(expected_objects[kind]["names"])
        actual_items = actual[kind]
        actual_by_name = {item["name"]: item for item in actual_items}
        actual_names = sorted(actual_by_name)
        for name in sorted(set(expected_names) - set(actual_names)):
            issues.append(f"schema {kind} missing: {name}")
        for name in sorted(set(actual_names) - set(expected_names)):
            issues.append(f"schema {kind} unexpected: {name}")
        if _aggregate(actual_items) != expected_objects[kind]["aggregate_sql_sha256"]:
            try:
                reference_items = {item["name"]: item for item in _reference_inventory()[kind]}
            except Exception as exc:
                raise SchemaManifestError("Max schema reference verification failed") from exc
            for name in sorted(set(actual_names) & set(reference_items)):
                if actual_by_name[name]["sql_sha256"] != reference_items[name]["sql_sha256"]:
                    issues.append(f"schema {kind} definition mismatch: {name}")
    return {
        "ok": not issues,
        "schema_version": CONTROL_SCHEMA_VERSION,
        "object_counts": {kind: len(actual[kind]) for kind in _OBJECT_TYPES},
        "issues": issues,
    }


__all__ = [
    "MANIFEST_RESOURCE",
    "SchemaManifestError",
    "load_schema_manifest",
    "schema_inventory",
    "verify_schema_manifest",
]
