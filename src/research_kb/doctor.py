"""Read-only system governance diagnostics for research-kb.

``run_doctor`` intentionally has no access to the writable database
connection, migration runner, ingestion code, reindexer, or audit helper.  It
opens an existing SQLite database in URI read-only mode and reports findings
without returning source text or project payloads.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
import tomllib
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import __version__
from .checkpoint import is_standard_checkpoint_payload
from .config import Settings
from .db import SCHEMA_VERSION, connect, migration_paths
from .system_manifest import (
    CATALOG_LIFECYCLE,
    CHECKPOINT_POLICIES,
    CODEX_MCP_SERVER_NAME,
    EXPECTED_MCP_TOOLS,
    MCPAuthoritySpec,
    MCPInstallationSpec,
    MCP_SERVER_NAME,
    PROTOCOL,
    REQUIRED_MCP_TABLES,
    REQUIRED_MCP_TRIGGERS,
    ComponentSpec,
    ManifestError,
    SystemManifest,
    load_manifest,
    redact_path,
    relative_path_issue,
    resolve_manifest_path,
    sha256_file,
)


DOCTOR_VERSION = "1"
_STALE_DAYS = 30
_CATALOG_SUMMARY_MAX_BYTES = 8 * 1024 * 1024
SKILL_SCAN_MAX_DEPTH = 8
SKILL_SCAN_MAX_DIRECTORIES = 1024
SKILL_SCAN_MAX_FILES = 4096
SKILL_SCAN_MAX_ENTRIES_PER_DIRECTORY = 5120
SKILL_SCAN_TIME_BUDGET_SECONDS = 1.0
_ACTUAL_CAPABILITIES = {
    "lexical": True,
    "semantic": False,
    "hybrid": False,
    "local_model": False,
    "remote_deployment": False,
}


class _Collector:
    def __init__(self, *, show_paths: bool) -> None:
        self.show_paths = show_paths
        self.findings: list[dict[str, Any]] = []

    def _path(self, value: str | Path | None) -> str | None:
        return str(value) if self.show_paths and value is not None else redact_path(value)

    def _safe_value(self, value: Any) -> Any:
        """Redact structured finding details before JSON serialization."""
        if isinstance(value, Mapping):
            return {str(key): self._safe_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._safe_value(item) for item in value]
        if isinstance(value, Path):
            return self._path(value)
        if isinstance(value, str):
            return value if self.show_paths else (redact_path(value) or "")
        return value

    def add(
        self,
        finding_id: str,
        severity: str,
        message: str,
        details: Mapping[str, Any] | None = None,
        ) -> None:
        record: dict[str, Any] = {
            "id": finding_id,
            "severity": severity,
            "status": "ok" if severity == "INFO" else "finding",
            "message": message,
        }
        if details:
            record["details"] = self._safe_value(details)
        self.findings.append(record)

    def info(self, finding_id: str, message: str, details: Mapping[str, Any] | None = None) -> None:
        self.add(finding_id, "INFO", message, details)

    def problem(
        self,
        finding_id: str,
        severity: str,
        message: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.add(finding_id, severity, message, details)

    def report(
        self,
        *,
        config_path: str | Path,
        settings: Settings | None,
        manifest: SystemManifest | None,
        strict: bool,
        deep: bool,
    ) -> dict[str, Any]:
        counts = {level: 0 for level in ("P0", "P1", "P2", "INFO")}
        for finding in self.findings:
            counts[finding["severity"]] += 1
        failed = counts["P0"] > 0
        warning = counts["P1"] > 0 or counts["P2"] > 0
        status = "failed" if failed else ("warning" if warning else "healthy")
        exit_code = 2 if failed or (strict and warning) else (1 if warning else 0)
        system = {
            "package": "research-kb",
            "package_version": __version__,
            "protocol": PROTOCOL,
            "schema_version": SCHEMA_VERSION,
            "mcp_server": MCP_SERVER_NAME,
            "mcp_tools": list(EXPECTED_MCP_TOOLS),
            "database": self._path(settings.database) if settings else None,
            "config": self._path(config_path),
        }
        return {
            "doctor_version": DOCTOR_VERSION,
            "status": status,
            "exit_code": exit_code,
            "strict": strict,
            "deep": deep,
            "redaction": {
                "paths": "shown" if self.show_paths else "redacted",
                "research_content": "never emitted",
            },
            "summary": counts,
            "system": system,
            "manifest": manifest.to_dict(show_paths=self.show_paths) if manifest else None,
            "checks": self.findings,
        }


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _component_paths(component: ComponentSpec) -> tuple[str, ...]:
    if component.paths:
        return component.paths
    return (component.path,) if component.path is not None else ()


def _safe_ids(values: Iterable[str]) -> list[str]:
    return sorted(str(value) for value in values)


def _catalog_stage(summary: Mapping[str, Any]) -> str:
    for key in ("lifecycle_stage", "stage", "state"):
        value = summary.get(key)
        if isinstance(value, str) and value in CATALOG_LIFECYCLE:
            return value
    if summary.get("ingested") is True or summary.get("ingest_complete") is True:
        return "ingested"
    ready_count = summary.get("ready_for_manifest", summary.get("first_batch_ready_count", 0))
    if isinstance(ready_count, (int, float)) and ready_count > 0:
        return "ready"
    review_keys = (
        "reviewed_count",
        "first_batch_review_count",
        "first_batch_metadata_review_count",
        "metadata_review_count",
        "privacy_review_count",
    )
    if any(isinstance(summary.get(key), (int, float)) and summary.get(key) > 0 for key in review_keys):
        return "reviewed"
    return "cataloged"


def _catalog_summary_details(summary: Mapping[str, Any]) -> dict[str, Any]:
    duplicate_counts = summary.get("duplicate_status_counts")
    safe_duplicate_counts = {}
    if isinstance(duplicate_counts, Mapping):
        for key in ("exact_duplicate", "possible_duplicate", "none"):
            value = duplicate_counts.get(key)
            if isinstance(value, int):
                safe_duplicate_counts[key] = value
    ready = summary.get("ready_for_manifest", summary.get("first_batch_ready_count", 0))
    return {
        "catalog_version": summary.get("catalog_version") if isinstance(summary.get("catalog_version"), int) else None,
        "stage": _catalog_stage(summary),
        "ready_for_manifest": ready if isinstance(ready, int) else 0,
        "duplicate_status_counts": safe_duplicate_counts,
    }


def _check_config_paths(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
) -> None:
    actual: dict[str, tuple[Path, ...]] = {
        "database": (settings.database,),
        "corpus": tuple(settings.corpus_roots),
        "workspace": (settings.workspace,),
        "backup": (settings.workspace / "backups",),
        "skills": (settings.workspace / ".agents" / "skills",),
    }
    for name, paths in actual.items():
        for path in paths:
            if path.exists():
                continue
            severity = "P0" if name == "database" else ("P1" if name in {"corpus", "workspace"} else "P2")
            collector.problem(
                f"path_missing_{name}",
                severity,
                f"{name} path is missing",
                {"path": collector._path(path)},
            )
    if manifest is None:
        collector.info(
            "path_manifest_not_supplied",
            "runtime paths were checked from config; no external component mapping was supplied",
        )
        return

    expected_config = resolve_manifest_path(manifest.config_path, settings.root)
    if expected_config is None:
        collector.problem("manifest_path_unresolved_config", "P1", "config path contains an unresolved environment path")
    elif expected_config != settings.config_path.resolve():
        collector.problem(
            "manifest_path_mismatch_config",
            "P1",
            "config path differs between invocation and manifest",
            {"manifest": collector._path(expected_config), "config": collector._path(settings.config_path)},
        )
    else:
        collector.info("manifest_path_match_config", "config path matches manifest")

    expected_names = ("database", "corpus", "workspace", "backup", "skills")
    for name in expected_names:
        component = manifest.components.get(name)
        if component is None:
            continue
        expected_paths: list[Path] = []
        unresolved = False
        for value in _component_paths(component):
            resolved = resolve_manifest_path(value, settings.root)
            if resolved is None:
                unresolved = True
            else:
                expected_paths.append(resolved)
        if unresolved:
            collector.problem(
                f"manifest_path_unresolved_{name}",
                "P1",
                f"{name} component contains an unresolved environment path",
            )
            continue
        actual_paths = list(actual[name])
        if {path.resolve() for path in expected_paths} != {path.resolve() for path in actual_paths}:
            collector.problem(
                f"manifest_path_mismatch_{name}",
                "P1",
                f"{name} path differs between config and manifest",
                {
                    "manifest": [collector._path(path) for path in expected_paths],
                    "config": [collector._path(path) for path in actual_paths],
                },
            )
        else:
            collector.info(f"manifest_path_match_{name}", f"{name} path matches manifest")

    for name, component in manifest.components.items():
        values = _component_paths(component)
        for value in values:
            resolved = resolve_manifest_path(value, settings.root)
            if resolved is None:
                continue
            if component.boundary == "runtime_root" and not _within(resolved, settings.root):
                collector.problem(
                    f"manifest_boundary_{name}",
                    "P1",
                    f"{name} component escapes the declared runtime boundary",
                    {"path": collector._path(resolved)},
                )


def _check_catalog(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
) -> Mapping[str, Any] | None:
    if manifest is None or "catalog" not in manifest.components:
        collector.info("catalog_not_configured", "catalog component was not supplied")
        return None
    component = manifest.components["catalog"]
    values = _component_paths(component)
    if not values:
        if component.required:
            collector.problem("catalog_path_missing", "P2", "catalog component has no path")
        return None
    catalog_path = resolve_manifest_path(values[0], settings.root)
    if catalog_path is None:
        if component.required:
            collector.problem("catalog_path_unresolved", "P2", "catalog path environment is unresolved")
        else:
            collector.info("catalog_path_unresolved_optional", "optional catalog path environment is unresolved")
        return None
    if not catalog_path.is_dir():
        severity = "P2" if component.required else "INFO"
        if severity == "P2":
            collector.problem("catalog_path_missing", severity, "catalog directory is missing", {"path": collector._path(catalog_path)})
        else:
            collector.info("catalog_path_missing_optional", "optional catalog directory is missing")
        return None
    summary_names = manifest.catalog_summary_files
    for summary_name in summary_names:
        summary_path = (catalog_path / summary_name).resolve()
        if not _within(summary_path, catalog_path):
            collector.problem("catalog_summary_boundary", "P1", "catalog summary escapes the catalog directory")
            continue
        if not summary_path.is_file():
            continue
        try:
            if summary_path.stat().st_size > _CATALOG_SUMMARY_MAX_BYTES:
                raise ValueError
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            collector.problem("catalog_summary_invalid", "P2", "catalog summary is missing or unreadable")
            return None
        if not isinstance(summary, Mapping):
            collector.problem("catalog_summary_invalid", "P2", "catalog summary is not an object")
            return None
        details = _catalog_summary_details(summary)
        collector.info("catalog_summary_readable", "catalog summary is readable", details)
        duplicate_counts = details["duplicate_status_counts"]
        risk_count = sum(value for key, value in duplicate_counts.items() if key != "none")
        if risk_count:
            collector.problem(
                "catalog_duplicate_risk",
                "P2",
                "catalog summary records duplicate-risk groups",
                {"duplicate_risk_groups": risk_count},
            )
        return summary
    collector.problem("catalog_summary_missing", "P2", "catalog summary is missing")
    return None


def _check_registry(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
    projects: list[dict[str, Any]],
) -> None:
    if manifest is None or not manifest.has_project_registry:
        collector.info("project_registry_not_supplied", "project registry is optional and was not supplied")
        return
    database_ids = {str(row["project_id"]) for row in projects}
    registry_ids = {project.project_id for project in manifest.projects}
    missing_from_registry = database_ids - registry_ids
    missing_from_database = registry_ids - database_ids
    if missing_from_registry or missing_from_database:
        collector.problem(
            "project_registry_mapping_orphan",
            "P1",
            "database projects and manifest registry do not map one-to-one",
            {
                "database_only": _safe_ids(missing_from_registry),
                "registry_only": _safe_ids(missing_from_database),
            },
        )
    else:
        collector.info("project_registry_mapping_ok", "database projects map to the manifest registry")
    corpus_roots = tuple(Path(root).resolve() for root in settings.corpus_roots)
    for project in manifest.projects:
        if project.checkpoint_policy not in CHECKPOINT_POLICIES:
            collector.problem(
                "project_checkpoint_policy_unsupported",
                "P1",
                "project checkpoint policy is not supported by SG-1A",
                {
                    "project_id": project.project_id,
                    "checkpoint_policy": project.checkpoint_policy,
                    "supported": list(CHECKPOINT_POLICIES),
                },
            )
        workspace_issue = relative_path_issue(project.workspace)
        if workspace_issue is not None:
            collector.problem(
                "project_workspace_not_relative",
                "P1",
                "project workspace mapping is not relative to the workspace root",
                {"project_id": project.project_id, "reason": workspace_issue},
            )
        else:
            workspace_path = (settings.workspace / project.workspace).resolve()
            if not _within(workspace_path, settings.workspace) or not workspace_path.is_dir():
                collector.problem(
                    "project_workspace_mapping_orphan",
                    "P1",
                    "project workspace mapping is missing or outside the workspace root",
                    {"project_id": project.project_id, "path": collector._path(workspace_path)},
                )

        if not project.corpus_scope:
            collector.problem(
                "project_corpus_scope_missing",
                "P1",
                "project registry has no corpus scope",
                {"project_id": project.project_id},
            )
            continue
        for scope in project.corpus_scope:
            scope_issue = relative_path_issue(scope)
            if scope_issue is not None:
                collector.problem(
                    "project_corpus_scope_invalid",
                    "P1",
                    "project corpus scope is not a safe relative logical path",
                    {"project_id": project.project_id, "scope": scope, "reason": scope_issue},
                )
                continue
            matches: list[tuple[Path, Path]] = []
            outside: list[Path] = []
            for root in corpus_roots:
                candidate = (root / Path(scope)).resolve()
                if not _within(candidate, root):
                    outside.append(candidate)
                elif candidate.is_dir():
                    matches.append((root, candidate))
            if outside:
                collector.problem(
                    "project_corpus_scope_boundary",
                    "P1",
                    "project corpus scope resolves outside a configured corpus root",
                    {
                        "project_id": project.project_id,
                        "scope": scope,
                        "outside_candidates": outside,
                    },
                )
                continue
            if not matches:
                collector.problem(
                    "project_corpus_scope_unmapped",
                    "P1",
                    "project corpus scope cannot be mapped to a configured corpus root",
                    {
                        "project_id": project.project_id,
                        "scope": scope,
                        "configured_root_count": len(corpus_roots),
                    },
            )
            elif len(matches) > 1:
                collector.problem(
                    "project_corpus_scope_ambiguous",
                    "P1",
                    "project corpus scope maps to multiple configured corpus roots",
                    {
                        "project_id": project.project_id,
                        "scope": scope,
                        "matching_roots": [root for root, _ in matches],
                    },
                )
            else:
                collector.info(
                    "project_corpus_scope_mapped",
                    "project corpus scope maps to one configured corpus root",
                    {"project_id": project.project_id, "scope": scope},
                )


def _check_checkpoints(
    collector: _Collector,
    connection: sqlite3.Connection,
    projects: list[dict[str, Any]],
) -> None:
    item_counts = {
        str(row[0]): int(row[1])
        for row in connection.execute(
            "SELECT project_id, COUNT(*) FROM research_items GROUP BY project_id"
        ).fetchall()
    }
    rows = connection.execute(
        """
        SELECT ri.item_id, ri.project_id, ri.status,
               riv.payload_json,
               NOT EXISTS(
                   SELECT 1 FROM research_items successor
                   WHERE successor.supersedes_item_id = ri.item_id
               ) AS is_current
        FROM research_items ri
        JOIN research_item_versions riv ON riv.item_id = ri.item_id
        WHERE ri.kind = 'note'
          AND riv.version_no = (
              SELECT MAX(latest.version_no)
              FROM research_item_versions latest
              WHERE latest.item_id = ri.item_id
          )
        ORDER BY ri.project_id, ri.item_id
        """
    ).fetchall()
    standard_current_by_project: Counter[str] = Counter()
    legacy_current_by_project: Counter[str] = Counter()
    for row in rows:
        if not bool(row["is_current"]) or row["status"] in {"archived", "rejected"}:
            continue
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = None
        project_id = str(row["project_id"])
        if is_standard_checkpoint_payload(payload):
            standard_current_by_project[project_id] += 1
        else:
            legacy_current_by_project[project_id] += 1
    for project in sorted(projects, key=lambda row: str(row["project_id"])):
        project_id = str(project["project_id"])
        project_status = str(project["status"])
        item_count = item_counts.get(project_id, 0)
        standard_count = standard_current_by_project.get(project_id, 0)
        legacy_count = legacy_current_by_project.get(project_id, 0)
        details = {
            "project_id": project_id,
            "project_status": project_status,
            "research_item_count": item_count,
            "standard_checkpoint_count": standard_count,
            "current_checkpoint_count": standard_count,
            "legacy_candidate_count": legacy_count,
        }
        if project_status == "archived":
            collector.info(
                "checkpoint_not_required_archived",
                "archived project does not require a current checkpoint",
                details,
            )
        elif item_count == 0:
            collector.info(
                "checkpoint_not_required_empty",
                "active project with no research items does not require a current checkpoint",
                details,
            )
        elif standard_count == 0 and legacy_count:
            collector.problem(
                "checkpoint_legacy_unrecognized",
                "P2",
                "active project has a legacy note or handoff record but no standard current checkpoint",
                details,
            )
        elif standard_count == 0:
            collector.problem(
                "checkpoint_zero_current",
                "P2",
                "active project has research activity but no standard current checkpoint",
                details,
            )
        elif standard_count == 1:
            collector.info("checkpoint_one_current", "active project has one standard current checkpoint", details)
        else:
            collector.problem(
                "checkpoint_multiple_current",
                "P1",
                "active project has multiple standard current checkpoints",
                details,
            )


def _check_checkpoint_cross_kind_successors(
    collector: _Collector,
    connection: sqlite3.Connection,
) -> None:
    """Report historical non-checkpoint successors without repairing them."""

    rows = connection.execute(
        """
        SELECT target.item_id AS checkpoint_item_id,
               target.project_id,
               target.status AS checkpoint_status,
               successor.item_id AS successor_item_id,
               successor.kind AS successor_kind,
               successor.status AS successor_status,
               target_version.payload_json AS checkpoint_payload_json,
               successor_version.payload_json AS successor_payload_json
        FROM research_items target
        JOIN research_item_versions target_version
          ON target_version.item_id = target.item_id
         AND target_version.version_no = (
             SELECT MAX(latest.version_no)
             FROM research_item_versions latest
             WHERE latest.item_id = target.item_id
         )
        JOIN research_items successor
          ON successor.supersedes_item_id = target.item_id
        JOIN research_item_versions successor_version
          ON successor_version.item_id = successor.item_id
         AND successor_version.version_no = (
             SELECT MAX(latest.version_no)
             FROM research_item_versions latest
             WHERE latest.item_id = successor.item_id
         )
        WHERE target.kind = 'note'
        ORDER BY target.project_id, target.item_id, successor.item_id
        """
    ).fetchall()
    anomalies: list[sqlite3.Row] = []
    for row in rows:
        try:
            checkpoint_payload = json.loads(row["checkpoint_payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            checkpoint_payload = None
        try:
            successor_payload = json.loads(row["successor_payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            successor_payload = None
        if not is_standard_checkpoint_payload(checkpoint_payload):
            continue
        if row["successor_kind"] != "note" or not is_standard_checkpoint_payload(successor_payload):
            anomalies.append(row)

    if not anomalies:
        return
    total = len(anomalies)
    for row in anomalies:
        collector.problem(
            "checkpoint_cross_kind_successor",
            "P1",
            "a non-standard item supersedes a standard checkpoint; manual governance is required",
            {
                "project_id": str(row["project_id"]),
                "checkpoint_item_id": str(row["checkpoint_item_id"]),
                "checkpoint_status": str(row["checkpoint_status"]),
                "successor_item_id": str(row["successor_item_id"]),
                "successor_kind": str(row["successor_kind"]),
                "successor_status": str(row["successor_status"]),
                "anomaly_count": total,
            },
        )


def _check_approvals(
    collector: _Collector,
    connection: sqlite3.Connection,
    *,
    now: datetime,
) -> None:
    rows = connection.execute(
        """
        SELECT project_id, target_type, item_id, verified_evidence_id, created_at
        FROM approval_requests_v2
        WHERE status = 'pending'
        ORDER BY project_id, target_type, item_id, verified_evidence_id, created_at
        """
    ).fetchall()
    stale = 0
    keys: Counter[tuple[str, str, str]] = Counter()
    for row in rows:
        target = str(row["item_id"] or row["verified_evidence_id"] or "")
        keys[(str(row["project_id"]), str(row["target_type"]), target)] += 1
        created = _parse_datetime(row["created_at"])
        if created is not None and now - created > timedelta(days=_STALE_DAYS):
            stale += 1
    duplicate_groups = sum(1 for count in keys.values() if count > 1)
    if stale or duplicate_groups:
        collector.problem(
            "approval_pending_risk",
            "P2",
            "pending approvals include stale or duplicate requests",
            {"pending": len(rows), "stale": stale, "duplicate_groups": duplicate_groups},
        )
    else:
        collector.info("approval_pending_ok", "pending approvals have no detected stale or duplicate risk", {"pending": len(rows)})


def _is_reparse_entry(entry: os.DirEntry[str] | Path) -> bool:
    """Return true for symlinks and Windows reparse points without following them."""
    try:
        if entry.is_symlink():
            return True
        if isinstance(entry, Path):
            metadata = entry.lstat()
        else:
            metadata = entry.stat(follow_symlinks=False)
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _unresolved_manifest_path(value: str, runtime_root: Path) -> Path | None:
    expanded = os.path.expandvars(value).strip()
    if "${" in expanded or "%" in expanded:
        return None
    candidate = Path(expanded).expanduser()
    if not candidate.is_absolute():
        candidate = runtime_root.expanduser().resolve() / candidate
    return candidate


def _has_reparse_component(path: Path) -> bool:
    parts = path.parts
    if not parts:
        return False
    current = Path(parts[0])
    for part in parts[1:]:
        current = current / part
        try:
            if current.is_symlink():
                return True
            metadata = current.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            return True
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag):
            return True
    try:
        if current.is_symlink():
            return True
        metadata = current.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _scan_skill_root(root: Path, declared: set[Path]) -> dict[str, Any]:
    """Scan one approved skill root with fixed depth, count, and time bounds."""
    stack: list[tuple[Path, int]] = [(root, 0)]
    directories_visited = 0
    files_visited = 0
    undeclared_count = 0
    reparse_skipped = 0
    unreadable_directories = 0
    limited_reason: str | None = None
    deadline = time.monotonic() + SKILL_SCAN_TIME_BUDGET_SECONDS

    while stack:
        if time.monotonic() >= deadline:
            limited_reason = "time_budget"
            break
        if directories_visited >= SKILL_SCAN_MAX_DIRECTORIES:
            limited_reason = "directory_count"
            break
        current, depth = stack.pop()
        if _is_reparse_entry(current):
            reparse_skipped += 1
            continue
        directories_visited += 1
        try:
            with os.scandir(current) as iterator:
                entries: list[os.DirEntry[str]] = []
                for entry in iterator:
                    if time.monotonic() >= deadline:
                        limited_reason = "time_budget"
                        break
                    entries.append(entry)
                    if len(entries) >= SKILL_SCAN_MAX_ENTRIES_PER_DIRECTORY:
                        limited_reason = "directory_entry_count"
                        break
                entries.sort(key=lambda item: (item.name.casefold(), item.name))
        except OSError:
            unreadable_directories += 1
            continue

        child_directories: list[tuple[Path, int]] = []
        for entry in entries:
            if time.monotonic() >= deadline:
                limited_reason = "time_budget"
                break
            if _is_reparse_entry(entry):
                reparse_skipped += 1
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if depth >= SKILL_SCAN_MAX_DEPTH:
                        limited_reason = "depth"
                        break
                    child_directories.append((Path(entry.path), depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if files_visited >= SKILL_SCAN_MAX_FILES:
                limited_reason = "file_count"
                break
            files_visited += 1
            if entry.name != "SKILL.md":
                continue
            candidate = Path(entry.path)
            try:
                resolved_candidate = candidate.resolve(strict=True)
            except OSError:
                continue
            if resolved_candidate not in declared:
                undeclared_count += 1
        if limited_reason is not None:
            break
        stack.extend(reversed(child_directories))

    return {
        "directories_visited": directories_visited,
        "files_visited": files_visited,
        "undeclared_count": undeclared_count,
        "reparse_skipped": reparse_skipped,
        "unreadable_directories": unreadable_directories,
        "limited_reason": limited_reason,
    }


def _check_skills(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
    *,
    deep: bool,
) -> None:
    if manifest is None:
        collector.info("skills_not_configured", "skill drift was not evaluated without a manifest")
        return
    declared: set[Path] = set()
    for skill in manifest.skills:
        skill_path = resolve_manifest_path(skill.path, settings.root)
        if skill_path is None or not skill_path.is_file():
            collector.problem("skill_file_missing", "P2", "declared skill file is missing", {"skill": skill.name})
            continue
        declared.add(skill_path.resolve())
        if not skill.content_sha256:
            collector.problem("skill_hash_missing", "P2", "declared skill has no content hash", {"skill": skill.name})
            continue
        try:
            actual_hash = sha256_file(skill_path)
        except OSError:
            collector.problem("skill_file_unreadable", "P2", "declared skill file is unreadable", {"skill": skill.name})
            continue
        if actual_hash != skill.content_sha256:
            collector.problem("skill_hash_drift", "P2", "declared skill content hash has drifted", {"skill": skill.name})
        else:
            collector.info("skill_hash_ok", "declared skill content hash matches", {"skill": skill.name})
    if not manifest.skills:
        collector.problem("skills_inventory_missing", "P2", "manifest contains no declared skills")
    if not deep:
        return

    component = manifest.components.get("skills")
    if component is None:
        collector.info("skill_inventory_not_configured", "deep skill inventory has no declared skill root")
        return
    if component.boundary != "runtime_root":
        collector.problem(
            "skill_inventory_external_boundary",
            "P1",
            "deep skill scan refused for a Skill root outside the runtime boundary",
            {"boundary": component.boundary},
        )
        return

    for value in _component_paths(component):
        raw_root = _unresolved_manifest_path(value, settings.root)
        if raw_root is not None and _has_reparse_component(raw_root):
            collector.problem(
                "skill_inventory_reparse_root",
                "P1",
                "deep skill scan refused for a symlink or reparse-point Skill root",
                {"path": raw_root},
            )
            continue
        root = resolve_manifest_path(value, settings.root)
        if root is None:
            collector.problem(
                "skill_inventory_root_unresolved",
                "P1",
                "deep skill scan refused for an unresolved Skill root",
            )
            continue
        if not _within(root, settings.root):
            collector.problem(
                "skill_inventory_boundary",
                "P1",
                "deep skill scan refused for a Skill root outside the runtime root",
                {"path": root},
            )
            continue
        if not root.is_dir():
            collector.info("skill_inventory_root_missing", "deep Skill root is not an existing directory")
            continue
        result = _scan_skill_root(root, declared)
        if result["undeclared_count"]:
            collector.problem(
                "skill_inventory_incomplete",
                "P2",
                "deep skill scan found undeclared SKILL.md files",
                {"undeclared_count": result["undeclared_count"]},
            )
        if result["limited_reason"] is not None:
            collector.problem(
                "skill_inventory_scan_limited",
                "P2",
                "deep skill scan stopped at a fixed safety limit",
                {
                    "limit": result["limited_reason"],
                    "directories_visited": result["directories_visited"],
                    "files_visited": result["files_visited"],
                },
            )
        if result["reparse_skipped"]:
            collector.info(
                "skill_inventory_reparse_skipped",
                "deep skill scan skipped symlinks and reparse points",
                {"count": result["reparse_skipped"]},
            )
        if result["unreadable_directories"]:
            collector.problem(
                "skill_inventory_unreadable",
                "P2",
                "deep skill scan encountered unreadable directories",
                {"count": result["unreadable_directories"]},
            )


def _authority_file_path(
    settings: Settings,
    *,
    path: str,
    boundary: str,
) -> tuple[Path | None, str | None]:
    raw = _unresolved_manifest_path(path, settings.root)
    if raw is None:
        return None, "unresolved"
    if _has_reparse_component(raw):
        return None, "reparse"
    resolved = resolve_manifest_path(path, settings.root)
    if resolved is None:
        return None, "unresolved"
    if boundary == "runtime_root" and not _within(resolved, settings.root):
        return None, "boundary"
    return resolved, None


def _installation_file_path(
    settings: Settings,
    *,
    path: str,
    boundary: str,
) -> tuple[Path | None, str | None]:
    """Resolve one installed-adapter file without traversing a directory."""
    raw_text = os.path.expandvars(path).strip()
    lower = raw_text.casefold()
    if lower.startswith("file:") or raw_text.startswith(("\\\\", "//")):
        return None, "unsafe_path"
    raw = _unresolved_manifest_path(path, settings.root)
    if raw is None:
        return None, "unresolved"
    if _has_reparse_component(raw):
        return None, "reparse"
    resolved = resolve_manifest_path(path, settings.root)
    if resolved is None:
        return None, "unresolved"
    if boundary == "runtime_root" and not _within(resolved, settings.root):
        return None, "boundary"
    if boundary == "external" and _within(resolved, settings.root):
        return None, "boundary"
    return resolved, None


def _read_installed_adapter_file(
    collector: _Collector,
    settings: Settings,
    *,
    installation: Any,
    role: str,
    path: str,
    boundary: str,
    expected_hash: str,
) -> tuple[bytes | None, str | None]:
    resolved, issue = _installation_file_path(settings, path=path, boundary=boundary)
    if issue is not None or resolved is None:
        collector.problem(
            "installed_adapter_path_invalid",
            "P1",
            "installed adapter file path is unresolved, outside its boundary, or a reparse point",
            {"installation": installation.name, "platform": installation.platform, "role": role, "reason": issue or "unresolved"},
        )
        return None, None
    if not resolved.is_file():
        severity = "P1" if installation.required else "P2"
        collector.problem(
            "installed_adapter_file_missing",
            severity,
            "installed adapter file is missing",
            {"installation": installation.name, "platform": installation.platform, "role": role},
        )
        return None, None
    try:
        content = resolved.read_bytes()
        text = content.decode("utf-8")
    except (OSError, UnicodeError):
        collector.problem(
            "installed_adapter_file_unreadable",
            "P1",
            "installed adapter file is unreadable or not UTF-8",
            {"installation": installation.name, "platform": installation.platform, "role": role},
        )
        return None, None
    actual_hash = hashlib.sha256(content).hexdigest()
    if actual_hash != expected_hash:
        collector.problem(
            f"installed_adapter_{role}_hash_drift",
            "P1",
            "installed adapter file hash differs from the manifest authority",
            {"installation": installation.name, "platform": installation.platform, "role": role},
        )
    else:
        collector.info(
            f"installed_adapter_{role}_hash_ok",
            "installed adapter file hash matches the manifest authority",
            {"installation": installation.name, "platform": installation.platform, "role": role},
        )
    return content, text


def _skill_frontmatter_issue(text: str) -> tuple[str | None, str | None]:
    match = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n", text, re.DOTALL)
    if match is None:
        return None, "frontmatter_invalid"
    values: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if not line.strip():
            continue
        field = re.fullmatch(r"([A-Za-z0-9_-]+):\s*(.*)", line)
        if field is None:
            return None, "frontmatter_invalid"
        key, value = field.groups()
        if key in values or key not in {"name", "description"}:
            return None, "frontmatter_fields"
        values[key] = value.strip().strip('"').strip("'")
    if set(values) != {"name", "description"}:
        return None, "frontmatter_fields"
    if values["name"] != "research-kb-pilot" or not values["description"]:
        return None, "frontmatter_identity"
    return text[match.end():], None


def _skill_contract_issue(text: str, canonical_text: str | None) -> str | None:
    body, issue = _skill_frontmatter_issue(text)
    if issue is not None or body is None:
        return issue or "frontmatter_invalid"
    if (
        "source-based-research/SKILL.md" not in text
        and "source-based-research\\SKILL.md" not in text
    ):
        return "runtime_skill_reference_missing"
    required_tools = (
        "search_corpus",
        "get_passage",
        "get_document_metadata",
        "get_research_context",
        "submit_hypothesis",
        "submit_objection",
        "save_research_note",
        "verify_quote_or_claim",
        "submit_verified_evidence",
        "get_search_history",
        "submit_research_report",
        "request_user_approval",
    )
    if any(tool not in text for tool in required_tools) or "exactly these 12 tools" not in text:
        return "exact_12_contract_missing"
    if "project_id" not in text or "missing or ambiguous" not in text or "never guess" not in text:
        return "project_id_fail_closed_missing"
    if "P0=0" not in text or "P1=0" not in text:
        return "governance_fail_closed_missing"
    if canonical_text:
        normalized = canonical_text.strip()
        if normalized in text or len(text.encode("utf-8")) > int(len(normalized.encode("utf-8")) * 0.75):
            return "canonical_copy"
    return None


def _metadata_contract_issue(text: str) -> str | None:
    values: dict[str, str] = {}
    for index, line in enumerate(text.splitlines()):
        if index == 0:
            if line != "interface:":
                return "metadata_interface_missing"
            continue
        field = re.fullmatch(r'  ([A-Za-z0-9_-]+):\s+"([^"]*)"', line)
        if field is None:
            return "metadata_strings_or_indentation"
        key, value = field.groups()
        if key in values or key not in {"display_name", "short_description", "default_prompt"}:
            return "metadata_fields"
        values[key] = value
    if set(values) != {"display_name", "short_description", "default_prompt"}:
        return "metadata_fields"
    if not 25 <= len(values["short_description"]) <= 64:
        return "metadata_short_description_length"
    if "$research-kb-pilot" not in values["default_prompt"] or "MCP" not in values["default_prompt"]:
        return "metadata_default_prompt_contract"
    return None


def _check_installed_adapters(
    collector: _Collector,
    settings: Settings,
    authority: Any,
    canonical_text: str | None,
) -> None:
    for installation in authority.installations:
        rendered_skill_bytes, rendered_skill_text = _read_installed_adapter_file(
            collector,
            settings,
            installation=installation,
            role="skill",
            path=installation.rendered_skill_path,
            boundary=installation.rendered_skill_boundary,
            expected_hash=installation.skill_sha256,
        )
        installed_skill_bytes, installed_skill_text = _read_installed_adapter_file(
            collector,
            settings,
            installation=installation,
            role="skill",
            path=installation.installed_skill_path,
            boundary=installation.installed_skill_boundary,
            expected_hash=installation.skill_sha256,
        )
        rendered_metadata_bytes, rendered_metadata_text = _read_installed_adapter_file(
            collector,
            settings,
            installation=installation,
            role="metadata",
            path=installation.rendered_metadata_path,
            boundary=installation.rendered_metadata_boundary,
            expected_hash=installation.metadata_sha256,
        )
        installed_metadata_bytes, installed_metadata_text = _read_installed_adapter_file(
            collector,
            settings,
            installation=installation,
            role="metadata",
            path=installation.installed_metadata_path,
            boundary=installation.installed_metadata_boundary,
            expected_hash=installation.metadata_sha256,
        )

        if rendered_skill_bytes is not None and installed_skill_bytes is not None:
            if rendered_skill_bytes == installed_skill_bytes:
                collector.info(
                    "installed_adapter_bytes_ok",
                    "rendered and installed adapter Skill bytes are identical",
                    {"installation": installation.name, "platform": installation.platform, "role": "skill"},
                )
            else:
                collector.problem(
                    "installed_adapter_bytes_drift",
                    "P1",
                    "rendered and installed adapter Skill bytes differ",
                    {"installation": installation.name, "platform": installation.platform, "role": "skill"},
                )
        if rendered_metadata_bytes is not None and installed_metadata_bytes is not None:
            if rendered_metadata_bytes == installed_metadata_bytes:
                collector.info(
                    "installed_adapter_bytes_ok",
                    "rendered and installed adapter metadata bytes are identical",
                    {"installation": installation.name, "platform": installation.platform, "role": "metadata"},
                )
            else:
                collector.problem(
                    "installed_adapter_bytes_drift",
                    "P1",
                    "rendered and installed adapter metadata bytes differ",
                    {"installation": installation.name, "platform": installation.platform, "role": "metadata"},
                )

        contract_issues: list[str] = []
        for role, skill_text, metadata_text in (
            ("rendered", rendered_skill_text, rendered_metadata_text),
            ("installed", installed_skill_text, installed_metadata_text),
        ):
            if skill_text is not None:
                issue = _skill_contract_issue(skill_text, canonical_text)
                if issue is not None:
                    contract_issues.append(f"{role}_skill:{issue}")
            if metadata_text is not None:
                issue = _metadata_contract_issue(metadata_text)
                if issue is not None:
                    contract_issues.append(f"{role}_metadata:{issue}")
        if contract_issues:
            collector.problem(
                "installed_adapter_contract_drift",
                "P1",
                "rendered or installed Codex adapter does not satisfy the thin adapter contract",
                {"installation": installation.name, "platform": installation.platform, "reasons": contract_issues},
            )
        else:
            collector.info(
                "installed_adapter_contract_ok",
                "rendered and installed Codex adapter satisfy the thin adapter contract",
                {"installation": installation.name, "platform": installation.platform},
            )


def _adapter_content_issue(text: str, canonical_text: str | None) -> str | None:
    if re.search(r"(?i)(?:[A-Za-z]:[\/]|\\|file://)", text):
        return "absolute_path"
    if re.search(r"(?m)(?:^|[s=([])/(?!/)", text):
        return "absolute_path"
    if "<RESEARCH_KB_CANONICAL_SKILL>" not in text:
        return "canonical_reference_missing"
    if canonical_text:
        normalized = canonical_text.strip()
        if normalized in text or len(text.encode("utf-8")) > int(len(normalized.encode("utf-8")) * 0.75):
            return "full_canonical_copy"
    copied_rule_markers = (
        "note_purpose",
        "supersedes_item_id",
        "source_links",
        "match_strategy",
        "query_relaxed",
        "Source Role Map",
        "citation_locator",
    )
    if any(marker in text for marker in copied_rule_markers):
        return "canonical_rules_copied"
    return None


def _check_skill_authority(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
) -> None:
    if manifest is None or manifest.skill_authority is None:
        collector.info(
            "skill_authority_not_configured",
            "canonical/runtime Skill authority was not declared in the manifest",
        )
        return

    authority = manifest.skill_authority
    canonical_path, canonical_issue = _authority_file_path(
        settings,
        path=authority.canonical.path,
        boundary=authority.canonical.boundary,
    )
    runtime_path, runtime_issue = _authority_file_path(
        settings,
        path=authority.runtime.path,
        boundary=authority.runtime.boundary,
    )
    canonical_text: str | None = None
    runtime_text: str | None = None

    if canonical_issue is not None or canonical_path is None or not canonical_path.is_file():
        collector.problem(
            "canonical_skill_missing",
            "P1",
            "declared canonical Skill is missing or outside its approved boundary",
            {"reason": canonical_issue or "missing"},
        )
    else:
        try:
            canonical_text = canonical_path.read_text(encoding="utf-8")
            canonical_hash = sha256_file(canonical_path)
        except (OSError, UnicodeError):
            collector.problem(
                "canonical_skill_unreadable",
                "P1",
                "declared canonical Skill is unreadable",
            )
        else:
            if canonical_hash != authority.canonical.content_sha256:
                collector.problem(
                    "canonical_skill_hash_drift",
                    "P1",
                    "canonical Skill hash differs from the manifest authority",
                )
            else:
                collector.info(
                    "canonical_skill_hash_ok",
                    "canonical Skill hash matches the manifest authority",
                )

    if runtime_issue is not None or runtime_path is None or not runtime_path.is_file():
        collector.problem(
            "runtime_skill_missing",
            "P1",
            "declared runtime Skill is missing or outside its approved boundary",
            {"reason": runtime_issue or "missing"},
        )
    else:
        try:
            runtime_text = runtime_path.read_text(encoding="utf-8")
            runtime_hash = sha256_file(runtime_path)
        except (OSError, UnicodeError):
            collector.problem(
                "runtime_skill_unreadable",
                "P1",
                "declared runtime Skill is unreadable",
            )
        else:
            if runtime_hash != authority.runtime.content_sha256:
                collector.problem(
                    "runtime_skill_hash_drift",
                    "P1",
                    "runtime Skill hash differs from the manifest authority",
                )
            else:
                collector.info(
                    "runtime_skill_hash_ok",
                    "runtime Skill hash matches the manifest authority",
                )

    if canonical_text is not None and runtime_text is not None:
        if canonical_text.encode("utf-8") != runtime_text.encode("utf-8"):
            collector.problem(
                "skill_source_runtime_drift",
                "P1",
                "runtime Skill is not byte-identical to the canonical Skill",
            )
        else:
            collector.info(
                "skill_source_runtime_ok",
                "runtime Skill is byte-identical to the canonical Skill",
            )

    for adapter in authority.adapters:
        adapter_path, adapter_issue = _authority_file_path(
            settings,
            path=adapter.path,
            boundary=adapter.boundary,
        )
        if adapter_issue is not None or adapter_path is None:
            collector.problem(
                "adapter_template_missing",
                "P1",
                "declared adapter template is missing or outside its approved boundary",
                {"adapter": adapter.name, "reason": adapter_issue or "missing"},
            )
            continue
        if not adapter_path.is_file():
            severity = "P1" if adapter.required else "P2"
            collector.problem(
                "adapter_template_missing",
                severity,
                "declared adapter template is missing or outside its approved boundary",
                {"adapter": adapter.name, "reason": "missing"},
            )
            continue
        try:
            adapter_bytes = adapter_path.read_bytes()
            adapter_text = adapter_bytes.decode("utf-8")
        except (OSError, UnicodeError):
            collector.problem(
                "adapter_template_drift",
                "P1",
                "declared adapter template is unreadable or not UTF-8",
                {"adapter": adapter.name},
            )
            continue
        adapter_hash = hashlib.sha256(adapter_bytes).hexdigest()
        hash_matches = adapter_hash == adapter.content_sha256
        if hash_matches:
            collector.info(
                "adapter_template_hash_ok",
                "adapter template hash matches the manifest authority",
                {"adapter": adapter.name},
            )
        else:
            collector.problem(
                "adapter_template_hash_drift",
                "P1",
                "adapter template hash differs from the manifest authority",
                {"adapter": adapter.name},
            )
        issue = _adapter_content_issue(adapter_text, canonical_text)
        if issue is not None:
            collector.problem(
                "adapter_template_drift",
                "P1",
                "adapter template is not a thin canonical Skill adapter",
                {"adapter": adapter.name, "reason": issue},
            )
        elif hash_matches:
            collector.info(
                "adapter_template_ok",
                "adapter template references canonical Skill without copying its rules",
                {"adapter": adapter.name},
            )
    if authority.installations:
        _check_installed_adapters(collector, settings, authority, canonical_text)


_MCP_FORBIDDEN_FIELDS = frozenset(
    {
        "url",
        "headers",
        "authorization",
        "bearer_token",
        "auth",
        "disabled_tools",
    }
)
_MCP_DANGEROUS_ENV = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|auth|bearer|credential|private[_-]?key|pythonpath|pythonhome|ld_preload|dyld_|node_options)"
)


def _normalize_mcp_value(value: Any) -> Any:
    if isinstance(value, str):
        text = value.replace("\\", "/")
        if re.match(r"^[A-Za-z]:/", text) or text.startswith("//"):
            return text.casefold().rstrip("/")
        return text
    return value


def _normalize_mcp_args(values: Any) -> tuple[Any, ...] | None:
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        return None
    return tuple(_normalize_mcp_value(value) for value in values)


def _mcp_contract_mismatches(
    installation: MCPInstallationSpec,
    server: Mapping[str, Any],
) -> list[str]:
    mismatches: list[str] = []
    expected_scalars = {
        "command": installation.command,
        "cwd": installation.cwd,
        "enabled": installation.enabled,
        "required": installation.required,
        "startup_timeout_sec": installation.startup_timeout_sec,
        "tool_timeout_sec": installation.tool_timeout_sec,
    }
    for key, expected in expected_scalars.items():
        if key not in server or _normalize_mcp_value(server.get(key)) != _normalize_mcp_value(expected):
            mismatches.append(key)
    expected_args = tuple(_normalize_mcp_value(value) for value in installation.args)
    actual_args = _normalize_mcp_args(server.get("args"))
    if actual_args != expected_args:
        mismatches.append("args")
    if "enabled_tools" not in server or not isinstance(server.get("enabled_tools"), list):
        mismatches.append("enabled_tools")
    else:
        actual_tools = server["enabled_tools"]
        if any(not isinstance(value, str) for value in actual_tools):
            mismatches.append("enabled_tools")
        elif len(actual_tools) != len(set(actual_tools)) or set(actual_tools) != set(installation.enabled_tools):
            mismatches.append("enabled_tools")
    return mismatches


def _mcp_process_value(settings: Settings, value: str, *, cwd: bool = False) -> str:
    if cwd:
        resolved = resolve_manifest_path(value, settings.root)
        return str(resolved) if resolved is not None else value
    if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith(("/", "\\", "//")):
        resolved = resolve_manifest_path(value, settings.root)
        return str(resolved) if resolved is not None else value
    return value


def _read_mcp_config(
    collector: _Collector,
    settings: Settings,
    installation: MCPInstallationSpec,
) -> Mapping[str, Any] | None:
    resolved, issue = _installation_file_path(
        settings,
        path=installation.config_path,
        boundary=installation.config_boundary,
    )
    if issue is not None or resolved is None:
        collector.problem(
            "codex_mcp_config_path_invalid",
            "P1",
            "Codex MCP configuration path is unresolved, outside its boundary, or a reparse point",
            {"installation": installation.name, "reason": issue or "invalid"},
        )
        return None
    if not resolved.is_file():
        collector.problem(
            "codex_mcp_config_missing",
            "P1",
            "Codex MCP configuration file is missing",
            {"installation": installation.name},
        )
        return None
    try:
        text = resolved.read_text(encoding="utf-8")
        raw = tomllib.loads(text)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        collector.problem(
            "codex_mcp_config_invalid",
            "P1",
            "Codex MCP configuration is not valid UTF-8 TOML",
            {"installation": installation.name},
        )
        return None
    return raw


def _check_mcp_authority(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
    *,
    deep: bool,
) -> None:
    if manifest is None or manifest.mcp_authority is None:
        if manifest is not None:
            collector.info(
                "mcp_installation_authority_not_configured",
                "Codex MCP installation authority was not declared in the manifest",
            )
        return
    authority: MCPAuthoritySpec = manifest.mcp_authority
    if not authority.installations:
        collector.problem(
            "codex_mcp_installation_missing",
            "P1",
            "MCP authority declares no Codex installation",
        )
        return
    for installation in authority.installations:
        raw = _read_mcp_config(collector, settings, installation)
        if raw is None:
            continue
        servers = raw.get("mcp_servers")
        if not isinstance(servers, Mapping):
            collector.problem(
                "codex_mcp_server_missing",
                "P1",
                "P1",
                "Codex MCP server table is missing",
                {"installation": installation.name},
            )
            continue
        server = servers.get(installation.server_name)
        if not isinstance(server, Mapping):
            collector.problem(
                "codex_mcp_server_missing",
                "P1",
                "Codex research-kb MCP server table is missing",
                {"installation": installation.name},
            )
            continue

        forbidden = sorted(
            key for key in _MCP_FORBIDDEN_FIELDS if key in server
        )
        if forbidden:
                collector.problem(
                    "codex_mcp_forbidden_field",
                    "P1",
                "Codex MCP server contains a forbidden URL, authentication, or disabled-tools field",
                {"installation": installation.name, "fields": forbidden},
            )
        transport = server.get("transport", "stdio")
        if transport != installation.transport:
            collector.problem(
                "codex_mcp_transport_drift",
                "P1",
                "Codex MCP transport differs from the declared stdio contract",
                {"installation": installation.name},
            )
        env = server.get("env")
        if env is not None:
            if not isinstance(env, Mapping):
                collector.problem(
                    "codex_mcp_dangerous_env",
                    "P1",
                    "Codex MCP env must be a table when present",
                    {"installation": installation.name},
                )
            else:
                dangerous = sorted(
                    str(key)
                    for key in env
                    if _MCP_DANGEROUS_ENV.search(str(key))
                )
                if dangerous:
                    collector.problem(
                        "codex_mcp_dangerous_env",
                        "P1",
                        "Codex MCP env contains a forbidden credential or process-injection key",
                        {"installation": installation.name, "keys": dangerous},
                    )

        mismatches = _mcp_contract_mismatches(installation, server)
        if mismatches:
            collector.problem(
                "codex_mcp_config_drift",
                "P1",
                "Codex research-kb MCP configuration differs from the manifest contract",
                {"installation": installation.name, "fields": sorted(set(mismatches))},
            )
        else:
            collector.info(
                "codex_mcp_config_ok",
                "Codex research-kb MCP configuration matches the manifest contract",
                {"installation": installation.name},
            )
        if deep and not forbidden and not mismatches and transport == installation.transport:
            _check_mcp_config_live(collector, settings, installation)


def _check_mcp_config_live(
    collector: _Collector,
    settings: Settings,
    installation: MCPInstallationSpec,
) -> None:
    async def _run() -> tuple[list[str], str]:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        server = StdioServerParameters(
            command=_mcp_process_value(settings, installation.command),
            args=list(installation.args),
            cwd=_mcp_process_value(settings, installation.cwd, cwd=True),
        )
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errlog:
            async with stdio_client(server, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await asyncio.wait_for(
                        session.initialize(),
                        timeout=installation.startup_timeout_sec,
                    )
                    listed = await asyncio.wait_for(
                        session.list_tools(),
                        timeout=installation.tool_timeout_sec,
                    )
                    names = [str(tool.name) for tool in listed.tools]
            errlog.seek(0)
            return names, errlog.read()

    try:
        actual_names, stderr = asyncio.run(_run())
    except ModuleNotFoundError:
        collector.problem(
            "codex_mcp_live_check_unavailable",
            "P2",
            "deep Codex MCP check is unavailable because the official MCP client is not installed",
            {"installation": installation.name},
        )
        return
    except Exception:
        collector.problem(
            "codex_mcp_live_check_failed",
            "P1",
            "deep Codex MCP initialization or tool listing failed",
            {"installation": installation.name},
        )
        return
    if stderr.strip():
        collector.problem(
            "codex_mcp_live_stderr",
            "P1",
            "deep Codex MCP check produced unexpected stderr",
            {"installation": installation.name, "stderr_bytes": len(stderr.encode("utf-8"))},
        )
    expected = set(EXPECTED_MCP_TOOLS)
    actual = set(actual_names)
    if len(actual_names) != len(actual) or actual != expected:
        collector.problem(
            "codex_mcp_live_tools_mismatch",
            "P1",
            "deep Codex MCP tool listing is not the strict twelve-tool contract",
            {
                "installation": installation.name,
                "count": len(actual_names),
                "missing_count": len(expected - actual),
                "extra_count": len(actual - expected),
            },
        )
    else:
        collector.info(
            "codex_mcp_live_tools_ok",
            "deep Codex MCP client listed exactly the twelve supported tools",
            {"installation": installation.name, "count": len(actual_names)},
        )


def _check_backups(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
    *,
    now: datetime,
) -> None:
    path = settings.workspace / "backups"
    if manifest is not None and "backup" in manifest.components:
        values = _component_paths(manifest.components["backup"])
        if values:
            resolved = resolve_manifest_path(values[0], settings.root)
            if resolved is not None:
                path = resolved
    if not path.is_dir():
        collector.problem("backup_directory_missing", "P2", "backup directory is missing")
        return
    try:
        files = [item for item in path.iterdir() if item.is_file() and item.suffix.casefold() == ".db"]
        files.sort(key=lambda item: (item.stat().st_mtime_ns, item.name))
    except OSError:
        collector.problem("backup_directory_unreadable", "P2", "backup directory is unreadable")
        return
    if not files:
        collector.problem("backup_missing", "P2", "no database backup was found")
        return
    latest = files[-1]
    try:
        mtime = datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc)
    except OSError:
        collector.problem("backup_metadata_unreadable", "P2", "latest backup metadata is unreadable")
        return
    age_days = max(0, (now - mtime).days)
    details = {"latest_name": latest.name, "age_days": age_days, "backup_count": len(files)}
    if age_days > _STALE_DAYS:
        collector.problem("backup_stale", "P2", "latest database backup is older than the freshness window", details)
    else:
        collector.info("backup_info", "a recent database backup is available", details)


def _check_compatibility(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
) -> None:
    if manifest is None:
        collector.info("compatibility_not_configured", "manifest compatibility checks were not requested")
        return
    if manifest.engine_package != "research-kb":
        collector.problem("manifest_package_mismatch", "P1", "manifest package does not match the engine")
    elif manifest.engine_version != __version__:
        collector.problem("manifest_package_version_mismatch", "P1", "manifest package version does not match the engine")
    else:
        collector.info("manifest_package_version_ok", "package version matches manifest")
    if manifest.schema_version != SCHEMA_VERSION:
        collector.problem("manifest_schema_mismatch", "P0", "manifest schema version is incompatible with the engine")
    else:
        collector.info("manifest_schema_ok", "schema version matches manifest")
    if manifest.protocol != PROTOCOL:
        collector.problem("manifest_protocol_mismatch", "P0", "manifest protocol is incompatible with the engine")
    else:
        collector.info("manifest_protocol_ok", "protocol matches manifest")
    if manifest.mcp_server_name != MCP_SERVER_NAME:
        collector.problem(
            "manifest_mcp_server_name_mismatch",
            "P1",
            "manifest MCP server name is not the supported server name",
            {"expected": MCP_SERVER_NAME, "declared": manifest.mcp_server_name},
        )
    else:
        collector.info("manifest_mcp_server_name_ok", "manifest MCP server name matches the supported server")
    if tuple(manifest.mcp_tools) != tuple(EXPECTED_MCP_TOOLS):
        collector.problem(
            "manifest_mcp_tools_mismatch",
            "P0",
            "manifest MCP tool set is not the strict supported set",
            {"expected_count": len(EXPECTED_MCP_TOOLS), "manifest_count": len(manifest.mcp_tools)},
        )
    else:
        collector.info("mcp_tool_set_ok", "MCP tool set is exactly the supported twelve tools")
    mismatches = [
        name for name, actual in _ACTUAL_CAPABILITIES.items()
        if bool(manifest.capabilities.get(name, False)) != actual
    ]
    if mismatches:
        collector.problem(
            "manifest_capability_mismatch",
            "P1",
            "manifest capability flags differ from the runtime",
            {"capabilities": mismatches},
        )
    else:
        collector.info("manifest_capabilities_ok", "manifest capability flags match the runtime")
    if settings.default_search_mode != "lexical" or settings.semantic_enabled:
        collector.problem("retrieval_capability_mismatch", "P1", "runtime retrieval settings are outside the supported lexical baseline")


def _check_mcp_live_registration(collector: _Collector, settings: Settings) -> None:
    """Compare the tools registered by FastMCP, without starting a transport."""
    try:
        from .mcp_server import create_mcp_server
    except SystemExit:
        collector.problem(
            "mcp_live_check_unavailable",
            "P2",
            "deep MCP registration check is unavailable because the MCP extra is not installed",
        )
        return
    except Exception:
        collector.problem(
            "mcp_live_check_unavailable",
            "P2",
            "deep MCP registration check is unavailable",
        )
        return

    try:
        server = create_mcp_server(settings)
        listed = asyncio.run(server.list_tools())
        actual_names = [str(getattr(tool, "name")) for tool in listed]
    except SystemExit:
        collector.problem(
            "mcp_live_check_unavailable",
            "P2",
            "deep MCP registration check is unavailable because the MCP extra is not installed",
        )
        return
    except Exception:
        collector.problem(
            "mcp_live_check_unavailable",
            "P2",
            "deep MCP registration check could not read the live FastMCP registry",
        )
        return

    expected = set(EXPECTED_MCP_TOOLS)
    actual = set(actual_names)
    if len(actual_names) != len(actual) or actual != expected:
        collector.problem(
            "mcp_live_tools_mismatch",
            "P0",
            "live FastMCP registration does not match the strict twelve-tool contract",
            {
                "expected": sorted(expected),
                "actual": sorted(actual_names),
                "missing": sorted(expected - actual),
                "extra": sorted(actual - expected),
            },
        )
    else:
        collector.info(
            "mcp_live_tools_ok",
            "live FastMCP registration contains exactly the twelve supported tools",
            {"count": len(actual_names), "names": sorted(actual_names)},
        )


def _inspect_database(
    collector: _Collector,
    settings: Settings,
    manifest: SystemManifest | None,
    *,
    now: datetime,
) -> list[dict[str, Any]] | None:
    if not settings.database.is_file():
        return None
    wal_path = settings.database.with_name(settings.database.name + "-wal")
    try:
        if wal_path.is_file() and wal_path.stat().st_size:
            collector.problem(
                "database_wal_pending",
                "P0",
                "database has a non-empty WAL; doctor will not open it in a way that can alter WAL/SHM state",
                {"path": wal_path},
            )
            return None
    except OSError:
        collector.problem("database_wal_inspection", "P0", "database WAL metadata could not be inspected")
        return None
    try:
        with connect(settings, read_only=True, immutable=True) as connection:
            foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
            quick_rows = [row[0] for row in connection.execute("PRAGMA quick_check").fetchall()]
            if foreign_keys != 1:
                collector.problem("database_foreign_keys", "P0", "database foreign_keys pragma is not enabled")
            else:
                collector.info("database_foreign_keys", "database foreign_keys pragma is enabled")
            if quick_rows != ["ok"]:
                collector.problem("database_quick_check", "P0", "database quick_check failed")
            else:
                collector.info("database_quick_check", "database quick_check is ok")

            applied = tuple(
                int(row[0]) for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
            )
            expected = tuple(version for version, _ in migration_paths())
            if applied != expected or not applied or applied[-1] != SCHEMA_VERSION:
                collector.problem("database_schema_current", "P0", "database schema migrations are not current")
            else:
                collector.info("database_schema_current", "database schema migrations are current")

            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table')")}
            triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
            missing_tables = sorted(REQUIRED_MCP_TABLES - tables)
            missing_triggers = sorted(REQUIRED_MCP_TRIGGERS - triggers)
            if missing_tables or missing_triggers:
                collector.problem(
                    "mcp_readiness_objects",
                    "P0",
                    "MCP readiness objects are incomplete",
                    {"missing_tables": missing_tables, "missing_triggers": missing_triggers},
                )
            else:
                collector.info("mcp_readiness_objects", "MCP readiness objects are present")

            count_names = ("projects", "documents", "passages", "passages_fts", "passages_search_fts", "audit_log")
            counts = {
                name: int(connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0])
                for name in count_names
            }
            if counts["passages"] != counts["passages_search_fts"]:
                collector.problem("fts_search_count", "P0", "active lexical FTS row count differs from passages", counts)
            else:
                collector.info("fts_search_count", "active lexical FTS row count matches passages", {"passages": counts["passages"], "fts": counts["passages_search_fts"]})
            if counts["passages"] != counts["passages_fts"]:
                collector.problem("fts_legacy_count", "P1", "legacy FTS row count differs from passages", counts)
            else:
                collector.info("fts_legacy_count", "FTS row counts are consistent", {"passages": counts["passages"]})
            collector.info("database_counts", "database counts were read without loading source text", counts)

            projects = [
                {"project_id": str(row[0]), "status": str(row[1])}
                for row in connection.execute("SELECT project_id, status FROM projects ORDER BY project_id")
            ]
            _check_checkpoint_cross_kind_successors(collector, connection)
            _check_checkpoints(collector, connection, projects)
            _check_approvals(collector, connection, now=now)
            _check_registry(collector, settings, manifest, projects)
            return projects
    except (OSError, sqlite3.Error, ValueError):
        collector.problem("database_read_only_inspection", "P0", "database read-only inspection failed")
        return None


def _empty_report(
    collector: _Collector,
    *,
    config_path: str | Path,
    strict: bool,
    deep: bool,
) -> dict[str, Any]:
    return collector.report(
        config_path=config_path,
        settings=None,
        manifest=None,
        strict=strict,
        deep=deep,
    )


def run_doctor(
    config_path: str | Path,
    *,
    manifest_path: str | Path | None = None,
    strict: bool = False,
    deep: bool = False,
    show_paths: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run the system doctor without creating or modifying any file."""
    collector = _Collector(show_paths=show_paths)
    selected_config = Path(config_path).expanduser()
    if not selected_config.is_file():
        collector.problem("config_missing", "P0", "configuration file is missing")
        return _empty_report(collector, config_path=selected_config, strict=strict, deep=deep)
    try:
        settings = Settings.load(selected_config)
    except (OSError, ValueError, TypeError):
        collector.problem("config_invalid", "P0", "configuration file cannot be parsed")
        return _empty_report(collector, config_path=selected_config, strict=strict, deep=deep)
    collector.info("config_readable", "configuration file is readable")

    manifest: SystemManifest | None = None
    if manifest_path is not None:
        try:
            manifest = load_manifest(manifest_path)
            collector.info("manifest_readable", "system manifest is valid")
        except (OSError, ManifestError):
            collector.problem("manifest_invalid", "P0", "system manifest is missing, invalid, or incompatible")
    else:
        collector.info("manifest_not_supplied", "no external system manifest was supplied")

    _check_config_paths(collector, settings, manifest)
    _check_catalog(collector, settings, manifest)
    _check_skills(collector, settings, manifest, deep=deep)
    _check_mcp_authority(collector, settings, manifest, deep=deep)
    if deep:
        _check_skill_authority(collector, settings, manifest)
    _check_backups(collector, settings, manifest, now=now or datetime.now(timezone.utc))
    _check_compatibility(collector, settings, manifest)
    _inspect_database(collector, settings, manifest, now=now or datetime.now(timezone.utc))
    if deep:
        _check_mcp_live_registration(collector, settings)
    collector.info(
        "mcp_tool_contract_declared",
        "doctor is reporting the declared twelve-tool MCP contract; live registration requires --deep",
        {"count": len(EXPECTED_MCP_TOOLS), "names": list(EXPECTED_MCP_TOOLS)},
    )
    return collector.report(
        config_path=selected_config,
        settings=settings,
        manifest=manifest,
        strict=strict,
        deep=deep,
    )


def format_doctor_text(report: Mapping[str, Any]) -> str:
    """Render a compact, path-safe transcript for human administrators."""
    lines = [
        f"research-kb doctor: {report.get('status')} (exit {report.get('exit_code')})",
        f"summary: {json.dumps(report.get('summary', {}), ensure_ascii=False, sort_keys=True)}",
    ]
    for finding in report.get("checks", []):
        severity = finding.get("severity", "INFO")
        lines.append(f"[{severity}] {finding.get('id')}: {finding.get('message')}")
    return "\n".join(lines)
