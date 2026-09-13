"""Versioned, read-only system manifest primitives for research-kb.

The manifest describes the control plane around a research-kb runtime.  It is
deliberately separate from the SQLite research database and never contains
source text, evidence, credentials, or other research content.
"""

from __future__ import annotations

import hashlib
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


MANIFEST_FORMAT_VERSION = 1
PROTOCOL = "research-kb/v1"
MCP_SERVER_NAME = "research-kb"
CODEX_MCP_SERVER_NAME = "research-kb-pilot"
EXPECTED_MCP_TOOLS = (
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
CHECKPOINT_POLICIES = ("one-current",)
CATALOG_LIFECYCLE = (
    "cataloged",
    "reviewed",
    "ready",
    "ingested",
    "indexed",
    "available",
    "retired",
)
CAPABILITY_NAMES = (
    "lexical",
    "semantic",
    "hybrid",
    "local_model",
    "remote_deployment",
)

# These are the read-only readiness objects required by the existing MCP
# adapter.  Keeping the names in this dependency-free module lets the core
# doctor run without importing the optional MCP SDK.
REQUIRED_MCP_TABLES = frozenset(
    {
        "schema_migrations",
        "projects",
        "documents",
        "passages",
        "passages_fts",
        "project_sources",
        "research_items",
        "research_item_versions",
        "verification_tokens",
        "verified_evidence",
        "evidence_links",
        "approval_requests",
        "agent_sessions",
        "search_events",
        "audit_log",
        "evidence_status_history",
        "source_metadata_audit",
        "approval_requests_v2",
        "passages_search_fts",
        "report_manifest",
    }
)
REQUIRED_MCP_TRIGGERS = frozenset(
    {
        "passages_fts_insert",
        "documents_identity_immutable",
        "documents_no_delete",
        "passages_no_update",
        "passages_no_delete",
        "item_versions_no_update",
        "item_versions_no_delete",
        "evidence_links_no_update",
        "evidence_links_no_delete",
        "verified_evidence_no_update",
        "verified_evidence_no_delete",
        "audit_no_update",
        "audit_no_delete",
        "accepted_item_no_update",
        "items_no_delete",
        "verification_token_binding_immutable",
        "verification_token_no_delete",
        "evidence_status_no_update",
        "evidence_status_no_delete",
        "evidence_status_transition",
        "source_metadata_audit_no_update",
        "source_metadata_audit_no_delete",
        "approval_v2_target_exists",
        "approval_v2_target_immutable",
        "approval_v2_status_transition",
        "approval_v2_no_delete",
        "research_item_status_transition",
        "evidence_status_transition_strict",
        "verification_token_session_immutable",
        "report_manifest_no_update",
        "report_manifest_no_delete",
        "report_manifest_target_exists",
    }
)

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_ENV_TOKEN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|%([A-Za-z_][A-Za-z0-9_]*)%")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class ManifestError(ValueError):
    """A manifest is malformed, unsupported, or incompatible."""


@dataclass(frozen=True)
class ComponentSpec:
    name: str
    path: str | None = None
    paths: tuple[str, ...] = ()
    boundary: str = "runtime_root"
    required: bool = True


@dataclass(frozen=True)
class ProjectSpec:
    project_id: str
    workspace: str
    corpus_scope: tuple[str, ...]
    checkpoint_policy: str


@dataclass(frozen=True)
class SkillSpec:
    name: str
    path: str
    version: str | None = None
    content_sha256: str | None = None


@dataclass(frozen=True)
class AuthorityFileSpec:
    path: str
    boundary: str
    content_sha256: str


@dataclass(frozen=True)
class AdapterTemplateSpec:
    name: str
    path: str
    boundary: str
    required: bool
    depends_on: str
    content_sha256: str


@dataclass(frozen=True)
class InstalledAdapterSpec:
    name: str
    platform: str
    template: str
    required: bool
    rendered_skill_path: str
    rendered_skill_boundary: str
    installed_skill_path: str
    installed_skill_boundary: str
    rendered_metadata_path: str
    rendered_metadata_boundary: str
    installed_metadata_path: str
    installed_metadata_boundary: str
    skill_sha256: str
    metadata_sha256: str


@dataclass(frozen=True)
class MCPInstallationSpec:
    name: str
    platform: str
    config_path: str
    config_boundary: str
    server_name: str
    transport: str
    command: str
    args: tuple[str, ...]
    cwd: str
    enabled: bool
    required: bool
    startup_timeout_sec: int
    tool_timeout_sec: int
    enabled_tools: tuple[str, ...]


@dataclass(frozen=True)
class MCPAuthoritySpec:
    authority: str
    installations: tuple[MCPInstallationSpec, ...]


@dataclass(frozen=True)
class SkillAuthoritySpec:
    authority: str
    canonical: AuthorityFileSpec
    runtime: AuthorityFileSpec
    adapters: tuple[AdapterTemplateSpec, ...]
    installations: tuple[InstalledAdapterSpec, ...]


@dataclass(frozen=True)
class SystemManifest:
    source_path: Path | None
    manifest_format_version: int
    engine_package: str
    engine_version: str
    schema_version: int
    protocol: str
    config_path: str
    components: Mapping[str, ComponentSpec]
    mcp_server_name: str
    mcp_tools: tuple[str, ...]
    projects: tuple[ProjectSpec, ...]
    skills: tuple[SkillSpec, ...]
    skill_authority: SkillAuthoritySpec | None
    mcp_authority: MCPAuthoritySpec | None
    catalog_lifecycle: tuple[str, ...]
    catalog_summary_files: tuple[str, ...]
    capabilities: Mapping[str, bool]

    @property
    def has_project_registry(self) -> bool:
        return bool(self.projects)

    def to_dict(self, *, show_paths: bool = False) -> dict[str, Any]:
        """Return a stable, structured view with local paths redacted by default.

        ``source_path`` is deliberately not part of this view.  The method is
        used by doctor output, so path handling happens before JSON encoding and
        cannot be bypassed by JSON escaping.
        """
        components: dict[str, Any] = {}
        for name in sorted(self.components):
            component = self.components[name]
            value: dict[str, Any] = {
                "boundary": component.boundary,
                "required": component.required,
            }
            if component.path is not None:
                value["path"] = _display_manifest_path(component.path, show_paths=show_paths)
            if component.paths:
                value["paths"] = [
                    _display_manifest_path(path, show_paths=show_paths)
                    for path in component.paths
                ]
            components[name] = value
        return {
            "manifest_format_version": self.manifest_format_version,
            "engine": {"package": self.engine_package, "version": self.engine_version},
            "schema": {"version": self.schema_version},
            "protocol": {"name": self.protocol},
            "config": {"path": _display_manifest_path(self.config_path, show_paths=show_paths)},
            "components": components,
            "mcp": {
                "server_name": self.mcp_server_name,
                "tools": list(self.mcp_tools),
            },
            "project_registry": {
                "projects": [
                    {
                        "project_id": project.project_id,
                        "workspace": _display_manifest_path(project.workspace, show_paths=show_paths),
                        "corpus_scope": [
                            _display_manifest_path(scope, show_paths=show_paths)
                            for scope in project.corpus_scope
                        ],
                        "checkpoint_policy": project.checkpoint_policy,
                    }
                    for project in self.projects
                ]
            },
            "skills": {
                "items": [
                    {
                        "name": skill.name,
                        "path": _display_manifest_path(skill.path, show_paths=show_paths),
                        "version": skill.version,
                        "content_sha256": skill.content_sha256,
                    }
                    for skill in self.skills
                ]
            },
            "skill_authority": (
                None
                if self.skill_authority is None
                else {
                    "authority": self.skill_authority.authority,
                    "canonical": {
                        "path": _display_manifest_path(
                            self.skill_authority.canonical.path,
                            show_paths=show_paths,
                        ),
                        "boundary": self.skill_authority.canonical.boundary,
                        "content_sha256": self.skill_authority.canonical.content_sha256,
                    },
                    "runtime": {
                        "path": _display_manifest_path(
                            self.skill_authority.runtime.path,
                            show_paths=show_paths,
                        ),
                        "boundary": self.skill_authority.runtime.boundary,
                        "content_sha256": self.skill_authority.runtime.content_sha256,
                    },
                    "adapters": [
                        {
                            "name": adapter.name,
                            "path": _display_manifest_path(adapter.path, show_paths=show_paths),
                            "boundary": adapter.boundary,
                            "required": adapter.required,
                            "depends_on": adapter.depends_on,
                            "content_sha256": adapter.content_sha256,
                        }
                        for adapter in self.skill_authority.adapters
                    ],
                    "installations": [
                        {
                            "name": installation.name,
                            "platform": installation.platform,
                            "template": installation.template,
                            "required": installation.required,
                            "rendered_skill_path": _display_manifest_path(
                                installation.rendered_skill_path,
                                show_paths=show_paths,
                            ),
                            "rendered_skill_boundary": installation.rendered_skill_boundary,
                            "installed_skill_path": _display_manifest_path(
                                installation.installed_skill_path,
                                show_paths=show_paths,
                            ),
                            "installed_skill_boundary": installation.installed_skill_boundary,
                            "rendered_metadata_path": _display_manifest_path(
                                installation.rendered_metadata_path,
                                show_paths=show_paths,
                            ),
                            "rendered_metadata_boundary": installation.rendered_metadata_boundary,
                            "installed_metadata_path": _display_manifest_path(
                                installation.installed_metadata_path,
                                show_paths=show_paths,
                            ),
                            "installed_metadata_boundary": installation.installed_metadata_boundary,
                            "skill_sha256": installation.skill_sha256,
                            "metadata_sha256": installation.metadata_sha256,
                        }
                        for installation in self.skill_authority.installations
                    ],
                }
            ),
            "mcp_authority": (
                None
                if self.mcp_authority is None
                else {
                    "authority": self.mcp_authority.authority,
                    "installations": [
                        {
                            "name": installation.name,
                            "platform": installation.platform,
                            "config_path": _display_manifest_path(
                                installation.config_path,
                                show_paths=show_paths,
                            ),
                            "config_boundary": installation.config_boundary,
                            "server_name": installation.server_name,
                            "transport": installation.transport,
                            "command": _display_mcp_value(
                                installation.command,
                                show_paths=show_paths,
                            ),
                            "args": [
                                _display_mcp_value(value, show_paths=show_paths)
                                for value in installation.args
                            ],
                            "cwd": _display_mcp_value(
                                installation.cwd,
                                show_paths=show_paths,
                            ),
                            "enabled": installation.enabled,
                            "required": installation.required,
                            "startup_timeout_sec": installation.startup_timeout_sec,
                            "tool_timeout_sec": installation.tool_timeout_sec,
                            "enabled_tools": list(installation.enabled_tools),
                        }
                        for installation in self.mcp_authority.installations
                    ],
                }
            ),
            "catalog": {
                "lifecycle": list(self.catalog_lifecycle),
                "summary_files": [
                    _display_manifest_path(path, show_paths=show_paths)
                    for path in self.catalog_summary_files
                ],
            },
            "capabilities": dict(sorted(self.capabilities.items())),
        }


def _expect_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{name} must be a table")
    return value


def _expect_keys(table: Mapping[str, Any], allowed: set[str], name: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ManifestError(f"unknown {name} field: {unknown[0]}")


def _required_text(table: Mapping[str, Any], key: str, name: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{name}.{key} must be a non-empty string")
    if any(ord(char) < 32 for char in value):
        raise ManifestError(f"{name}.{key} contains a control character")
    return value.strip()


def _optional_text(table: Mapping[str, Any], key: str, name: str) -> str | None:
    if key not in table or table[key] is None:
        return None
    return _required_text(table, key, name)


def _text_list(table: Mapping[str, Any], key: str, name: str) -> tuple[str, ...]:
    value = table.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ManifestError(f"{name}.{key} must be a list of non-empty strings")
    return tuple(item.strip() for item in value)


def _bool_value(table: Mapping[str, Any], key: str, default: bool, name: str) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ManifestError(f"{name}.{key} must be boolean")
    return value


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ManifestError(f"{name} must be a positive integer")
    return value


def _parse_component(name: str, raw: Any) -> ComponentSpec:
    table = _expect_mapping(raw, f"components.{name}")
    _expect_keys(table, {"path", "paths", "boundary", "required"}, f"components.{name}")
    path = _optional_text(table, "path", f"components.{name}")
    paths = _text_list(table, "paths", f"components.{name}")
    boundary = str(table.get("boundary", "runtime_root"))
    if boundary not in {"runtime_root", "external"}:
        raise ManifestError(f"components.{name}.boundary is unsupported")
    required = _bool_value(table, "required", True, f"components.{name}")
    if name == "corpus" and not paths and path is not None:
        paths = (path,)
        path = None
    if name != "corpus" and path is None and name in {"database", "workspace"}:
        raise ManifestError(f"components.{name}.path is required")
    if name == "corpus" and not paths:
        raise ManifestError("components.corpus.paths is required")
    return ComponentSpec(
        name=name,
        path=path,
        paths=paths,
        boundary=boundary,
        required=required,
    )


def _authority_path(table: Mapping[str, Any], name: str, *, boundary: str) -> str:
    path = _required_text(table, "path", name)
    lower = path.casefold()
    if lower.startswith("file:") or _is_windows_absolute(path) or path.startswith(("/", "\\")):
        raise ManifestError(f"{name}.path must not be an absolute or file URI path")
    if boundary == "runtime_root" and any(part == ".." for part in re.split(r"[\\/]", path)):
        raise ManifestError(f"{name}.path escapes the runtime root")
    return path


def _authority_file(name: str, raw: Any) -> AuthorityFileSpec:
    table = _expect_mapping(raw, name)
    _expect_keys(table, {"path", "boundary", "content_sha256"}, name)
    boundary = _required_text(table, "boundary", name)
    if boundary not in {"runtime_root", "external"}:
        raise ManifestError(f"{name}.boundary is unsupported")
    path = _authority_path(table, name, boundary=boundary)
    digest = _required_text(table, "content_sha256", name).lower()
    if not _SHA256.fullmatch(digest):
        raise ManifestError(f"{name}.content_sha256 must be a SHA-256 hex digest")
    return AuthorityFileSpec(path=path, boundary=boundary, content_sha256=digest)


def _installation_path(table: Mapping[str, Any], key: str, name: str) -> str:
    """Keep installation paths parseable so doctor can classify them as P1.

    Unlike canonical/runtime authority paths, an installed adapter path may
    contain an environment placeholder or an unsafe boundary that must be
    diagnosed by the read-only doctor rather than hidden as a manifest P0.
    """
    return _required_text(table, key, name)


def _required_sha256(table: Mapping[str, Any], key: str, name: str) -> str:
    digest = _required_text(table, key, name).lower()
    if not _SHA256.fullmatch(digest):
        raise ManifestError(f"{name}.{key} must be a SHA-256 hex digest")
    return digest


def _parse_skill_authority(raw: Any) -> SkillAuthoritySpec | None:
    if raw is None:
        return None
    table = _expect_mapping(raw, "skill_authority")
    _expect_keys(
        table,
        {"authority", "canonical", "runtime", "adapters", "installations"},
        "skill_authority",
    )
    authority = _required_text(table, "authority", "skill_authority")
    if authority != "canonical":
        raise ManifestError("skill_authority.authority must be canonical")
    canonical = _authority_file("skill_authority.canonical", table.get("canonical"))
    runtime = _authority_file("skill_authority.runtime", table.get("runtime"))
    adapter_rows = table.get("adapters", [])
    if not isinstance(adapter_rows, list):
        raise ManifestError("skill_authority.adapters must be a list")
    adapters: list[AdapterTemplateSpec] = []
    seen_names: set[str] = set()
    for index, row in enumerate(adapter_rows):
        name = f"skill_authority.adapters[{index}]"
        adapter = _expect_mapping(row, name)
        _expect_keys(
            adapter,
            {"name", "path", "boundary", "required", "depends_on", "content_sha256"},
            name,
        )
        adapter_name = _required_text(adapter, "name", name)
        if adapter_name in seen_names:
            raise ManifestError(f"duplicate adapter name: {adapter_name}")
        seen_names.add(adapter_name)
        boundary = _required_text(adapter, "boundary", name)
        if boundary not in {"runtime_root", "external"}:
            raise ManifestError(f"{name}.boundary is unsupported")
        path = _authority_path(adapter, name, boundary=boundary)
        required = _bool_value(adapter, "required", False, name)
        depends_on = _required_text(adapter, "depends_on", name)
        if depends_on != "canonical":
            raise ManifestError(f"{name}.depends_on must be canonical")
        content_sha256 = _required_text(adapter, "content_sha256", name).lower()
        if not _SHA256.fullmatch(content_sha256):
            raise ManifestError(f"{name}.content_sha256 must be a SHA-256 hex digest")
        adapters.append(
            AdapterTemplateSpec(
                name=adapter_name,
                path=path,
                boundary=boundary,
                required=required,
                depends_on=depends_on,
                content_sha256=content_sha256,
            )
        )
    installation_rows = table.get("installations", [])
    if not isinstance(installation_rows, list):
        raise ManifestError("skill_authority.installations must be a list")
    installations: list[InstalledAdapterSpec] = []
    seen_installations: set[str] = set()
    for index, row in enumerate(installation_rows):
        name = f"skill_authority.installations[{index}]"
        installation = _expect_mapping(row, name)
        _expect_keys(
            installation,
            {
                "name",
                "platform",
                "template",
                "required",
                "rendered_skill_path",
                "rendered_skill_boundary",
                "installed_skill_path",
                "installed_skill_boundary",
                "rendered_metadata_path",
                "rendered_metadata_boundary",
                "installed_metadata_path",
                "installed_metadata_boundary",
                "skill_sha256",
                "metadata_sha256",
            },
            name,
        )
        installation_name = _required_text(installation, "name", name)
        if installation_name in seen_installations:
            raise ManifestError(f"duplicate installation name: {installation_name}")
        seen_installations.add(installation_name)
        platform = _required_text(installation, "platform", name)
        template = _required_text(installation, "template", name)
        if template not in seen_names:
            raise ManifestError(f"{name}.template must reference a declared adapter")
        required = _bool_value(installation, "required", True, name)
        boundaries = {
            key: _required_text(installation, key, name)
            for key in (
                "rendered_skill_boundary",
                "installed_skill_boundary",
                "rendered_metadata_boundary",
                "installed_metadata_boundary",
            )
        }
        for key, boundary in boundaries.items():
            if boundary not in {"runtime_root", "external"}:
                raise ManifestError(f"{name}.{key} is unsupported")
        installations.append(
            InstalledAdapterSpec(
                name=installation_name,
                platform=platform,
                template=template,
                required=required,
                rendered_skill_path=_installation_path(installation, "rendered_skill_path", name),
                rendered_skill_boundary=boundaries["rendered_skill_boundary"],
                installed_skill_path=_installation_path(installation, "installed_skill_path", name),
                installed_skill_boundary=boundaries["installed_skill_boundary"],
                rendered_metadata_path=_installation_path(installation, "rendered_metadata_path", name),
                rendered_metadata_boundary=boundaries["rendered_metadata_boundary"],
                installed_metadata_path=_installation_path(installation, "installed_metadata_path", name),
                installed_metadata_boundary=boundaries["installed_metadata_boundary"],
                skill_sha256=_required_sha256(installation, "skill_sha256", name),
                metadata_sha256=_required_sha256(installation, "metadata_sha256", name),
            )
        )
    return SkillAuthoritySpec(
        authority=authority,
        canonical=canonical,
        runtime=runtime,
        adapters=tuple(adapters),
        installations=tuple(installations),
    )


def _parse_mcp_authority(raw: Any) -> MCPAuthoritySpec | None:
    if raw is None:
        return None
    table = _expect_mapping(raw, "mcp_authority")
    _expect_keys(table, {"authority", "installations"}, "mcp_authority")
    authority = _required_text(table, "authority", "mcp_authority")
    if authority != "manifest":
        raise ManifestError("mcp_authority.authority must be manifest")
    rows = table.get("installations", [])
    if not isinstance(rows, list):
        raise ManifestError("mcp_authority.installations must be a list")
    installations: list[MCPInstallationSpec] = []
    seen_names: set[str] = set()
    for index, row in enumerate(rows):
        name = f"mcp_authority.installations[{index}]"
        installation = _expect_mapping(row, name)
        _expect_keys(
            installation,
            {
                "name",
                "platform",
                "config_path",
                "config_boundary",
                "server_name",
                "transport",
                "command",
                "args",
                "cwd",
                "enabled",
                "required",
                "startup_timeout_sec",
                "tool_timeout_sec",
                "enabled_tools",
            },
            name,
        )
        installation_name = _required_text(installation, "name", name)
        if installation_name in seen_names:
            raise ManifestError(f"duplicate MCP installation name: {installation_name}")
        seen_names.add(installation_name)
        platform = _required_text(installation, "platform", name)
        if platform != "codex":
            raise ManifestError(f"{name}.platform must be codex")
        config_boundary = _required_text(installation, "config_boundary", name)
        if config_boundary not in {"runtime_root", "external"}:
            raise ManifestError(f"{name}.config_boundary is unsupported")
        config_path = _installation_path(installation, "config_path", name)
        server_name = _required_text(installation, "server_name", name)
        if server_name != CODEX_MCP_SERVER_NAME:
            raise ManifestError(f"{name}.server_name must be {CODEX_MCP_SERVER_NAME!r}")
        transport = _required_text(installation, "transport", name)
        if transport != "stdio":
            raise ManifestError(f"{name}.transport must be stdio")
        command = _required_text(installation, "command", name)
        if "args" not in installation:
            raise ManifestError(f"{name}.args is required")
        args = _text_list(installation, "args", name)
        cwd = _required_text(installation, "cwd", name)
        enabled = _bool_value(installation, "enabled", True, name)
        required = _bool_value(installation, "required", False, name)
        startup_timeout_sec = _positive_int(
            installation.get("startup_timeout_sec"),
            f"{name}.startup_timeout_sec",
        )
        tool_timeout_sec = _positive_int(
            installation.get("tool_timeout_sec"),
            f"{name}.tool_timeout_sec",
        )
        if "enabled_tools" not in installation:
            raise ManifestError(f"{name}.enabled_tools is required")
        enabled_tools = _text_list(installation, "enabled_tools", name)
        installations.append(
            MCPInstallationSpec(
                name=installation_name,
                platform=platform,
                config_path=config_path,
                config_boundary=config_boundary,
                server_name=server_name,
                transport=transport,
                command=command,
                args=args,
                cwd=cwd,
                enabled=enabled,
                required=required,
                startup_timeout_sec=startup_timeout_sec,
                tool_timeout_sec=tool_timeout_sec,
                enabled_tools=enabled_tools,
            )
        )
    return MCPAuthoritySpec(authority=authority, installations=tuple(installations))


def validate_manifest(raw: Mapping[str, Any], *, source_path: str | Path | None = None) -> SystemManifest:
    """Validate a parsed TOML table and return a typed manifest.

    Validation is intentionally closed-world.  A typo in a control-plane key
    must be visible to an administrator instead of being silently ignored.
    """
    if not isinstance(raw, Mapping):
        raise ManifestError("manifest root must be a table")
    _expect_keys(
        raw,
        {
            "manifest_format_version",
            "engine",
            "schema",
            "protocol",
            "config",
            "components",
            "mcp",
            "project_registry",
            "skills",
            "skill_authority",
            "mcp_authority",
            "catalog",
            "capabilities",
        },
        "manifest",
    )
    format_version = _positive_int(raw.get("manifest_format_version"), "manifest_format_version")
    if format_version != MANIFEST_FORMAT_VERSION:
        raise ManifestError(f"unsupported manifest_format_version: {format_version}")

    engine = _expect_mapping(raw.get("engine"), "engine")
    _expect_keys(engine, {"package", "version"}, "engine")
    engine_package = _required_text(engine, "package", "engine")
    engine_version = _required_text(engine, "version", "engine")

    schema = _expect_mapping(raw.get("schema"), "schema")
    _expect_keys(schema, {"version"}, "schema")
    schema_version = _positive_int(schema.get("version"), "schema.version")

    protocol = _expect_mapping(raw.get("protocol"), "protocol")
    _expect_keys(protocol, {"name"}, "protocol")
    protocol_name = _required_text(protocol, "name", "protocol")

    config = _expect_mapping(raw.get("config"), "config")
    _expect_keys(config, {"path"}, "config")
    config_path = _required_text(config, "path", "config")

    components_raw = _expect_mapping(raw.get("components"), "components")
    allowed_components = {"database", "corpus", "workspace", "catalog", "backup", "skills"}
    _expect_keys(components_raw, allowed_components, "components")
    components = {name: _parse_component(name, components_raw.get(name)) for name in sorted(allowed_components) if name in components_raw}
    for required_component in ("database", "corpus", "workspace"):
        if required_component not in components:
            raise ManifestError(f"components.{required_component} is required")

    mcp = _expect_mapping(raw.get("mcp"), "mcp")
    _expect_keys(mcp, {"server_name", "tools"}, "mcp")
    mcp_server_name = _required_text(mcp, "server_name", "mcp")
    if mcp_server_name != MCP_SERVER_NAME:
        raise ManifestError(f"mcp.server_name must be {MCP_SERVER_NAME!r}")
    if "tools" not in mcp:
        raise ManifestError("mcp.tools is required")
    mcp_tools = _text_list(mcp, "tools", "mcp")
    if len(mcp_tools) != len(set(mcp_tools)):
        raise ManifestError("mcp.tools must not contain duplicates")

    registry_raw = _expect_mapping(raw.get("project_registry", {}), "project_registry")
    _expect_keys(registry_raw, {"projects"}, "project_registry")
    project_rows = registry_raw.get("projects", [])
    if not isinstance(project_rows, list):
        raise ManifestError("project_registry.projects must be a list")
    projects: list[ProjectSpec] = []
    seen_projects: set[str] = set()
    for index, row in enumerate(project_rows):
        table = _expect_mapping(row, f"project_registry.projects[{index}]")
        name = f"project_registry.projects[{index}]"
        _expect_keys(table, {"project_id", "workspace", "corpus_scope", "checkpoint_policy"}, name)
        project_id = _required_text(table, "project_id", name)
        if project_id in seen_projects:
            raise ManifestError(f"duplicate project_id in registry: {project_id}")
        seen_projects.add(project_id)
        workspace = _required_text(table, "workspace", name)
        corpus_scope = _text_list(table, "corpus_scope", name)
        checkpoint_policy = _required_text(table, "checkpoint_policy", name)
        if checkpoint_policy not in CHECKPOINT_POLICIES:
            raise ManifestError(
                f"{name}.checkpoint_policy must be one of {CHECKPOINT_POLICIES!r}"
            )
        projects.append(ProjectSpec(project_id, workspace, corpus_scope, checkpoint_policy))

    skills_raw = _expect_mapping(raw.get("skills", {}), "skills")
    _expect_keys(skills_raw, {"items"}, "skills")
    skill_rows = skills_raw.get("items", [])
    if not isinstance(skill_rows, list):
        raise ManifestError("skills.items must be a list")
    skills: list[SkillSpec] = []
    seen_skills: set[str] = set()
    for index, row in enumerate(skill_rows):
        table = _expect_mapping(row, f"skills.items[{index}]")
        name = f"skills.items[{index}]"
        _expect_keys(table, {"name", "path", "version", "content_sha256"}, name)
        skill_name = _required_text(table, "name", name)
        if skill_name in seen_skills:
            raise ManifestError(f"duplicate skill name: {skill_name}")
        seen_skills.add(skill_name)
        skill_path = _required_text(table, "path", name)
        skill_version = _optional_text(table, "version", name)
        digest = _optional_text(table, "content_sha256", name)
        if digest is not None and not _SHA256.fullmatch(digest):
            raise ManifestError(f"{name}.content_sha256 must be a SHA-256 hex digest")
        skills.append(SkillSpec(skill_name, skill_path, skill_version, digest.lower() if digest else None))
    skill_authority = _parse_skill_authority(raw.get("skill_authority"))
    mcp_authority = _parse_mcp_authority(raw.get("mcp_authority"))

    catalog = _expect_mapping(raw.get("catalog"), "catalog")
    _expect_keys(catalog, {"lifecycle", "summary_files"}, "catalog")
    lifecycle = _text_list(catalog, "lifecycle", "catalog")
    if lifecycle != CATALOG_LIFECYCLE:
        raise ManifestError("catalog.lifecycle must match the supported lifecycle")
    summary_files = _text_list(catalog, "summary_files", "catalog")
    if not summary_files:
        raise ManifestError("catalog.summary_files must not be empty")

    capabilities_raw = _expect_mapping(raw.get("capabilities"), "capabilities")
    _expect_keys(capabilities_raw, set(CAPABILITY_NAMES), "capabilities")
    missing_capabilities = [name for name in CAPABILITY_NAMES if name not in capabilities_raw]
    if missing_capabilities:
        raise ManifestError(f"capabilities.{missing_capabilities[0]} is required")
    capabilities = {
        name: _bool_value(capabilities_raw, name, False, "capabilities")
        for name in CAPABILITY_NAMES
    }
    source = Path(source_path).expanduser().resolve() if source_path is not None else None
    return SystemManifest(
        source_path=source,
        manifest_format_version=format_version,
        engine_package=engine_package,
        engine_version=engine_version,
        schema_version=schema_version,
        protocol=protocol_name,
        config_path=config_path,
        components=components,
        mcp_server_name=mcp_server_name,
        mcp_tools=mcp_tools,
        projects=tuple(projects),
        skills=tuple(skills),
        skill_authority=skill_authority,
        mcp_authority=mcp_authority,
        catalog_lifecycle=lifecycle,
        catalog_summary_files=summary_files,
        capabilities=capabilities,
    )


def load_manifest(path: str | Path) -> SystemManifest:
    """Load and validate a UTF-8 TOML manifest without creating anything."""
    selected = Path(path).expanduser().resolve(strict=True)
    try:
        with selected.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError("manifest TOML is invalid") from exc
    except UnicodeDecodeError as exc:
        raise ManifestError("manifest must be UTF-8") from exc
    return validate_manifest(raw, source_path=selected)


def _is_windows_absolute(value: str) -> bool:
    return bool(_WINDOWS_DRIVE.match(value)) or value.startswith(("\\\\", "//"))


def _has_unresolved_env(value: str) -> bool:
    return any(
        (match.group(1) or match.group(2)) not in os.environ
        for match in _ENV_TOKEN.finditer(value)
    )


def resolve_manifest_path(value: str, runtime_root: str | Path) -> Path | None:
    """Resolve a manifest path against the runtime root.

    Unset environment placeholders return ``None`` so doctor can report a
    controlled finding without echoing the missing variable's value.
    """
    expanded = os.path.expandvars(value).strip()
    if _has_unresolved_env(expanded):
        return None
    # ``Path.resolve()`` may call the Windows final-path API for an existing
    # UNC target.  A doctor run must remain a local, read-only validation and
    # must not fail merely because a declared remote path is unreachable.
    if _is_windows_absolute(expanded) or expanded.startswith("/"):
        return Path(expanded).expanduser().absolute()
    return (Path(runtime_root).expanduser().absolute() / Path(expanded)).absolute()


def redact_path(value: str | Path | None) -> str | None:
    """Return a safe display value for local paths and file URIs."""
    if value is None:
        return None
    text = str(value)
    lower = text.casefold()
    if lower.startswith("http://") or lower.startswith("https://"):
        return text
    if _ENV_TOKEN.search(text):
        return "<env-path>"
    if lower.startswith("file:"):
        return "<file-uri>"
    if _is_windows_absolute(text):
        if text.startswith(("\\\\", "//")):
            return "<unc-path>"
        return "<local-path>"
    if text.startswith("/"):
        return "<local-path>"
    return text.replace("\\", "/")


def _display_manifest_path(value: str, *, show_paths: bool) -> str:
    text = str(value)
    if not show_paths:
        return redact_path(text) or ""
    lower = text.casefold()
    if (
        lower.startswith(("http://", "https://", "file:"))
        or _is_windows_absolute(text)
        or text.startswith("/")
    ):
        return text
    return text.replace("\\", "/")


def _display_mcp_value(value: str, *, show_paths: bool) -> str:
    """Redact path-like MCP command values without hiding flags or modules."""
    text = str(value)
    lower = text.casefold()
    if lower.startswith(("http://", "https://")):
        return text if show_paths else "<url>"
    if lower.startswith("file:") or _is_windows_absolute(text) or text.startswith(("/", "\\")):
        return _display_manifest_path(text, show_paths=show_paths)
    if _ENV_TOKEN.search(text):
        return "<env-path>" if not show_paths else text
    return text.replace("\\", "/")


def relative_path_issue(value: str | Path | None) -> str | None:
    """Return a stable reason when ``value`` is not a safe relative path."""
    if value is None:
        return "missing"
    text = str(value).strip()
    if not text:
        return "empty"
    lower = text.casefold()
    if lower.startswith("file:"):
        return "file_uri"
    if _is_windows_absolute(text) or text.startswith(("/", "\\")) or (
        len(text) >= 2 and text[1] == ":"
    ):
        return "absolute"
    if any(part == ".." for part in re.split(r"[\\/]", text)):
        return "parent_segment"
    return None


def sha256_file(path: str | Path) -> str:
    """Hash one declared control-plane file; callers must pass a file path."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
