"""Official MCP adapter for the research-only surface.

This module intentionally imports only the researcher-facing service. The
admin service and approval decision path are not part of the MCP process.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Literal, Sequence

try:  # Keep the optional dependency failure explicit at the executable boundary.
    from mcp.server.fastmcp import FastMCP
    from pydantic import BaseModel, ConfigDict, Field
except ModuleNotFoundError as exc:  # pragma: no cover - exercised without the extra
    if exc.name and exc.name.split(".", 1)[0] in {"mcp", "pydantic"}:
        raise SystemExit(
            "MCP support is not installed. Install it with: "
            "python -m pip install 'research-kb[mcp]'"
        ) from None
    raise

from .config import Settings
from .db import SCHEMA_VERSION, connect, migration_paths
from .policy import Actor, PolicyError, validate_text
from .service import ResearchService
from .system_manifest import (
    EXPECTED_MCP_TOOLS,
    MCP_SERVER_NAME,
    PROTOCOL as SYSTEM_PROTOCOL,
    REQUIRED_MCP_TABLES,
    REQUIRED_MCP_TRIGGERS,
)


PROTOCOL = SYSTEM_PROTOCOL
TOOL_NAMES = EXPECTED_MCP_TOOLS

ErrorCode = Literal[
    "INVALID_ARGUMENT",
    "NOT_FOUND",
    "OUT_OF_SCOPE",
    "FORBIDDEN",
    "QUOTA_EXCEEDED",
    "UNSUPPORTED_MODE",
    "TOKEN_EXPIRED",
    "TOKEN_CONSUMED",
    "CONFLICT",
    "INTERNAL",
]

_LOG = logging.getLogger("research_kb.mcp")
_SENSITIVE_KEYS = {
    "database", "database_path", "db_path", "corpus", "corpus_path", "corpus_root", "config_path",
    "file_path", "filepath", "source_path", "source_uri", "absolute_path", "path", "root", "root_path", "workspace",
    "file", "filename", "directory", "dir", "verification_token", "token", "secret", "password", "environment", "env",
}


@dataclass(frozen=True)
class ServerIdentity:
    """Connection/server supplied identity; it is never a tool argument."""

    actor_id: str
    session_id: str
    framework: str = "mcp"
    model: str | None = None

    def actor(self) -> Actor:
        return Actor(
            actor_id=self.actor_id,
            session_id=self.session_id,
            actor_kind="agent",
            role="researcher",
            framework=self.framework,
            model=self.model,
        )


def _default_identity() -> ServerIdentity:
    # One process is one MCP connection in stdio mode. The generated ID is
    # stable for every call handled by that process and cannot grant admin.
    process_nonce = uuid.uuid4().hex
    return ServerIdentity(
        actor_id=f"mcp-agent-{process_nonce}",
        session_id=f"mcp-session-{process_nonce}",
    )


def _trace_id() -> str:
    return uuid.uuid4().hex[:20]


def _ok(data: Any, warnings: list[str], trace_id: str) -> dict[str, Any]:
    return {
        "ok": True,
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "data": data,
        "warnings": warnings,
        "trace_id": trace_id,
    }


def _failure(code: ErrorCode, trace_id: str) -> dict[str, Any]:
    messages = {
        "INVALID_ARGUMENT": "The supplied arguments are invalid.",
        "NOT_FOUND": "The requested research object was not found.",
        "OUT_OF_SCOPE": "The object is not in the active project scope.",
        "FORBIDDEN": "The operation is not permitted for this agent session.",
        "QUOTA_EXCEEDED": "The session quota has been exceeded.",
        "UNSUPPORTED_MODE": "The requested mode is not supported in this release.",
        "TOKEN_EXPIRED": "The verification token has expired.",
        "TOKEN_CONSUMED": "The verification token has already been consumed.",
        "CONFLICT": "The source or research state conflicts with this operation.",
        "INTERNAL": "The research service could not complete the operation.",
    }
    return {
        "ok": False,
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "error": {"code": code, "message": messages[code]},
        "warnings": [],
        "trace_id": trace_id,
    }


def _classify_error(exc: BaseException) -> ErrorCode:
    if isinstance(exc, KeyError):
        return "NOT_FOUND"
    message = str(exc).casefold()
    if "semantic retrieval" in message or "unsupported" in message:
        return "UNSUPPORTED_MODE"
    if "quota" in message:
        return "QUOTA_EXCEEDED"
    if "already been consumed" in message:
        return "TOKEN_CONSUMED"
    if "has expired" in message:
        return "TOKEN_EXPIRED"
    if "another actor" in message or "another session" in message:
        return "FORBIDDEN"
    if "invalid verification token" in message:
        return "OUT_OF_SCOPE"
    if any(phrase in message for phrase in (
        "outside project scope", "outside project", "active project not found",
        "not in the same project",
    )):
        return "OUT_OF_SCOPE"
    if any(phrase in message for phrase in (
        "source content or version changed", "conflict", "already exists",
    )):
        return "CONFLICT"
    if isinstance(exc, PolicyError) or isinstance(exc, (TypeError, ValueError)):
        return "INVALID_ARGUMENT"
    if exc.__class__.__name__ == "IntegrityError":
        return "CONFLICT"
    return "INTERNAL"


def _is_local_path(value: str) -> bool:
    """Recognize local path forms without treating ordinary web URLs as paths."""

    candidate = value.strip()
    lowered = candidate.casefold()
    if lowered.startswith(("http://", "https://")):
        return False
    if lowered.startswith("file://"):
        return True
    if candidate.startswith("\\"):
        # UNC shares and Windows device paths both begin with two backslashes.
        return True
    if len(candidate) >= 3 and candidate[1] == ":" and candidate[2] in "\\/":
        return True
    return candidate.startswith("/")


def _safe_data(value: Any, *, allow_token: bool = False) -> Any:
    """Recursively remove sensitive fields and local paths from output data."""

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).casefold()
            if normalized in _SENSITIVE_KEYS and not (allow_token and normalized == "verification_token"):
                continue
            result[str(key)] = _safe_data(item, allow_token=allow_token)
        return result
    if isinstance(value, (list, tuple)):
        return [_safe_data(item, allow_token=allow_token) for item in value]
    if isinstance(value, Path):
        return "[redacted-local-path]"
    if isinstance(value, str) and _is_local_path(value):
        return "[redacted-local-path]"
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def _fit_requested_section(data: dict[str, Any], maximum: int) -> tuple[dict[str, Any], bool]:
    """Fit an explicit context section without dropping its item container.

    If the caller's requested chunk is larger than the envelope budget, shorten
    only the current content chunk and advance ``next_offset``. The next call
    can therefore recover the omitted suffix without guessing or duplication.
    """
    items = data.get("items")
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        return data, False
    first = dict(items[0])
    section = first.get("section")
    if not isinstance(section, dict) or not isinstance(section.get("content"), str):
        return data, False
    original = section["content"]
    total_chars = section.get("total_chars")
    offset = section.get("offset", data.get("offset", 0))
    if not isinstance(total_chars, int) or not isinstance(offset, int):
        return data, False

    trimmed = dict(data)
    project = trimmed.get("project")
    if isinstance(project, dict) and "config" in project:
        compact_project = dict(project)
        compact_project.pop("config", None)
        trimmed["project"] = compact_project

    def candidate(length: int, base: dict[str, Any] | None = None) -> dict[str, Any]:
        selected = dict(section)
        selected["content"] = original[:length]
        end = offset + length
        selected["next_offset"] = end if end < total_chars else None
        record = dict(first)
        record["section"] = selected
        result = dict(base or trimmed)
        result["items"] = [record] + list(items[1:])
        result["next_offset"] = selected["next_offset"]
        return result

    if _json_size(trimmed) <= maximum:
        return trimmed, True
    low, high = 0, len(original)
    best = candidate(0)
    while low <= high:
        middle = (low + high) // 2
        trial = candidate(middle)
        if _json_size(trial) <= maximum:
            best = trial
            low = middle + 1
        else:
            high = middle - 1
    if _json_size(best) <= maximum:
        return best, True

    # Keep the requested section even if an unusually large project/index
    # record consumes the normal budget. This is a defensive last resort.
    minimal_base = {
        key: trimmed[key]
        for key in ("item_id", "section", "offset", "next_offset")
        if key in trimmed
    }
    minimal = candidate(0, minimal_base)
    if _json_size(minimal) <= maximum:
        return minimal, True
    return {"items": [best["items"][0]]}, True


def _fit_return_data(
    data: Any,
    maximum: int,
    *,
    preserve_items: bool = False,
) -> tuple[Any, list[str]]:
    """Keep valid JSON while honoring the configured output cap.

    Explicit ``get_research_context(item_id, section=...)`` responses keep
    their requested item/section container. Only the current section chunk may
    be shortened, with a truthful ``next_offset`` for continuation.
    """

    if _json_size(data) <= maximum:
        return data, []
    if isinstance(data, dict):
        trimmed = dict(data)
        if preserve_items:
            adjusted, changed = _fit_requested_section(trimmed, maximum)
            if _json_size(adjusted) <= maximum:
                return adjusted, ["RETURN_TRUNCATED"] if changed else []
        for key in ("results", "context", "items", "events", "pending_approvals"):
            values = trimmed.get(key)
            if isinstance(values, list) and not (preserve_items and key == "items"):
                while values and _json_size(trimmed) > maximum:
                    values.pop()
                trimmed[key] = values
        if _json_size(trimmed) <= maximum:
            trimmed["truncated"] = True
            if _json_size(trimmed) <= maximum:
                return trimmed, ["RETURN_TRUNCATED"]
        preview = json.dumps(trimmed, ensure_ascii=False, separators=(",", ":"))
        return {"truncated": True, "preview": preview[: max(32, maximum // 2)]}, ["RETURN_TRUNCATED"]
    serialized = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return {"truncated": True, "preview": serialized[: max(32, maximum // 2)]}, ["RETURN_TRUNCATED"]


class MCPStartupError(RuntimeError):
    """A safe, user-actionable readiness failure before the MCP transport starts."""


_REQUIRED_TABLES = REQUIRED_MCP_TABLES
_REQUIRED_TRIGGERS = REQUIRED_MCP_TRIGGERS


def _readiness_check(settings: Settings) -> None:
    """Perform only read-only checks; never create, migrate, or rebuild anything."""

    if not settings.database.is_file():
        raise MCPStartupError(
            "MCP startup failed: the database is not ready. "
            "Run the Admin CLI init/migrate/reindex commands first."
        )
    try:
        with connect(settings, read_only=True, immutable=True) as connection:
            versions = tuple(
                row[0] for row in connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                )
            )
            expected_versions = tuple(version for version, _ in migration_paths())
            if versions != expected_versions or not versions or versions[-1] != SCHEMA_VERSION:
                raise MCPStartupError(
                    "MCP startup failed: the database schema is not current. "
                    "Run the Admin CLI migrate command first."
                )
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table', 'virtual table')"
                )
            }
            if not _REQUIRED_TABLES.issubset(tables):
                raise MCPStartupError(
                    "MCP startup failed: required database objects are missing. "
                    "Run the Admin CLI migrate/reindex commands first."
                )
            triggers = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                )
            }
            if not _REQUIRED_TRIGGERS.issubset(triggers):
                raise MCPStartupError(
                    "MCP startup failed: required database triggers are missing. "
                    "Run the Admin CLI migrate command first."
                )
            connection.execute("SELECT COUNT(*) FROM passages_search_fts").fetchone()
    except MCPStartupError:
        raise
    except (OSError, sqlite3.Error):
        raise MCPStartupError(
            "MCP startup failed: the database is not ready. "
            "Run the Admin CLI init/migrate/reindex commands first."
        ) from None


class MCPRuntime:
    def __init__(self, settings: Settings, identity: ServerIdentity):
        _readiness_check(settings)
        self.settings = settings
        self.identity = identity
        self.service = ResearchService(settings, identity.actor())

    def _validate_text(self, value: str, name: str, maximum: int, *, required: bool = True) -> str:
        return validate_text(value, name, maximum, required=required)

    def _validate_id(self, value: str, name: str = "id") -> str:
        return self._validate_text(value, name, 256)

    def _validate_list(
        self,
        values: Sequence[str] | None,
        name: str,
        maximum: int,
        item_maximum: int = 256,
    ) -> list[str]:
        if values is None:
            return []
        if not isinstance(values, (list, tuple)) or len(values) > maximum:
            raise PolicyError(f"{name} contains too many values")
        return [self._validate_text(item, name, item_maximum) for item in values]

    def invoke(
        self,
        operation: str,
        function: Callable[[], Any],
        *,
        allow_token: bool = False,
        preserve_items: bool = False,
    ) -> dict[str, Any]:
        trace_id = _trace_id()
        try:
            data = _safe_data(function(), allow_token=allow_token)
            maximum = max(256, int(self.settings.limits.max_return_chars))
            fitted, warnings = _fit_return_data(
                data, max(32, maximum - 240), preserve_items=preserve_items
            )
            response = _ok(fitted, warnings, trace_id)
            if _json_size(response) > maximum:
                if preserve_items:
                    tighter, tighter_warnings = _fit_return_data(
                        data, max(32, maximum - 420), preserve_items=True
                    )
                    response = _ok(
                        tighter, warnings + tighter_warnings or ["RETURN_TRUNCATED"], trace_id
                    )
                    if _json_size(response) <= maximum:
                        return response
                response = _ok({}, ["RETURN_TRUNCATED"], trace_id)
            return response
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            code = _classify_error(exc)
            _LOG.error("trace_id=%s operation=%s code=%s exception=%s", trace_id, operation, code, type(exc).__name__)
            return _failure(code, trace_id)


SearchMode = Literal["auto", "lexical", "semantic", "hybrid"]
MatchStrategy = Literal["all", "any", "auto"]
DetailMode = Literal["brief", "full"]
EpistemicStatus = Literal[
    "source_interpretation", "analytical_inference", "exploratory_hypothesis",
    "cross_source_synthesis", "cross_domain_analogy", "open_question",
    "unresolved", "counterevidence", "source_fact",
]


class ClaimInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str | None = Field(default=None, max_length=64)
    text: str = Field(min_length=1, max_length=4000)
    epistemic_status: EpistemicStatus
    verified_evidence_ids: list[str] = Field(default_factory=list, max_length=50)


class ResearchLeadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idea: str = Field(min_length=1, max_length=4000)
    source_bridges: list[str] = Field(min_length=1, max_length=10)
    supporting_passage_ids: list[str] = Field(default_factory=list, max_length=50)
    why_not_literature_summary: str = Field(min_length=1, max_length=2000)
    possible_counterevidence: list[str] = Field(default_factory=list, max_length=20)
    missing_evidence: list[str] = Field(default_factory=list, max_length=20)
    next_search: list[str] = Field(default_factory=list, max_length=20)
    epistemic_status: Literal[
        "analytical_inference", "exploratory_hypothesis", "open_question", "unresolved"
    ]
    confidence: Literal["low", "medium", "high"]


class CitationRecordInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: str = Field(default="unknown", max_length=64)
    document_id: str = Field(min_length=1, max_length=256)
    content_hash: str = Field(min_length=1, max_length=128)
    source_version: str = Field(min_length=1, max_length=256)
    authors: list[str] | str = Field(default="unknown", max_length=50)
    editors: list[str] | str = Field(default="unknown", max_length=50)
    translators: list[str] | str = Field(default="unknown", max_length=50)
    title: str = Field(default="unknown", max_length=1000)
    container_title: str = Field(default="unknown", max_length=500)
    year: str | int = "unknown"
    volume: str | int = "unknown"
    issue: str | int = "unknown"
    page_range: str = Field(default="unknown", max_length=128)
    doi: str = Field(default="unknown", max_length=256)
    publisher: str = Field(default="unknown", max_length=500)
    edition: str = Field(default="unknown", max_length=128)
    place: str = Field(default="unknown", max_length=256)
    isbn: str = Field(default="unknown", max_length=128)


class CitationLocatorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page: str | int = "unknown"
    location: dict[str, Any] | str = "unknown"
    document_id: str = Field(min_length=1, max_length=256)
    passage_id: str = Field(min_length=1, max_length=256)
    source_version: str = Field(min_length=1, max_length=256)


class SourceCitationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: str = Field(min_length=1, max_length=256)
    citation_record: CitationRecordInput


class EvidenceCitationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=256)
    passage_id: str = Field(min_length=1, max_length=256)
    document_id: str = Field(min_length=1, max_length=256)
    citation_record: CitationRecordInput
    citation_locator: CitationLocatorInput


class ResearchFastMCP(FastMCP):
    """FastMCP adapter with a sanitized response for SDK schema failures."""

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            listed = await self.list_tools()
            tool = next((item for item in listed if item.name == name), None)
            if tool is None or not isinstance(arguments, dict):
                raise ValueError("invalid tool arguments")
            allowed = set((tool.inputSchema or {}).get("properties", {}))
            if set(arguments) - allowed:
                raise ValueError("unknown tool argument")
            return await super().call_tool(name, arguments)
        except Exception:
            # FastMCP validates arguments before the registered function runs.
            # Never expose its Pydantic/ToolError text to an external agent.
            trace_id = _trace_id()
            _LOG.error("trace_id=%s operation=protocol_validation code=INVALID_ARGUMENT", trace_id)
            return _failure("INVALID_ARGUMENT", trace_id)


def create_mcp_server(settings: Settings, identity: ServerIdentity | None = None) -> ResearchFastMCP:
    """Build a server with only the public, researcher-facing tool set."""

    runtime = MCPRuntime(settings, identity or _default_identity())
    if not _LOG.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        _LOG.addHandler(handler)
    _LOG.setLevel(logging.ERROR)
    _LOG.propagate = False
    server = ResearchFastMCP(
        MCP_SERVER_NAME,
        instructions="Project-scoped local research tools. Administration is unavailable.",
        log_level="ERROR",
    )

    @server.tool(name="search_corpus", structured_output=True)
    def search_corpus(
        project_id: str = Field(..., min_length=1, max_length=256),
        query: str = Field(..., min_length=1, max_length=1000),
        search_mode: SearchMode = "auto",
        match_strategy: MatchStrategy = "auto",
        source_types: list[str] | None = Field(default=None, max_length=20),
        languages: list[str] | None = Field(default=None, max_length=20),
        document_ids: list[str] | None = Field(default=None, max_length=100),
        reliability_levels: list[str] | None = Field(default=None, max_length=20),
        date_from: str | None = Field(default=None, max_length=64),
        date_to: str | None = Field(default=None, max_length=64),
        top_k: int = Field(default=10, ge=1, le=20),
        diversify_results: bool = True,
        include_possible_counterevidence: bool = False,
    ) -> dict[str, Any]:
        def call() -> Any:
            mode = "lexical" if search_mode == "auto" else search_mode
            return runtime.service.search_corpus(
                project_id=runtime._validate_id(project_id, "project_id"),
                query=runtime._validate_text(query, "query", runtime.settings.limits.max_query_chars),
                search_mode=mode,
                match_strategy=match_strategy,
                source_types=runtime._validate_list(source_types, "source_types", 20),
                languages=runtime._validate_list(languages, "languages", 20),
                document_ids=runtime._validate_list(document_ids, "document_ids", 100),
                reliability_levels=runtime._validate_list(reliability_levels, "reliability_levels", 20),
                date_from=runtime._validate_text(date_from or "", "date_from", 64, required=False) or None,
                date_to=runtime._validate_text(date_to or "", "date_to", 64, required=False) or None,
                top_k=top_k,
                diversify_results=diversify_results,
                include_possible_counterevidence=include_possible_counterevidence,
            )

        return runtime.invoke("search_corpus", call)

    @server.tool(name="get_passage", structured_output=True)
    def get_passage(
        project_id: str = Field(..., min_length=1, max_length=256),
        passage_id: str = Field(..., min_length=1, max_length=256),
        context: int = Field(default=1, ge=0, le=3),
    ) -> dict[str, Any]:
        return runtime.invoke(
            "get_passage",
            lambda: runtime.service.get_passage(
                project_id=runtime._validate_id(project_id, "project_id"),
                passage_id=runtime._validate_id(passage_id, "passage_id"),
                context=context,
            ),
        )

    @server.tool(name="get_document_metadata", structured_output=True)
    def get_document_metadata(
        project_id: str = Field(..., min_length=1, max_length=256),
        document_id: str = Field(..., min_length=1, max_length=256),
    ) -> dict[str, Any]:
        return runtime.invoke(
            "get_document_metadata",
            lambda: runtime.service.get_document_metadata(
                project_id=runtime._validate_id(project_id, "project_id"),
                document_id=runtime._validate_id(document_id, "document_id"),
            ),
        )

    @server.tool(name="get_research_context", structured_output=True)
    def get_research_context(
        project_id: str = Field(..., min_length=1, max_length=256),
        detail: DetailMode = "brief",
        item_id: str | None = Field(default=None, min_length=1, max_length=256),
        section: str | None = Field(default=None, min_length=1, max_length=128),
        offset: int = Field(default=0, ge=0, le=1000000),
        limit: int | None = Field(default=None, ge=1, le=20),
        cursor: str | None = Field(default=None, min_length=1, max_length=512),
        chunk_size: int = Field(default=1400, ge=256, le=2400),
    ) -> dict[str, Any]:
        return runtime.invoke(
            "get_research_context",
            lambda: runtime.service.get_research_context(
                project_id=runtime._validate_id(project_id, "project_id"),
                detail=detail,
                item_id=(runtime._validate_id(item_id, "item_id") if item_id else None),
                section=(runtime._validate_text(section or "", "section", 128, required=False) or None),
                offset=offset,
                limit=limit,
                cursor=(runtime._validate_text(cursor or "", "cursor", 512, required=False) or None),
                chunk_size=chunk_size,
            ),
            preserve_items=bool(item_id and section),
        )

    @server.tool(name="submit_hypothesis", structured_output=True)
    def submit_hypothesis(
        project_id: str = Field(..., min_length=1, max_length=256),
        title: str = Field(..., min_length=1, max_length=500),
        claim: str = Field(..., min_length=1, max_length=4000),
        epistemic_status: EpistemicStatus = "exploratory_hypothesis",
        supporting_passage_ids: list[str] | None = Field(default=None, max_length=50),
        counter_passage_ids: list[str] | None = Field(default=None, max_length=50),
        alternative_explanations: list[str] | None = Field(default=None, max_length=20),
        open_questions: list[str] | None = Field(default=None, max_length=20),
        confidence: Literal["low", "medium", "high"] = "low",
        status: Literal["draft", "candidate"] = "candidate",
        supersedes_item_id: str | None = Field(default=None, max_length=256),
    ) -> dict[str, Any]:
        def call() -> Any:
            return runtime.service.submit_hypothesis(
                project_id=runtime._validate_id(project_id, "project_id"),
                title=runtime._validate_text(title, "title", 500),
                claim=runtime._validate_text(claim, "claim", 4000),
                epistemic_status=epistemic_status,
                supporting_passage_ids=runtime._validate_list(supporting_passage_ids, "supporting_passage_ids", 50),
                counter_passage_ids=runtime._validate_list(counter_passage_ids, "counter_passage_ids", 50),
                alternative_explanations=runtime._validate_list(alternative_explanations, "alternative_explanations", 20, 1000),
                open_questions=runtime._validate_list(open_questions, "open_questions", 20, 1000),
                confidence=confidence,
                status=status,
                supersedes_item_id=(runtime._validate_id(supersedes_item_id, "supersedes_item_id") if supersedes_item_id else None),
            )

        return runtime.invoke("submit_hypothesis", call)

    @server.tool(name="submit_objection", structured_output=True)
    def submit_objection(
        project_id: str = Field(..., min_length=1, max_length=256),
        target_item_id: str = Field(..., min_length=1, max_length=256),
        objection_type: str = Field(..., min_length=1, max_length=128),
        text: str = Field(..., min_length=1, max_length=4000),
        passage_ids: list[str] | None = Field(default=None, max_length=50),
        status: Literal["draft", "candidate"] = "candidate",
    ) -> dict[str, Any]:
        def call() -> Any:
            return runtime.service.submit_objection(
                project_id=runtime._validate_id(project_id, "project_id"),
                target_item_id=runtime._validate_id(target_item_id, "target_item_id"),
                objection_type=runtime._validate_text(objection_type, "objection_type", 128),
                text=runtime._validate_text(text, "text", 4000),
                passage_ids=runtime._validate_list(passage_ids, "passage_ids", 50),
                status=status,
            )

        return runtime.invoke("submit_objection", call)

    @server.tool(name="save_research_note", structured_output=True)
    def save_research_note(
        project_id: str = Field(..., min_length=1, max_length=256),
        title: str = Field(..., min_length=1, max_length=500),
        body: str = Field(..., min_length=1, max_length=8000),
        note_purpose: Literal["research_note", "checkpoint"] = Field(default="research_note"),
        supersedes_item_id: str | None = Field(default=None, max_length=256),
    ) -> dict[str, Any]:
        return runtime.invoke(
            "save_research_note",
            lambda: runtime.service.save_research_note(
                project_id=runtime._validate_id(project_id, "project_id"),
                title=runtime._validate_text(title, "title", 500),
                body=runtime._validate_text(body, "body", 8000),
                note_purpose=runtime._validate_text(note_purpose, "note_purpose", 32),
                supersedes_item_id=(
                    runtime._validate_id(supersedes_item_id, "supersedes_item_id")
                    if supersedes_item_id is not None else None
                ),
            ),
        )

    @server.tool(name="verify_quote_or_claim", structured_output=True)
    def verify_quote_or_claim(
        project_id: str = Field(..., min_length=1, max_length=256),
        passage_id: str = Field(..., min_length=1, max_length=256),
        quote_text: str = Field(..., min_length=8, max_length=4000),
        verification_type: str = Field(default="exact_quote", max_length=64),
    ) -> dict[str, Any]:
        if verification_type != "exact_quote":
            def unsupported() -> Any:
                raise PolicyError("unsupported verification type")
            return runtime.invoke("verify_quote_or_claim", unsupported)
        return runtime.invoke(
            "verify_quote_or_claim",
            lambda: runtime.service.verify_quote(
                project_id=runtime._validate_id(project_id, "project_id"),
                passage_id=runtime._validate_id(passage_id, "passage_id"),
                quote=runtime._validate_text(quote_text, "quote_text", 4000),
            ),
            allow_token=True,
        )

    @server.tool(name="submit_verified_evidence", structured_output=True)
    def submit_verified_evidence(
        project_id: str = Field(..., min_length=1, max_length=256),
        verification_token: str = Field(..., min_length=16, max_length=512),
    ) -> dict[str, Any]:
        return runtime.invoke(
            "submit_verified_evidence",
            lambda: runtime.service.submit_verified_evidence(
                project_id=runtime._validate_id(project_id, "project_id"),
                verification_token=runtime._validate_text(verification_token, "verification_token", 512),
            ),
        )

    @server.tool(name="get_search_history", structured_output=True)
    def get_search_history(
        project_id: str = Field(..., min_length=1, max_length=256),
        limit: int = Field(default=20, ge=1, le=100),
    ) -> dict[str, Any]:
        return runtime.invoke(
            "get_search_history",
            lambda: runtime.service.get_search_history(
                project_id=runtime._validate_id(project_id, "project_id"), limit=limit
            ),
        )

    @server.tool(name="submit_research_report", structured_output=True)
    def submit_research_report(
        project_id: str = Field(..., min_length=1, max_length=256),
        question: str = Field(..., min_length=1, max_length=2000),
        summary: str = Field(..., min_length=1, max_length=8000),
        claims: list[ClaimInput] = Field(..., min_length=1, max_length=50),
        strongest_objection: str = Field(..., min_length=1, max_length=4000),
        alternative_explanations: list[str] = Field(default_factory=list, max_length=20),
        unresolved_questions: list[str] = Field(default_factory=list, max_length=20),
        evidence_limits: list[str] = Field(default_factory=list, max_length=20),
        next_steps: list[str] = Field(default_factory=list, max_length=20),
        research_leads: list[ResearchLeadInput] = Field(default_factory=list, max_length=6),
        source_table: list[SourceCitationInput] = Field(default_factory=list, max_length=50),
        evidence_citation_map: list[EvidenceCitationInput] = Field(default_factory=list, max_length=100),
        status: Literal["draft", "candidate"] = "candidate",
        supersedes_item_id: str | None = Field(default=None, max_length=256),
        deliverable_layer: Literal["A", "B", "C"] | None = Field(default=None),
        artifact_profile: Literal[
            "academic_paper", "method_appendix", "technical_report", "research_memo"
        ] | None = Field(default=None),
        writing_policy_id: str | None = Field(default=None, max_length=256),
        writing_policy_version: str | None = Field(default=None, max_length=64),
        writing_policy_snapshot: dict[str, Any] | None = Field(default=None),
        writing_policy_overrides: dict[str, Any] | None = Field(default=None),
        compression_review_status: Literal[
            "not_required", "pending", "passed", "returned"
        ] | None = Field(default=None),
        writing_audit_summary: dict[str, Any] | None = Field(default=None),
    ) -> dict[str, Any]:
        def call() -> Any:
            clean_claims = [claim.model_dump(exclude_none=True) for claim in claims]
            clean_leads = [lead.model_dump(exclude_none=True) for lead in research_leads]
            clean_source_table = [entry.model_dump(exclude_none=True) for entry in source_table]
            clean_evidence_map = [entry.model_dump(exclude_none=True) for entry in evidence_citation_map]
            return runtime.service.submit_research_report(
                project_id=runtime._validate_id(project_id, "project_id"),
                question=runtime._validate_text(question, "question", 2000),
                summary=runtime._validate_text(summary, "summary", 8000),
                claims=clean_claims,
                strongest_objection=runtime._validate_text(strongest_objection, "strongest_objection", 4000),
                alternative_explanations=runtime._validate_list(alternative_explanations, "alternative_explanations", 20, 1000),
                unresolved_questions=runtime._validate_list(unresolved_questions, "unresolved_questions", 20, 1000),
                evidence_limits=runtime._validate_list(evidence_limits, "evidence_limits", 20, 1000),
                next_steps=runtime._validate_list(next_steps, "next_steps", 20, 1000),
                research_leads=clean_leads,
                source_table=clean_source_table,
                evidence_citation_map=clean_evidence_map,
                status=status,
                supersedes_item_id=(runtime._validate_id(supersedes_item_id, "supersedes_item_id") if supersedes_item_id else None),
                deliverable_layer=deliverable_layer,
                artifact_profile=artifact_profile,
                writing_policy_id=writing_policy_id,
                writing_policy_version=writing_policy_version,
                writing_policy_snapshot=writing_policy_snapshot,
                writing_policy_overrides=writing_policy_overrides,
                compression_review_status=compression_review_status,
                writing_audit_summary=writing_audit_summary,
            )

        return runtime.invoke("submit_research_report", call)

    @server.tool(name="request_user_approval", structured_output=True)
    def request_user_approval(
        project_id: str = Field(..., min_length=1, max_length=256),
        target_type: Literal["research_item", "evidence"] = Field(...),
        target_id: str = Field(..., min_length=1, max_length=256),
        rationale: str = Field(default="", max_length=4000),
    ) -> dict[str, Any]:
        def call() -> Any:
            clean_project = runtime._validate_id(project_id, "project_id")
            clean_target = runtime._validate_id(target_id, "target_id")
            return runtime.service.request_user_approval(
                project_id=clean_project,
                target_type=target_type,
                item_id=clean_target if target_type == "research_item" else None,
                verified_evidence_id=clean_target if target_type == "evidence" else None,
                rationale=runtime._validate_text(rationale, "rationale", 4000, required=False),
            )

        return runtime.invoke("request_user_approval", call)

    return server


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the research-kb MCP stdio server")
    parser.add_argument("--config", default=None, help="Path to the research-kb TOML configuration")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    try:
        settings = Settings.load(args.config)
        server = create_mcp_server(settings)
    except MCPStartupError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None
    except (OSError, ValueError, sqlite3.Error):
        print(
            "MCP startup failed: configuration or database is not ready. "
            "Run the Admin CLI init/status/migrate commands first.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    server.run(transport="stdio")


if __name__ == "__main__":
    main()



