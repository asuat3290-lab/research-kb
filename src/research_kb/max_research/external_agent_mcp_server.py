"""Independent MCP transport for the external-Agent control protocol.

This is deliberately a different MCP server from :mod:`research_kb.mcp_server`.
The researcher server keeps the exact-12 source/evidence tools; this server
only exposes the bounded Max work-session surface.  A process-started Actor is
the connection identity.  No tool accepts an actor id, role, admin flag,
database path, or source path from the worker.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

try:  # Keep the optional MCP dependency failure at the transport boundary.
    from mcp.server.fastmcp import FastMCP
    from pydantic import Field
except ModuleNotFoundError as exc:  # pragma: no cover - exercised without the extra
    if exc.name and exc.name.split(".", 1)[0] in {"mcp", "pydantic"}:
        raise SystemExit(
            "MCP support is not installed. Install it with: "
            "python -m pip install 'research-kb[mcp]'"
        ) from None
    raise

from ..config import Settings
from ..policy import Actor, PolicyError
from ..service import ResearchService
from .external_agent import EXTERNAL_AGENT_PROTOCOL, ExternalAgentService
from .persistence import MaxControlError, MaxControlRepository


MAX_CONTROL_MCP_PROTOCOL = "research-kb/max-control-mcp/v1"
MAX_CONTROL_MCP_NAME = "research-kb-max-control"
MAX_CONTROL_MCP_TOOLS = (
    "max_discover",
    "max_open_session",
    "max_close_session",
    "max_get_work_packet",
    "max_claim_work",
    "max_recover_work",
    "max_release_work",
    "max_submit_candidate",
    "max_get_submission_status",
    "max_verify",
)

_LOG = logging.getLogger("research_kb.max_control_mcp")


def _trace_id() -> str:
    return uuid.uuid4().hex[:20]


def _error_code(exc: BaseException) -> str:
    message = str(exc).casefold()
    if "outside the project" in message or "project boundary" in message or "not authorized" in message:
        return "OUT_OF_SCOPE"
    if "expired" in message:
        return "TOKEN_EXPIRED"
    if "not found" in message:
        return "NOT_FOUND"
    if "does not match" in message or "not permitted" in message or "requires the human" in message:
        return "FORBIDDEN"
    if "conflict" in message or "already" in message or "stale" in message or "current" in message:
        return "CONFLICT"
    if isinstance(exc, (TypeError, ValueError, PolicyError)):
        return "INVALID_ARGUMENT"
    return "INTERNAL"


def _failure(operation: str, exc: BaseException) -> dict[str, Any]:
    trace_id = _trace_id()
    _LOG.error("trace_id=%s operation=%s code=%s", trace_id, operation, _error_code(exc))
    return {
        "ok": False,
        "protocol": MAX_CONTROL_MCP_PROTOCOL,
        "operation": operation,
        "error": {
            "code": _error_code(exc),
            "message": "The Max control operation was rejected.",
        },
        "trace_id": trace_id,
    }


def _invoke(operation: str, call: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {
            "ok": True,
            "protocol": MAX_CONTROL_MCP_PROTOCOL,
            "operation": operation,
            "data": call(),
            "trace_id": _trace_id(),
        }
    except Exception as exc:  # The transport never exposes exception text.
        return _failure(operation, exc)


@dataclass(frozen=True)
class ExternalAgentConnection:
    """Trusted process-start configuration for one local MCP connection."""

    actor_id: str
    actor_session: str
    allowed_projects: tuple[str, ...]
    framework: str = "max-control-mcp"

    def actor(self) -> Actor:
        # A worker connection can never become an admin by choosing tool args.
        return Actor(
            actor_id=self.actor_id,
            session_id=self.actor_session,
            actor_kind="agent",
            role="researcher",
            framework=self.framework,
        )

    def require_project(self, project_id: str) -> str:
        if project_id not in self.allowed_projects:
            raise MaxControlError("project is not authorized for this connection")
        return project_id


class ResearchGatewaySourceResolver:
    """Resolve source identities through the existing governed research DB.

    The resolver intentionally returns only stable identifiers.  It may read a
    passage internally to validate project membership, but never returns its
    text to the Max control MCP or persists it in the control database.
    """

    def __init__(self, settings: Settings, actor: Actor) -> None:
        self.service = ResearchService(settings, actor)

    def resolve_reference(self, *, project_id: str, reference: Mapping[str, Any]) -> Mapping[str, Any] | None:
        try:
            passage_id = reference.get("passage_id")
            if isinstance(passage_id, str) and passage_id:
                passage = self.service.get_passage(project_id=project_id, passage_id=passage_id, context=0)
                return {
                    "project_id": project_id,
                    "document_id": passage["document_id"],
                    "passage_id": passage["passage_id"],
                }
            document_id = reference.get("document_id")
            if isinstance(document_id, str) and document_id:
                document = self.service.get_document_metadata(project_id=project_id, document_id=document_id)
                return {
                    "project_id": project_id,
                    "document_id": document["document_id"],
                }
        except Exception:
            return None
        return None


class ExternalAgentFastMCP(FastMCP):
    """FastMCP wrapper with bounded, non-sensitive validation errors."""

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
        except Exception as exc:
            return _failure(name, exc)


class ExternalAgentMCPRuntime:
    """MCP-facing facade around the single server-owned service."""

    def __init__(
        self,
        *,
        database: str | Path,
        connection: ExternalAgentConnection,
        source_resolver: Any | None = None,
    ) -> None:
        self.connection = connection
        self.actor = connection.actor()
        repository = MaxControlRepository(database, source_resolver=source_resolver)
        self.service = ExternalAgentService(repository)

    def project(self, project_id: str) -> str:
        return self.connection.require_project(project_id)

    def session(self, session_id: str) -> str:
        if not isinstance(session_id, str) or not session_id.strip():
            raise MaxControlError("session_id must be a non-empty string")
        return session_id


def create_external_agent_mcp_server(
    *,
    database: str | Path,
    actor_id: str,
    allowed_projects: Sequence[str],
    actor_session: str | None = None,
    source_resolver: Any | None = None,
) -> ExternalAgentFastMCP:
    """Build only the independent Max control tool surface.

    ``actor_id`` and ``actor_session`` are process-start configuration, not
    tool arguments.  A local stdio launch proves only that the configured
    process identity was used; it does not prove a remote model identity.
    """

    if not isinstance(actor_id, str) or not actor_id.strip():
        raise ValueError("actor_id is required at process start")
    projects = tuple(sorted({item.strip() for item in allowed_projects if isinstance(item, str) and item.strip()}))
    if not projects:
        raise ValueError("at least one allowed project is required at process start")
    connection = ExternalAgentConnection(
        actor_id=actor_id.strip(),
        actor_session=(actor_session or f"max-control-session-{uuid.uuid4().hex}"),
        allowed_projects=projects,
    )
    runtime = ExternalAgentMCPRuntime(
        database=database,
        connection=connection,
        source_resolver=source_resolver,
    )
    server = ExternalAgentFastMCP(
        MAX_CONTROL_MCP_NAME,
        instructions=(
            "Independent Max control surface. Research passages and evidence "
            "remain on the governed researcher MCP exact-12 surface."
        ),
        log_level="ERROR",
    )

    @server.tool(name="max_discover", structured_output=True)
    def max_discover() -> dict[str, Any]:
        return _invoke(
            "max_discover",
            lambda: {
                **ExternalAgentService.discover(),
                "operations": [tool.removeprefix("max_") for tool in MAX_CONTROL_MCP_TOOLS],
                "admin_operations": ["issue_work_packet", "issue_next_round"],
                "transport": MAX_CONTROL_MCP_PROTOCOL,
                "server_injected_connection": True,
                "worker_project_scope_is_startup_bound": True,
                "admin_operations_exposed": False,
                "tools": list(MAX_CONTROL_MCP_TOOLS),
                "research_surface": "existing exact-12 researcher MCP",
            },
        )

    @server.tool(name="max_open_session", structured_output=True)
    def max_open_session(
        project_id: str = Field(..., min_length=1, max_length=256),
        claimed_agent_id: str = Field(..., min_length=1, max_length=256),
        claimed_model: str | None = Field(default=None, max_length=256),
        ttl_seconds: int = Field(default=3600, ge=1, le=86400),
    ) -> dict[str, Any]:
        return _invoke(
            "max_open_session",
            lambda: runtime.service.open_session(
                project_id=runtime.project(project_id),
                authenticated_actor=runtime.actor,
                claimed_agent_id=claimed_agent_id,
                claimed_model=claimed_model,
                ttl_seconds=ttl_seconds,
            ),
        )

    @server.tool(name="max_close_session", structured_output=True)
    def max_close_session(session_id: str = Field(..., min_length=1, max_length=256)) -> dict[str, Any]:
        return _invoke(
            "max_close_session",
            lambda: runtime.service.close_session(
                session_id=runtime.session(session_id), authenticated_actor=runtime.actor
            ),
        )

    @server.tool(name="max_get_work_packet", structured_output=True)
    def max_get_work_packet(
        session_id: str = Field(..., min_length=1, max_length=256),
        work_packet_id: str = Field(..., min_length=1, max_length=256),
    ) -> dict[str, Any]:
        return _invoke(
            "max_get_work_packet",
            lambda: runtime.service.get_work_packet(
                session_id=runtime.session(session_id), work_packet_id=work_packet_id
            ),
        )

    @server.tool(name="max_claim_work", structured_output=True)
    def max_claim_work(
        session_id: str = Field(..., min_length=1, max_length=256),
        work_packet_id: str = Field(..., min_length=1, max_length=256),
        claim_ttl_seconds: int = Field(default=600, ge=1, le=3600),
    ) -> dict[str, Any]:
        return _invoke(
            "max_claim_work",
            lambda: runtime.service.claim_work(
                session_id=runtime.session(session_id),
                work_packet_id=work_packet_id,
                claim_ttl_seconds=claim_ttl_seconds,
            ),
        )

    @server.tool(name="max_recover_work", structured_output=True)
    def max_recover_work(
        session_id: str = Field(..., min_length=1, max_length=256),
        work_packet_id: str | None = Field(default=None, max_length=256),
    ) -> dict[str, Any]:
        return _invoke(
            "max_recover_work",
            lambda: runtime.service.recover_work(
                session_id=runtime.session(session_id), work_packet_id=work_packet_id
            ),
        )

    @server.tool(name="max_release_work", structured_output=True)
    def max_release_work(
        session_id: str = Field(..., min_length=1, max_length=256),
        work_packet_id: str = Field(..., min_length=1, max_length=256),
        claim_id: str = Field(..., min_length=1, max_length=256),
        reason: str = Field(..., min_length=1, max_length=500),
    ) -> dict[str, Any]:
        return _invoke(
            "max_release_work",
            lambda: runtime.service.release_work(
                session_id=runtime.session(session_id),
                work_packet_id=work_packet_id,
                claim_id=claim_id,
                reason=reason,
            ),
        )

    @server.tool(name="max_submit_candidate", structured_output=True)
    def max_submit_candidate(
        session_id: str = Field(..., min_length=1, max_length=256),
        work_packet_id: str = Field(..., min_length=1, max_length=256),
        claim_id: str = Field(..., min_length=1, max_length=256),
        result: dict[str, Any] = Field(...),
        expected_state_version: int = Field(..., ge=1),
        expected_state_hash: str = Field(..., min_length=64, max_length=64),
        idempotency_key: str = Field(..., min_length=1, max_length=128),
    ) -> dict[str, Any]:
        return _invoke(
            "max_submit_candidate",
            lambda: runtime.service.submit_candidate(
                session_id=runtime.session(session_id),
                work_packet_id=work_packet_id,
                claim_id=claim_id,
                expected_state_version=expected_state_version,
                expected_state_hash=expected_state_hash,
                idempotency_key=idempotency_key,
                result=result,
            ),
        )

    @server.tool(name="max_get_submission_status", structured_output=True)
    def max_get_submission_status(
        session_id: str = Field(..., min_length=1, max_length=256),
        work_packet_id: str = Field(..., min_length=1, max_length=256),
        idempotency_key: str = Field(..., min_length=1, max_length=128),
    ) -> dict[str, Any]:
        return _invoke(
            "max_get_submission_status",
            lambda: runtime.service.get_submission_status(
                session_id=runtime.session(session_id),
                work_packet_id=work_packet_id,
                idempotency_key=idempotency_key,
                authenticated_actor=runtime.actor,
            ),
        )

    @server.tool(name="max_verify", structured_output=True)
    def max_verify(
        session_id: str = Field(..., min_length=1, max_length=256),
        run_id: str | None = Field(default=None, max_length=256),
    ) -> dict[str, Any]:
        return _invoke(
            "max_verify",
            lambda: runtime.service.verify(
                run_id=run_id,
                session_id=runtime.session(session_id),
                authenticated_actor=runtime.actor,
            ),
        )

    return server


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the independent Max control MCP stdio server")
    parser.add_argument("--database", required=True, help="Server-selected Max control database")
    parser.add_argument("--actor-id", required=True, help="Trusted connection actor configured by the host")
    parser.add_argument("--actor-session", default=None, help="Optional trusted connection session id")
    parser.add_argument("--allowed-project", action="append", required=True, help="Project authorized for this process")
    parser.add_argument("--research-config", default=None, help="Optional research-kb config for server-owned source validation")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    try:
        actor_session = args.actor_session or f"max-control-session-{uuid.uuid4().hex}"
        actor = Actor(args.actor_id, actor_session, "agent", "researcher", "max-control-mcp")
        resolver = None
        if args.research_config:
            resolver = ResearchGatewaySourceResolver(Settings.load(args.research_config), actor)
        server = create_external_agent_mcp_server(
            database=args.database,
            actor_id=args.actor_id,
            actor_session=actor_session,
            allowed_projects=args.allowed_project,
            source_resolver=resolver,
        )
    except (OSError, ValueError, MaxControlError) as exc:
        print("Max control MCP startup failed: configuration or database is not ready.", file=sys.stderr)
        _LOG.error("startup failure: %s", type(exc).__name__)
        raise SystemExit(2) from None
    server.run(transport="stdio")


if __name__ == "__main__":
    main()


__all__ = [
    "ExternalAgentConnection",
    "ExternalAgentFastMCP",
    "ExternalAgentMCPRuntime",
    "MAX_CONTROL_MCP_NAME",
    "MAX_CONTROL_MCP_PROTOCOL",
    "MAX_CONTROL_MCP_TOOLS",
    "ResearchGatewaySourceResolver",
    "create_external_agent_mcp_server",
    "main",
]
